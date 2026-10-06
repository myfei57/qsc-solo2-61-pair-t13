"""Access service: approvals are durable and time bounded.

Ordering and recovery rule (write-ahead into the shared, append only event
log):

1. every decision is appended to the durable :class:`EventLog` first;
2. approval status, door state and audit trail are projections of that same
   log, rebuilt on restart, so they always read one source of truth;
3. a physical door action runs *after* its intent event is durable.  If the
   seal fails a ``door_seal_failed`` fact is appended and the intent stays
   pending; :meth:`reconcile` retries it, which makes a partial revocation
   recoverable;
4. every command carries an idempotency key, so retries and duplicate
   revocations never apply the same fact twice;
5. past entry/exit facts are immutable: corrections arrive as new events.

Revocation while the holder is still inside is *exit-first*: access is
withdrawn and the door becomes exit-only immediately, but the physical seal
waits for the recorded exit.  ``force_seal`` is an explicit emergency bypass.
"""

from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Callable
from typing import Protocol

from tunnelnet.store import Approval, Store
from tunnelnet.store.accesslog import Event, EventLog
from tunnelnet.store.approval import (
    DEFAULT_ACTIVATION_WINDOW,
    DEFAULT_VALID_SECONDS,
    STATUS_ACTIVE,
    STATUS_EXPIRED,
    STATUS_REVOKED,
    save_approval,
)

from .model import AccessRequest
from .projection import (
    EVENT_APPROVED,
    EVENT_ENTERED,
    EVENT_EXPIRED,
    EVENT_EXITED,
    EVENT_OPENED,
    EVENT_RELEASED,
    EVENT_REVOKED,
    EVENT_SEALED,
    EVENT_SEAL_FAILED,
    EVENT_SEAL_REQUESTED,
    AccessProjection,
    audit_events,
    expiry_reason,
    is_expired,
    replay,
)
from .report import AccessState, request_payloads
from .summary import summarize


def utc_epoch() -> float:
    return time.time()


def iso(epoch: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


class DoorController(Protocol):
    """Physical cabin door driven after an intent is durable."""

    def release_door(self, cabin_id: str) -> None:  # pragma: no cover - structural
        ...

    def seal_door(self, cabin_id: str) -> None:  # pragma: no cover - structural
        ...


class DoorSealError(RuntimeError):
    """Raised by a door controller when a physical seal could not complete."""


class AccessService:
    """Grants time bounded approvals, releases doors, revokes and expires them."""

    def __init__(
        self,
        store: Store,
        doors: DoorController,
        clock: Callable[[], float] = utc_epoch,
        *,
        reconcile_on_start: bool = True,
    ) -> None:
        self._store = store
        self._doors = doors
        self._clock = clock
        self._log = EventLog(store)
        self._lock = threading.RLock()
        self._requests: list[AccessRequest] = []
        self._view: AccessProjection = replay(self._log.events())
        # Complete seals whose durable intent survived a crash or a jam, so a
        # partially failed revocation heals itself on (re)start.
        if reconcile_on_start:
            self.reconcile()

    # ---------------------------------------------------------------- requests

    def submit(self, cabin_id: str, requester: str) -> AccessRequest:
        request = AccessRequest(id=uuid.uuid4().hex, cabin_id=cabin_id, requester=requester)
        with self._lock:
            self._requests.append(request)
        return request

    def pending(self) -> list[AccessRequest]:
        with self._lock:
            return [request for request in self._requests if request.status == "pending"]

    # ------------------------------------------------------------- approving

    def approve(
        self,
        cabin_id: str,
        requester: str,
        valid_for_seconds: int = DEFAULT_VALID_SECONDS,
        activation_window_seconds: int = DEFAULT_ACTIVATION_WINDOW,
        *,
        idem: str = "",
    ) -> Approval:
        """Grant a time bounded approval, persist it, then release the door.

        The validity window starts at the first release/entry.  An unreleased
        approval must be activated within ``activation_window_seconds``.
        """

        if valid_for_seconds <= 0:
            raise ValueError("valid_for_seconds must be positive")
        if activation_window_seconds <= 0:
            raise ValueError("activation_window_seconds must be positive")
        with self._lock:
            now = self._clock()
            approval_id = uuid.uuid4().hex
            activate_by = now + activation_window_seconds
            event = self._commit(
                Event(
                    seq=0,
                    at=str(now),
                    type=EVENT_APPROVED,
                    approval_id=approval_id,
                    cabin_id=cabin_id,
                    requester=requester,
                    key=idem,
                    payload={
                        "valid_for_seconds": str(valid_for_seconds),
                        "activate_by": str(activate_by),
                    },
                )
            )
            approval = self._materialize(approval_id, event)
            # Open the door so the ticket is usable.  Opening does not consume
            # the validity window: the clock starts at the first recorded
            # entry, not while an approved holder is still en route.
            self._open_door(approval_id)
            return self._snapshot_approval(approval_id)

    def grant(self, request_id: str, **options: object) -> Approval:
        with self._lock:
            target = next((item for item in self._requests if item.id == request_id), None)
            if target is None:
                raise ValueError("request not found")
            target.status = "granted"
            cabin_id, requester = target.cabin_id, target.requester
        return self.approve(cabin_id, requester, **options)  # type: ignore[arg-type]

    # --------------------------------------------------------------- releases

    def _open_door(self, approval_id: str) -> None:
        """Persist a physical door opening without anchoring the time window."""

        approval = self._view.approvals[approval_id]
        self._commit(
            Event(
                seq=0,
                at=str(self._clock()),
                type=EVENT_OPENED,
                approval_id=approval_id,
                cabin_id=approval.cabin_id,
                requester=approval.requester,
                key=f"open:{approval_id}",
            )
        )
        self._doors.release_door(approval.cabin_id)

    def _release(self, approval_id: str) -> bool:
        """Persist the first-release anchor, then ensure the door is open.

        Returns ``False`` when the approval no longer admits entry.  The door
        call happens after the durable event, so a crash leaves a release that
        reconciliation can resume rather than a door open with no ticket.
        """

        approval = self._view.approvals.get(approval_id)
        if approval is None or not self._admits(approval):
            return False
        now = self._clock()
        if approval.first_release_at is None:
            self._commit(
                Event(
                    seq=0,
                    at=str(now),
                    type=EVENT_RELEASED,
                    approval_id=approval_id,
                    cabin_id=approval.cabin_id,
                    requester=approval.requester,
                    key=f"release:{approval_id}",
                )
            )
        if not self._view.cabin(approval.cabin_id).physical_open:
            self._doors.release_door(approval.cabin_id)
        return True

    def _admits(self, approval) -> bool:  # type: ignore[no-untyped-def]
        if approval.status != STATUS_ACTIVE:
            return False
        return not is_expired(approval, self._clock())

    def enter(self, approval_id: str, *, idem: str = "") -> bool:
        """Record a physical entry under an approval and anchor its window."""

        with self._lock:
            approval = self._view.approvals.get(approval_id)
            if approval is None:
                return False
            # A withdrawn ticket can never enter or re-enter, even standing in
            # an open, exit-only doorway.
            if not self._admits(approval):
                return False
            if approval.occupied:
                return True
            # First entry anchors the validity window; later entries while the
            # ticket is live just reuse the already open door.
            if approval.first_release_at is None:
                self._release(approval_id)
            elif not self._view.cabin(approval.cabin_id).physical_open:
                self._doors.release_door(approval.cabin_id)
            self._commit(
                Event(
                    seq=0,
                    at=str(self._clock()),
                    type=EVENT_ENTERED,
                    approval_id=approval_id,
                    cabin_id=approval.cabin_id,
                    requester=approval.requester,
                    key=idem or f"enter:{approval_id}:1",
                )
            )
            self._persist_document(approval_id)
            return True

    def exit(self, approval_id: str, *, idem: str = "") -> bool:
        """Record a physical exit; an exit-only door may seal afterwards."""

        with self._lock:
            approval = self._view.approvals.get(approval_id)
            if approval is None or not approval.occupied:
                return False
            self._commit(
                Event(
                    seq=0,
                    at=str(self._clock()),
                    type=EVENT_EXITED,
                    approval_id=approval_id,
                    cabin_id=approval.cabin_id,
                    requester=approval.requester,
                    key=idem or f"exit:{approval_id}:1",
                )
            )
            self._persist_document(approval_id)
            self.reconcile()
            return True

    # -------------------------------------------------------------- revoking

    def revoke(self, approval_id: str, reason: str = "", *, force_seal: bool = False) -> bool:
        """Withdraw an approval and reclaim its door release.

        Idempotent: revoking an already revoked/expired approval is a no-op
        that still reports the current withdrawn state.  When the holder is
        inside, the door becomes exit-only and seals on exit; ``force_seal``
        seals immediately regardless of occupancy.
        """

        with self._lock:
            approval = self._view.approvals.get(approval_id)
            if approval is None:
                raise KeyError(approval_id)
            if approval.status != STATUS_ACTIVE:
                return False
            now = self._clock()
            self._commit(
                Event(
                    seq=0,
                    at=str(now),
                    type=EVENT_REVOKED,
                    approval_id=approval_id,
                    cabin_id=approval.cabin_id,
                    requester=approval.requester,
                    payload={"reason": reason},
                )
            )
            self._request_seal(approval_id, force=force_seal)
            self._persist_document(approval_id)
            self.reconcile()
            return True

    def _request_seal(self, approval_id: str, *, force: bool) -> None:
        approval = self._view.approvals[approval_id]
        if approval.pending_seal:
            return
        self._commit(
            Event(
                seq=0,
                at=str(self._clock()),
                type=EVENT_SEAL_REQUESTED,
                approval_id=approval_id,
                cabin_id=approval.cabin_id,
                requester=approval.requester,
                payload={"force": "1" if force else "0"},
                key=f"seal-request:{approval_id}",
            )
        )
        if force and self._view.approvals[approval_id].occupied:
            # Emergency bypass: occupancy is overridden by the operator.
            forced = self._view.approvals[approval_id]
            forced.occupied = False
            cabin = self._view.cabin(forced.cabin_id)
            cabin.occupants.discard(forced.requester)

    # --------------------------------------------------------------- expiry

    def expire_due(self) -> list[str]:
        """Expire every active approval whose window or deadline has lapsed."""

        expired: list[str] = []
        with self._lock:
            now = self._clock()
            for approval_id, approval in list(self._view.approvals.items()):
                if not is_expired(approval, now):
                    continue
                self._commit(
                    Event(
                        seq=0,
                        at=str(now),
                        type=EVENT_EXPIRED,
                        approval_id=approval_id,
                        cabin_id=approval.cabin_id,
                        requester=approval.requester,
                        payload={"reason": expiry_reason(approval, now)},
                        key=f"expire:{approval_id}",
                    )
                )
                self._request_seal(approval_id, force=False)
                self._persist_document(approval_id)
                expired.append(approval_id)
            if expired:
                self.reconcile()
        return expired

    # ----------------------------------------------------------- reconciliation

    def reconcile(self) -> dict[str, int]:
        """Drive physical doors to match the durable projection.

        Seals pending from a failed or interrupted revocation/expiry are
        retried here; a failed attempt is recorded but never blocks the rest.
        Every physically open cabin with no live approval and no occupant is
        brought closed, which also heals a seal whose completion crashed before
        its ``door_sealed`` fact was written.
        """

        sealed = failed = 0
        with self._lock:
            for cabin_id, cabin in list(self._view.cabins.items()):
                if not cabin.physical_open:
                    continue
                live = [
                    a
                    for a in self._view.approvals.values()
                    if a.cabin_id == cabin_id
                    and a.status == STATUS_ACTIVE
                    and not is_expired(a, self._clock())
                ]
                if live or cabin.occupants:
                    continue
                if not self._seal_cabin(cabin_id):
                    failed += 1
                else:
                    sealed += 1
        return {"sealed": sealed, "failed": failed}

    def _seal_cabin(self, cabin_id: str) -> bool:
        # Approvals that lost admission for this cabin but never recorded the
        # sealed fact, including a seal interrupted by a restart, all close now.
        due = [
            approval_id
            for approval_id, approval in self._view.approvals.items()
            if approval.cabin_id == cabin_id
            and not approval.active()
            and not approval.occupied
            and (approval.pending_seal or approval.ended_at is None)
        ]
        pending = [
            approval_id for approval_id in due if self._view.approvals[approval_id].pending_seal
        ]
        unrequested = [approval_id for approval_id in due if approval_id not in pending]
        for approval_id in unrequested:
            approval = self._view.approvals[approval_id]
            self._commit(
                Event(
                    seq=0,
                    at=str(self._clock()),
                    type=EVENT_SEAL_REQUESTED,
                    approval_id=approval_id,
                    cabin_id=cabin_id,
                    requester=approval.requester,
                    payload={"reason": "reconcile"},
                    key=f"seal-request:{approval_id}",
                )
            )
        try:
            self._doors.seal_door(cabin_id)
        except Exception as exc:  # controller failure is a fact, not a crash
            for approval_id in due:
                approval = self._view.approvals[approval_id]
                if approval.seal_failed:
                    continue
                self._commit(
                    Event(
                        seq=0,
                        at=str(self._clock()),
                        type=EVENT_SEAL_FAILED,
                        approval_id=approval_id,
                        cabin_id=cabin_id,
                        requester=approval.requester,
                        payload={"error": str(exc)},
                        key=f"seal-failed:{approval_id}",
                    )
                )
            cabin = self._view.cabin(cabin_id)
            cabin.seal_failed = True
            cabin.physical_open = True
            return False

        for approval_id in due:
            self._commit(
                Event(
                    seq=0,
                    at=str(self._clock()),
                    type=EVENT_SEALED,
                    approval_id=approval_id,
                    cabin_id=cabin_id,
                    key=f"sealed:{approval_id}",
                )
            )
            self._persist_document(approval_id)
        cabin = self._view.cabin(cabin_id)
        cabin.door_open = False
        cabin.physical_open = False
        cabin.exit_only = False
        cabin.pending_seal = False
        cabin.seal_failed = False
        return True

    # -------------------------------------------------------------- internals

    def _commit(self, template: Event) -> Event:
        """Append an event unless its idempotency key was already seen.

        Returns the event carrying the real sequence number.  A duplicate key
        is silently dropped and the earlier event is returned instead.
        """

        if template.key and template.key in self._view.seen_keys:
            for prior in reversed(self._view.events):
                if prior.key == template.key:
                    return prior
        event = Event(
            seq=self._log.next_seq(),
            at=template.at,
            type=template.type,
            approval_id=template.approval_id,
            cabin_id=template.cabin_id,
            requester=template.requester,
            key=template.key,
            payload=template.payload,
        )
        self._log.append(event)
        self._apply_one(event)
        return event

    def _apply_one(self, event: Event) -> None:
        from .projection import _apply  # local import keeps replay cohesive

        _apply(self._view, event)
        self._view.events.append(event)

    def _materialize(self, approval_id: str, event: Event) -> Approval:
        state = self._view.approvals[approval_id]
        approval = Approval(
            id=approval_id,
            cabin_id=state.cabin_id,
            requester=state.requester,
            granted_at=iso(state.granted_at),
            valid_for_seconds=state.valid_for_seconds,
            activate_by=iso(state.activate_by) if state.activate_by else "",
            status=STATUS_ACTIVE,
        )
        save_approval(self._store, approval)
        return approval

    def _persist_document(self, approval_id: str) -> None:
        state = self._view.approvals[approval_id]
        if state.status == STATUS_ACTIVE:
            status = STATUS_ACTIVE
        elif state.status == STATUS_EXPIRED:
            status = STATUS_EXPIRED
        else:
            status = STATUS_REVOKED
        approval = Approval(
            id=state.id,
            cabin_id=state.cabin_id,
            requester=state.requester,
            granted_at=iso(state.granted_at),
            valid_for_seconds=state.valid_for_seconds,
            activate_by=iso(state.activate_by) if state.activate_by else "",
            status=status,
            first_release_at=iso(state.first_release_at) if state.first_release_at else "",
            effective_expires_at=iso(state.expires_at) if state.expires_at else "",
            revoked_at=iso(state.revoked_at) if state.revoked_at else "",
            revoked_reason=state.revoked_reason,
            expires_at=iso(state.expires_at) if state.expires_at else "",
            sealed_at=iso(state.ended_at) if state.ended_at and state.pending_seal is False else "",
        )
        save_approval(self._store, approval)

    # ---------------------------------------------------------------- readers

    def approved(self, approval_id: str) -> bool:
        """Whether the approval currently admits entry (live and unexpired)."""

        with self._lock:
            self.expire_due()
            approval = self._view.approvals.get(approval_id)
            return approval is not None and self._admits(approval)

    def status(self, approval_id: str) -> str:
        with self._lock:
            self.expire_due()
            approval = self._view.approvals.get(approval_id)
            if approval is None:
                return "missing"
            if approval.status == STATUS_ACTIVE:
                return STATUS_ACTIVE
            if approval.pending_seal:
                return f"{approval.status}_pending_seal"
            return approval.status

    def door_state(self, cabin_id: str) -> bool:
        """Physical door position, reconciled toward the durable projection."""

        with self._lock:
            self.reconcile()
            cabin = self._view.cabins.get(cabin_id)
            return bool(cabin and cabin.physical_open)

    def release_active(self, cabin_id: str) -> bool:
        """Whether a live approval still logically releases the cabin door."""

        with self._lock:
            self.expire_due()
            cabin = self._view.cabins.get(cabin_id)
            return bool(cabin and cabin.door_open)

    def door_is_exit_only(self, cabin_id: str) -> bool:
        with self._lock:
            self.reconcile()
            cabin = self._view.cabins.get(cabin_id)
            return bool(cabin and cabin.exit_only)

    def occupants(self, cabin_id: str) -> list[str]:
        with self._lock:
            cabin = self._view.cabins.get(cabin_id)
            return sorted(cabin.occupants) if cabin else []

    def stream(self) -> list[Event]:
        with self._lock:
            return audit_events(self._view)

    def approval_state(self, approval_id: str):  # type: ignore[no-untyped-def]
        with self._lock:
            return self._view.approvals.get(approval_id)

    def _snapshot_approval(self, approval_id: str) -> Approval:
        state = self._view.approvals[approval_id]
        return Approval(
            id=state.id,
            cabin_id=state.cabin_id,
            requester=state.requester,
            granted_at=iso(state.granted_at),
            valid_for_seconds=state.valid_for_seconds,
            activate_by=iso(state.activate_by) if state.activate_by else "",
            status=STATUS_ACTIVE,
        )

    def request_count(self) -> int:
        with self._lock:
            return len(self._requests)

    def requests(self) -> list[AccessRequest]:
        with self._lock:
            return list(self._requests)

    def summary(self) -> dict[str, int]:
        return summarize(self.requests())

    def state(self) -> AccessState:
        summary = self.summary()
        return AccessState(
            requests=request_payloads(self.requests()),
            pending=summary["pending"],
            granted=summary["granted"],
        )

    def describe(self) -> str:
        summary = self.summary()
        return f"access requests={summary['requests']} pending={summary['pending']}"
