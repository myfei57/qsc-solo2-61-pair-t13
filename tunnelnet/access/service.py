"""Access service: time boxed approvals persisted before the door is released."""

from __future__ import annotations

import threading
import uuid
from collections.abc import Callable

from tunnelnet.audit import AuditRegistry, Record
from tunnelnet.drain import utc_now
from tunnelnet.store import (
    ACTIVE,
    EXPIRED,
    REVOKED,
    Approval,
    Store,
    approval_exists,
    epoch_to_iso,
    is_expired,
    iso_to_epoch,
    list_approvals,
    load_approval,
    save_approval,
    transition_approval,
)

from .doors import DoorLedger, DoorRecord
from .model import AccessRequest
from .report import AccessState, request_payloads
from .summary import summarize

DEFAULT_TTL_SECONDS = 8 * 3600
MAX_TTL_SECONDS = 7 * 24 * 3600

TERMINAL_EVENTS = {REVOKED: "access_revoked", EXPIRED: "access_expired"}


class AccessService:
    """Grants time boxed approvals and reclaims the door when they end.

    The validity window starts at the approval moment, so an approval
    requested ahead of time still expires on a fixed, persisted stamp.
    Revocation takes effect on the authorization immediately; a door with
    people still inside is flagged ``closing_pending`` and seals itself
    once the cabin is empty, instead of locking people in.
    """

    def __init__(
        self,
        store: Store,
        doors: DoorLedger,
        clock: Callable[[], str] = utc_now,
        default_ttl_seconds: int = DEFAULT_TTL_SECONDS,
        max_ttl_seconds: int = MAX_TTL_SECONDS,
        audit: AuditRegistry | None = None,
    ) -> None:
        self._store = store
        self._doors = doors
        self._clock = clock
        self._default_ttl = default_ttl_seconds
        self._max_ttl = max_ttl_seconds
        self._audit = audit if audit is not None else doors.audit
        self._lock = threading.RLock()
        self._requests: list[AccessRequest] = []

    def submit(self, cabin_id: str, requester: str) -> AccessRequest:
        request = AccessRequest(id=uuid.uuid4().hex, cabin_id=cabin_id, requester=requester)
        with self._lock:
            self._requests.append(request)
        return request

    def pending(self) -> list[AccessRequest]:
        with self._lock:
            return [request for request in self._requests if request.status == "pending"]

    def approve(self, cabin_id: str, requester: str, ttl_seconds: int = 0) -> Approval:
        """Persist the approval first, then release the cabin door.

        When the door release fails the just persisted approval is revoked
        again, so a half granted approval never lingers as a valid ticket.
        """

        granted_at = self._clock()
        approval = Approval(
            id=uuid.uuid4().hex,
            cabin_id=cabin_id,
            requester=requester,
            granted_at=granted_at,
            expires_at=epoch_to_iso(iso_to_epoch(granted_at) + self._ttl(ttl_seconds)),
        )
        save_approval(self._store, approval)
        self._write_audit("access_approved", approval.id)
        try:
            self._doors.release(cabin_id, approval_id=approval.id, source="approval")
        except Exception:
            transition_approval(self._store, approval, REVOKED, self._clock())
            self._write_audit("access_revoked", approval.id)
            raise
        return approval

    def grant(self, request_id: str, ttl_seconds: int = 0) -> Approval:
        with self._lock:
            target = next((item for item in self._requests if item.id == request_id), None)
            if target is None:
                raise ValueError("request not found")
            target.status = "granted"
        return self.approve(target.cabin_id, target.requester, ttl_seconds)

    def revoke(self, approval_id: str) -> tuple[Approval, str]:
        """Revoke one approval and reclaim the door release it paid for.

        Every step is idempotent and the whole operation is re-entrant: a
        partial failure is recovered by calling revoke again, and a repeated
        revoke returns the same outcome instead of failing.
        """

        with self._lock:
            approval = load_approval(self._store, approval_id)
            if approval is None:
                raise KeyError(approval_id)
            if approval.status != REVOKED:
                approval = transition_approval(self._store, approval, REVOKED, self._clock())
                self._write_audit("access_revoked", approval.id)
            return approval, self._reclaim_door(approval)

    def sweep_expired(self) -> list[Approval]:
        """Expire every approval whose window has closed and reclaim its door."""

        now = self._clock()
        expired: list[Approval] = []
        with self._lock:
            for approval in list_approvals(self._store):
                if approval.status == ACTIVE and is_expired(approval, now, self._default_ttl):
                    updated = transition_approval(self._store, approval, EXPIRED, now)
                    self._write_audit("access_expired", updated.id)
                    self._reclaim_door(updated)
                    expired.append(updated)
        return expired

    def enter(self, approval_id: str) -> DoorRecord:
        """Register one person walking in; only a valid approval gets in."""

        with self._lock:
            approval = self._require(approval_id)
            if approval.status != ACTIVE:
                self._deny(approval, f"approval {approval_id} is {approval.status}")
            if is_expired(approval, self._clock(), self._default_ttl):
                approval = transition_approval(self._store, approval, EXPIRED, self._clock())
                self._write_audit("access_expired", approval.id)
                self._reclaim_door(approval)
                self._deny(approval, f"approval {approval_id} has expired")
            door = self._doors.state(approval.cabin_id)
            if not door.released or door.closing_pending:
                self._deny(approval, f"door {approval.cabin_id} is not released")
            record = self._doors.enter(approval.cabin_id)
            self._write_audit("access_entered", approval.cabin_id)
            return record

    def exit(self, approval_id: str, cabin_id: str = "") -> DoorRecord:
        """Register one person walking out; exit is never refused.

        The approval may already be revoked or expired by the time the
        person leaves, and a wiped store must not trap anyone either, so a
        bare cabin id is accepted as a fallback reference.
        """

        with self._lock:
            approval = load_approval(self._store, approval_id) if approval_id else None
            if approval is None and not cabin_id:
                raise KeyError(approval_id)
            cabin = approval.cabin_id if approval is not None else cabin_id
            record = self._doors.exit(cabin)
            self._write_audit("access_exited", cabin)
            return record

    def is_valid(self, approval_id: str) -> bool:
        """Whether the approval is active and inside its validity window."""

        approval = load_approval(self._store, approval_id)
        return (
            approval is not None
            and approval.status == ACTIVE
            and not is_expired(approval, self._clock(), self._default_ttl)
        )

    def approved(self, approval_id: str) -> bool:
        return approval_exists(self._store, approval_id)

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

    def _ttl(self, ttl_seconds: int) -> int:
        if ttl_seconds <= 0:
            return self._default_ttl
        return min(ttl_seconds, self._max_ttl)

    def _require(self, approval_id: str) -> Approval:
        approval = load_approval(self._store, approval_id)
        if approval is None:
            raise KeyError(approval_id)
        return approval

    def _reclaim_door(self, approval: Approval) -> str:
        """Take back the door release one approval paid for.

        Only the release tagged with this approval is reclaimed; a door
        since re-released manually or by another approval is left alone.
        """

        door = self._doors.state(approval.cabin_id)
        if not door.released or door.approval_id != approval.id:
            return "already_clear"
        if door.occupancy > 0:
            self._doors.request_close(approval.cabin_id)
            return "closing_pending"
        self._doors.seal(approval.cabin_id, reason="revoked")
        return "sealed"

    def _deny(self, approval: Approval, message: str) -> None:
        self._write_audit("access_enter_denied", approval.cabin_id)
        raise ValueError(message)

    def _write_audit(self, event: str, ref: str) -> None:
        if self._audit is not None:
            self._audit.append(Record(id=uuid.uuid4().hex, event=event, at=self._clock(), ref=ref))
