"""State rebuilt by replaying the durable access event stream.

Every reader in the access domain derives its view from the same ordered
events: approval lifecycle, who is inside a cabin, whether the physical door
should be open, and the audit trail.  Nothing here is written directly; a
state change is always one more appended event, replayed on restart.

Validity policy (a single, deliberate choice):

* the validity window starts at the **first release/entry**, not at the
  approval instant, so applying ahead of a job does not burn the window;
* an unreleased approval still has an ``activate_by`` ceiling, after which it
  expires unused;
* while someone is inside, an expiring or revoked approval turns the door
  exit-only and seals on exit rather than locking a person in.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from tunnelnet.store.accesslog import Event
from tunnelnet.store.approval import (
    DEFAULT_ACTIVATION_WINDOW,
    DEFAULT_VALID_SECONDS,
    STATUS_ACTIVE,
    STATUS_EXPIRED,
    STATUS_REVOKED,
)

# Lifecycle events ----------------------------------------------------------
EVENT_APPROVED = "approval_granted"
EVENT_OPENED = "door_opened"
EVENT_RELEASED = "door_released"
EVENT_ENTERED = "cabin_entered"
EVENT_EXITED = "cabin_exited"
EVENT_REVOKED = "approval_revoked"
EVENT_EXPIRED = "approval_expired"
EVENT_SEAL_REQUESTED = "door_seal_requested"
EVENT_SEALED = "door_sealed"
EVENT_SEAL_FAILED = "door_seal_failed"


@dataclass
class ApprovalState:
    """Lifecycle view of one approval."""

    id: str
    cabin_id: str
    requester: str
    granted_at: float
    valid_for_seconds: int = DEFAULT_VALID_SECONDS
    activate_by: float = 0.0
    status: str = STATUS_ACTIVE
    first_release_at: float | None = None
    entered_at: float | None = None
    expires_at: float | None = None
    revoked_at: float | None = None
    revoked_reason: str = ""
    ended_at: float | None = None
    pending_seal: bool = False
    seal_failed: bool = False
    occupied: bool = False

    def active(self) -> bool:
        return self.status == STATUS_ACTIVE

    def inside(self) -> bool:
        return self.occupied

    def effective_expiry(self) -> float | None:
        """Absolute deadline once first release anchored the window."""

        return self.expires_at


@dataclass
class CabinAccess:
    """Door and occupancy projection for one cabin."""

    door_open: bool = False
    physical_open: bool = False
    exit_only: bool = False
    occupants: set[str] = field(default_factory=set)
    active_approval_ids: set[str] = field(default_factory=set)
    pending_seal: bool = False
    seal_failed: bool = False


@dataclass
class AccessProjection:
    """Everything the access domain can answer, rebuilt from events."""

    approvals: dict[str, ApprovalState] = field(default_factory=dict)
    cabins: dict[str, CabinAccess] = field(default_factory=dict)
    seen_keys: set[str] = field(default_factory=set)
    events: list[Event] = field(default_factory=list)

    def cabin(self, cabin_id: str) -> CabinAccess:
        return self.cabins.setdefault(cabin_id, CabinAccess())

    def audit(self) -> list[Event]:
        return list(self.events)


def replay(events: list[Event]) -> AccessProjection:
    """Fold the durable event stream into the current projection."""

    view = AccessProjection()
    for event in sorted(events, key=lambda item: item.seq):
        _apply(view, event)
        view.events.append(event)
    return view


def _stamp(event: Event) -> float:
    try:
        return float(event.at)
    except ValueError:
        return 0.0


def _apply(view: AccessProjection, event: Event) -> None:
    if event.key:
        view.seen_keys.add(event.key)

    kind = event.type
    if kind == EVENT_APPROVED:
        payload = event.payload or {}
        try:
            valid_for = int(payload.get("valid_for_seconds", DEFAULT_VALID_SECONDS))
        except ValueError:
            valid_for = DEFAULT_VALID_SECONDS
        activate_by = _optional(payload.get("activate_by", ""))
        view.approvals[event.approval_id] = ApprovalState(
            id=event.approval_id,
            cabin_id=event.cabin_id,
            requester=event.requester,
            granted_at=_stamp(event),
            valid_for_seconds=valid_for,
            activate_by=activate_by if activate_by is not None else 0.0,
        )
        return

    approval = view.approvals.get(event.approval_id) if event.approval_id else None
    cabin = view.cabin(event.cabin_id) if event.cabin_id else None

    if kind == EVENT_OPENED and approval is not None and cabin is not None:
        # The door is physically open and admission is live, yet the validity
        # window stays un-anchored until the first actual release/entry.
        cabin.door_open = True
        cabin.physical_open = True
        cabin.seal_failed = False
        cabin.exit_only = False
        cabin.active_approval_ids.add(approval.id)

    elif kind == EVENT_RELEASED and approval is not None and cabin is not None:
        if approval.first_release_at is None:
            approval.first_release_at = _stamp(event)
            approval.expires_at = approval.first_release_at + approval.valid_for_seconds
        cabin.door_open = True
        cabin.physical_open = True
        cabin.seal_failed = False
        cabin.exit_only = not approval.active()
        if approval.active():
            cabin.active_approval_ids.add(approval.id)

    elif kind == EVENT_ENTERED and approval is not None and cabin is not None:
        if not approval.occupied:
            approval.occupied = True
            approval.entered_at = _stamp(event)
            cabin.occupants.add(event.requester or approval.requester)

    elif kind == EVENT_EXITED and approval is not None and cabin is not None:
        if approval.occupied:
            approval.occupied = False
            cabin.occupants.discard(event.requester or approval.requester)

    elif kind == EVENT_REVOKED and approval is not None:
        approval.status = STATUS_REVOKED
        approval.revoked_at = _stamp(event)
        approval.revoked_reason = (event.payload or {}).get("reason", "")
        if cabin is not None:
            cabin.active_approval_ids.discard(approval.id)

    elif kind == EVENT_EXPIRED and approval is not None:
        approval.status = STATUS_EXPIRED
        approval.ended_at = _stamp(event)
        if cabin is not None:
            cabin.active_approval_ids.discard(approval.id)

    elif kind == EVENT_SEAL_REQUESTED and approval is not None and cabin is not None:
        approval.pending_seal = True
        approval.seal_failed = False
        cabin.pending_seal = True
        cabin.seal_failed = False

    elif kind == EVENT_SEAL_FAILED and approval is not None and cabin is not None:
        approval.seal_failed = True
        cabin.seal_failed = True

    elif kind == EVENT_SEALED and approval is not None and cabin is not None:
        approval.pending_seal = False
        approval.seal_failed = False
        approval.ended_at = _stamp(event)
        cabin.pending_seal = False
        cabin.seal_failed = False
        cabin.physical_open = False

    if cabin is not None:
        _reconcile_cabin(cabin)


def _reconcile_cabin(cabin: CabinAccess) -> None:
    """Derive the desired admission shape from approvals and occupancy.

    ``door_open`` answers "does a live approval still release this door?";
    ``physical_open`` reflects the hardware.  A pending seal turns the door
    exit-only while someone is inside; a failed physical seal keeps the
    hardware reported open until a retry succeeds, so operators can see it.
    """

    if cabin.pending_seal:
        cabin.exit_only = True
        if not cabin.occupants and not cabin.seal_failed:
            cabin.door_open = False
    elif cabin.active_approval_ids:
        cabin.exit_only = False
        cabin.door_open = True
    elif not cabin.occupants:
        cabin.exit_only = False
        cabin.door_open = False
        cabin.seal_failed = False


def _optional(value: str) -> float | None:
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None


# --- pure timing decisions -------------------------------------------------


def is_expired(approval: ApprovalState, now: float) -> bool:
    """Whether an active approval has run out at ``now``."""

    if approval.status != STATUS_ACTIVE:
        return False
    if approval.expires_at is not None:
        return now >= approval.expires_at
    # Never released: only the activation ceiling can kill an unused ticket.
    return approval.activate_by > 0 and now >= approval.activate_by


def expiry_reason(approval: ApprovalState, now: float) -> str:
    if approval.expires_at is not None and now >= approval.expires_at:
        return "validity_window_elapsed"
    return "activation_deadline_passed"


def requires_seal(approval: ApprovalState, view: AccessProjection) -> bool:
    """Whether this approval is waiting on a physical door seal.

    The actual seal only happens when no one is inside; reconciliation itself
    decides whether another live approval on the same cabin keeps the door.
    """

    return approval.pending_seal and not approval.occupied


def audit_events(view: AccessProjection) -> list[Event]:
    return list(view.events)


def event_tally(view: AccessProjection) -> dict[str, int]:
    return dict(Counter(event.type for event in view.events))
