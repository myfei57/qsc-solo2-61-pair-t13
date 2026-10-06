"""Durable access approvals written before a cabin door is released."""

from __future__ import annotations

import calendar
import time
from dataclasses import dataclass, replace

from .store import Store

APPROVAL_KIND = "approval"
EPOCH_ZERO = "1970-01-01T00:00:00Z"
STAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

ACTIVE = "active"
REVOKED = "revoked"
EXPIRED = "expired"


def epoch_to_iso(epoch: float) -> str:
    """Render an epoch second in the stamp format used by every record."""

    return time.strftime(STAMP_FORMAT, time.gmtime(epoch))


def iso_to_epoch(stamp: str) -> float | None:
    """Parse one stored stamp, returning ``None`` when it is not a valid stamp."""

    try:
        return float(calendar.timegm(time.strptime(stamp, STAMP_FORMAT)))
    except (ValueError, OverflowError):
        return None


@dataclass(frozen=True)
class Approval:
    """One granted cabin entry approval with a bounded validity window."""

    id: str
    cabin_id: str
    requester: str
    granted_at: str
    expires_at: str = ""
    status: str = ACTIVE
    revoked_at: str = ""

    def as_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "cabin_id": self.cabin_id,
            "requester": self.requester,
            "granted_at": self.granted_at,
            "expires_at": self.expires_at,
            "status": self.status,
            "revoked_at": self.revoked_at,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> "Approval":
        return cls(
            id=str(payload.get("id", "")),
            cabin_id=str(payload.get("cabin_id", "")),
            requester=str(payload.get("requester", "")),
            granted_at=str(payload.get("granted_at", "")),
            expires_at=str(payload.get("expires_at", "")),
            status=str(payload.get("status", ACTIVE)),
            revoked_at=str(payload.get("revoked_at", "")),
        )


def expires_at_of(approval: Approval, default_ttl_seconds: int) -> str:
    """Effective expiry stamp; legacy records derive it from the grant time.

    A record whose grant time cannot be parsed expires at the epoch, so an
    unreadable approval fails closed instead of living forever.
    """

    if approval.expires_at:
        return approval.expires_at
    epoch = iso_to_epoch(approval.granted_at)
    if epoch is None:
        return EPOCH_ZERO
    return epoch_to_iso(epoch + default_ttl_seconds)


def is_expired(approval: Approval, now: str, default_ttl_seconds: int) -> bool:
    """Whether the approval window has closed; stamps compare lexically."""

    return now >= expires_at_of(approval, default_ttl_seconds)


def save_approval(store: Store, approval: Approval) -> None:
    """Persist an approval so a restart cannot forget the release."""

    store.save(APPROVAL_KIND, approval.id, approval.as_dict())


def load_approval(store: Store, approval_id: str) -> Approval | None:
    payload = store.load(APPROVAL_KIND, approval_id)
    if payload is None:
        return None
    return Approval.from_dict(payload)


def approval_exists(store: Store, approval_id: str) -> bool:
    return store.exists(APPROVAL_KIND, approval_id)


def list_approvals(store: Store) -> list[Approval]:
    approvals: list[Approval] = []
    for approval_id in store.list(APPROVAL_KIND):
        approval = load_approval(store, approval_id)
        if approval is not None:
            approvals.append(approval)
    return approvals


def transition_approval(store: Store, approval: Approval, status: str, at: str) -> Approval:
    """Move one approval to a terminal status and persist the transition."""

    updated = replace(
        approval,
        status=status,
        revoked_at=at if status == REVOKED else approval.revoked_at,
    )
    save_approval(store, updated)
    return updated


def revoke_approval(store: Store, approval_id: str, revoked_at: str = "") -> Approval | None:
    """Mark an approval revoked, keeping the record for the audit trail.

    The transition is idempotent: an already revoked approval is returned as
    is, so a repeated revoke converges instead of failing.
    """

    approval = load_approval(store, approval_id)
    if approval is None:
        return None
    if approval.status == REVOKED:
        return approval
    return transition_approval(store, approval, REVOKED, revoked_at)
