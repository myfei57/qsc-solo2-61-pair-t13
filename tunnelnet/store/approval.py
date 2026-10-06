"""Durable access approvals written before a cabin door is released.

An approval carries two timing windows:

* ``valid_for_seconds`` counts from the *first door release* (entry), not from
  the approval instant, so an approval raised ahead of a job does not burn its
  window while it waits to be used;
* ``activate_by`` bounds how long an unreleased approval may wait, so an early
  approval cannot become an everlasting ticket.

The document is kept after revocation and expiry (status moves on) because the
audit trail must still be able to show what once granted entry.
"""

from __future__ import annotations

from dataclasses import dataclass

from .store import Store

APPROVAL_KIND = "approval"

STATUS_ACTIVE = "active"
STATUS_REVOKED = "revoked"
STATUS_EXPIRED = "expired"

DEFAULT_VALID_SECONDS = 8 * 3600
DEFAULT_ACTIVATION_WINDOW = 24 * 3600


@dataclass(frozen=True)
class Approval:
    """One granted, time bounded cabin entry approval."""

    id: str
    cabin_id: str
    requester: str
    granted_at: str
    valid_for_seconds: int = DEFAULT_VALID_SECONDS
    activate_by: str = ""
    status: str = STATUS_ACTIVE
    first_release_at: str = ""
    effective_expires_at: str = ""
    revoked_at: str = ""
    revoked_reason: str = ""
    expires_at: str = ""
    sealed_at: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "cabin_id": self.cabin_id,
            "requester": self.requester,
            "granted_at": self.granted_at,
            "valid_for_seconds": self.valid_for_seconds,
            "activate_by": self.activate_by,
            "status": self.status,
            "first_release_at": self.first_release_at,
            "effective_expires_at": self.effective_expires_at,
            "revoked_at": self.revoked_at,
            "revoked_reason": self.revoked_reason,
            "expires_at": self.expires_at,
            "sealed_at": self.sealed_at,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> "Approval":
        def text(key: str) -> str:
            return str(payload.get(key, "") or "")

        def number(key: str) -> int:
            try:
                return int(payload.get(key, DEFAULT_VALID_SECONDS))  # type: ignore[arg-type]
            except (TypeError, ValueError):
                return DEFAULT_VALID_SECONDS

        return cls(
            id=text("id"),
            cabin_id=text("cabin_id"),
            requester=text("requester"),
            granted_at=text("granted_at"),
            valid_for_seconds=number("valid_for_seconds"),
            activate_by=text("activate_by"),
            status=text("status") or STATUS_ACTIVE,
            first_release_at=text("first_release_at"),
            effective_expires_at=text("effective_expires_at"),
            revoked_at=text("revoked_at"),
            revoked_reason=text("revoked_reason"),
            expires_at=text("expires_at"),
            sealed_at=text("sealed_at"),
        )

    def replaced(self, **changes: object) -> "Approval":
        """Return a copy with selected lifecycle fields moved on."""

        fields = self.as_dict()
        fields.update(changes)
        return Approval.from_dict(fields)


def save_approval(store: Store, approval: Approval) -> None:
    """Persist an approval so a restart cannot forget the release."""

    store.save(APPROVAL_KIND, approval.id, approval.as_dict())


def load_approval(store: Store, approval_id: str) -> Approval | None:
    payload = store.load(APPROVAL_KIND, approval_id)
    if payload is None:
        return None
    return Approval.from_dict(payload)


def approval_exists(store: Store, approval_id: str) -> bool:
    approval = load_approval(store, approval_id)
    return approval is not None and approval.status == STATUS_ACTIVE


def list_approvals(store: Store) -> list[Approval]:
    approvals: list[Approval] = []
    for approval_id in store.list(APPROVAL_KIND):
        approval = load_approval(store, approval_id)
        if approval is not None:
            approvals.append(approval)
    return approvals


def revoke_approval(store: Store, approval_id: str) -> bool:
    """Mark an active approval revoked.

    Returns ``True`` when an active approval was revoked and ``False`` when the
    document is missing or already past its active life.  Revoked documents are
    retained for audit instead of being deleted.
    """

    approval = load_approval(store, approval_id)
    if approval is None or approval.status != STATUS_ACTIVE:
        return False
    save_approval(
        store,
        approval.replaced(status=STATUS_REVOKED, revoked_at=approval.revoked_at),
    )
    return True
