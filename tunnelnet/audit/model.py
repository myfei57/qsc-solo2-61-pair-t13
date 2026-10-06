"""Audit records written for every linkage event."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Record:
    """One linkage audit entry; ``ref`` ties it to a cabin or approval."""

    id: str
    event: str
    at: str
    ref: str = ""

    def as_dict(self) -> dict[str, str]:
        return {"id": self.id, "event": self.event, "at": self.at, "ref": self.ref}

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> "Record":
        return cls(
            id=str(payload.get("id", "")),
            event=str(payload.get("event", "")),
            at=str(payload.get("at", "")),
            ref=str(payload.get("ref", "")),
        )
