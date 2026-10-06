"""Durable, append only event stream shared by every access projection.

The event log is the single source of truth for the access domain. Approval
status, cabin door state and the audit trail are all projections of the same
ordered stream, so they can never silently disagree.

Events are written one JSON document per sequence number with atomic file
replacements and replayed in filename order.  Once written an event is never
updated or deleted: a wrong fact is corrected by appending another event.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

from .store import Store

EVENT_KIND = "access_event"

_SEQ_WIDTH = 12
_SEQ_LIMIT = 10**_SEQ_WIDTH


@dataclass(frozen=True)
class Event:
    """One immutable fact appended to the access stream."""

    seq: int
    at: str
    type: str
    approval_id: str = ""
    cabin_id: str = ""
    requester: str = ""
    key: str = ""
    payload: dict[str, str] | None = None

    def as_dict(self) -> dict[str, object]:
        value: dict[str, object] = {
            "seq": self.seq,
            "at": self.at,
            "type": self.type,
        }
        if self.approval_id:
            value["approval_id"] = self.approval_id
        if self.cabin_id:
            value["cabin_id"] = self.cabin_id
        if self.requester:
            value["requester"] = self.requester
        if self.key:
            value["key"] = self.key
        if self.payload:
            value["payload"] = self.payload
        return value

    @classmethod
    def from_dict(cls, body: dict[str, object]) -> "Event":
        raw_payload = body.get("payload")
        payload: dict[str, str] | None = None
        if isinstance(raw_payload, dict):
            payload = {str(k): str(v) for k, v in raw_payload.items()}
        return cls(
            seq=int(body.get("seq", 0)),
            at=str(body.get("at", "")),
            type=str(body.get("type", "")),
            approval_id=str(body.get("approval_id", "")),
            cabin_id=str(body.get("cabin_id", "")),
            requester=str(body.get("requester", "")),
            key=str(body.get("key", "")),
            payload=payload,
        )


def sequence_name(seq: int) -> str:
    """Stable, zero padded record id for one sequence number."""

    if not 0 <= seq < _SEQ_LIMIT:
        raise ValueError("event sequence out of range")
    return f"{seq:0{_SEQ_WIDTH}d}"


class EventLog:
    """Append only access events behind the shared file :class:`Store`."""

    def __init__(self, store: Store) -> None:
        self._store = store
        self._lock = threading.RLock()

    def append(self, event: Event) -> Event:
        """Persist one event, raising when its sequence is already occupied."""

        name = sequence_name(event.seq)
        with self._lock:
            if self._store.exists(EVENT_KIND, name):
                raise ValueError(f"event {name} already committed")
            self._store.save(EVENT_KIND, name, event.as_dict())
        return event

    def load(self, seq: int) -> Event | None:
        body = self._store.load(EVENT_KIND, sequence_name(seq))
        return Event.from_dict(body) if body is not None else None

    def events(self) -> list[Event]:
        """Every committed event in commit order."""

        result: list[Event] = []
        for name in self._store.list(EVENT_KIND):
            body = self._store.load(EVENT_KIND, name)
            if body is not None:
                result.append(Event.from_dict(body))
        result.sort(key=lambda event: event.seq)
        return result

    def next_seq(self) -> int:
        """Sequence number of the next event, surviving restarts."""

        names = self._store.list(EVENT_KIND)
        if not names:
            return 0
        return max(int(name) for name in names) + 1

    def count(self) -> int:
        return len(self._store.list(EVENT_KIND))
