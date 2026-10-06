"""Door release ledger: the durable record behind every cabin door."""

from __future__ import annotations

import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from tunnelnet.audit import AuditRegistry, Record
from tunnelnet.drain import utc_now
from tunnelnet.store import Store

DOOR_KIND = "door"


class DoorController(Protocol):
    """Physical door actuator mirrored by the ledger."""

    def release_door(self, cabin_id: str) -> None:  # pragma: no cover - structural
        ...

    def seal_door(self, cabin_id: str) -> None:  # pragma: no cover - structural
        ...


@dataclass
class DoorRecord:
    """Current release state of one cabin door.

    The record is the durable source of truth; the physical door is a
    projection of it. ``occupancy`` materializes the append only enter and
    exit audit events, and ``closing_pending`` marks a door whose release
    was reclaimed while people are still inside.
    """

    cabin_id: str
    released: bool = False
    approval_id: str = ""
    source: str = ""
    occupancy: int = 0
    closing_pending: bool = False
    updated_at: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "cabin_id": self.cabin_id,
            "released": self.released,
            "approval_id": self.approval_id,
            "source": self.source,
            "occupancy": self.occupancy,
            "closing_pending": self.closing_pending,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> "DoorRecord":
        return cls(
            cabin_id=str(payload.get("cabin_id", "")),
            released=bool(payload.get("released", False)),
            approval_id=str(payload.get("approval_id", "")),
            source=str(payload.get("source", "")),
            occupancy=int(payload.get("occupancy", 0)),
            closing_pending=bool(payload.get("closing_pending", False)),
            updated_at=str(payload.get("updated_at", "")),
        )


class DoorLedger:
    """Owns the durable release state of every cabin door.

    Every transition is persisted first and then applied to the physical
    door; when the physical step fails the record is rolled back so a
    retried operation can converge. Manual and approval driven releases
    share the same ledger, so the door state and the audit trail are read
    from one durable source.
    """

    def __init__(
        self,
        store: Store,
        actuator: DoorController,
        audit: AuditRegistry | None = None,
        clock: Callable[[], str] = utc_now,
    ) -> None:
        self._store = store
        self._actuator = actuator
        self._audit = audit
        self._clock = clock
        self._lock = threading.RLock()

    @property
    def audit(self) -> AuditRegistry | None:
        return self._audit

    def state(self, cabin_id: str) -> DoorRecord:
        """Current record of one door, or a closed default when none exists."""

        with self._lock:
            payload = self._store.load(DOOR_KIND, cabin_id)
        if payload is None:
            return DoorRecord(cabin_id=cabin_id)
        return DoorRecord.from_dict(payload)

    def all(self) -> list[DoorRecord]:
        with self._lock:
            return [self.state(cabin_id) for cabin_id in self._store.list(DOOR_KIND)]

    def release(self, cabin_id: str, approval_id: str = "", source: str = "manual") -> DoorRecord:
        """Release one door, keeping any people still inside accounted for."""

        with self._lock:
            previous = self.state(cabin_id)
            record = DoorRecord(
                cabin_id=cabin_id,
                released=True,
                approval_id=approval_id,
                source=source,
                occupancy=previous.occupancy,
                closing_pending=False,
                updated_at=self._clock(),
            )
            self._apply(record, previous, lambda: self._actuator.release_door(cabin_id))
        self._write_audit("door_released", cabin_id)
        return record

    def seal(self, cabin_id: str, reason: str = "manual") -> DoorRecord:
        """Seal one door; idempotent when the door is already closed."""

        with self._lock:
            record = self.state(cabin_id)
            if not record.released and not record.closing_pending:
                return record
            previous = DoorRecord.from_dict(record.as_dict())
            record.released = False
            record.closing_pending = False
            record.updated_at = self._clock()
            self._apply(record, previous, lambda: self._actuator.seal_door(cabin_id))
        self._write_audit("door_sealed", cabin_id)
        return record

    def request_close(self, cabin_id: str) -> DoorRecord:
        """Flag a released door to seal itself once the cabin is empty."""

        with self._lock:
            record = self.state(cabin_id)
            if record.closing_pending or not record.released:
                return record
            record.closing_pending = True
            record.updated_at = self._clock()
            self._save(record)
        self._write_audit("door_closing_pending", cabin_id)
        return record

    def enter(self, cabin_id: str) -> DoorRecord:
        """Account for one person walking in through a released door."""

        with self._lock:
            record = self.state(cabin_id)
            record.occupancy += 1
            record.updated_at = self._clock()
            self._save(record)
        return record

    def exit(self, cabin_id: str) -> DoorRecord:
        """Account for one person walking out, sealing a reclaimed door.

        Exit registration never fails: once the last person leaves a door
        flagged ``closing_pending`` seals itself. The physical seal is best
        effort here because the durable record already reads closed.
        """

        with self._lock:
            record = self.state(cabin_id)
            record.occupancy = max(0, record.occupancy - 1)
            record.updated_at = self._clock()
            if record.occupancy == 0 and record.closing_pending:
                record.closing_pending = False
                record.released = False
                self._save(record)
                try:
                    self._actuator.seal_door(cabin_id)
                except ValueError:
                    pass
                self._write_audit("door_sealed", cabin_id)
                return record
            self._save(record)
        return record

    def reconcile(self) -> None:
        """Re-apply every persisted record to the physical doors on boot."""

        with self._lock:
            for cabin_id in self._store.list(DOOR_KIND):
                record = self.state(cabin_id)
                try:
                    if record.released:
                        self._actuator.release_door(cabin_id)
                    else:
                        self._actuator.seal_door(cabin_id)
                except ValueError:
                    continue

    def reset(self) -> None:
        """Drop every record and seal every door, as a factory reset would."""

        with self._lock:
            for cabin_id in self._store.list(DOOR_KIND):
                self._store.delete(DOOR_KIND, cabin_id)
                try:
                    self._actuator.seal_door(cabin_id)
                except ValueError:
                    continue

    def _apply(self, record: DoorRecord, previous: DoorRecord, actuate: Callable[[], None]) -> None:
        """Persist first, then actuate, rolling the record back on failure."""

        had_previous = self._store.exists(DOOR_KIND, record.cabin_id)
        self._save(record)
        try:
            actuate()
        except Exception:
            if had_previous:
                self._save(previous)
            else:
                self._store.delete(DOOR_KIND, record.cabin_id)
            raise

    def _save(self, record: DoorRecord) -> None:
        self._store.save(DOOR_KIND, record.cabin_id, record.as_dict())

    def _write_audit(self, event: str, cabin_id: str) -> None:
        if self._audit is not None:
            self._audit.append(
                Record(id=uuid.uuid4().hex, event=event, at=self._clock(), ref=cabin_id)
            )
