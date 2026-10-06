"""Append only audit registry, durable when bound to a store."""

from __future__ import annotations

import threading

from tunnelnet.store import Store

from .model import Record
from .report import AuditState
from .summary import count_by_event, summary

AUDIT_KIND = "audit"


class AuditRegistry:
    """Keeps every linkage audit record in the order it was written.

    When a store is bound, each record is persisted before it becomes
    visible, so the audit trail survives a restart and is read from the
    same durable source as the approvals and the door ledger. Records are
    append only: nothing rewrites or removes a single entry.
    """

    def __init__(self, store: Store | None = None) -> None:
        self._store = store
        self._records: list[Record] = []
        self._lock = threading.RLock()
        if store is not None:
            for record_id in store.list(AUDIT_KIND):
                payload = store.load(AUDIT_KIND, record_id)
                if payload is not None:
                    self._records.append(Record.from_dict(payload))
            self._records.sort(key=lambda record: (record.at, record.id))

    def append(self, record: Record) -> Record:
        with self._lock:
            if self._store is not None:
                self._store.save(AUDIT_KIND, record.id, record.as_dict())
            self._records.append(record)
        return record

    def records(self) -> list[Record]:
        with self._lock:
            return list(self._records)

    def list(self) -> list[Record]:
        """Records sorted by identifier, for stable console output."""

        return sorted(self.records(), key=lambda record: record.id)

    def count(self) -> int:
        with self._lock:
            return len(self._records)

    def clear(self) -> int:
        with self._lock:
            self._records = []
            if self._store is not None:
                for record_id in self._store.list(AUDIT_KIND):
                    self._store.delete(AUDIT_KIND, record_id)
        return 0

    def latest_id(self) -> str:
        with self._lock:
            if not self._records:
                return ""
            return self._records[-1].id

    def state(self) -> AuditState:
        return AuditState(entries=[record.as_dict() for record in self.list()], count=self.count())

    def count_by_event(self) -> dict[str, int]:
        return count_by_event(self.records())

    def summary(self) -> dict[str, int]:
        return summary(self.records())

    def describe(self) -> str:
        return f"audit records={self.count()}"
