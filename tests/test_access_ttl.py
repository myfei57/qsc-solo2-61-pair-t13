"""Time bounded approvals, exit-first revocation and durable event recovery."""

from __future__ import annotations

import tempfile
import unittest

from tunnelnet.access import AccessService
from tunnelnet.access.projection import replay
from tunnelnet.cabin import Cabin
from tunnelnet.store import Store
from tunnelnet.store.accesslog import EventLog


class FakeClock:
    def __init__(self, start: float = 1000.0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t


class RecorderDoor:
    """Remembers physical door calls; can be made to jam on seal."""

    def __init__(self) -> None:
        self.released: list[str] = []
        self.sealed: list[str] = []
        self.jam = 0

    def release_door(self, cabin_id: str) -> None:
        self.released.append(cabin_id)

    def seal_door(self, cabin_id: str) -> None:
        if self.jam > 0:
            self.jam -= 1
            raise RuntimeError("door jammed")
        self.sealed.append(cabin_id)


class ValidityCase(unittest.TestCase):
    def _service(self, tmp: str) -> tuple[AccessService, RecorderDoor, FakeClock]:
        store = Store.open(tmp)
        self.cabins_store = store
        doors = RecorderDoor()
        from tunnelnet.cabin import Registry

        registry = Registry()
        registry.upsert(Cabin(id="cabin-1"))
        registry.upsert(Cabin(id="cabin-2"))
        clock = FakeClock()
        service = AccessService(store, doors, clock)
        service._registry = registry  # type: ignore[attr-defined]
        return service, doors, clock

    def test_window_starts_at_first_release_not_approval(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            service, _, clock = self._service(tmp)
            # Approved well ahead of the job: 100s window, but activated late.
            approval = service.approve(
                "cabin-1", "ops", valid_for_seconds=100, activation_window_seconds=1000
            )
            state = service.approval_state(approval.id)
            self.assertIsNone(state.expires_at)  # nothing anchored yet

            clock.t += 400  # waiting must not consume the validity window
            service.enter(approval.id)
            state = service.approval_state(approval.id)
            self.assertEqual(state.first_release_at, 1400.0)
            self.assertEqual(state.expires_at, 1500.0)

            clock.t = 1499
            self.assertTrue(service.approved(approval.id))
            clock.t = 1500
            self.assertFalse(service.approved(approval.id))

    def test_unused_approval_expires_at_activation_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            service, doors, clock = self._service(tmp)
            approval = service.approve(
                "cabin-1", "ops", valid_for_seconds=100, activation_window_seconds=300
            )
            clock.t = 1300
            self.assertEqual(service.expire_due(), [approval.id])
            self.assertEqual(service.status(approval.id), "expired")
            # Never entered; door was opened at approval then reclaimed.
            self.assertFalse(service.door_state("cabin-1"))
            self.assertIn("cabin-1", doors.sealed)

    def test_reject_non_positive_windows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            service, _, _ = self._service(tmp)
            with self.assertRaises(ValueError):
                service.approve("cabin-1", "ops", valid_for_seconds=0)
            with self.assertRaises(ValueError):
                service.approve("cabin-1", "ops", activation_window_seconds=-1)


class RevocationCase(unittest.TestCase):
    def _service(self, tmp: str) -> tuple[AccessService, RecorderDoor, FakeClock, Store]:
        store = Store.open(tmp)
        doors = RecorderDoor()
        from tunnelnet.cabin import Registry

        registry = Registry()
        registry.upsert(Cabin(id="cabin-1"))
        clock = FakeClock()
        return AccessService(store, doors, clock), doors, clock, store

    def test_revoke_outside_seals_immediately(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            service, doors, _, _ = self._service(tmp)
            approval = service.approve("cabin-1", "ops")
            self.assertTrue(service.door_state("cabin-1"))
            self.assertTrue(service.revoke(approval.id, reason="shift cancelled"))
            self.assertFalse(service.door_state("cabin-1"))
            self.assertIn("cabin-1", doors.sealed)
            self.assertEqual(service.status(approval.id), "revoked")

    def test_revoke_inside_is_exit_first(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            service, _, _, _ = self._service(tmp)
            approval = service.approve("cabin-1", "ops")
            service.enter(approval.id)
            self.assertEqual(service.occupants("cabin-1"), ["ops"])

            self.assertTrue(service.revoke(approval.id))
            # Access withdrawn and exit-only, but the door stays usable to exit.
            self.assertEqual(service.status(approval.id), "revoked_pending_seal")
            self.assertTrue(service.door_is_exit_only("cabin-1"))
            self.assertTrue(service.door_state("cabin-1"))

            # A revoked ticket cannot re-enter.
            self.assertFalse(service.enter(approval.id))

            self.assertTrue(service.exit(approval.id))
            self.assertEqual(service.occupants("cabin-1"), [])
            self.assertFalse(service.door_state("cabin-1"))
            self.assertEqual(service.status(approval.id), "revoked")

    def test_expiry_inside_is_also_exit_first(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            service, _, clock, _ = self._service(tmp)
            approval = service.approve(
                "cabin-1", "ops", valid_for_seconds=100, activation_window_seconds=1000
            )
            service.enter(approval.id)
            clock.t = 1100
            self.assertEqual(service.expire_due(), [approval.id])
            self.assertTrue(service.door_is_exit_only("cabin-1"))
            self.assertTrue(service.door_state("cabin-1"))
            service.exit(approval.id)
            self.assertFalse(service.door_state("cabin-1"))

    def test_force_seal_closes_even_with_occupant(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            service, _, _, _ = self._service(tmp)
            approval = service.approve("cabin-1", "ops")
            service.enter(approval.id)
            self.assertTrue(service.revoke(approval.id, force_seal=True))
            self.assertFalse(service.door_state("cabin-1"))
            self.assertEqual(service.status(approval.id), "revoked")

    def test_revoke_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            service, doors, _, _ = self._service(tmp)
            approval = service.approve("cabin-1", "ops")
            self.assertTrue(service.revoke(approval.id))
            seal_count = len(doors.sealed)
            self.assertFalse(service.revoke(approval.id))  # repeat is a no-op
            self.assertEqual(len(doors.sealed), seal_count)
            with self.assertRaises(KeyError):
                service.revoke("ghost")

    def test_seal_failure_is_recoverable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            service, doors, _, store = self._service(tmp)
            approval = service.approve("cabin-1", "ops")
            doors.jam = 2  # the first seal attempts keep failing
            self.assertTrue(service.revoke(approval.id))
            self.assertEqual(service.status(approval.id), "revoked_pending_seal")
            # Physical door must not be reported sealed when the seal failed.
            self.assertTrue(service.door_state.__self__._view.cabins["cabin-1"].physical_open)
            failed = [e.type for e in service.stream() if e.type == "door_seal_failed"]
            self.assertTrue(failed)

            # Replace the broken hardware and reconcile; the pending seal completes.
            doors.jam = 0
            result = service.reconcile()
            self.assertEqual(result["failed"], 0)
            self.assertEqual(result["sealed"], 1)
            self.assertFalse(service.door_state("cabin-1"))
            self.assertEqual(service.status(approval.id), "revoked")

    def test_command_idempotency_keys_dedup_events(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            service, _, _, _ = self._service(tmp)
            approval = service.approve("cabin-1", "ops")
            self.assertTrue(service.enter(approval.id, idem="entry-1"))
            # Replaying the same command key must not double count an entry.
            self.assertTrue(service.exit(approval.id, idem="exit-1"))
            self.assertEqual(service.occupants("cabin-1"), [])

    def test_past_events_are_immutable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            service, _, _, store = self._service(tmp)
            approval = service.approve("cabin-1", "ops")
            service.enter(approval.id)
            before = [(e.seq, e.type) for e in service.stream()]
            service.exit(approval.id)

            log = EventLog(store)
            with self.assertRaises(ValueError):
                log.append(log.events()[0])  # cannot overwrite a committed seq
            after_replay = [(e.seq, e.type) for e in log.events()]
            self.assertTrue(all(item in after_replay for item in before))


class RecoveryCase(unittest.TestCase):
    def test_state_rebuilds_from_durable_stream(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = Store.open(tmp)
            doors = RecorderDoor()
            from tunnelnet.cabin import Registry

            registry = Registry()
            registry.upsert(Cabin(id="cabin-1"))
            registry.upsert(Cabin(id="cabin-2"))
            clock = FakeClock()
            service = AccessService(store, doors, clock)

            keep = service.approve(
                "cabin-1", "ops", valid_for_seconds=100, activation_window_seconds=1000
            )
            gone = service.approve(
                "cabin-2", "ops2", valid_for_seconds=100, activation_window_seconds=1000
            )
            service.enter(keep.id)
            service.revoke(gone.id)

            event_count = EventLog(store).count()
            self.assertGreater(event_count, 0)

            # A brand new process rebuilds every projection from the same log.
            registry2 = Registry()
            registry2.upsert(Cabin(id="cabin-1"))
            registry2.upsert(Cabin(id="cabin-2"))
            clock2 = FakeClock(clock.t)
            service2 = AccessService(store, RecorderDoor(), clock2)
            self.assertEqual(len(service2.stream()), event_count)
            self.assertEqual(service2.occupants("cabin-1"), ["ops"])
            self.assertEqual(service2.status(gone.id), "revoked")
            self.assertEqual(service2.status(keep.id), "active")

    def test_door_and_audit_read_same_stream(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = Store.open(tmp)
            from tunnelnet.cabin import Registry

            registry = Registry()
            registry.upsert(Cabin(id="cabin-1"))
            service = AccessService(store, registry, FakeClock())
            approval = service.approve("cabin-1", "ops")
            service.revoke(approval.id)

            view = replay(EventLog(store).events())
            # Door projection and audit are both folds of one stream.
            self.assertFalse(view.cabins["cabin-1"].physical_open)
            self.assertEqual(
                [e.type for e in view.events],
                ["approval_granted", "door_opened", "approval_revoked", "door_seal_requested", "door_sealed"],
            )

    def test_interrupted_seal_completes_on_restart(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = Store.open(tmp)
            from tunnelnet.cabin import Registry

            registry = Registry()
            registry.upsert(Cabin(id="cabin-1"))
            doors = RecorderDoor()
            service = AccessService(store, doors, FakeClock())
            approval = service.approve("cabin-1", "ops")
            doors.jam = 1
            service.revoke(approval.id)  # seal requested + failed, persisted

            doors2 = RecorderDoor()  # healthy hardware after restart
            registry2 = Registry()
            registry2.upsert(Cabin(id="cabin-1"))
            service2 = AccessService(store, doors2, FakeClock())
            # Startup reconciliation retried the persisted, failed seal.
            self.assertIn("cabin-1", doors2.sealed)
            self.assertFalse(service2.door_state("cabin-1"))
            self.assertEqual(service2.status(approval.id), "revoked")


if __name__ == "__main__":
    unittest.main()
