import unittest
from concurrency_harness import run_case, SCHEDULES


class ConcurrentContractTests(unittest.TestCase):
    def test_late_dependencies_invalidate_an_unserialized_scan(self):
        for schedule in ("commit_in_gap", "prepare_in_gap"):
            with self.subTest(schedule=schedule):
                row, trace = run_case("unserialized", schedule, 1, 512)
                checked = next(e for e in trace["events"] if e.get("status") == "checked")
                deleted = next(e for e in trace["events"] if e.get("status") == "deleted")
                self.assertTrue(checked["eligible"])
                self.assertNotIn(0, checked["checked_inventory"]["pending"])
                self.assertIn(0, deleted["before_delete"]["live"] + deleted["before_delete"]["pending"])
                self.assertEqual(row["live_missing_key"], 1)
                self.assertEqual(row["backup_restored"], 1)

    def test_registered_pending_work_is_included_in_the_guard(self):
        row, trace = run_case("unserialized", "writer_first", 1, 512)
        checked = next(e for e in trace["events"] if e.get("status") == "checked")
        self.assertEqual(checked["checked_inventory"]["pending"], [0])
        self.assertFalse(checked["eligible"])
        self.assertEqual(row["retained"], 1)
        self.assertEqual(row["live_restored"], 1)

    def test_shared_lock_serializes_the_selected_schedules(self):
        for schedule in SCHEDULES:
            with self.subTest(schedule=schedule):
                row, trace = run_case("shared_lock", schedule, 1, 512)
                self.assertEqual((row["live_restored"], row["backup_restored"]), (1, 1))
                self.assertEqual((row["live_missing_key"], row["backup_missing_key"]), (0, 0))
                for event in trace["events"]:
                    if event.get("status") in ("checked", "prepared"):
                        self.assertTrue(event["lock_held"])
                if schedule == "writer_first":
                    self.assertEqual((row["retirer_blocked"], row["writer_committed"], row["retained"]), (1, 1, 1))
                else:
                    self.assertEqual((row["writer_rejected"], row["retired"]), (1, 1))


if __name__ == "__main__":
    unittest.main()
