import itertools
import unittest
from model import State, initial, successors, properties, explore

def step(s, action, policy="recovery_set", generations=2):
    return dict(successors(s, generations, policy))[action]

class ContractTests(unittest.TestCase):
    def test_live_only_loses_snapshot_after_commit(self):
        s=initial(1)
        for action in ["activate(1)","prepare(0,1)","commit(0,1)","retire(0)"]:
            s=step(s,action,"live_only")
        self.assertFalse(properties(s)["missing_live_key"])
        self.assertTrue(properties(s)["missing_backup_key"])

    def test_uncommitted_intent_does_not_survive_crash(self):
        s=initial(1)
        for action in ["activate(1)","prepare(0,1)","retire(0)","crash"]:
            s=step(s,action,"intent_only")
        self.assertEqual(s.live,(0,))
        self.assertEqual(s.pending,(-1,))
        self.assertTrue(properties(s)["missing_live_key"])

    def test_retirement_becomes_possible_after_snapshot_release(self):
        s=initial(1)
        for action in ["activate(1)","prepare(0,1)","commit(0,1)"]:
            s=step(s,action)
        self.assertNotIn("retire(0)",dict(successors(s,2,"recovery_set")))
        s=step(s,"release_snapshot")
        s=step(s,"retire(0)")
        self.assertEqual(s.keys,frozenset({1}))
        self.assertFalse(properties(s)["missing_live_key"])

    def test_profile_coverage_is_separate_from_recoverability(self):
        s=initial(1)
        for action in ["activate(1)","prepare(0,1)","commit(0,1)"]:
            s=step(s,action)
        p=properties(s)
        self.assertTrue(p["live_target_backup_legacy"])
        self.assertFalse(p["missing_live_key"] or p["missing_backup_key"])

    def test_every_guarded_transition_preserves_small_valid_universe(self):
        # Covers structurally valid states, including unreachable ones. This
        # checks the preservation argument independently of the BFS traversal.
        checked=0
        for a in range(3):
            epochs=range(a+1)
            vectors=list(itertools.product(epochs, repeat=2))
            pendings=list(itertools.product(range(-1,a+1),repeat=2))
            for bits in range(1<<(a+1)):
                keys=frozenset(k for k in epochs if bits & (1<<k))
                if a not in keys: continue
                for live in vectors:
                    if not set(live)<=keys: continue
                    for backup in [None]+vectors:
                        if not set(backup or ())<=keys: continue
                        for pending in pendings:
                            s=State(a,live,backup,pending,keys)
                            for action,nxt in successors(s,3,"recovery_set"):
                                p=properties(nxt)
                                self.assertFalse(p["missing_live_key"],(s,action,nxt))
                                self.assertFalse(p["missing_backup_key"],(s,action,nxt))
                                checked+=1
        self.assertGreater(checked,0)  # Ensure the preservation check is nonempty.

    def test_control_policies_are_detected_by_explorer(self):
        for p in ("intent_only","live_only"):
            summary,traces=explore(1,2,p)
            self.assertGreater(summary["missing_backup_key"],0)
            self.assertIn("missing_backup_key",traces)
        summary,_=explore(3,3,"recovery_set")
        self.assertEqual(summary["missing_live_key"],0)
        self.assertEqual(summary["missing_backup_key"],0)

if __name__=="__main__": unittest.main()
