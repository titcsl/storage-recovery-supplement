#!/usr/bin/env python3
"""Finite key-reference model; no cryptography, timings, or implementation proof.

Explore every reachable state to a fixed point within the selected object and
generation bounds. A snapshot is immutable until explicitly released. Pending
rewraps are volatile; live references, snapshots, and keys are durable.
"""
from __future__ import annotations
from collections import deque
from dataclasses import dataclass, replace, asdict
import argparse
import csv
import hashlib
import json
from pathlib import Path
import platform
import sys

POLICIES = ("intent_only", "live_only", "recovery_set")

@dataclass(frozen=True)
class State:
    active: int
    live: tuple[int, ...]
    backup: tuple[int, ...] | None
    pending: tuple[int, ...]  # -1 means no pending update
    keys: frozenset[int]

def initial(n: int) -> State:
    refs = (0,) * n
    return State(0, refs, refs, (-1,) * n, frozenset({0}))

def update(t: tuple[int, ...], i: int, value: int) -> tuple[int, ...]:
    return t[:i] + (value,) + t[i+1:]

def references(s: State, policy: str) -> set[int]:
    if policy == "intent_only":
        return {p if p >= 0 else l for l, p in zip(s.live, s.pending)}
    if policy == "live_only":
        return set(s.live)
    if policy == "recovery_set":
        return set(s.live) | set(s.backup or ()) | {p for p in s.pending if p >= 0}
    raise ValueError(policy)

def successors(s: State, generations: int, policy: str):
    # Activation includes durable provisioning. Never reuse a retired identifier.
    if s.active + 1 < generations:
        new = s.active + 1
        yield f"activate({new})", replace(s, active=new, keys=s.keys | {new})
    for i, old in enumerate(s.live):
        if s.pending[i] < 0 and old != s.active and old in s.keys:
            yield f"prepare({i},{s.active})", replace(s, pending=update(s.pending, i, s.active))
        target = s.pending[i]
        if target >= 0 and target in s.keys:
            yield f"commit({i},{target})", replace(s, live=update(s.live, i, target), pending=update(s.pending, i, -1))
    if s.backup is None and all(k in s.keys for k in s.live):
        yield "snapshot", replace(s, backup=s.live)
    if s.backup is not None:
        yield "release_snapshot", replace(s, backup=None)
    if any(p >= 0 for p in s.pending):
        yield "crash", replace(s, pending=(-1,) * len(s.live))
    refs = references(s, policy)
    for k in sorted(s.keys):
        if k != s.active and k not in refs:
            yield f"retire({k})", replace(s, keys=s.keys - {k})

def properties(s: State) -> dict[str, bool]:
    live_ok = all(k in s.keys for k in s.live)
    backup_ok = all(k in s.keys for k in (s.backup or ()))
    # Generation zero is labelled legacy, later generations target. This label
    # is an uninterpreted policy annotation, not a security measurement.
    live_target = all(k > 0 for k in s.live)
    restore_target = all(k > 0 for k in s.live + (s.backup or ()))
    return {
        "missing_live_key": not live_ok,
        "missing_backup_key": not backup_ok,
        "live_target_backup_legacy": live_target and not restore_target,
    }

def encode(s: State):
    d = asdict(s)
    d["keys"] = sorted(s.keys)
    return d

def walk_trace(end, parent):
    rev = []
    s = end
    while parent[s] is not None:
        prev, action = parent[s]
        rev.append({"action": action, "state": encode(s)})
        s = prev
    return [{"action": "initial", "state": encode(s)}] + list(reversed(rev))

def explore(n: int, generations: int, policy: str):
    root = initial(n)
    parent = {root: None}
    q = deque([root])
    bad = {k: 0 for k in properties(root)}
    first = {}
    edges = 0
    while q:
        s = q.popleft()
        for prop, value in properties(s).items():
            if value:
                bad[prop] += 1
                if prop not in first:
                    first[prop] = walk_trace(s, parent)
        for action, nxt in successors(s, generations, policy):
            edges += 1
            if nxt not in parent:
                parent[nxt] = (s, action)
                q.append(nxt)
    summary = {"records": n, "generations": generations, "policy": policy,
               "states": len(parent), "transitions": edges, **bad}
    return summary, first

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=Path("results"))
    ap.add_argument("--records", type=int, nargs="+", default=[1, 2, 3])
    ap.add_argument("--generations", type=int, nargs="+", default=[2, 3])
    args = ap.parse_args()
    if min(args.records) < 1 or min(args.generations) < 2:
        ap.error("records >= 1 and generations >= 2 are required")
    args.out.mkdir(parents=True, exist_ok=True)
    summaries, traces = [], {}
    for n in args.records:
        for g in args.generations:
            for policy in POLICIES:
                s, t = explore(n, g, policy)
                summaries.append(s)
                traces[f"n{n}_g{g}_{policy}"] = t
                print(json.dumps(s), flush=True)
    with (args.out / "model_summary.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(summaries[0]))
        w.writeheader(); w.writerows(summaries)
    (args.out / "model_traces.json").write_text(json.dumps(traces, indent=2) + "\n")
    (args.out / "model_results.json").write_text(json.dumps(summaries, indent=2) + "\n")
    manifest = {
        "python": sys.version, "platform": platform.platform(),
        "records": args.records, "generations": args.generations,
        "enumeration": "BFS until queue empty; no depth or state cutoff",
        "initial": "all live records and one retained snapshot reference generation zero",
        "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "meaning": "finite abstraction; state fractions are NOT failure probabilities"
    }
    (args.out / "model_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

if __name__ == "__main__":
    main()
