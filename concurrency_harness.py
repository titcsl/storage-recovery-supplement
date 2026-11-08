#!/usr/bin/env python3
"""Two real worker processes, a deterministic IPC scheduler, and observed restores.

Tests a complete recovery-set scan followed by deletion, with or without one
cooperative local flock shared by both workers. This extends the forward-only
model with admission of a request carrying a previously selected generation.
It is not an exhaustive concurrency test, distributed protocol, or secure KMS.
No expected-result function is used to generate or filter the observations.
"""
from __future__ import annotations
import argparse
from collections import Counter
from contextlib import closing
import csv
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import multiprocessing as mp
import os
from pathlib import Path
import platform
import sqlite3
import sys
import tempfile
import traceback
import cryptography
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crash_harness import (
    aad, connect, durable_refs, initialize, load_keys, restore, rotate, save_keys,
)

PROTOCOLS = ("unserialized", "shared_lock")
SCHEDULES = ("commit_in_gap", "prepare_in_gap", "writer_first", "delete_first")
ACTIVE, CANDIDATE = 1, 0
IPC_TIMEOUT = 20


def inventory(root: Path) -> dict:
    with closing(sqlite3.connect(root / "live.db")) as c:
        live = [r[0] for r in c.execute("SELECT epoch FROM records ORDER BY id")]
        pending = [r[0] for r in c.execute("SELECT epoch FROM pending ORDER BY owner")]
    with closing(sqlite3.connect(root / "backup.db")) as c:
        backup = [r[0] for r in c.execute("SELECT epoch FROM records ORDER BY id")]
    return {"active": ACTIVE, "live": live, "backup": backup,
            "pending": pending, "keys": sorted(load_keys(root))}


def initialize_case(root: Path, records: int, size: int):
    # First rotate normally, then refresh the snapshot at generation 1. Key 0
    # stays available but initially has no live, snapshot, or pending reference.
    initialize(root, records, size)
    rotate(root, "recovery_set", "complete")
    with closing(connect(root / "live.db")) as src:
        with closing(connect(root / "backup.db")) as dst:
            src.backup(dst)
        src.execute("CREATE TABLE pending(owner TEXT PRIMARY KEY, epoch INTEGER NOT NULL)")
        src.commit()
    # Persistent inode: never replaced or unlinked during either worker's life.
    (root / "lifecycle.lock").touch()
    s = inventory(root)
    if set(s["live"] + s["backup"]) != {1} or s["pending"] or s["keys"] != [0, 1]:
        raise RuntimeError("Invalid concurrent-trial initial state")


class LifecycleWorker:
    def __init__(self, root: Path, role: str, protocol: str):
        self.root, self.role, self.protocol = root, role, protocol
        self.lock_file = (root / "lifecycle.lock").open("a+b")
        self.held = False
        self.prepared = None
        self.scan = None

    def acquire(self) -> bool:
        if self.protocol == "unserialized":
            return True
        if self.held:
            raise RuntimeError("Nested acquisition is not part of this protocol")
        try:
            fcntl.flock(self.lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        self.held = True
        return True

    def release(self):
        if self.held:
            fcntl.flock(self.lock_file.fileno(), fcntl.LOCK_UN)
            self.held = False

    def require_lock(self):
        if self.protocol == "shared_lock" and not self.held:
            raise RuntimeError("Protected mutation without the lifecycle lock")

    def action(self, command: str) -> dict:
        if self.role == "retirer" and command == "check":
            if self.scan is not None:
                raise RuntimeError("A retirement check is already in progress")
            if not self.acquire():
                return {"status": "blocked", "reason": "lifecycle_lock_busy"}
            s = inventory(self.root)
            used = set(s["live"] + s["backup"] + s["pending"])
            eligible = CANDIDATE in s["keys"] and CANDIDATE != s["active"] and CANDIDATE not in used
            self.scan = {"eligible": eligible, "checked_inventory": s}
            return {"status": "checked", **self.scan}

        if self.role == "retirer" and command == "delete":
            if self.scan is None:
                raise RuntimeError("Deletion without a preceding check")
            self.require_lock()
            decision = self.scan
            before = inventory(self.root)
            deleted = False
            if decision["eligible"]:
                keys = load_keys(self.root)
                if CANDIDATE in keys:
                    del keys[CANDIDATE]
                    save_keys(self.root, keys)
                    deleted = True
            self.scan = None
            self.release()
            return {"status": "deleted" if deleted else "retained",
                    "cached_eligible": decision["eligible"], "before_delete": before}

        if self.role == "writer" and command == "prepare":
            if self.prepared is not None:
                raise RuntimeError("Writer already has prepared work")
            if not self.acquire():
                return {"status": "blocked", "reason": "lifecycle_lock_busy"}
            keys = load_keys(self.root)
            # A stale epoch choice is admitted only while its key is available.
            # The protected protocol keeps the lock through publication/cleanup.
            if CANDIDATE not in keys:
                self.release()
                return {"status": "rejected", "reason": "target_key_unavailable"}
            self.require_lock()
            with closing(connect(self.root / "live.db")) as c:
                c.execute("INSERT INTO pending VALUES(?,?)", ("writer", CANDIDATE))
                c.commit()
                rows = c.execute("SELECT id,epoch,wrap_nonce,wrapped_key FROM records ORDER BY id").fetchall()
            updates = []
            for i, old, nonce, wrapped in rows:
                dek = AESGCM(keys[old]).decrypt(nonce, wrapped, aad(i, old))
                new_nonce = os.urandom(12)
                new_wrapped = AESGCM(keys[CANDIDATE]).encrypt(new_nonce, dek, aad(i, CANDIDATE))
                updates.append((CANDIDATE, new_nonce, new_wrapped, i))
            self.prepared = updates
            return {"status": "prepared", "target": CANDIDATE, "records_prepared": len(updates)}

        if self.role == "writer" and command == "commit":
            if self.prepared is None:
                raise RuntimeError("Commit without prepared work")
            self.require_lock()
            with closing(connect(self.root / "live.db")) as c:
                c.execute("BEGIN IMMEDIATE")
                c.executemany("UPDATE records SET epoch=?,wrap_nonce=?,wrapped_key=? WHERE id=?", self.prepared)
                # Transfer the dependency from the pin to committed records in
                # the same SQL transaction, then release the lifecycle lock.
                c.execute("DELETE FROM pending WHERE owner=?", ("writer",))
                c.commit()
            self.prepared = None
            self.release()
            return {"status": "committed", "target": CANDIDATE}

        raise RuntimeError(f"Invalid {self.role} command: {command}")

    def close(self):
        self.release()
        self.lock_file.close()


def worker_main(root: str, role: str, protocol: str, pipe):
    worker = LifecycleWorker(Path(root), role, protocol)
    try:
        while True:
            command = pipe.recv()
            if command == "stop":
                if worker.scan is not None or worker.prepared is not None:
                    raise RuntimeError("Worker stopped with unfinished operation")
                pipe.send({"status": "stopped"})
                break
            outcome = worker.action(command)
            pipe.send({**outcome, "lock_held": worker.held, "inventory": inventory(Path(root))})
    except BaseException:
        pipe.send({"status": "error", "traceback": traceback.format_exc()})
        raise
    finally:
        worker.close()
        pipe.close()


def run_case(protocol: str, schedule: str, records: int, size: int) -> tuple[dict, dict]:
    if protocol not in PROTOCOLS or schedule not in SCHEDULES:
        raise ValueError((protocol, schedule))
    with tempfile.TemporaryDirectory(prefix="recovery-race-") as td:
        root = Path(td)
        initialize_case(root, records, size)
        ctx = mp.get_context("spawn")
        workers, pipes = {}, {}
        trace = [{"sequence": 0, "actor": "parent", "command": "initial", "inventory": inventory(root)}]
        for role in ("retirer", "writer"):
            parent, child = ctx.Pipe()
            proc = ctx.Process(target=worker_main, args=(td, role, protocol, child))
            proc.start()
            child.close()
            workers[role], pipes[role] = proc, parent

        def perform(role: str, command: str):
            pipe = pipes[role]
            pipe.send(command)
            if not pipe.poll(IPC_TIMEOUT):
                raise TimeoutError(f"{role}.{command} did not respond")
            event = pipe.recv()
            trace.append({"sequence": len(trace), "actor": role, "command": command, **event})
            if event["status"] == "error":
                raise RuntimeError(event["traceback"])
            return event["status"]

        try:
            if schedule in ("commit_in_gap", "prepare_in_gap"):
                perform("retirer", "check")
                admitted = perform("writer", "prepare")
                if admitted == "prepared" and schedule == "commit_in_gap":
                    perform("writer", "commit")
                perform("retirer", "delete")
                if admitted == "blocked":
                    admitted = perform("writer", "prepare")
                    if admitted == "prepared":
                        perform("writer", "commit")
                elif admitted == "prepared" and schedule == "prepare_in_gap":
                    perform("writer", "commit")
            elif schedule == "writer_first":
                perform("writer", "prepare")
                checked = perform("retirer", "check")
                perform("writer", "commit")
                if checked == "blocked":
                    perform("retirer", "check")
                perform("retirer", "delete")
            else:
                perform("retirer", "check")
                perform("retirer", "delete")
                admitted = perform("writer", "prepare")
                if admitted == "prepared":
                    perform("writer", "commit")

            for role in workers:
                perform(role, "stop")
                workers[role].join(IPC_TIMEOUT)
                if workers[role].exitcode != 0:
                    raise RuntimeError(f"Unexpected {role} exit: {workers[role].exitcode}")

            final = inventory(root)
            if final["pending"]:
                raise RuntimeError("Dangling prepared dependency at trial completion")
            live, live_missing = restore(root, "live.db", records, size)
            backup, backup_missing = restore(root, "backup.db", records, size)
            # Independent inventory and decryption observations must agree.
            if live_missing != sum(k not in final["keys"] for k in final["live"]):
                raise RuntimeError("Live reference inventory disagrees with restore")
            if backup_missing != sum(k not in final["keys"] for k in final["backup"]):
                raise RuntimeError("Backup reference inventory disagrees with restore")
            counts = Counter((e["actor"], e.get("status")) for e in trace)
            row = {"protocol": protocol, "schedule": schedule, "records": records,
                   "payload_bytes": size, "live_restored": live,
                   "live_missing_key": live_missing, "backup_restored": backup,
                   "backup_missing_key": backup_missing,
                   "writer_committed": counts["writer", "committed"],
                   "writer_rejected": counts["writer", "rejected"],
                   "writer_blocked": counts["writer", "blocked"],
                   "retirer_blocked": counts["retirer", "blocked"],
                   "retired": counts["retirer", "deleted"],
                   "retained": counts["retirer", "retained"],
                   "workers_exited_zero": all(p.exitcode == 0 for p in workers.values())}
            trace.append({"sequence": len(trace), "actor": "parent", "command": "restore",
                          "inventory": final, "observed": row.copy()})
            return row, {"case": row.copy(), "events": trace}
        finally:
            for proc in workers.values():
                if proc.is_alive():
                    proc.terminate()
                proc.join(IPC_TIMEOUT)
            for pipe in pipes.values():
                pipe.close()


def summarize(rows: list[dict]) -> list[dict]:
    output = []
    for protocol in PROTOCOLS:
        for schedule in SCHEDULES:
            cases = [r for r in rows if r["protocol"] == protocol and r["schedule"] == schedule]
            output.append({"protocol": protocol, "schedule": schedule, "cases": len(cases),
                           "live_failure_cases": sum(r["live_missing_key"] > 0 for r in cases),
                           "backup_failure_cases": sum(r["backup_missing_key"] > 0 for r in cases),
                           "both_restored_cases": sum(r["live_restored"] == r["records"] and r["backup_restored"] == r["records"] for r in cases),
                           **{k: sum(r[k] for r in cases) for k in ("writer_committed", "writer_rejected", "writer_blocked", "retirer_blocked", "retired", "retained")}})
    return output


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=Path("results"))
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    rows, traces = [], []
    for n in (1, 8):
        for size in (512, 16384, 262144):
            for protocol in PROTOCOLS:
                for schedule in SCHEDULES:
                    row, trace = run_case(protocol, schedule, n, size)
                    rows.append(row)
                    traces.append(trace)
    with (args.out / "concurrency_trials.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader(); w.writerows(rows)
    for name, data in [("concurrency_summary.json", summarize(rows)), ("concurrency_traces.json", traces)]:
        (args.out / name).write_text(json.dumps(data, indent=2) + "\n")
    sources = [Path(__file__), Path(__file__).with_name("crash_harness.py")]
    manifest = {"run_completed_utc": datetime.now(timezone.utc).isoformat(),
                "python": sys.version, "platform": platform.platform(),
                "sqlite": sqlite3.sqlite_version, "cryptography": cryptography.__version__,
                "source_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},
                "processes": "one parent scheduler and two spawned worker processes per case",
                "scheduling": "synchronous IPC gates; nonblocking flock attempts; no sleep-based ordering",
                "lock": "fcntl.flock(LOCK_EX | LOCK_NB), cooperative workers, one stable local lock-file inode",
                "lock_scope": "retirer: full inventory scan through deletion; writer: availability check, pin registration, preparation, SQL publication and pin removal",
                "fixed_during_trials": "active generation 1 and one snapshot at generation 1; no concurrent snapshot or activation changes",
                "admission": "request for still-available inactive generation 0; extends forward-only model to represent a delayed epoch choice/import",
                "pending_registry": "SQLite table committed at admission; removed atomically with live publication; no worker crashes in these trials",
                "records": [1, 8], "payload_bytes": [512, 16384, 262144],
                "protocols": PROTOCOLS, "schedules": SCHEDULES, "repetitions_per_configuration": 1,
                "case_count": len(rows), "outcome_source": "durable inventory and actual AES-GCM restoration; no expected-result substitution",
                "limits": "selected schedules only; no distributed, malicious, power-loss, performance, or post-quantum implementation claim"}
    (args.out / "concurrency_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(summarize(rows), indent=2))


if __name__ == "__main__":
    main()
