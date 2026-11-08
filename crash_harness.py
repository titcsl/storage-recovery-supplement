#!/usr/bin/env python3
"""Synthetic envelope-storage crash experiment (AES-GCM, SQLite, local keyring).

This is NOT a post-quantum cryptographic implementation, KMS service, benchmark,
or test of the earlier middleware. Child processes terminate with os._exit at
documented checkpoints. The host operating system and filesystem stay alive.
"""
from __future__ import annotations
import argparse
import base64
from collections import Counter
import csv
import hashlib
import json
import os
from pathlib import Path
import platform
import sqlite3
import subprocess
import sys
import tempfile
import cryptography
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

POLICIES = ("intent_only", "live_only", "recovery_set")
STAGES = ("after_provision", "after_prepare", "after_retire_attempt",
          "before_db_commit", "after_db_commit", "after_final_retire", "complete")
CRASH_EXIT = 93

def payload(record: int, size: int) -> bytes:
    block = hashlib.sha256(f"synthetic-record-{record}".encode()).digest()
    return (block * ((size + 31) // 32))[:size]

def aad(record: int, epoch: int) -> bytes:
    return f"DEK:{record}:epoch:{epoch}".encode()

def data_aad(record: int) -> bytes:
    return f"record:{record}:version:1".encode()

def save_keys(root: Path, keys: dict[int, bytes]):
    tmp = root / "keyring.tmp"
    with tmp.open("w") as f:
        json.dump({str(k): base64.b64encode(v).decode() for k,v in keys.items()}, f, sort_keys=True)
        f.flush(); os.fsync(f.fileno())
    os.replace(tmp, root / "keyring.json")
    # Directory fsync is meaningful on this Linux harness; no power-loss claim.
    fd = os.open(root, os.O_RDONLY)
    try: os.fsync(fd)
    finally: os.close(fd)

def load_keys(root: Path):
    return {int(k): base64.b64decode(v) for k,v in json.loads((root / "keyring.json").read_text()).items()}

def connect(db: Path):
    con = sqlite3.connect(db)
    con.execute("PRAGMA journal_mode=DELETE")
    con.execute("PRAGMA synchronous=FULL")
    return con

def initialize(root: Path, records: int, size: int):
    keys = {0: os.urandom(32)}
    save_keys(root, keys)
    with connect(root / "live.db") as c:
        c.execute("CREATE TABLE records(id INTEGER PRIMARY KEY, epoch INTEGER, nonce BLOB, ciphertext BLOB, wrap_nonce BLOB, wrapped_key BLOB)")
        for i in range(records):
            dek, nonce, wn = os.urandom(32), os.urandom(12), os.urandom(12)
            ct = AESGCM(dek).encrypt(nonce, payload(i,size), data_aad(i))
            wk = AESGCM(keys[0]).encrypt(wn, dek, aad(i,0))
            c.execute("INSERT INTO records VALUES(?,?,?,?,?,?)", (i,0,nonce,ct,wn,wk))
        c.commit()
        with sqlite3.connect(root / "backup.db") as backup:
            c.backup(backup)

def durable_refs(db: Path) -> set[int]:
    with sqlite3.connect(db) as c:
        return {r[0] for r in c.execute("SELECT DISTINCT epoch FROM records")}

def rotate(root: Path, policy: str, stop: str):
    def checkpoint(name):
        if stop == name:
            os._exit(CRASH_EXIT)
    keys = load_keys(root)
    keys[1] = os.urandom(32)
    save_keys(root, keys)
    checkpoint("after_provision")
    c = connect(root / "live.db")
    rows = c.execute("SELECT id,epoch,wrap_nonce,wrapped_key FROM records ORDER BY id").fetchall()
    pending = []
    for i, old, wn, wk in rows:
        dek = AESGCM(keys[old]).decrypt(wn, wk, aad(i,old))
        new_nonce = os.urandom(12)
        new_wrapped = AESGCM(keys[1]).encrypt(new_nonce, dek, aad(i,1))
        pending.append((1,new_nonce,new_wrapped,i))
    checkpoint("after_prepare")
    def retire():
        if policy == "intent_only":
            used = {1}  # Intentionally faulty: assumes volatile intent is durable.
        else:
            used = durable_refs(root / "live.db")
            if policy == "recovery_set":
                used |= durable_refs(root / "backup.db") | {1}
        for k in list(keys):
            if k != 1 and k not in used:
                del keys[k]
        save_keys(root, keys)
    retire()
    checkpoint("after_retire_attempt")
    c.execute("BEGIN IMMEDIATE")
    c.executemany("UPDATE records SET epoch=?,wrap_nonce=?,wrapped_key=? WHERE id=?", pending)
    checkpoint("before_db_commit")
    c.commit()
    checkpoint("after_db_commit")
    retire()
    checkpoint("after_final_retire")
    c.close()

def restore(root: Path, db: str, records: int, size: int):
    keys = load_keys(root)
    counts = Counter()
    with connect(root / db) as c:
        rows = c.execute("SELECT id,epoch,nonce,ciphertext,wrap_nonce,wrapped_key FROM records ORDER BY id").fetchall()
    if len(rows) != records:
        raise RuntimeError("Unexpected row count")
    for i, epoch, nonce, ct, wn, wk in rows:
        if epoch not in keys:
            counts["missing_key"] += 1
            continue
        dek = AESGCM(keys[epoch]).decrypt(wn, wk, aad(i,epoch))
        plain = AESGCM(dek).decrypt(nonce, ct, data_aad(i))
        if plain != payload(i,size):
            raise RuntimeError("Plaintext mismatch")
        counts["restored"] += 1
    return counts["restored"], counts["missing_key"]

def expected(policy, stage):
    if policy == "recovery_set":
        return True, True
    if policy == "live_only":
        return True, stage not in ("after_final_retire", "complete")
    return (stage not in ("after_retire_attempt", "before_db_commit"),
            stage in ("after_provision", "after_prepare"))

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--out",type=Path,default=Path("results"))
    ap.add_argument("--worker",type=Path)
    ap.add_argument("--policy",choices=POLICIES)
    ap.add_argument("--stage",choices=STAGES)
    args=ap.parse_args()
    if args.worker:
        rotate(args.worker,args.policy,args.stage)
        return
    args.out.mkdir(parents=True,exist_ok=True)
    results=[]
    # Six deterministic datasets; each policy/cut-point is run once per dataset.
    for n in (1,8):
        for size in (512,16384,262144):
            for policy in POLICIES:
                for stage in STAGES:
                    with tempfile.TemporaryDirectory(prefix="restore-contract-") as td:
                        root=Path(td)
                        initialize(root,n,size)
                        child=subprocess.run([sys.executable,str(Path(__file__).resolve()),"--worker",td,"--policy",policy,"--stage",stage],capture_output=True,text=True)
                        want=0 if stage=="complete" else CRASH_EXIT
                        if child.returncode!=want:
                            raise RuntimeError(f"Unexpected child exit {child.returncode}: {child.stderr}")
                        live,live_missing=restore(root,"live.db",n,size)
                        backup,backup_missing=restore(root,"backup.db",n,size)
                        exp_live,exp_backup=expected(policy,stage)
                        if (live==n,backup==n)!=(exp_live,exp_backup):
                            raise AssertionError((policy,stage,live,backup))
                        results.append({"records":n,"payload_bytes":size,"policy":policy,"checkpoint":stage,"exit_code":child.returncode,"live_restored":live,"live_missing_key":live_missing,"backup_restored":backup,"backup_missing_key":backup_missing})
    with (args.out/"crash_trials.csv").open("w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=list(results[0]));w.writeheader();w.writerows(results)
    summaries=[]
    for p in POLICIES:
        rows=[r for r in results if r["policy"]==p]
        summaries.append({"policy":p,"cases":len(rows),"live_failure_cases":sum(r["live_missing_key"]>0 for r in rows),"backup_failure_cases":sum(r["backup_missing_key"]>0 for r in rows),"both_restored_cases":sum(r["live_restored"]==r["records"] and r["backup_restored"]==r["records"] for r in rows)})
    (args.out/"crash_summary.json").write_text(json.dumps(summaries,indent=2)+"\n")
    (args.out/"crash_manifest.json").write_text(json.dumps({"python":sys.version,"platform":platform.platform(),"sqlite":sqlite3.sqlite_version,"cryptography":cryptography.__version__,"source_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),"records":[1,8],"payload_bytes":[512,16384,262144],"policies":POLICIES,"checkpoints":STAGES,"repetitions_per_configuration":1,"failure_model":"child process exits with os._exit(93); host and filesystem remain running","crypto":"AES-256-GCM data and DEK wrapping; no PQC implementation","datasets":"deterministic synthetic bytes; independent random keys/nonces per case","statistics":"case outcomes, not empirical failure probabilities or timings"},indent=2)+"\n")
    print(json.dumps(summaries,indent=2))

if __name__=="__main__":
    main()
