#!/usr/bin/env python3
"""Verify recorded files and published reproduction totals; never generate data."""
import argparse
import csv
import hashlib
import json
from pathlib import Path


def read_csv(path):
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def check(condition, description):
    if not condition:
        raise RuntimeError(description)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", type=Path, default=Path("results"))
    args = ap.parse_args()
    root, source = args.results, Path(__file__).parent
    for name, filename in (("model", "model.py"), ("crash", "crash_harness.py")):
        manifest = json.loads((root / f"{name}_manifest.json").read_text())
        check(manifest["source_sha256"] == hashlib.sha256((source / filename).read_bytes()).hexdigest(), f"{name} source differs from recorded run")
    manifest = json.loads((root / "concurrency_manifest.json").read_text())
    for filename, recorded in manifest["source_sha256"].items():
        check(recorded == hashlib.sha256((source / filename).read_bytes()).hexdigest(), f"concurrency source mismatch: {filename}")

    model = json.loads((root / "model_results.json").read_text())
    check(len(model) == 18, "Expected 18 model configurations")
    for row in read_csv(root / "model_summary.csv"):
        match = [x for x in model if x["records"] == int(row["records"]) and x["generations"] == int(row["generations"]) and x["policy"] == row["policy"]]
        check(len(match) == 1, "Model CSV configuration mismatch")
        check(all(str(v) == row[k] for k, v in match[0].items()), "Model CSV/JSON disagree")
    guarded = [r for r in model if r["policy"] == "recovery_set"]
    check(sum(r["states"] for r in guarded) == 1890 and sum(r["transitions"] for r in guarded) == 7232, "Guarded model totals changed")
    check(all(r["missing_live_key"] == r["missing_backup_key"] == 0 for r in guarded), "Guarded model invariant failed")

    crash = read_csv(root / "crash_trials.csv")
    check(len(crash) == 126, "Expected 126 interruption cases")
    check(sum(int(r["exit_code"]) == 93 for r in crash) == 108, "Expected 108 child terminations")
    for s in json.loads((root / "crash_summary.json").read_text()):
        rows = [r for r in crash if r["policy"] == s["policy"]]
        actual = [sum(int(r[k]) > 0 for r in rows) for k in ("live_missing_key", "backup_missing_key")]
        check(len(rows) == s["cases"] == 42, "Crash case grouping mismatch")
        check(actual == [s["live_failure_cases"], s["backup_failure_cases"]], "Crash summary disagrees with raw outcomes")
    check(all(int(r["live_missing_key"]) == int(r["backup_missing_key"]) == 0 for r in crash if r["policy"] == "recovery_set"), "Guarded interruption restore failed")

    concurrent = read_csv(root / "concurrency_trials.csv")
    traces = json.loads((root / "concurrency_traces.json").read_text())
    check(len(concurrent) == len(traces) == manifest["case_count"] == 48, "Expected 48 concurrent cases/traces")
    signatures = set()
    for row, trace in zip(concurrent, traces):
        signature = tuple(row[k] for k in ("protocol", "schedule", "records", "payload_bytes"))
        check(signature not in signatures, "Duplicate concurrent configuration")
        signatures.add(signature)
        check(all(str(v) == row[k] for k, v in trace["case"].items()), "Concurrent CSV/trace disagree")
        final = trace["events"][-1]
        check(final["observed"] == trace["case"], "Trace restore result differs from case summary")
        check(final["command"] == "restore" and not final["inventory"]["pending"], "Incomplete concurrent trial")
        check(row["workers_exited_zero"] == "True", "Worker failed")
    for s in json.loads((root / "concurrency_summary.json").read_text()):
        rows = [r for r in concurrent if r["protocol"] == s["protocol"] and r["schedule"] == s["schedule"]]
        check(len(rows) == s["cases"] == 6, "Concurrent schedule grouping mismatch")
        for output, raw in (("live_failure_cases", "live_missing_key"), ("backup_failure_cases", "backup_missing_key")):
            check(s[output] == sum(int(r[raw]) > 0 for r in rows), "Concurrent summary disagrees with raw outcomes")
    failures = {p: sum(int(r["live_missing_key"]) > 0 for r in concurrent if r["protocol"] == p) for p in ("unserialized", "shared_lock")}
    check(failures == {"unserialized": 12, "shared_lock": 0}, "Published concurrent outcome totals did not reproduce")
    check(all(int(r["backup_missing_key"]) == 0 for r in concurrent), "Concurrent snapshot restoration failed")
    print("Verified: 18 bounded configurations; 126 interruption cases; 48 concurrency cases.")
    print("Source hashes, raw outcomes, summaries, traces, and published totals agree.")
    print("These checks reproduce selected cases; they do not certify untested interleavings.")


if __name__ == "__main__":
    main()
