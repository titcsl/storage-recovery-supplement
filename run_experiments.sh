#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
experiment_dir=.
if [ -d experiment ]; then experiment_dir=experiment; fi
python3 -m unittest discover -s "$experiment_dir" -p 'test_*.py' -v
python3 "$experiment_dir/model.py" --out results
python3 "$experiment_dir/crash_harness.py" --out results
python3 "$experiment_dir/concurrency_harness.py" --out results
python3 "$experiment_dir/verify_results.py" --results results
