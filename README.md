# Storage recovery contracts: supplementary artifact

Executable model, interruption experiments, controlled concurrent schedules,
and recorded results for **Recovery-Set Contracts for Cryptographic Storage
Migration**, by Ishan Teredesai, Tushar Rahangdale, Karanjyot Singh, and Ayush Pure.

## Reproduce

Use Python 3.10+ on Linux, or Ubuntu through WSL. The recorded environment used
Python 3.12.14, SQLite 3.53.1, cryptography 50.0.2, and Linux 6.18.57 x86-64.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
unzip -o recorded_results.zip
python3 verify_results.py --results results
```

Run all nine tests and all three experiments:

```bash
bash run_experiments.sh
```

Run each experiment separately:

```bash
python3 model.py --out results
python3 crash_harness.py --out results
python3 concurrency_harness.py --out results
```

Run the tests separately:

```bash
python3 -m unittest discover -s . -p 'test_*.py' -v
```

Preserve the distributed results before rerunning: commands overwrite `results/`.
The recorded manifests capture exact versions, source hashes, and configurations.

## Observed outcomes

| Experiment | Coverage | Recorded outcome |
|---|---|---|
| Finite model | 18 bounded configurations | Guarded configurations: 1,890 states, 7,232 transitions, zero missing-key states |
| Interruption harness | 126 cases; 108 process terminations | Live/backup failure cases: intent-only 12/30, live-only 0/12, recovery-set 0/0 |
| Concurrent admission | 48 cases across four schedules | Live failures: unlocked 12/24; shared lock 0/24; all backups restore |

These are outcomes of selected deterministic cases, not failure probabilities.
Live and backup failure columns can overlap. The concurrent experiment adds
admission of a still-available inactive generation; it is not a refinement proof
of the finite model's current-generation-only prepare operation.

## Files and evidence

| File | Contents |
|---|---|
| `model.py`, `test_model.py` | Bounded model exploration and six model checks |
| `crash_harness.py` | Actual process interruption and ciphertext restoration |
| `concurrency_harness.py`, `test_concurrency.py` | Two real workers, four schedules, and three regression tests |
| `verify_results.py` | Consistency checks for recorded outcomes and source hashes |
| `recorded_results.zip` | Raw CSV/JSON outcomes, traces, manifests, and console logs under `results/` |
| `PROTOCOL.md` | State, synchronization scope, schedules, file-to-table map, and limitations |
| `Supplementary_Artifact.zip` | Complete supplementary artifact for offline reproduction |
| `SHA256SUMS` | Checksums for the distributed files |

Check the distributed files before rerunning:

```bash
sha256sum --check SHA256SUMS
```

## Scope

The harness uses synthetic data, SQLite, and AES-256-GCM wrapping-key epochs.
The local JSON key file stores plaintext test keys and is not a secure KMS.
The shared lock is local and cooperative; it covers the complete retirement
scan/delete interval and the writer's availability check through publication.
Worker crashes during locked concurrent schedules, changing snapshots,
distributed coordination, production performance, and cryptographic security
proofs are outside this evaluation. The artifact does not implement ML-KEM or
a hybrid KEM.

OpenAI ChatGPT assisted with model formulation, code, and documentation.
Reported results were obtained by executing the supplied programs.
