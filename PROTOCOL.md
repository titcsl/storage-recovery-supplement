# Experimental protocol and recorded evidence

## State and contracts

The finite state is `(a, L, B, P, K)`: active generation, committed live
references, an optional retained snapshot, volatile prepared targets, and
available keys. Initially live records and the snapshot reference generation
zero, and only key zero is available.

Reference availability requires every live and retained-snapshot reference to
name an available key. Pending targets are not retained recovery references;
the retirement guard additionally protects them until commit. Profile coverage
is a separate property: retained references must carry approved profile labels.
Labels represent migration state, not proven cryptographic security.

Snapshot release assumes an authorized retention decision. It does not migrate
a copy or demonstrate secure erasure. Preserving references can block retirement
indefinitely while profile migration remains incomplete.

## Bounded exploration

Breadth-first exploration reaches a fixed point for each combination of one,
two, or three records; two or three generations; and three retirement rules.
The 18 configurations have no depth cutoff. States are deduplicated; transition
counts include edges to already visited states.

Intent-only retirement substitutes pending targets for live references and
ignores snapshots. Live-only checks committed live references. Recovery-set
checks live, retained-snapshot, and pending references. The first two are
constructed negative controls, not defects reported in third-party products.

## Interruption harness

Each synthetic record has a fresh 32-byte data key. AES-256-GCM protects payloads
and wrapped keys with separate random 12-byte nonces. Associated data binds
record identity and content version or key epoch. A separate JSON key file is
updated through file synchronization and atomic replacement. SQLite uses
rollback journaling with `synchronous=FULL`; its transaction does not include
the key file.

The worker provisions generation 1, prepares replacements, attempts retirement,
updates all records in one transaction, commits, and attempts retirement again.
A retained pre-rotation snapshot references generation 0. Six checkpoints call
`os._exit(93)`: after provisioning, preparation, first retirement, SQL updates
before commit, commit, and final retirement. A seventh case completes normally.
The parent reopens both databases and verifies recovered plaintext byte-for-byte.

One and eight records, at 512 B, 16 KiB, and 256 KiB each, produce six datasets.
Three policies and seven cut/completion points yield 126 cases, including 108
process terminations. All 42 recovery-set cases restore both copies. The weak
controls produce live/backup failures of 12/30 and 0/12. Failure columns overlap.
The host kernel remains running: this is not a power-loss experiment.

## Controlled concurrent admission

A parent scheduler starts two real workers with Python's `spawn` method.
Initially active generation, live records, and the snapshot are at generation 1.
Keys 0 and 1 exist; no pin is pending. The retirement candidate is generation 0.
The writer carries a previously selected generation choice, representing delayed
work or import, and attempts to publish references to generation 0.

This admission operation extends the finite model's forward-only prepare step.
A current-generation-only implementation could reject stale choices instead.
The experiment admits an inactive choice only while its key is available, to
examine reference availability under late dependency creation.

Both implementations scan live, snapshot, and registered pending references.
The unlocked implementation caches eligibility before deletion. The protected
implementation uses one stable local lock-file inode and nonblocking
`fcntl.flock(LOCK_EX | LOCK_NB)`:

| Actor | Protected interval |
|---|---|
| Retirement worker | Acquire lock; inspect the full inventory and active generation; decide; delete or retain candidate key; release lock |
| Writer | Acquire same lock; check target-key availability; register durable SQLite pin; prepare envelopes; atomically publish live references and remove pin; release lock |
| Parent | No lifecycle lock; send IPC commands, record responses and inventories, then restore both copies |

Publication and pin removal share one SQL transaction. Locking only deletion
does not protect a preceding scan. Active-generation and snapshot changes are
disabled in these trials; enabling them requires synchronizing their changes too.
The concurrent registry uses durable SQLite pins, while abstract pending work is
volatile. No concurrent worker failure is injected, so abandoned-pin recovery
is not established.

Let C = retirement check, P = writer prepare/register, W = writer commit,
and D = retirement delete. The scheduler requests:

| Schedule | Requested order | Unlocked live/backup failures | Protected live/backup failures | Protected writer outcome |
|---|---|---:|---:|---|
| `commit_in_gap` | C, P, W, D | 6/0 | 0/0 | 6 rejected |
| `prepare_in_gap` | C, P, D, W | 6/0 | 0/0 | 6 rejected |
| `writer_first` | P, C, W, D | 0/0 | 0/0 | 6 committed |
| `delete_first` | C, D, P | 0/0 | 0/0 | 6 rejected |

Each implementation/schedule has six datasets, yielding 48 cases. Commands are
ordered through IPC gates, without sleep-based scheduling. If a lock attempt is
blocked, the holder completes before the action retries. The protected protocol
therefore prevents the unsafe requested interleaving. Outcomes come from durable
inventories and actual AES-GCM restoration, not an expected-result function.

In the unlocked prepare-gap trace, C observes no dependency on 0; P registers
one; D acts on the stale scan and removes 0; W commits the prepared envelope;
the parent observes a live reference without its key and failed live restoration.
In the protected trace, P encounters the held lock; D deletes 0; P retries,
rejects the unavailable target, and both existing copies remain restorable.

When the writer prepares first, even the unlocked scan sees its registered pin
and retains the key. The unsafe schedules do not omit already registered work.
The protected trials preserve both copies in 24/24 cases. These selected schedules
do not establish exhaustive concurrency safety, progress, or distributed correctness.

## File-to-table map

Extract `recorded_results.zip` to obtain the following `results/` files:

| File | Evidence |
|---|---|
| `model_summary.csv`, `model_results.json` | Main Table II; all 18 configurations and bounded totals |
| `model_traces.json` | Shortest missing-key and profile-gap witnesses |
| `crash_trials.csv`, `crash_summary.json` | Main Table III; 126 cases and policy aggregates |
| `concurrency_trials.csv`, `concurrency_summary.json` | Main Table IV; 48 cases and schedule aggregates |
| `concurrency_traces.json` | Every command, lock status, cached eligibility, inventory, and final restore |
| `model_manifest.json`, `crash_manifest.json`, `concurrency_manifest.json` | Exact runtime versions, source SHA-256 hashes, bounds, and assumptions |
| `execution_log.txt`, `verification_log.txt` | Successful test/experiment console output and result verification |

Main Tables I and V are a source comparison and illustrative acceptance
obligations; they are not measured experiment outcomes.

## Failure conditions and environment

Nine tests pass; the reference run contains 18 model configurations, 126
interruption cases, and 48 concurrent cases. The verifier checks source hashes,
raw/summarized agreement, and published totals after results are generated.
A timeout, failed worker, unexpected exit, authentication error, wrong row count,
plaintext mismatch, dangling pin, or inventory/restore disagreement aborts a run.
Protected missing-key states and inconsistent recorded outputs fail validation.
Expected negative-control failures are evidence and must not be relabeled.

The definitive concurrent run completed at `2026-11-08T06:49:15.591912+00:00`:

- Python: `3.12.14 (main, Aug 25 2026, 14:00:49) [Clang 22.1.3 ]`
- Platform: `Linux-6.18.57-x86_64-with-glibc2.39`
- SQLite: `3.53.1`; cryptography: `50.0.2`.

Randomized ciphertext and key bytes are not archived. Recorded traces contain
synthetic reference inventories and outcomes. Independent runs in the same
environment reproduced the result CSV/JSON and concurrency traces byte-for-byte;
this does not establish cross-platform reproduction. Removing a JSON key entry
does not demonstrate physical erasure. Decoder compatibility, authorization,
retention decisions, and complete service restoration require deployment evidence.
