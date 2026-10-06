# lock-audit — restricted-view locked-vote trajectory audit service

Before the redundant controller switches its master node, this service
re-audits a captured voting trajectory and confirms that no validator voted
for a conflicting branch without a higher-certificate unlock — the condition
under which two chains could be finalized at once. The service is pure
Python 3.11 standard library (including a dependency-free RFC 8032 Ed25519
implementation), so the image builds with no network access.

## Model

* **Validators** — 4 or 7 distinct Ed25519 public keys (32 bytes, lowercase
  hex). With `n` validators, `f = (n-1)//3` and the threshold is
  `2f+1` (3 of 4, or 5 of 7).
* **Genesis** — the caller-supplied genesis block (`view 0`). Its certificate
  is implicit: every validator starts locked on genesis, and proposals may
  justify against it.
* **Events** — at most 64, replayed strictly in capture order:
  * `proposal` — a block extending a certificate. The referenced certificate
    must already be formed (2f+1 distinct valid votes, or genesis), the
    parent block must equal the certified block, the proposal view must
    exceed the certificate view, and `block_id` must equal the canonical
    block hash.
  * `vote` — a validator's Ed25519 signature over the canonical UTF-8 vote
    fields (see below). A certificate forms the moment 2f+1 *distinct*
    validators voted for the same `(block, view)`; later distinct signers
    still join the certificate.
  * `qc_observation` — records that a validator has observed a formed
    certificate. A validator's **locked block** is the block of the
    highest-view certificate it has observed; locks only move to strictly
    higher views.

### Locking rules (checked per vote)

A validator may vote for a candidate only if

1. the candidate **extends its locked block**, or
2. the candidate's justifying certificate has a **strictly higher view**
   than the validator's locked certificate (the higher-proof unlock);

and it may vote **at most once per view**. The first missing certificate,
invalid signature, duplicate identity, dangling parent, or unsafe vote
**freezes the audit at that event**: the verdict is `rejected`, the
violating event index and reason are reported, and no conclusions are drawn
from later events. Duplicate validator public keys in the submission itself
are rejected up front with HTTP 400 (`duplicate_identity`).

### Commit rule

When certificates (each actually reaching 2f+1 distinct signers) exist for a
chain of **three blocks in three consecutive views** — `B1@v ← B2@v+1 ←
B3@v+2` — the head `B1` and its uncommitted ancestors are committed. The
verdict reports the committed blocks in order, the deciding certificate and
its signers for each commit, every formed certificate with its signers, and
every validator's lock changes.

## Canonical formats

Vote signatures cover the UTF-8 encoding of

```
lock-audit.v1
vote
audit:{audit_id}
view:{view}
block:{block_id}
```

and `block_id` is `sha256` of the UTF-8 encoding of

```
lock-audit.v1
block
view:{view}
parent:{parent_id}
qc_view:{qc.view}
qc_block:{qc.block_id}
proposer:{proposer_pubkey_hex}
payload:{payload as JSON string}
```

## HTTP API

Port is configurable via `PORT` (default 8080). All bodies are JSON.

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/health` | Liveness: `200 {"status":"ok"}` |
| `POST` | `/v1/audits` | Submit a trajectory for audit |
| `GET` | `/v1/audits/{audit_id}` | Fetch the stored verdict (`404` if none) |
| `GET` | `/v1/audits/{audit_id}/locks/{validator}?view=V` | Stable evidence chain for one recorded lock |

`POST /v1/audits` responses:

* `201` — new verdict (`"replayed": false`), status `accepted` or `rejected`;
* `200` — the same `audit_id` was resubmitted with semantically identical
  content: the original verdict is replayed (`"replayed": true`);
* `409` — the same `audit_id` with different content: explicit conflict;
* `400` — structurally invalid submission (wrong key count,
  `duplicate_identity`, more than 64 events, malformed fields, ...).

### Submission

```json
{
  "audit_id": "capture-2026-10-05-a",
  "validators": ["<64 hex chars>", "... 4 or 7 keys ..."],
  "genesis": {"id": "<64 hex chars>", "view": 0},
  "events": [
    {"type": "proposal", "proposer": "<hex>", "view": 1,
     "block_id": "<hex>", "parent_id": "<hex>",
     "qc": {"block_id": "<hex>", "view": 0}, "payload": "optional"},
    {"type": "vote", "validator": "<hex>", "view": 1,
     "block_id": "<hex>", "signature": "<128 hex chars>"},
    {"type": "qc_observation", "validator": "<hex>",
     "block_id": "<hex>", "view": 1}
  ]
}
```

### Verdict

```json
{
  "audit_id": "capture-2026-10-05-a",
  "status": "accepted | rejected",
  "validator_count": 4, "f": 1, "quorum": 3,
  "events_total": 30, "events_processed": 30,
  "violation": null | {"event_index": 7, "type": "unsafe_vote", "detail": "..."},
  "committed": ["<block_id>", "..."],
  "commits": [{"blocks": ["..."], "decide_qc": {"block_id": "...", "view": 3,
               "signers": ["..."]}}],
  "certificates": [{"block_id": "...", "view": 1, "signers": ["..."],
                    "formed_at": 3}],
  "locks": {"<validator>": {"locked": {"block_id": "...", "view": 4},
            "history": [{"event_index": 5, "block_id": "...", "view": 1}]}}
}
```

Violation types: `missing_certificate`, `invalid_signature`,
`unknown_validator`, `dangling_parent`, `parent_qc_mismatch`,
`invalid_block_hash`, `invalid_view`, `double_vote`, `unknown_block`,
`view_mismatch`, `unsafe_vote`.

### Lock evidence

A lock summary cannot, by itself, justify an unlock.  The lock-evidence
read lets an auditor pick a validator and one of that validator's
*recorded* lock views (`?view=V`; view `0` is the implicit genesis lock
and is only addressable while the validator is still on genesis) and
returns a chain rebuilt from a fresh deterministic replay of the stored
trajectory:

* `evidence.observation` — the captured `qc_observation` event (index,
  block, view, validator) that moved the lock;
* `evidence.proposal` — the captured proposal event that formed the
  locked block;
* `evidence.certificate_formation` — the vote event at which 2f+1
  distinct signers first reached the threshold (`formed_at`, with the
  `threshold_vote` record), and the quorum size;
* `evidence.votes` — every signed vote contributing to that
  certificate, in capture order, each with its event index, block,
  view, validator and Ed25519 signature (re-verifiable against the
  canonical vote message);
* `parent_chain` — the locked block's proposal-parent chain back to
  genesis where every non-genesis hop carries the certificate
  referencing its parent, so each hop's `parent_id` equals the next
  hop's certified block (the final hop is the implicit genesis
  certificate).

Every item is attributable (event index, block, view, validator) and is
derived only from events actually processed: a lock whose observation
or certificate formation occurs at or after the freeze violation is
refused with no evidence fabricated from later events.  A response for a
frozen audit carries `"frozen": true` and a `freeze` descriptor
`{event_index, type}`.

Query refusals:

* `404 not_found` — no such audit;
* `404 unknown_validator` — the public key is not in the audit's
  validator set;
* `404 lock_view_not_recorded` — the validator never had a recorded
  lock at that view in the processed prefix (including locks that would
  only form after a freeze);
* `400 invalid_query` — missing/duplicate/non-integer/negative `view`,
  malformed validator or `block_id`;
* `409 evidence_unavailable` — a verdict stored by an older build
  without the captured submission (resubmit to enable).

An optional `block_id` query parameter additionally pins the expected
locked block and is refused (`404 lock_view_not_recorded`) on mismatch.

## Run

```sh
docker compose up --build audit          # serves on ${HOST_PORT:-8080}
# or locally, no container:
PORT=8080 python -m app.server
```

Verdicts are kept in memory; set `AUDIT_STORE_FILE=/path/audits.json` to
persist them across restarts.

## Verify

`verify.sh` (or `docker compose up --build --exit-code-from verify verify`)
performs the whole review in one run and exits with the result status:

1. builds the image (`--build`);
2. runs the lock-rule unit tests (Ed25519 vectors, consensus rules, API);
3. waits for the healthy `audit` container and runs HTTP smoke checks:
   commit trajectories for 4 and 7 validators, reject trajectories (unsafe
   vote, invalid signature, missing certificate), idempotent replay,
   conflict handling, and lock-evidence chain queries (valid chain,
   historical lock, frozen-trajectory boundaries).

Exit code `0` means everything passed; any failure exits `1`.

```sh
./verify.sh
```

## Layout

```
app/
  ed25519.py     pure-stdlib RFC 8032 Ed25519 (extended coordinates)
  canonical.py   canonical UTF-8 vote/block encodings and digests
  schema.py      structural validation of submissions (HTTP 400)
  consensus.py   lock-rule engine, certificate formation, 3-chain commits
  evidence.py    lock evidence chains (observation -> formation -> votes)
  store.py       idempotent verdict store (replay / conflict)
  server.py      HTTP API (PORT env, health, audit and lock-evidence reads)
  healthcheck.py container HEALTHCHECK
  trajgen.py     deterministic signed-trajectory builder (tests/verify)
tests/           Ed25519 vectors, lock-rule tests, evidence/API tests
verify/run.py    one-shot verify: unit tests + HTTP smoke, exit code
```
