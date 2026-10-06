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
| `GET` | `/v1/audits/{audit_id}/locks/{validator}?view=v` | Stable evidence chain behind one recorded validator lock |

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

`GET /v1/audits/{audit_id}/locks/{validator_hex}?view={view}` lets an auditor
reopening a stored (possibly frozen) trace a validator's **final or
historical** lock back to the proof that caused it, rather than trusting the
lock summary alone. `view` must name a lock the validator actually recorded
via an accepted `qc_observation`. The evidence is re-derived from the stored
submission through the real replay engine, so every cited event index, block,
view and signature comes from the replayed prefix:

* `observation` — the `qc_observation` capture event that moved the lock
  (event index, block, view, validator);
* `certificate.formation_event` — the threshold-crossing (2f+1-th distinct)
  vote at which the observed certificate formed;
* `certificate.forming_votes` — every distinct signed vote that makes up the
  certificate, each with its capture event index, block, view, validator and
  signature;
* `parent_chain` — the continuous certificate references from the locked
  block's justifying certificate down the proposal parent links to the
  implicit genesis certificate. Each hop gives the proposal event index, the
  parent block and the referenced (`block_id`, `view`, `formed_at`,
  `signers`) certificate with `parent_matches_certified_block: true`, so each
  hop's parent block and certified block can be checked to agree.

Errors (never back-filled from later events):

* `404 not_found` — no stored audit with that id;
* `404 unknown_validator` — the hex key is not in the audit's validator set;
* `404 lock_view_not_found` — the validator never recorded a lock at that
  view;
* `409 evidence_unavailable` — the lock would only form at or after the
  freeze violation (the replay horizon), or its chain cannot be proven from
  the replayed prefix;
* `400 invalid_request` — missing/malformed `view` query parameter.

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
   conflict handling, and lock-evidence queries (valid historical/final
   evidence chains plus the frozen-trace query boundaries).

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
  store.py       idempotent verdict store (replay / conflict)
  server.py      HTTP API (PORT env, /health, two audit operations)
  healthcheck.py container HEALTHCHECK
  trajgen.py     deterministic signed-trajectory builder (tests/verify)
tests/           Ed25519 vectors, lock-rule tests, in-process API tests
verify/run.py    one-shot verify: unit tests + HTTP smoke, exit code
```
