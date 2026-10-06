"""One-shot verification entry point used by Docker Compose.

A single run of ``python -m verify.run``:

1. executes the lock-rule unit tests (Ed25519 vectors, consensus rules,
   in-process API tests);
2. waits for the ``audit`` service to become healthy and runs HTTP smoke
   checks against it: a commit trajectory, reject trajectories, idempotent
   replay, and conflict handling;

then exits with status 0 on success and 1 on any failure.
"""

from __future__ import annotations

import json
import os
import sys
import time
import unittest
import urllib.error
import urllib.request

AUDIT_URL = os.environ.get("AUDIT_URL", "http://127.0.0.1:8080").rstrip("/")
WAIT_SECONDS = float(os.environ.get("AUDIT_WAIT_SECONDS", "60"))

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import trajgen  # noqa: E402

_FAILURES: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"  PASS {name}")
    else:
        print(f"  FAIL {name} {detail}")
        _FAILURES.append(name)


def run_unit_tests() -> bool:
    print("== lock-rule unit tests ==")
    suite = unittest.TestLoader().discover("tests")
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    return result.wasSuccessful()


def wait_for_service() -> bool:
    print(f"== waiting for audit service at {AUDIT_URL} ==")
    deadline = time.time() + WAIT_SECONDS
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(AUDIT_URL + "/health", timeout=3) as r:
                if r.status == 200:
                    print("  service is healthy")
                    return True
        except Exception:
            pass
        time.sleep(1)
    print("  service did not become healthy in time")
    return False


def http(method: str, path: str, body=None):
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(AUDIT_URL + path, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def smoke() -> None:
    print("== HTTP smoke: health ==")
    status, body = http("GET", "/health")
    check("health 200", status == 200 and body.get("status") == "ok",
          f"got {status} {body}")

    print("== HTTP smoke: commit trajectory (n=4) ==")
    builder, blocks = trajgen.build_commit_trajectory("smoke-commit-4", 4, 4)
    submission = builder.submission()
    status, verdict = http("POST", "/v1/audits", submission)
    check("commit accepted", status == 201 and verdict.get("status") == "accepted",
          f"got {status} {verdict.get('violation')}")
    check("commit derives 3-chain commits",
          verdict.get("committed") == blocks[:2],
          f"got {verdict.get('committed')}")
    check("commit certificates have 2f+1 signers",
          all(len(c["signers"]) >= 3 for c in verdict.get("certificates", []))
          and len(verdict.get("certificates", [])) == 4)
    check("commit locks climbed to view 4",
          all(l["locked"]["view"] == 4 for l in verdict.get("locks", {}).values()))

    print("== HTTP smoke: lock evidence chain ==")
    v0 = submission["validators"][0]
    status, chain = http("GET", f"/v1/audits/smoke-commit-4/locks/{v0}?view=4")
    check("lock evidence 200 for a recorded lock",
          status == 200 and chain.get("queried_lock") == {
              "block_id": blocks[3], "view": 4},
          f"got {status} {chain if status != 200 else ''}")
    evidence = chain.get("evidence", {})
    check("evidence links the triggering observation",
          (evidence.get("observation") or {}).get("view") == 4
          and evidence["observation"].get("validator") == v0)
    formation = evidence.get("certificate_formation", {})
    check("evidence names the threshold-forming vote",
          formation.get("quorum") == 3
          and formation.get("threshold_vote", {}).get("event_index")
          == formation.get("formed_at"))
    votes = evidence.get("votes", [])
    check("evidence carries the signed quorum, in capture order",
          len(votes) == 3
          and [v["event_index"] for v in votes]
          == sorted(v["event_index"] for v in votes)
          and len({v["validator"] for v in votes}) == 3
          and all(v["view"] == 4 and v["block_id"] == blocks[3]
                  and len(v["signature"]) == 128 for v in votes))
    parent_chain = chain.get("parent_chain", [])
    chain_ok = (
        [h.get("view") for h in parent_chain] == [4, 3, 2, 1, 0]
        and parent_chain[-1].get("genesis") is True
        and all(hop.get("parent_id") == parent.get("block_id")
                and hop.get("certificate", {}).get("block_id")
                == parent.get("block_id")
                for hop, parent in zip(parent_chain, parent_chain[1:]))
    )
    check("parent chain runs continuously back to genesis",
          chain_ok, f"got {parent_chain}")
    # historical lock views stay auditable
    status, old = http("GET", f"/v1/audits/smoke-commit-4/locks/{v0}?view=1")
    check("historical lock view still resolvable",
          status == 200
          and old.get("queried_lock") == {"block_id": blocks[0], "view": 1},
          f"got {status}")

    print("== HTTP smoke: commit trajectory (n=7) ==")
    builder7, blocks7 = trajgen.build_commit_trajectory("smoke-commit-7", 7, 3)
    status, verdict7 = http("POST", "/v1/audits", builder7.submission())
    check("n=7 accepted", status == 201 and verdict7.get("status") == "accepted",
          f"got {status} {verdict7.get('violation')}")
    check("n=7 quorum 5 and commit",
          verdict7.get("quorum") == 5 and verdict7.get("committed") == blocks7[:1])

    print("== HTTP smoke: idempotent replay and conflict ==")
    status, replay = http("POST", "/v1/audits", submission)
    check("replay returns original verdict",
          status == 200 and replay.get("replayed") is True
          and replay.get("committed") == blocks[:2],
          f"got {status}")
    mutated = json.loads(json.dumps(submission))
    mutated["events"] = mutated["events"][:-1]
    status, conflict = http("POST", "/v1/audits", mutated)
    check("conflicting content rejected with 409",
          status == 409 and conflict.get("error", {}).get("code") == "conflict",
          f"got {status} {conflict}")
    status, fetched = http("GET", "/v1/audits/smoke-commit-4")
    check("stored verdict fetchable",
          status == 200 and fetched.get("committed") == blocks[:2],
          f"got {status}")

    print("== HTTP smoke: reject trajectories ==")
    unsafe, offending = trajgen.build_unsafe_vote_trajectory("smoke-unsafe")
    unsafe_submission = unsafe.submission()
    # an observation captured *after* the violating event: it must never be
    # able to back a lock, even though the certificate itself formed earlier
    unsafe_submission["events"].append(
        unsafe.observe(1, unsafe.events[0]["block_id"], 1))
    status, verdict = http("POST", "/v1/audits", unsafe_submission)
    check("unsafe vote frozen at earliest event",
          status == 201 and verdict.get("status") == "rejected"
          and verdict.get("violation", {}).get("type") == "unsafe_vote"
          and verdict.get("violation", {}).get("event_index") == offending,
          f"got {status} {verdict.get('violation')}")
    check("frozen trajectory yields no commits",
          verdict.get("committed") == [])

    # evidence query boundaries on the frozen trajectory
    uv0 = unsafe.pubkeys[0]
    uv1 = unsafe.pubkeys[1]
    frozen_block = unsafe.events[0]["block_id"]
    status, locked = http(
        "GET", f"/v1/audits/smoke-unsafe/locks/{uv0}?view=1")
    check("pre-freeze lock evidence still served",
          status == 200 and locked.get("frozen") is True
          and locked.get("freeze", {}).get("event_index") == offending
          and locked.get("evidence", {}).get("observation", {})
          .get("event_index") == 4,
          f"got {status} {locked if status != 200 else ''}")
    status, body = http(
        "GET", f"/v1/audits/smoke-unsafe/locks/{uv1}?view=1")
    check("lock appearing only after freeze is refused",
          status == 404
          and body.get("error", {}).get("code") == "lock_view_not_recorded",
          f"got {status} {body}")
    status, body = http(
        "GET", f"/v1/audits/smoke-unsafe/locks/{uv0}?view=2")
    check("unrecorded lock view refused on frozen audit",
          status == 404
          and body.get("error", {}).get("code") == "lock_view_not_recorded",
          f"got {status} {body}")
    outsider = "01" * 32
    status, body = http(
        "GET", f"/v1/audits/smoke-unsafe/locks/{outsider}?view=1")
    check("unknown validator refused",
          status == 404
          and body.get("error", {}).get("code") == "unknown_validator",
          f"got {status} {body}")
    status, body = http(
        "GET", f"/v1/audits/smoke-unsafe/locks/{uv0}")
    check("missing view parameter rejected",
          status == 400
          and body.get("error", {}).get("code") == "invalid_query",
          f"got {status} {body}")
    status, body = http(
        "GET", f"/v1/audits/never-existed/locks/{uv0}?view=1")
    check("evidence for unknown audit refused",
          status == 404
          and body.get("error", {}).get("code") == "not_found",
          f"got {status} {body}")
    status, body = http(
        "GET", f"/v1/audits/smoke-unsafe/locks/{uv0}"
        f"?view=1&block_id={'ab' * 32}")
    check("mismatched block_id refused",
          status == 404
          and body.get("error", {}).get("code")
          == "lock_view_not_recorded",
          f"got {status} {body}")
    status, matching = http(
        "GET", f"/v1/audits/smoke-unsafe/locks/{uv0}"
        f"?view=1&block_id={frozen_block}")
    check("matching block_id accepted",
          status == 200 and matching.get("queried_lock", {}).get("block_id")
          == frozen_block, f"got {status}")

    bad_sig = trajgen.TrajectoryBuilder("smoke-bad-signature", 4)
    block = bad_sig.propose(0, 1, (bad_sig.genesis_id, 0))
    bad_sig.vote(0, 1, block, sign=False)
    status, verdict = http("POST", "/v1/audits", bad_sig.submission())
    check("invalid signature frozen",
          status == 201 and verdict.get("status") == "rejected"
          and verdict.get("violation", {}).get("type") == "invalid_signature",
          f"got {status} {verdict.get('violation')}")

    missing = trajgen.TrajectoryBuilder("smoke-missing-qc", 4)
    block = missing.propose(0, 1, (missing.genesis_id, 0))
    missing.observe(0, block, 1)  # no certificate formed yet
    status, verdict = http("POST", "/v1/audits", missing.submission())
    check("missing certificate frozen",
          status == 201 and verdict.get("status") == "rejected"
          and verdict.get("violation", {}).get("type") == "missing_certificate",
          f"got {status} {verdict.get('violation')}")

    print("== HTTP smoke: envelope errors ==")
    status, body = http("GET", "/v1/audits/never-submitted")
    check("unknown audit id 404", status == 404, f"got {status}")
    dup = trajgen.TrajectoryBuilder("smoke-dup", 4).submission()
    dup["validators"][1] = dup["validators"][0]
    status, body = http("POST", "/v1/audits", dup)
    check("duplicate identity 400",
          status == 400 and body.get("error", {}).get("code") == "duplicate_identity",
          f"got {status} {body}")


def main() -> int:
    ok = run_unit_tests()
    if not ok:
        print("unit tests failed; skipping HTTP smoke")
        return 1
    if not wait_for_service():
        return 1
    try:
        smoke()
    except Exception as exc:  # connection reset, JSON decode, ...
        print(f"  FAIL smoke raised {exc!r}")
        _FAILURES.append(str(exc))
    if _FAILURES:
        print(f"VERIFY FAILED: {len(_FAILURES)} check(s) failed: {_FAILURES}")
        return 1
    print("VERIFY OK: unit tests and HTTP smoke passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
