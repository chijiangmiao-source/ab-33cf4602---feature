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
    status, verdict = http("POST", "/v1/audits", unsafe.submission())
    check("unsafe vote frozen at earliest event",
          status == 201 and verdict.get("status") == "rejected"
          and verdict.get("violation", {}).get("type") == "unsafe_vote"
          and verdict.get("violation", {}).get("event_index") == offending,
          f"got {status} {verdict.get('violation')}")
    check("frozen trajectory yields no commits",
          verdict.get("committed") == [])

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

    print("== HTTP smoke: lock evidence chains ==")
    # The accepted n=4 trajectory from earlier is stored as smoke-commit-4;
    # query a historical (view 2) and the final (view 4) lock for validator 0.
    v0 = submission["validators"][0]
    genesis_id = submission["genesis"]["id"]
    for view, block in ((2, blocks[1]), (4, blocks[3])):
        status, ev = http(
            "GET",
            f"/v1/audits/smoke-commit-4/locks/{v0}?view={view}")
        check(f"lock evidence view {view} returns 200", status == 200,
              f"got {status} {ev}")
        check(f"lock evidence view {view} names the lock",
              ev.get("locked") == {"block_id": block, "view": view},
              f"got {ev.get('locked')}")
        obs = ev.get("observation", {})
        check(f"lock evidence view {view} cites the triggering observation "
              "with index/block/view/validator",
              obs.get("type") == "qc_observation"
              and isinstance(obs.get("event_index"), int)
              and obs.get("block_id") == block and obs.get("view") == view
              and obs.get("validator") == v0,
              f"got {obs}")
        cert = ev.get("certificate", {})
        forming = cert.get("forming_votes", [])
        check(f"lock evidence view {view} carries 2f+1 signed forming votes",
              cert.get("quorum") == 3 and len(forming) == 3
              and all(len(f.get("signature", "")) == 128
                      and f.get("block_id") == block and f.get("view") == view
                      and isinstance(f.get("event_index"), int)
                      for f in forming),
              f"got {cert}")
        check(f"lock evidence view {view} forms before the observation",
              cert.get("formed_at") == cert.get("formation_event", {}).get(
                  "event_index")
              and cert.get("formed_at", 1 << 30) < obs.get("event_index", -1),
              f"formed_at={cert.get('formed_at')} obs={obs.get('event_index')}")
        chain = ev.get("parent_chain", [])
        check(f"lock evidence view {view} runs a continuous parent chain to "
              "genesis",
              len(chain) == view
              and all(h.get("parent_matches_certified_block") for h in chain)
              and chain[-1].get("reaches_genesis") is True
              and chain[-1].get("parent_block_id") == genesis_id
              and chain[-1].get("certificate", {}).get("implicit") is True
              and all(chain[i]["parent_block_id"] == chain[i + 1]["block_id"]
                      for i in range(len(chain) - 1)),
              f"got {chain}")

    print("== HTTP smoke: lock evidence frozen-trajectory boundaries ==")
    frozen_builder, frozen_index, later_block = \
        trajgen.build_frozen_trajectory_with_later_lock("smoke-evidence-frozen")
    frozen_submission = frozen_builder.submission()
    status, frozen_verdict = http("POST", "/v1/audits", frozen_submission)
    check("frozen evidence trajectory rejected",
          status == 201 and frozen_verdict.get("status") == "rejected"
          and frozen_verdict.get("violation", {}).get("event_index")
          == frozen_index,
          f"got {status}")
    fv0 = frozen_submission["validators"][0]
    status, pre = http(
        "GET", f"/v1/audits/smoke-evidence-frozen/locks/{fv0}?view=1")
    check("pre-freeze lock evidence is served from the replayed prefix",
          status == 200 and pre.get("status") == "rejected"
          and pre.get("events_processed") == frozen_index
          and all(f["event_index"] < frozen_index
                  for f in pre.get("certificate", {}).get("forming_votes", [])),
          f"got {status} {pre}")
    status, body = http(
        "GET", f"/v1/audits/smoke-evidence-frozen/locks/{fv0}?view=2")
    check("post-freeze lock is refused without back-filling",
          status == 409 and body.get("error", {}).get("code")
          == "evidence_unavailable",
          f"got {status} {body}")
    status, pre = http(
        "GET", f"/v1/audits/smoke-evidence-frozen/locks/{fv0}?view=1")
    leaked = later_block in json.dumps(pre)
    check("post-freeze block never leaks into pre-freeze evidence",
          not leaked, "later block present in evidence payload")
    # unknown audit / unknown validator / never-recorded view stay explicit
    status, body = http(
        "GET", f"/v1/audits/no-such-audit/locks/{fv0}?view=1")
    check("evidence for unknown audit is 404", status == 404,
          f"got {status}")
    status, body = http(
        "GET", f"/v1/audits/smoke-evidence-frozen/locks/{'ab' * 32}?view=1")
    check("evidence for unknown validator is 404",
          status == 404 and body.get("error", {}).get("code")
          == "unknown_validator", f"got {status} {body}")
    status, body = http(
        "GET", f"/v1/audits/smoke-evidence-frozen/locks/{fv0}?view=9")
    check("evidence for a never-recorded future view is refused",
          status in (404, 409), f"got {status} {body}")
    status, body = http(
        "GET", f"/v1/audits/smoke-evidence-frozen/locks/{fv0}")
    check("evidence without view parameter is 400", status == 400,
          f"got {status}")

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
