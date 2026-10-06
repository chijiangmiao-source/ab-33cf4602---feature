"""HTTP tests for the lock-evidence read endpoint."""

import json
import threading
import unittest
import urllib.error
import urllib.request

from app import server, store, trajgen


class EvidenceApiTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = server.make_server(0, store.AuditStore())
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def request(self, method, path, body=None):
        data = None if body is None else json.dumps(body).encode("utf-8")
        req = urllib.request.Request(self.base + path, data=data,
                                     method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def submit(self, audit_id, builder):
        status, verdict = self.request("POST", "/v1/audits",
                                       builder.submission())
        self.assertEqual(status, 201)
        return verdict

    def evidence_path(self, audit_id, validator, view):
        return (f"/v1/audits/{audit_id}/locks/{validator}"
                f"?view={view}")

    def test_valid_lock_chain_end_to_end(self):
        builder, blocks = trajgen.build_commit_trajectory(
            "http-ev-commit", 4, 4)
        self.submit("http-ev-commit", builder)
        v0 = builder.pubkeys[0]

        status, ev = self.request(
            "GET", self.evidence_path("http-ev-commit", v0, 2))
        self.assertEqual(status, 200, ev)
        self.assertEqual(ev["audit_id"], "http-ev-commit")
        self.assertEqual(ev["query"], {"validator": v0, "view": 2})
        self.assertEqual(ev["status"], "accepted")
        self.assertEqual(ev["locked"], {"block_id": blocks[1], "view": 2})

        obs = ev["observation"]
        self.assertEqual(obs["type"], "qc_observation")
        self.assertEqual(obs["validator"], v0)
        self.assertEqual(obs["block_id"], blocks[1])
        self.assertEqual(obs["view"], 2)
        self.assertIsInstance(obs["event_index"], int)

        cert = ev["certificate"]
        self.assertEqual(cert["view"], 2)
        self.assertEqual(cert["quorum"], 3)
        self.assertEqual(len(cert["forming_votes"]), 3)
        for vote in cert["forming_votes"]:
            self.assertEqual(set(vote),
                             {"event_index", "block_id", "view",
                              "validator", "signature"})
            self.assertEqual(len(vote["signature"]), 128)
        # threshold-crossing vote is the formation event
        self.assertEqual(cert["formed_at"],
                         cert["formation_event"]["event_index"])
        self.assertEqual(cert["formed_at"],
                         cert["forming_votes"][-1]["event_index"])
        self.assertLess(cert["formed_at"], obs["event_index"])

        chain = ev["parent_chain"]
        self.assertEqual([h["block_view"] for h in chain], [2, 1])
        self.assertTrue(all(h["parent_matches_certified_block"] for h in chain))
        self.assertTrue(chain[-1]["reaches_genesis"])

    def test_historical_and_final_lock_views(self):
        builder, blocks = trajgen.build_commit_trajectory(
            "http-ev-hist", 7, 3)
        self.submit("http-ev-hist", builder)
        for view, block in ((1, blocks[0]), (3, blocks[2])):
            status, ev = self.request(
                "GET", self.evidence_path("http-ev-hist",
                                          builder.pubkeys[6], view))
            self.assertEqual(status, 200, ev)
            self.assertEqual(ev["locked"], {"block_id": block, "view": view})
            self.assertEqual(ev["certificate"]["quorum"], 5)

    def test_nonexistent_audit_404(self):
        builder, _ = trajgen.build_commit_trajectory("x", 4, 1)
        status, body = self.request(
            "GET", self.evidence_path("missing-audit-id",
                                      builder.pubkeys[0], 1))
        self.assertEqual(status, 404)
        self.assertEqual(body["error"]["code"], "not_found")

    def test_unknown_validator_404(self):
        builder, _ = trajgen.build_commit_trajectory(
            "http-ev-unknown-val", 4, 2)
        self.submit("http-ev-unknown-val", builder)
        outsider = "ab" * 32
        status, body = self.request(
            "GET", self.evidence_path("http-ev-unknown-val", outsider, 1))
        self.assertEqual(status, 404)
        self.assertEqual(body["error"]["code"], "unknown_validator")

    def test_lock_view_that_never_appeared_404(self):
        builder = trajgen.TrajectoryBuilder("http-ev-nolock", 4)
        b1 = builder.propose(0, 1, (builder.genesis_id, 0))
        for v in range(3):
            builder.vote(v, 1, b1)  # certified, but nobody observes it
        self.submit("http-ev-nolock", builder)
        status, body = self.request(
            "GET", self.evidence_path("http-ev-nolock",
                                      builder.pubkeys[0], 1))
        self.assertEqual(status, 404)
        self.assertEqual(body["error"]["code"], "lock_view_not_found")

    def test_query_boundaries(self):
        builder, _ = trajgen.build_commit_trajectory(
            "http-ev-bounds", 4, 2)
        self.submit("http-ev-bounds", builder)
        v0 = builder.pubkeys[0]
        base = f"/v1/audits/http-ev-bounds/locks/{v0}"
        # missing view
        status, body = self.request("GET", base)
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_request")
        # malformed / negative view
        status, _ = self.request("GET", base + "?view=abc")
        self.assertEqual(status, 400)
        status, _ = self.request("GET", base + "?view=-1")
        self.assertEqual(status, 400)
        # repeated view parameter
        status, _ = self.request("GET", base + "?view=1&view=2")
        self.assertEqual(status, 400)
        # malformed validator hex (shorter than 64 hex chars -> unknown path)
        status, body = self.request("GET", "/v1/audits/http-ev-bounds/locks/abc?view=1")
        self.assertEqual(status, 404)

    def test_frozen_trajectory_query_boundary(self):
        builder, offending, later = \
            trajgen.build_frozen_trajectory_with_later_lock("http-ev-frozen")
        self.submit("http-ev-frozen", builder)
        v0 = builder.pubkeys[0]

        # the pre-freeze lock is fully answerable
        status, ev = self.request(
            "GET", self.evidence_path("http-ev-frozen", v0, 1))
        self.assertEqual(status, 200, ev)
        self.assertEqual(ev["status"], "rejected")
        self.assertEqual(ev["events_processed"], offending)
        self.assertLess(ev["certificate"]["formed_at"], offending)

        # the view-2 lock exists only in events after the freeze: refuse
        status, body = self.request(
            "GET", self.evidence_path("http-ev-frozen", v0, 2))
        self.assertEqual(status, 409, body)
        self.assertEqual(body["error"]["code"], "evidence_unavailable")
        self.assertIn("freeze", body["error"]["message"])
        # the later block must not leak into the error nor any evidence
        status, ev = self.request(
            "GET", self.evidence_path("http-ev-frozen", v0, 1))
        referenced = {h["block_id"] for h in ev["parent_chain"]} | \
                     {h["certificate"]["block_id"] for h in ev["parent_chain"]}
        self.assertNotIn(later, referenced)

    def test_replay_semantics_unchanged(self):
        builder, blocks = trajgen.build_commit_trajectory(
            "http-ev-replay", 4, 3)
        submission = builder.submission()
        status, first = self.request("POST", "/v1/audits", submission)
        self.assertEqual((status, first["replayed"]), (201, False))
        status, replay = self.request("POST", "/v1/audits", submission)
        self.assertEqual((status, replay["replayed"]), (200, True))
        replay = dict(replay)
        replay.pop("replayed")
        original = dict(first)
        original.pop("replayed")
        self.assertEqual(replay, original)

        mutated = json.loads(json.dumps(submission))
        mutated["events"] = mutated["events"][:-1]
        status, conflict = self.request("POST", "/v1/audits", mutated)
        self.assertEqual(status, 409)
        self.assertEqual(conflict["error"]["code"], "conflict")


if __name__ == "__main__":
    unittest.main()
