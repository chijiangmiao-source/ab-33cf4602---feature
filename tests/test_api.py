"""In-process HTTP API tests: health, submit, replay, conflict, fetch."""

import json
import threading
import unittest
import urllib.error
import urllib.request

from app import server, store, trajgen


class ApiTestCase(unittest.TestCase):
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

    def test_health(self):
        status, body = self.request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")

    def test_commit_lifecycle(self):
        builder, blocks = trajgen.build_commit_trajectory("api-commit", 4, 4)
        submission = builder.submission()

        status, verdict = self.request("POST", "/v1/audits", submission)
        self.assertEqual(status, 201)
        self.assertEqual(verdict["status"], "accepted")
        self.assertEqual(verdict["committed"], blocks[:2])
        self.assertFalse(verdict["replayed"])

        # same id + same content: the original verdict is replayed
        status, replay = self.request("POST", "/v1/audits", submission)
        self.assertEqual(status, 200)
        self.assertTrue(replay["replayed"])
        replay = dict(replay)
        replay.pop("replayed")
        original = dict(verdict)
        original.pop("replayed")
        self.assertEqual(replay, original)

        # same id + different content: explicit conflict
        mutated = json.loads(json.dumps(submission))
        mutated["events"] = mutated["events"][:-1]
        status, conflict = self.request("POST", "/v1/audits", mutated)
        self.assertEqual(status, 409)
        self.assertEqual(conflict["error"]["code"], "conflict")

        # fetch by id
        status, fetched = self.request("GET", "/v1/audits/api-commit")
        self.assertEqual(status, 200)
        self.assertEqual(fetched["committed"], blocks[:2])

    def test_reject_trajectory_verdict(self):
        builder, index = trajgen.build_unsafe_vote_trajectory("api-unsafe")
        status, verdict = self.request("POST", "/v1/audits", builder.submission())
        self.assertEqual(status, 201)
        self.assertEqual(verdict["status"], "rejected")
        self.assertEqual(verdict["violation"]["type"], "unsafe_vote")
        self.assertEqual(verdict["violation"]["event_index"], index)

    def test_unknown_audit_id_404(self):
        status, body = self.request("GET", "/v1/audits/nope")
        self.assertEqual(status, 404)
        self.assertEqual(body["error"]["code"], "not_found")

    def test_malformed_submissions_400(self):
        builder = trajgen.TrajectoryBuilder("api-dup", 4)
        dup = builder.submission()
        dup["validators"][1] = dup["validators"][0]
        status, body = self.request("POST", "/v1/audits", dup)
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "duplicate_identity")

        too_many = builder.submission()
        too_many["audit_id"] = "api-too-many"
        too_many["events"] = [
            {"type": "qc_observation", "validator": builder.pubkeys[0],
             "block_id": builder.genesis_id, "view": 0}
        ] * 65
        status, _ = self.request("POST", "/v1/audits", too_many)
        self.assertEqual(status, 400)

        status, _ = self.request("POST", "/v1/audits", {"audit_id": "x"})
        self.assertEqual(status, 400)

    def test_unknown_path_and_method(self):
        status, _ = self.request("GET", "/nope")
        self.assertEqual(status, 404)
        status, _ = self.request("PUT", "/v1/audits", {})
        self.assertEqual(status, 405)


if __name__ == "__main__":
    unittest.main()
