"""Tests for the lock evidence chain: observation -> certificate formation
-> signed votes, and the continuous parent-chain references back to genesis.

Both the pure evidence builder (fresh engine replay) and the HTTP read
endpoint are exercised, including the refusal boundaries for frozen
trajectories.
"""

import json
import threading
import unittest
import urllib.error
import urllib.request

from app import canonical, consensus, ed25519, evidence, server, store, trajgen


def replay(submission):
    engine = consensus.Engine(submission)
    engine.run()
    return engine


class EvidenceChainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.builder, cls.blocks = trajgen.build_commit_trajectory(
            "ev-chain", 4, views=4)
        cls.submission = cls.builder.submission()
        cls.engine = replay(cls.submission)
        cls.v0 = cls.builder.pubkeys[0]
        # commit trajectory event layout per view (0-based):
        #   view v: 1 proposal + quorum votes + 4 observations
        # so for view 2: proposal@8, votes@9..11, v0 observation@12
        cls.obs_index = 1 + 8 + 3  # 12

    def test_chain_links_observation_formation_and_votes(self):
        result = evidence.lock_evidence(self.engine, self.v0, 2)
        ev = result["evidence"]
        self.assertEqual(ev["kind"], "observed_certificate")
        self.assertEqual(ev["block_id"], self.blocks[1])
        self.assertFalse(result["frozen"])

        # observation that actually moved the lock
        self.assertEqual(ev["observation"], {
            "event_index": self.obs_index,
            "validator": self.v0,
            "block_id": self.blocks[1],
            "view": 2,
        })

        # certificate formed exactly on the quorum-th distinct vote
        formation = ev["certificate_formation"]
        self.assertEqual(formation["formed_at"], 11)
        self.assertEqual(formation["quorum"], 3)
        self.assertEqual(formation["threshold_vote"]["event_index"], 11)
        self.assertEqual(formation["threshold_vote"]["view"], 2)
        self.assertEqual(formation["threshold_vote"]["block_id"],
                         self.blocks[1])

        votes = ev["votes"]
        self.assertEqual([v["event_index"] for v in votes], [9, 10, 11])
        self.assertEqual(len({v["validator"] for v in votes}), 3)
        for vote in votes:
            self.assertEqual(vote["block_id"], self.blocks[1])
            self.assertEqual(vote["view"], 2)
            # every evidence item carries a real signature that verifies
            self.assertTrue(ed25519.verify(
                bytes.fromhex(vote["validator"]),
                bytes.fromhex(vote["signature"]),
                canonical.vote_message("ev-chain", 2, self.blocks[1])))

        # block formation (proposal) is part of the chain
        self.assertEqual(ev["proposal"]["event_index"], 8)
        self.assertEqual(ev["proposal"]["proposer"],
                         self.builder.pubkeys[1])

    def test_formation_precedes_observation_and_votes_ordered(self):
        result = evidence.lock_evidence(self.engine, self.v0, 4)
        ev = result["evidence"]
        indices = [v["event_index"] for v in ev["votes"]]
        self.assertEqual(indices, sorted(indices))
        self.assertLess(ev["certificate_formation"]["formed_at"],
                        ev["observation"]["event_index"])
        self.assertLess(ev["proposal"]["event_index"],
                        ev["certificate_formation"]["formed_at"])

    def test_historical_lock_view_is_addressable(self):
        # validator 0 is currently locked at view 4, but its earlier view-1
        # lock remains an auditable recorded lock view
        current = evidence.lock_evidence(self.engine, self.v0, 4)
        self.assertEqual(current["queried_lock"]["block_id"], self.blocks[3])
        historical = evidence.lock_evidence(self.engine, self.v0, 1)
        self.assertEqual(historical["queried_lock"]["block_id"],
                         self.blocks[0])
        self.assertEqual(historical["evidence"]["observation"]["view"], 1)

    def test_parent_chain_is_continuous_to_genesis(self):
        result = evidence.lock_evidence(self.engine, self.v0, 4)
        chain = result["parent_chain"]
        # locked block, three ancestors, genesis
        self.assertEqual([h["view"] for h in chain], [4, 3, 2, 1, 0])
        self.assertEqual(chain[0]["block_id"], self.blocks[3])
        self.assertEqual(chain[-1]["block_id"], self.builder.genesis_id)
        self.assertTrue(chain[-1]["genesis"])
        self.assertTrue(chain[-1]["certificate"]["implicit"])
        for hop in chain[:-1]:
            self.assertFalse(hop["genesis"])
            self.assertIsNotNone(hop["proposal_event_index"])
        # each hop: parent block == block certified by the justifying qc
        for hop, parent_hop in zip(chain, chain[1:]):
            self.assertEqual(hop["parent_id"], parent_hop["block_id"])
            self.assertEqual(hop["certificate"]["block_id"],
                             parent_hop["block_id"])
            self.assertEqual(hop["certificate"]["view"], parent_hop["view"])
            if not parent_hop["genesis"]:
                # the parent was proposed before its certificate formed
                self.assertLessEqual(parent_hop["proposal_event_index"],
                                     hop["certificate"]["formed_at"])

    def test_genesis_lock_evidence(self):
        builder = trajgen.TrajectoryBuilder("ev-genesis", 4)
        engine = replay(builder.submission())
        result = evidence.lock_evidence(engine, builder.pubkeys[2], 0)
        self.assertEqual(result["evidence"]["kind"], "implicit_genesis")
        self.assertEqual(result["queried_lock"]["block_id"],
                         builder.genesis_id)
        self.assertEqual(result["evidence"]["votes"], [])
        self.assertEqual(len(result["parent_chain"]), 1)
        self.assertTrue(result["parent_chain"][0]["genesis"])

    def test_genesis_lock_not_addressable_after_validator_moved(self):
        with self.assertRaises(evidence.EvidenceError) as ctx:
            evidence.lock_evidence(self.engine, self.v0, 0)
        self.assertEqual(ctx.exception.code, "lock_view_not_recorded")

    def test_unknown_validator_refused(self):
        outsider = ed25519.publickey(b"\x42" * 32).hex()
        with self.assertRaises(evidence.EvidenceError) as ctx:
            evidence.lock_evidence(self.engine, outsider, 1)
        self.assertEqual(ctx.exception.status, 404)
        self.assertEqual(ctx.exception.code, "unknown_validator")

    def test_unrecorded_lock_view_refused(self):
        # view 9 never happened; the message lists recorded views
        with self.assertRaises(evidence.EvidenceError) as ctx:
            evidence.lock_evidence(self.engine, self.v0, 9)
        self.assertEqual(ctx.exception.status, 404)
        self.assertEqual(ctx.exception.code, "lock_view_not_recorded")


class FrozenTrajectoryEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.builder, self.offending = \
            trajgen.build_unsafe_vote_trajectory("ev-frozen")
        self.submission = self.builder.submission()
        self.b1 = self.builder.events[0]["block_id"]
        # post-freeze event: validator 1 observes the view-1 certificate
        # after the unsafe vote froze the audit at event 6
        self.post_freeze_obs = self.builder.observe(1, self.b1, 1)
        self.engine = replay(self.submission)
        self.assertEqual(self.engine.violation["event_index"], self.offending)

    def test_pre_freeze_lock_has_full_evidence(self):
        # validator 0 observed b1@1 at event 4, well before the freeze
        result = evidence.lock_evidence(
            self.engine, self.builder.pubkeys[0], 1)
        self.assertTrue(result["frozen"])
        self.assertEqual(result["freeze"]["event_index"], self.offending)
        self.assertEqual(result["freeze"]["type"], "unsafe_vote")
        ev = result["evidence"]
        self.assertEqual(ev["observation"]["event_index"], 4)
        self.assertEqual(ev["certificate_formation"]["formed_at"], 3)
        self.assertEqual(len(ev["votes"]), 3)
        self.assertEqual([h["view"] for h in result["parent_chain"]], [1, 0])

    def test_lock_only_seen_after_freeze_refused(self):
        # validator 1's only observation is event 7, after the freeze:
        # it must never appear as a recorded lock
        with self.assertRaises(evidence.EvidenceError) as ctx:
            evidence.lock_evidence(
                self.engine, self.builder.pubkeys[1], 1)
        err = ctx.exception
        self.assertEqual(err.code, "lock_view_not_recorded")

    def test_post_freeze_event_not_replayed_into_engine(self):
        # the engine itself must not carry the post-freeze observation
        verdict = self.engine.verdict()
        lock1 = verdict["locks"][self.builder.pubkeys[1]]
        self.assertEqual(lock1["locked"]["view"], 0)
        self.assertEqual(lock1["history"], [])
        self.assertEqual(self.engine.events_processed, self.offending)

    def test_genesis_lock_still_visible_after_freeze(self):
        result = evidence.lock_evidence(
            self.engine, self.builder.pubkeys[1], 0)
        self.assertTrue(result["frozen"])
        self.assertEqual(result["evidence"]["kind"], "implicit_genesis")


class EvidenceHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = server.make_server(0, store.AuditStore())
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}"

        cls.builder, cls.blocks = trajgen.build_commit_trajectory(
            "http-ev", 4, views=4)
        cls._post("/v1/audits", cls.builder.submission())

        cls.frozen, cls.offending = \
            trajgen.build_unsafe_vote_trajectory("http-ev-frozen")
        cls.frozen.observe(1, cls.frozen.events[0]["block_id"], 1)
        cls._post("/v1/audits", cls.frozen.submission())

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    @classmethod
    def _request(cls, method, path, body=None):
        data = None if body is None else json.dumps(body).encode("utf-8")
        req = urllib.request.Request(cls.base + path, data=data,
                                     method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    @classmethod
    def _post(cls, path, body):
        return cls._request("POST", path, body)

    @classmethod
    def _get(cls, path):
        return cls._request("GET", path)

    def test_valid_lock_chain_over_http(self):
        v0 = self.builder.pubkeys[0]
        status, body = self._get(f"/v1/audits/http-ev/locks/{v0}?view=3")
        self.assertEqual(status, 200)
        self.assertEqual(body["queried_lock"],
                         {"block_id": self.blocks[2], "view": 3})
        ev = body["evidence"]
        self.assertEqual(ev["observation"]["event_index"], 20)
        self.assertEqual(ev["certificate_formation"]["formed_at"], 19)
        self.assertEqual(len(ev["votes"]), 3)
        chain = body["parent_chain"]
        self.assertEqual([h["view"] for h in chain], [3, 2, 1, 0])
        for hop, parent in zip(chain, chain[1:]):
            self.assertEqual(hop["parent_id"], parent["block_id"])
            self.assertEqual(hop["certificate"]["block_id"],
                             parent["block_id"])

    def test_block_id_parameter_must_match(self):
        v0 = self.builder.pubkeys[0]
        status, body = self._get(
            f"/v1/audits/http-ev/locks/{v0}?view=3&block_id={'ab' * 32}")
        self.assertEqual(status, 404)
        self.assertEqual(body["error"]["code"], "lock_view_not_recorded")
        status, body = self._get(
            f"/v1/audits/http-ev/locks/{v0}"
            f"?view=3&block_id={self.blocks[2]}")
        self.assertEqual(status, 200)

    def test_unknown_audit_refused(self):
        v0 = self.builder.pubkeys[0]
        status, body = self._get(f"/v1/audits/nope/locks/{v0}?view=1")
        self.assertEqual(status, 404)
        self.assertEqual(body["error"]["code"], "not_found")

    def test_unknown_validator_refused(self):
        outsider = ed25519.publickey(b"\x01" * 32).hex()
        status, body = self._get(
            f"/v1/audits/http-ev/locks/{outsider}?view=1")
        self.assertEqual(status, 404)
        self.assertEqual(body["error"]["code"], "unknown_validator")

    def test_unrecorded_view_refused(self):
        v0 = self.builder.pubkeys[0]
        status, body = self._get(f"/v1/audits/http-ev/locks/{v0}?view=42")
        self.assertEqual(status, 404)
        self.assertEqual(body["error"]["code"], "lock_view_not_recorded")

    def test_query_parameter_validation(self):
        v0 = self.builder.pubkeys[0]
        for suffix in ("", "?block_id=x", "?view=1&view=2",
                       "?view=-1", "?view=abc", "?view=true"):
            status, body = self._get(
                f"/v1/audits/http-ev/locks/{v0}{suffix}")
            self.assertEqual(status, 400, suffix)
            self.assertEqual(body["error"]["code"], "invalid_query", suffix)
        status, body = self._get("/v1/audits/http-ev/locks/not-hex?view=1")
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_query")

    def test_frozen_pre_freeze_lock_readable(self):
        v0 = self.frozen.pubkeys[0]
        status, body = self._get(
            f"/v1/audits/http-ev-frozen/locks/{v0}?view=1")
        self.assertEqual(status, 200)
        self.assertTrue(body["frozen"])
        self.assertEqual(body["evidence"]["observation"]["event_index"], 4)

    def test_frozen_post_freeze_lock_refused(self):
        v1 = self.frozen.pubkeys[1]
        status, body = self._get(
            f"/v1/audits/http-ev-frozen/locks/{v1}?view=1")
        self.assertEqual(status, 404)
        self.assertEqual(body["error"]["code"], "lock_view_not_recorded")

    def test_evidence_survives_replay_semantics(self):
        # resubmitting identical content keeps evidence available; the
        # conflicting submission does not replace the stored trajectory
        v0 = self.builder.pubkeys[0]
        status, _ = self._post(
            "/v1/audits", self.builder.submission())
        self.assertEqual(status, 200)
        status, body = self._get(f"/v1/audits/http-ev/locks/{v0}?view=2")
        self.assertEqual(status, 200)
        self.assertEqual(body["evidence"]["observation"]["event_index"], 12)


if __name__ == "__main__":
    unittest.main()
