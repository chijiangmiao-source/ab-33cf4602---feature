"""Stable evidence chain behind a recorded validator lock."""

import unittest

from app import consensus, ed25519, trajgen


def engine_for(submission):
    engine = consensus.Engine(submission)
    engine.run()
    return engine


class TestLockEvidence(unittest.TestCase):
    def setUp(self):
        self.builder, self.blocks = trajgen.build_commit_trajectory(
            "ev-commit", 4, views=4)
        self.engine = engine_for(self.builder.submission())

    def test_evidence_for_final_and_historical_locks(self):
        for view, block in ((1, self.blocks[0]), (4, self.blocks[3])):
            ev = self.engine.lock_evidence(self.builder.pubkeys[0], view)
            self.assertEqual(ev["status"], "accepted")
            self.assertEqual(ev["locked"], {"block_id": block, "view": view})
            # every item names capture event index, block, view and validator
            obs = ev["observation"]
            self.assertEqual(obs["event_index"],
                             self.builder.events.index(
                                 next(e for e in self.builder.events
                                      if e["type"] == "qc_observation"
                                      and e["validator"] == self.builder.pubkeys[0]
                                      and e["view"] == view)))
            self.assertEqual(obs["block_id"], block)
            self.assertEqual(obs["view"], view)
            self.assertEqual(obs["validator"], self.builder.pubkeys[0])

    def test_certificate_formation_and_signed_votes(self):
        ev = self.engine.lock_evidence(self.builder.pubkeys[0], 3)
        cert = ev["certificate"]
        block3 = self.blocks[2]
        self.assertEqual(cert["block_id"], block3)
        self.assertEqual(cert["view"], 3)
        self.assertEqual(cert["quorum"], 3)
        self.assertEqual(len(cert["signers"]), 3)
        self.assertEqual(len(set(cert["signers"])), 3)
        # formation happens on the threshold-crossing vote, strictly after the
        # first forming vote and before/at the triggering observation
        indices = [v["event_index"] for v in cert["forming_votes"]]
        self.assertEqual(indices, sorted(indices))
        self.assertEqual(cert["formation_event"]["event_index"],
                         cert["formed_at"])
        self.assertEqual(indices[-1], cert["formed_at"])
        self.assertLess(cert["formed_at"], ev["observation"]["event_index"])
        self.assertEqual(cert["formation_event"]["validator"],
                         cert["signers"][-1])
        # each forming vote is a real recorded signed vote and verifies
        message = None
        for vote in cert["forming_votes"]:
            self.assertEqual(vote["block_id"], block3)
            self.assertEqual(vote["view"], 3)
            self.assertIn(vote["validator"], cert["signers"])
            recorded = self.builder.events[vote["event_index"]]
            self.assertEqual(recorded["type"], "vote")
            self.assertEqual(recorded["signature"], vote["signature"])
            message = trajgen.canonical.vote_message("ev-commit", 3, block3)
            self.assertTrue(ed25519.verify(
                bytes.fromhex(vote["validator"]),
                bytes.fromhex(vote["signature"]), message))

    def test_parent_chain_runs_continuously_to_genesis(self):
        ev = self.engine.lock_evidence(self.builder.pubkeys[2], 4)
        chain = ev["parent_chain"]
        # hops: block4<-qc3, block3<-qc2, block2<-qc1, block1<-genesis qc
        self.assertEqual([h["block_view"] for h in chain], [4, 3, 2, 1])
        self.assertEqual([h["certificate"]["view"] for h in chain],
                         [3, 2, 1, 0])
        for hop in chain:
            self.assertTrue(hop["parent_matches_certified_block"])
        # each parent equals the previous hop's certified block
        for lower, higher in zip(chain, chain[1:]):
            self.assertEqual(lower["parent_block_id"], higher["block_id"])
        last = chain[-1]
        self.assertTrue(last["reaches_genesis"])
        self.assertEqual(last["parent_block_id"], self.builder.genesis_id)
        self.assertTrue(last["certificate"]["implicit"])
        # every cited proposal/certificate event is within the replay horizon
        for hop in chain:
            self.assertLess(hop["proposal_event_index"],
                            ev["events_processed"])

    def test_unknown_validator_rejected(self):
        outsider = ed25519.publickey(b"\x55" * 32).hex()
        with self.assertRaises(consensus.EvidenceError) as ctx:
            self.engine.lock_evidence(outsider, 1)
        self.assertEqual(ctx.exception.code, "unknown_validator")

    def test_lock_view_that_never_appeared_rejected(self):
        # A gap trajectory locks validators at views 1, 2 and 4 (never 3).
        builder = trajgen.TrajectoryBuilder("ev-gap", 4)
        qc = (builder.genesis_id, 0)
        b1 = builder.propose(0, 1, qc)
        for v in range(3):
            builder.vote(v, 1, b1)
        b2 = builder.propose(1, 2, (b1, 1))
        for v in range(3):
            builder.vote(v, 2, b2)
        b4 = builder.propose(2, 4, (b2, 2))
        for v in range(3):
            builder.vote(v, 4, b4)
        builder.observe(0, b1, 1)
        builder.observe(0, b2, 2)
        builder.observe(0, b4, 4)
        engine = engine_for(builder.submission())
        with self.assertRaises(consensus.EvidenceError) as ctx:
            engine.lock_evidence(builder.pubkeys[0], 3)
        self.assertEqual(ctx.exception.code, consensus.LOCK_VIEW_NOT_FOUND)
        with self.assertRaises(consensus.EvidenceError) as ctx:
            engine.lock_evidence(builder.pubkeys[0], 99)
        self.assertEqual(ctx.exception.code, consensus.LOCK_VIEW_NOT_FOUND)

    def test_validator_without_any_observation(self):
        # validators only observe in build_commit_trajectory; build a small run
        # where validator 3 never observes any certificate.
        builder = trajgen.TrajectoryBuilder("ev-noobs", 4)
        b1 = builder.propose(0, 1, (builder.genesis_id, 0))
        for v in range(3):
            builder.vote(v, 1, b1)
        engine = engine_for(builder.submission())
        with self.assertRaises(consensus.EvidenceError) as ctx:
            engine.lock_evidence(builder.pubkeys[3], 1)
        self.assertEqual(ctx.exception.code, consensus.LOCK_VIEW_NOT_FOUND)
        # the implicit genesis lock is not a recorded observation-derived lock
        with self.assertRaises(consensus.EvidenceError) as ctx:
            engine.lock_evidence(builder.pubkeys[3], 0)
        self.assertEqual(ctx.exception.code, consensus.LOCK_VIEW_NOT_FOUND)


class TestFrozenTrajectoryEvidence(unittest.TestCase):
    def test_pre_freeze_lock_is_answerable(self):
        builder, offending = trajgen.build_unsafe_vote_trajectory("ev-frozen")
        engine = engine_for(builder.submission())
        ev = engine.lock_evidence(builder.pubkeys[0], 1)
        self.assertEqual(ev["status"], "rejected")
        self.assertEqual(ev["locked"]["view"], 1)
        self.assertLess(ev["observation"]["event_index"], offending)
        self.assertLess(ev["certificate"]["formed_at"], offending)
        self.assertEqual(
            [h["certificate"]["view"] for h in ev["parent_chain"]], [0])
        self.assertTrue(ev["parent_chain"][-1]["reaches_genesis"])

    def test_post_freeze_lock_never_back_filled(self):
        # The suffix after the violation would have locked validator 0 on a
        # certified view-2 block; the read path must refuse rather than use it.
        builder, offending, later = \
            trajgen.build_frozen_trajectory_with_later_lock("ev-frozen-later")
        engine = engine_for(builder.submission())
        self.assertEqual(engine.events_processed, offending)
        with self.assertRaises(consensus.EvidenceError) as ctx:
            engine.lock_evidence(builder.pubkeys[0], 2)
        self.assertEqual(ctx.exception.code, consensus.EVIDENCE_UNAVAILABLE)
        self.assertIn("freeze", ctx.exception.message)
        # and no view-2 certificate/vote data leaks into any view-1 answer
        ev = engine.lock_evidence(builder.pubkeys[0], 1)
        for vote in ev["certificate"]["forming_votes"]:
            self.assertLess(vote["event_index"], offending)
        self.assertNotIn(later, {h["block_id"] for h in ev["parent_chain"]})

    def test_future_view_on_frozen_audit_refused(self):
        builder, _ = trajgen.build_unsafe_vote_trajectory("ev-frozen-future")
        engine = engine_for(builder.submission())
        with self.assertRaises(consensus.EvidenceError) as ctx:
            engine.lock_evidence(builder.pubkeys[0], 7)
        self.assertEqual(ctx.exception.code, consensus.EVIDENCE_UNAVAILABLE)


if __name__ == "__main__":
    unittest.main()
