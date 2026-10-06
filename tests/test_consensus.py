"""Lock-rule and commit-rule tests for the audit engine."""

import unittest

from app import canonical, consensus, ed25519, schema, trajgen


def run(submission):
    return consensus.Engine(submission).run()


class TestCommitRule(unittest.TestCase):
    def test_commit_trajectory_n4(self):
        builder, blocks = trajgen.build_commit_trajectory("t-commit-4", 4, views=4)
        verdict = run(builder.submission())
        self.assertEqual(verdict["status"], "accepted")
        self.assertIsNone(verdict["violation"])
        self.assertEqual(verdict["events_processed"], verdict["events_total"])
        # 3-chain rule: QC at view 3 commits block@1, QC at view 4 commits block@2
        self.assertEqual(verdict["committed"], blocks[:2])
        self.assertEqual(len(verdict["commits"]), 2)
        self.assertEqual(verdict["commits"][0]["blocks"], [blocks[0]])
        self.assertEqual(verdict["commits"][0]["decide_qc"]["view"], 3)
        self.assertEqual(verdict["commits"][1]["blocks"], [blocks[1]])
        self.assertEqual(verdict["commits"][1]["decide_qc"]["view"], 4)
        # one certificate per view, each with exactly the quorum of signers
        self.assertEqual(len(verdict["certificates"]), 4)
        for i, cert in enumerate(verdict["certificates"]):
            self.assertEqual(cert["view"], i + 1)
            self.assertEqual(len(cert["signers"]), 3)
            self.assertEqual(len(set(cert["signers"])), 3)
        # every validator observed every certificate: locks climb to view 4
        for validator in builder.pubkeys:
            lock = verdict["locks"][validator]
            self.assertEqual(lock["locked"]["view"], 4)
            self.assertEqual(lock["locked"]["block_id"], blocks[3])
            self.assertEqual([h["view"] for h in lock["history"]], [1, 2, 3, 4])

    def test_commit_trajectory_n7(self):
        builder, blocks = trajgen.build_commit_trajectory("t-commit-7", 7, views=3)
        verdict = run(builder.submission())
        self.assertEqual(verdict["status"], "accepted")
        self.assertEqual(verdict["quorum"], 5)
        self.assertEqual(verdict["committed"], blocks[:1])
        for cert in verdict["certificates"]:
            self.assertEqual(len(cert["signers"]), 5)

    def test_empty_trajectory_is_accepted_with_no_commits(self):
        builder = trajgen.TrajectoryBuilder("t-empty", 4)
        verdict = run(builder.submission())
        self.assertEqual(verdict["status"], "accepted")
        self.assertEqual(verdict["committed"], [])
        self.assertEqual(verdict["certificates"], [])

    def test_no_commit_without_consecutive_views(self):
        # Certificates at views 1, 2 and 4 (view 3 missing): no 3-chain.
        builder = trajgen.TrajectoryBuilder("t-gap", 4)
        qc = (builder.genesis_id, 0)
        b1 = builder.propose(0, 1, qc)
        for v in range(3):
            builder.vote(v, 1, b1)
        b2 = builder.propose(1, 2, (b1, 1))
        for v in range(3):
            builder.vote(v, 2, b2)
        b4 = builder.propose(2, 4, (b2, 2))  # skips view 3
        for v in range(3):
            builder.vote(v, 4, b4)
        verdict = run(builder.submission())
        self.assertEqual(verdict["status"], "accepted")
        self.assertEqual(verdict["committed"], [])

    def test_no_commit_when_chain_is_broken(self):
        # Certificates at views 1, 2, 3 but the view-3 block extends the
        # view-1 block, not the view-2 block: no 3-chain.
        builder = trajgen.TrajectoryBuilder("t-broken", 4)
        qc = (builder.genesis_id, 0)
        b1 = builder.propose(0, 1, qc)
        for v in range(3):
            builder.vote(v, 1, b1)
        b2 = builder.propose(1, 2, (b1, 1))
        for v in range(3):
            builder.vote(v, 2, b2)
        b3 = builder.propose(2, 3, (b1, 1))  # extends b1, not b2
        for v in range(3):
            builder.vote(v, 3, b3)
        verdict = run(builder.submission())
        self.assertEqual(verdict["status"], "accepted")
        self.assertEqual(verdict["committed"], [])

    def test_late_distinct_signer_joins_certificate(self):
        builder = trajgen.TrajectoryBuilder("t-late-signer", 4)
        b1 = builder.propose(0, 1, (builder.genesis_id, 0))
        for v in range(3):
            builder.vote(v, 1, b1)  # certificate forms with 3 signers
        builder.vote(3, 1, b1)      # 4th distinct signer still counts
        verdict = run(builder.submission())
        self.assertEqual(verdict["status"], "accepted")
        self.assertEqual(len(verdict["certificates"]), 1)
        self.assertEqual(len(verdict["certificates"][0]["signers"]), 4)


class TestLockingRules(unittest.TestCase):
    def test_unsafe_vote_freezes(self):
        builder, index = trajgen.build_unsafe_vote_trajectory("t-unsafe")
        submission = builder.submission()
        # pad with extra events that must never be processed
        submission["events"].append({
            "type": "qc_observation",
            "validator": builder.pubkeys[1],
            "block_id": builder.genesis_id,
            "view": 0,
        })
        verdict = run(submission)
        self.assertEqual(verdict["status"], "rejected")
        self.assertEqual(verdict["violation"]["type"], consensus.UNSAFE_VOTE)
        self.assertEqual(verdict["violation"]["event_index"], index)
        self.assertEqual(verdict["events_processed"], index)
        self.assertEqual(verdict["committed"], [])

    def test_higher_certificate_unlocks_conflicting_branch(self):
        # Validator 0 locks on b1@1. A rival branch b2'@2 (off genesis) gets a
        # certificate from validators 1-3 (still locked on genesis, so safe).
        # Validator 0 may then vote for the rival's child: justify view 2 > 1.
        builder = trajgen.TrajectoryBuilder("t-unlock", 4)
        genesis_qc = (builder.genesis_id, 0)
        b1 = builder.propose(0, 1, genesis_qc, payload="main")
        for v in range(3):
            builder.vote(v, 1, b1)
        builder.observe(0, b1, 1)  # validator 0 locks on b1

        rival = builder.propose(1, 2, genesis_qc, payload="rival")
        for v in (1, 2, 3):
            builder.vote(v, 2, rival)  # certificate for rival@2

        child = builder.propose(2, 3, (rival, 2), payload="rival-child")
        builder.vote(0, 3, child)  # unlocked by the higher certificate
        verdict = run(builder.submission())
        self.assertEqual(verdict["status"], "accepted", verdict["violation"])

    def test_observation_then_vote_on_locked_chain(self):
        # After observing the rival certificate, validator 0's lock moves and
        # voting for the rival's child is safe by extension as well.
        builder = trajgen.TrajectoryBuilder("t-relock", 4)
        genesis_qc = (builder.genesis_id, 0)
        b1 = builder.propose(0, 1, genesis_qc)
        for v in range(3):
            builder.vote(v, 1, b1)
        builder.observe(0, b1, 1)
        rival = builder.propose(1, 2, genesis_qc, payload="rival")
        for v in (1, 2, 3):
            builder.vote(v, 2, rival)
        builder.observe(0, rival, 2)  # validator 0 relocks on the rival
        child = builder.propose(2, 3, (rival, 2))
        builder.vote(0, 3, child)
        verdict = run(builder.submission())
        self.assertEqual(verdict["status"], "accepted", verdict["violation"])
        lock = verdict["locks"][builder.pubkeys[0]]
        self.assertEqual(lock["locked"]["block_id"], rival)
        self.assertEqual([h["view"] for h in lock["history"]], [1, 2])

    def test_lock_only_moves_to_higher_views(self):
        builder = trajgen.TrajectoryBuilder("t-lock-monotonic", 4)
        b1 = builder.propose(0, 1, (builder.genesis_id, 0))
        for v in range(3):
            builder.vote(v, 1, b1)
        b2 = builder.propose(1, 2, (b1, 1))
        for v in range(3):
            builder.vote(v, 2, b2)
        builder.observe(0, b2, 2)
        builder.observe(0, b1, 1)  # stale observation: no lock change
        verdict = run(builder.submission())
        self.assertEqual(verdict["status"], "accepted")
        lock = verdict["locks"][builder.pubkeys[0]]
        self.assertEqual(lock["locked"]["view"], 2)
        self.assertEqual(len(lock["history"]), 1)

    def test_double_vote_freezes(self):
        builder = trajgen.TrajectoryBuilder("t-double", 4)
        b1 = builder.propose(0, 1, (builder.genesis_id, 0))
        builder.vote(0, 1, b1)
        builder.vote(0, 1, b1)  # same view again: not allowed
        verdict = run(builder.submission())
        self.assertEqual(verdict["status"], "rejected")
        self.assertEqual(verdict["violation"]["type"], consensus.DOUBLE_VOTE)
        self.assertEqual(verdict["violation"]["event_index"], 2)

    def test_double_vote_different_block_same_view_freezes(self):
        builder = trajgen.TrajectoryBuilder("t-double-equiv", 4)
        genesis_qc = (builder.genesis_id, 0)
        b1 = builder.propose(0, 1, genesis_qc, payload="a")
        b2 = builder.propose(1, 1, genesis_qc, payload="b")
        builder.vote(0, 1, b1)
        builder.vote(0, 1, b2)
        verdict = run(builder.submission())
        self.assertEqual(verdict["status"], "rejected")
        self.assertEqual(verdict["violation"]["type"], consensus.DOUBLE_VOTE)


class TestFreezeConditions(unittest.TestCase):
    def test_invalid_signature_freezes(self):
        builder = trajgen.TrajectoryBuilder("t-badsig", 4)
        b1 = builder.propose(0, 1, (builder.genesis_id, 0))
        builder.vote(0, 1, b1, sign=False)
        verdict = run(builder.submission())
        self.assertEqual(verdict["status"], "rejected")
        self.assertEqual(verdict["violation"]["type"], consensus.INVALID_SIGNATURE)

    def test_signature_for_wrong_audit_id_freezes(self):
        builder = trajgen.TrajectoryBuilder("t-badsig2", 4)
        b1 = builder.propose(0, 1, (builder.genesis_id, 0))
        # sign a message bound to a *different* audit id
        message = canonical.vote_message("other-audit", 1, b1)
        signature = ed25519.sign(builder.seeds[0], message).hex()
        builder.events.append({
            "type": "vote", "validator": builder.pubkeys[0], "view": 1,
            "block_id": b1, "signature": signature,
        })
        verdict = run(builder.submission())
        self.assertEqual(verdict["violation"]["type"], consensus.INVALID_SIGNATURE)

    def test_missing_certificate_on_proposal_freezes(self):
        builder = trajgen.TrajectoryBuilder("t-missing-qc", 4)
        b1 = builder.propose(0, 1, (builder.genesis_id, 0))
        builder.vote(0, 1, b1)
        builder.vote(1, 1, b1)  # only 2 votes: no certificate yet
        # a proposal referencing the not-yet-formed certificate for b1@1
        fake_child = canonical.block_id(2, b1, b1, 1, builder.pubkeys[1], "x")
        builder.events.append({
            "type": "proposal", "proposer": builder.pubkeys[1], "view": 2,
            "block_id": fake_child, "parent_id": b1,
            "qc": {"block_id": b1, "view": 1}, "payload": "x",
        })
        verdict = run(builder.submission())
        self.assertEqual(verdict["status"], "rejected")
        self.assertEqual(verdict["violation"]["type"],
                         consensus.MISSING_CERTIFICATE)

    def test_missing_certificate_on_observation_freezes(self):
        builder = trajgen.TrajectoryBuilder("t-missing-obs", 4)
        b1 = builder.propose(0, 1, (builder.genesis_id, 0))
        builder.observe(0, b1, 1)  # no certificate formed for b1@1
        verdict = run(builder.submission())
        self.assertEqual(verdict["status"], "rejected")
        self.assertEqual(verdict["violation"]["type"],
                         consensus.MISSING_CERTIFICATE)
        self.assertEqual(verdict["violation"]["event_index"], 1)

    def test_dangling_parent_freezes(self):
        builder = trajgen.TrajectoryBuilder("t-dangling", 4)
        unknown = "ab" * 32
        block_id = canonical.block_id(1, unknown, builder.genesis_id, 0,
                                      builder.pubkeys[0], "")
        builder.events.append({
            "type": "proposal", "proposer": builder.pubkeys[0], "view": 1,
            "block_id": block_id, "parent_id": unknown,
            "qc": {"block_id": builder.genesis_id, "view": 0}, "payload": "",
        })
        verdict = run(builder.submission())
        self.assertEqual(verdict["status"], "rejected")
        self.assertEqual(verdict["violation"]["type"], consensus.DANGLING_PARENT)

    def test_parent_qc_mismatch_freezes(self):
        builder = trajgen.TrajectoryBuilder("t-qc-mismatch", 4)
        b1 = builder.propose(0, 1, (builder.genesis_id, 0))
        for v in range(3):
            builder.vote(v, 1, b1)
        # parent says b1 but the referenced certificate is the genesis one
        block_id = canonical.block_id(2, b1, builder.genesis_id, 0,
                                      builder.pubkeys[1], "")
        builder.events.append({
            "type": "proposal", "proposer": builder.pubkeys[1], "view": 2,
            "block_id": block_id, "parent_id": b1,
            "qc": {"block_id": builder.genesis_id, "view": 0}, "payload": "",
        })
        verdict = run(builder.submission())
        self.assertEqual(verdict["status"], "rejected")
        self.assertEqual(verdict["violation"]["type"],
                         consensus.PARENT_QC_MISMATCH)

    def test_unknown_block_vote_freezes(self):
        builder = trajgen.TrajectoryBuilder("t-unknown-block", 4)
        builder.vote(0, 1, "cd" * 32)
        verdict = run(builder.submission())
        self.assertEqual(verdict["status"], "rejected")
        self.assertEqual(verdict["violation"]["type"], consensus.UNKNOWN_BLOCK)

    def test_view_mismatch_freezes(self):
        builder = trajgen.TrajectoryBuilder("t-view-mismatch", 4)
        b1 = builder.propose(0, 1, (builder.genesis_id, 0))
        builder.vote(0, 2, b1)  # block lives in view 1, vote claims view 2
        verdict = run(builder.submission())
        self.assertEqual(verdict["status"], "rejected")
        self.assertEqual(verdict["violation"]["type"], consensus.VIEW_MISMATCH)

    def test_unknown_validator_freezes(self):
        builder = trajgen.TrajectoryBuilder("t-unknown-val", 4)
        outsider = ed25519.publickey(b"\x99" * 32).hex()
        builder.events.append({
            "type": "qc_observation", "validator": outsider,
            "block_id": builder.genesis_id, "view": 0,
        })
        verdict = run(builder.submission())
        self.assertEqual(verdict["status"], "rejected")
        self.assertEqual(verdict["violation"]["type"],
                         consensus.UNKNOWN_VALIDATOR)

    def test_invalid_block_hash_freezes(self):
        builder = trajgen.TrajectoryBuilder("t-bad-hash", 4)
        builder.events.append({
            "type": "proposal", "proposer": builder.pubkeys[0], "view": 1,
            "block_id": "ef" * 32, "parent_id": builder.genesis_id,
            "qc": {"block_id": builder.genesis_id, "view": 0}, "payload": "",
        })
        verdict = run(builder.submission())
        self.assertEqual(verdict["status"], "rejected")
        self.assertEqual(verdict["violation"]["type"],
                         consensus.INVALID_BLOCK_HASH)

    def test_invalid_view_freezes(self):
        builder = trajgen.TrajectoryBuilder("t-bad-view", 4)
        b1 = builder.propose(0, 1, (builder.genesis_id, 0))
        for v in range(3):
            builder.vote(v, 1, b1)
        # proposal view must exceed its certificate's view (1)
        block_id = canonical.block_id(1, b1, b1, 1, builder.pubkeys[1], "x")
        builder.events.append({
            "type": "proposal", "proposer": builder.pubkeys[1], "view": 1,
            "block_id": block_id, "parent_id": b1,
            "qc": {"block_id": b1, "view": 1}, "payload": "x",
        })
        verdict = run(builder.submission())
        self.assertEqual(verdict["status"], "rejected")
        self.assertEqual(verdict["violation"]["type"], consensus.INVALID_VIEW)

    def test_identical_reproposal_is_noop(self):
        builder = trajgen.TrajectoryBuilder("t-repropose", 4)
        b1 = builder.propose(0, 1, (builder.genesis_id, 0))
        builder.events.append(dict(builder.events[0]))  # identical re-proposal
        for v in range(3):
            builder.vote(v, 1, b1)
        verdict = run(builder.submission())
        self.assertEqual(verdict["status"], "accepted", verdict["violation"])


class TestSchema(unittest.TestCase):
    def test_duplicate_identity_rejected(self):
        builder = trajgen.TrajectoryBuilder("t-dup", 4)
        submission = builder.submission()
        submission["validators"][1] = submission["validators"][0]
        with self.assertRaises(schema.SchemaError) as ctx:
            schema.validate_submission(submission)
        self.assertEqual(ctx.exception.code, "duplicate_identity")

    def test_validator_count_must_be_4_or_7(self):
        builder = trajgen.TrajectoryBuilder("t-count", 4)
        submission = builder.submission()
        submission["validators"] = submission["validators"][:3]
        with self.assertRaises(schema.SchemaError) as ctx:
            schema.validate_submission(submission)
        self.assertEqual(ctx.exception.code, "invalid_validator_set")

    def test_event_cap(self):
        builder = trajgen.TrajectoryBuilder("t-cap", 4)
        submission = builder.submission()
        submission["events"] = [
            {"type": "qc_observation", "validator": builder.pubkeys[0],
             "block_id": builder.genesis_id, "view": 0}
        ] * 65
        with self.assertRaises(schema.SchemaError) as ctx:
            schema.validate_submission(submission)
        self.assertEqual(ctx.exception.code, "too_many_events")

    def test_unknown_event_type(self):
        builder = trajgen.TrajectoryBuilder("t-type", 4)
        submission = builder.submission()
        submission["events"] = [{"type": "heartbeat"}]
        with self.assertRaises(schema.SchemaError):
            schema.validate_submission(submission)

    def test_boolean_view_rejected(self):
        builder = trajgen.TrajectoryBuilder("t-bool", 4)
        submission = builder.submission()
        submission["events"] = [{
            "type": "qc_observation", "validator": builder.pubkeys[0],
            "block_id": builder.genesis_id, "view": True,
        }]
        with self.assertRaises(schema.SchemaError):
            schema.validate_submission(submission)


if __name__ == "__main__":
    unittest.main()
