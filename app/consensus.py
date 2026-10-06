"""Restricted-view locked-vote trajectory audit engine.

The engine replays a captured trajectory of proposal / certificate-observation
/ vote events against HotStuff-style locking rules:

* a proposal must reference an already-formed threshold certificate
  (2f+1 distinct valid vote signatures, or the implicit genesis certificate)
  and its parent block must equal the certified block;
* every validator keeps a locked block taken from the highest certificate it
  has *observed* (via ``qc_observation`` events); all validators start locked
  on genesis;
* a validator may vote for a candidate only when the candidate extends its
  locked block or the candidate's justifying certificate has a strictly
  higher view than the validator's locked certificate;
* a validator votes at most once per view;
* the first missing certificate, invalid signature, duplicate identity,
  dangling parent, or unsafe vote freezes the audit at that event and no
  conclusions are drawn from later events;
* a block is committed when it heads a chain of three certified blocks in
  three consecutive views (the certificates must actually reach 2f+1
  distinct signers); committing a block commits its uncommitted ancestors.
"""

from __future__ import annotations

from . import canonical, ed25519

# Violation types (each freezes the audit at the earliest offending event).
UNKNOWN_VALIDATOR = "unknown_validator"
INVALID_BLOCK_HASH = "invalid_block_hash"
MISSING_CERTIFICATE = "missing_certificate"
DANGLING_PARENT = "dangling_parent"
PARENT_QC_MISMATCH = "parent_qc_mismatch"
INVALID_VIEW = "invalid_view"
DOUBLE_VOTE = "double_vote"
UNKNOWN_BLOCK = "unknown_block"
VIEW_MISMATCH = "view_mismatch"
INVALID_SIGNATURE = "invalid_signature"
UNSAFE_VOTE = "unsafe_vote"


class _Block:
    __slots__ = ("block_id", "view", "parent_id", "qc_block_id", "qc_view",
                 "proposer", "payload")

    def __init__(self, block_id, view, parent_id, qc_block_id, qc_view,
                 proposer, payload):
        self.block_id = block_id
        self.view = view
        self.parent_id = parent_id
        self.qc_block_id = qc_block_id
        self.qc_view = qc_view
        self.proposer = proposer
        self.payload = payload


class Engine:
    """Replays one trajectory and produces the audit verdict."""

    def __init__(self, submission: dict):
        self.audit_id = submission["audit_id"]
        self.validators = list(submission["validators"])
        self.validator_set = set(self.validators)
        n = len(self.validators)
        self.f = (n - 1) // 3
        self.quorum = 2 * self.f + 1

        genesis = submission["genesis"]
        self.genesis_id = genesis["id"]
        self.blocks = {
            self.genesis_id: _Block(self.genesis_id, 0, None, None, None,
                                    None, ""),
        }
        # The genesis certificate is implicit: formed from the start.
        self.certificates = {}  # (block_id, view) -> record
        self.certificates[(self.genesis_id, 0)] = {
            "block_id": self.genesis_id,
            "view": 0,
            "signers": [],
            "formed_at": None,
            "implicit": True,
        }
        self.certificate_order = []  # non-implicit certificates, in order

        self.locks = {v: (self.genesis_id, 0) for v in self.validators}
        self.lock_history = {v: [] for v in self.validators}

        # (block_id, view) -> arrival-order vote records, each carrying the
        # capture event index and the (already verified) signature, so audits
        # can attribute certificate formation to concrete captured votes.
        self.votes: dict[tuple, list[dict]] = {}
        self.voted = {}  # (validator, view) -> block_id

        # block_id -> {"event_index", "proposer"} of the proposal that first
        # introduced the block (identical re-proposals do not overwrite it).
        self.proposal_events: dict[str, dict] = {}

        self.committed_tip = self.genesis_id
        self.committed = []  # flat list of newly committed block ids, in order
        self.commits = []  # commit batches with their deciding certificate

        self.violation = None
        self.events_processed = 0
        self.events = submission["events"]

    # -- helpers -----------------------------------------------------------

    def _freeze(self, index, vtype, detail):
        self.violation = {
            "event_index": index,
            "type": vtype,
            "detail": detail,
        }
        return False

    def _extends(self, block_id, ancestor_id):
        """True iff walking parents from ``block_id`` reaches ``ancestor_id``."""
        current = block_id
        while current is not None:
            if current == ancestor_id:
                return True
            current = self.blocks[current].parent_id
        return False

    # -- event handlers ----------------------------------------------------

    def _apply_proposal(self, index, ev):
        proposer = ev["proposer"]
        if proposer not in self.validator_set:
            return self._freeze(index, UNKNOWN_VALIDATOR,
                                f"proposer {proposer} is not a registered validator")

        qc_block = ev["qc"]["block_id"]
        qc_view = ev["qc"]["view"]
        payload = ev.get("payload", "")

        expected = canonical.block_id(ev["view"], ev["parent_id"], qc_block,
                                      qc_view, proposer, payload)
        if expected != ev["block_id"]:
            return self._freeze(
                index, INVALID_BLOCK_HASH,
                "block_id does not match the canonical hash of the block fields")

        if ev["block_id"] in self.blocks:
            # Identical re-proposal of an already known block: harmless no-op.
            return True

        if (qc_block, qc_view) not in self.certificates:
            return self._freeze(
                index, MISSING_CERTIFICATE,
                f"proposal references certificate ({qc_block}, view {qc_view}) "
                "that has not reached the 2f+1 threshold")

        if ev["parent_id"] != qc_block:
            if ev["parent_id"] not in self.blocks:
                return self._freeze(
                    index, DANGLING_PARENT,
                    f"parent block {ev['parent_id']} is not known")
            return self._freeze(
                index, PARENT_QC_MISMATCH,
                "parent block does not match the referenced certificate's block")

        if ev["view"] <= qc_view:
            return self._freeze(
                index, INVALID_VIEW,
                f"proposal view {ev['view']} must exceed its certificate view {qc_view}")

        self.blocks[ev["block_id"]] = _Block(
            ev["block_id"], ev["view"], ev["parent_id"], qc_block, qc_view,
            proposer, payload)
        self.proposal_events[ev["block_id"]] = {
            "event_index": index,
            "proposer": proposer,
        }
        return True

    def _apply_vote(self, index, ev):
        validator = ev["validator"]
        if validator not in self.validator_set:
            return self._freeze(index, UNKNOWN_VALIDATOR,
                                f"voter {validator} is not a registered validator")

        view = ev["view"]
        block_id = ev["block_id"]

        if (validator, view) in self.voted:
            return self._freeze(
                index, DOUBLE_VOTE,
                f"validator {validator} already voted in view {view} "
                f"(block {self.voted[(validator, view)]})")

        block = self.blocks.get(block_id)
        if block is None or block_id == self.genesis_id:
            return self._freeze(index, UNKNOWN_BLOCK,
                                f"vote references unknown block {block_id}")

        if block.view != view:
            return self._freeze(
                index, VIEW_MISMATCH,
                f"vote view {view} does not match block view {block.view}")

        message = canonical.vote_message(self.audit_id, view, block_id)
        if not ed25519.verify(bytes.fromhex(validator),
                              bytes.fromhex(ev["signature"]), message):
            return self._freeze(index, INVALID_SIGNATURE,
                                "vote signature does not verify")

        locked_block, locked_view = self.locks[validator]
        justify_view = block.qc_view
        if not (self._extends(block_id, locked_block)
                or justify_view > locked_view):
            return self._freeze(
                index, UNSAFE_VOTE,
                f"candidate neither extends locked block {locked_block} "
                f"(view {locked_view}) nor carries a higher certificate "
                f"(justify view {justify_view})")

        self.voted[(validator, view)] = block_id
        self.votes.setdefault((block_id, view), []).append({
            "validator": validator,
            "event_index": index,
            "signature": ev["signature"],
        })

        key = (block_id, view)
        if key not in self.certificates and len(self.votes[key]) >= self.quorum:
            self.certificates[key] = {
                "block_id": block_id,
                "view": view,
                "signers": [r["validator"] for r in self.votes[key]],
                "formed_at": index,
                "implicit": False,
            }
            self.certificate_order.append(key)
            self._try_commit()
        elif key in self.certificates and not self.certificates[key]["implicit"]:
            signers = self.certificates[key]["signers"]
            if validator not in signers:
                signers.append(validator)
        return True

    def _apply_observation(self, index, ev):
        validator = ev["validator"]
        if validator not in self.validator_set:
            return self._freeze(index, UNKNOWN_VALIDATOR,
                                f"observer {validator} is not a registered validator")

        key = (ev["block_id"], ev["view"])
        if key not in self.certificates:
            return self._freeze(
                index, MISSING_CERTIFICATE,
                f"observed certificate ({ev['block_id']}, view {ev['view']}) "
                "has not reached the 2f+1 threshold")

        locked_block, locked_view = self.locks[validator]
        if ev["view"] > locked_view:
            self.locks[validator] = (ev["block_id"], ev["view"])
            self.lock_history[validator].append({
                "event_index": index,
                "block_id": ev["block_id"],
                "view": ev["view"],
            })
        return True

    # -- commit rule ---------------------------------------------------------

    def _try_commit(self):
        """Commit the head of every completed 3-chain of certified blocks."""
        changed = True
        while changed:
            changed = False
            for block3_id, view3 in sorted(self.certificate_order,
                                           key=lambda k: k[1]):
                block3 = self.blocks[block3_id]
                parent2 = block3.parent_id
                if parent2 is None:
                    continue
                block2 = self.blocks[parent2]
                if (parent2, view3 - 1) not in self.certificates:
                    continue
                parent1 = block2.parent_id
                if parent1 is None:
                    continue
                block1 = self.blocks[parent1]
                if (parent1, view3 - 2) not in self.certificates:
                    continue
                if block1.view <= self.blocks[self.committed_tip].view:
                    continue  # already committed at or above this height
                if not self._extends(parent1, self.committed_tip):
                    continue  # cannot happen in a safe trajectory; stay put
                self._commit_chain(parent1, block3_id, view3)
                changed = True

    def _commit_chain(self, head_id, decide_block_id, decide_view):
        chain = []
        current = head_id
        while current != self.committed_tip:
            chain.append(current)
            current = self.blocks[current].parent_id
        chain.reverse()
        self.committed.extend(chain)
        self.commits.append({
            "blocks": chain,
            "decide_qc": {
                "block_id": decide_block_id,
                "view": decide_view,
                "signers": list(
                    self.certificates[(decide_block_id, decide_view)]["signers"]),
            },
        })
        self.committed_tip = head_id

    # -- driver --------------------------------------------------------------

    def run(self):
        handlers = {
            "proposal": self._apply_proposal,
            "vote": self._apply_vote,
            "qc_observation": self._apply_observation,
        }
        for index, event in enumerate(self.events):
            if not handlers[event["type"]](index, event):
                break  # frozen at the earliest offending event
            self.events_processed = index + 1
        return self.verdict()

    def verdict(self):
        certificates = [
            {
                "block_id": cert["block_id"],
                "view": cert["view"],
                "signers": list(cert["signers"]),
                "formed_at": cert["formed_at"],
            }
            for cert in (self.certificates[key] for key in self.certificate_order)
        ]
        locks = {
            validator: {
                "locked": {
                    "block_id": self.locks[validator][0],
                    "view": self.locks[validator][1],
                },
                "history": list(self.lock_history[validator]),
            }
            for validator in self.validators
        }
        return {
            "audit_id": self.audit_id,
            "status": "rejected" if self.violation else "accepted",
            "validator_count": len(self.validators),
            "f": self.f,
            "quorum": self.quorum,
            "genesis": self.genesis_id,
            "events_total": len(self.events),
            "events_processed": self.events_processed,
            "violation": self.violation,
            "committed": list(self.committed),
            "commits": self.commits,
            "certificates": certificates,
            "locks": locks,
        }
