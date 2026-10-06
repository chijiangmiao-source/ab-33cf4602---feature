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

# Read-path evidence errors (raised by Engine.lock_evidence).
LOCK_VIEW_NOT_FOUND = "lock_view_not_found"
EVIDENCE_UNAVAILABLE = "evidence_unavailable"


class EvidenceError(Exception):
    """A lock-evidence query cannot be answered from the replayed state."""

    def __init__(self, code, message, status=404):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


class _Block:
    __slots__ = ("block_id", "view", "parent_id", "qc_block_id", "qc_view",
                 "proposer", "payload", "proposed_at")

    def __init__(self, block_id, view, parent_id, qc_block_id, qc_view,
                 proposer, payload, proposed_at):
        self.block_id = block_id
        self.view = view
        self.parent_id = parent_id
        self.qc_block_id = qc_block_id
        self.qc_view = qc_view
        self.proposer = proposer
        self.payload = payload
        self.proposed_at = proposed_at


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
                                    None, "", None),
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
        # Accepted qc_observation events per validator, in capture order;
        # each entry is (event_index, block_id, view).
        self.observations = {v: [] for v in self.validators}

        self.votes = {}  # (block_id, view) -> [validator, ...] in arrival order
        self.vote_events = {}  # (block_id, view) -> [event index, ...]
        self.voted = {}  # (validator, view) -> block_id

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
            proposer, payload, index)
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
        key = (block_id, view)
        self.votes.setdefault(key, []).append(validator)
        self.vote_events.setdefault(key, []).append(index)

        if key not in self.certificates and len(self.votes[key]) >= self.quorum:
            self.certificates[key] = {
                "block_id": block_id,
                "view": view,
                "signers": list(self.votes[key]),
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

        self.observations[validator].append(
            (index, ev["block_id"], ev["view"]))
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

    # -- lock evidence read path ----------------------------------------------

    def lock_evidence(self, validator: str, view: int) -> dict:
        """Build the stable evidence chain behind one recorded validator lock.

        The queried lock must be a view the validator actually reached through
        an accepted ``qc_observation`` in the replayed (and, when frozen,
        pre-violation) prefix.  Every cited event index, block, view and
        signature comes from that prefix; later events are never consulted and
        never used to back-fill evidence.
        """
        if validator not in self.validator_set:
            raise EvidenceError(
                "unknown_validator",
                f"validator {validator} is not registered for this audit",
                status=404)

        record = None
        for entry in self.lock_history[validator]:
            if entry["view"] == view:
                record = entry
                break
        if record is None:
            current_view = self.locks[validator][1]
            if self.violation is not None and view > current_view:
                # The requested lock can only exist beyond the replay horizon:
                # it would first form at or after the freeze event.
                raise EvidenceError(
                    EVIDENCE_UNAVAILABLE,
                    f"validator {validator} has no recorded lock at view "
                    f"{view} within the {self.events_processed} replayed "
                    f"event(s); its last recorded lock is view {current_view} "
                    "and a lock forming after the freeze violation is never "
                    "back-filled from later events")
            raise EvidenceError(
                LOCK_VIEW_NOT_FOUND,
                f"validator {validator} has no recorded lock at view {view}")

        obs_index = record["event_index"]
        locked_block = record["block_id"]
        locked_view = record["view"]
        cert = self.certificates.get((locked_block, locked_view))
        # A recorded history entry always points at a certificate that was
        # present when the observation was accepted; guard regardless so the
        # read path never fabricates one.
        if cert is None or cert.get("implicit"):
            raise EvidenceError(
                EVIDENCE_UNAVAILABLE,
                f"no threshold certificate backs the lock at view {locked_view}")

        if obs_index >= self.events_processed:
            # Defensive: the triggering observation must itself be inside the
            # replayed prefix, never reconstructed from later events.
            raise EvidenceError(
                EVIDENCE_UNAVAILABLE,
                "the triggering observation lies beyond the replay horizon")

        observation_event = self.events[obs_index]
        if (observation_event.get("validator") != validator
                or observation_event.get("block_id") != locked_block
                or observation_event.get("view") != locked_view):
            raise EvidenceError(
                EVIDENCE_UNAVAILABLE,
                "the triggering observation event does not match the record")

        chain = self._lock_chain_refs(locked_block)

        forming_votes = []
        for idx, signer in zip(self.vote_events[(locked_block, locked_view)],
                               self.votes[(locked_block, locked_view)]):
            vote_event = self.events[idx]
            if (vote_event.get("validator") != signer
                    or vote_event.get("block_id") != locked_block
                    or vote_event.get("view") != locked_view
                    or idx >= self.events_processed):
                raise EvidenceError(
                    EVIDENCE_UNAVAILABLE,
                    "a forming vote lies outside the replayed prefix")
            forming_votes.append({
                "event_index": idx,
                "block_id": locked_block,
                "view": locked_view,
                "validator": signer,
                "signature": vote_event["signature"],
            })

        formation_event = self.events[cert["formed_at"]]
        if (formation_event.get("block_id") != locked_block
                or formation_event.get("view") != locked_view
                or cert["formed_at"] >= self.events_processed):
            raise EvidenceError(
                EVIDENCE_UNAVAILABLE,
                "the certificate formation event lies outside the replayed "
                "prefix")

        return {
            "audit_id": self.audit_id,
            "query": {
                "validator": validator,
                "view": view,
            },
            "status": self.verdict()["status"],
            "events_processed": self.events_processed,
            "locked": {
                "block_id": locked_block,
                "view": locked_view,
            },
            "observation": {
                "event_index": obs_index,
                "type": "qc_observation",
                "block_id": locked_block,
                "view": locked_view,
                "validator": validator,
            },
            "certificate": {
                "block_id": locked_block,
                "view": locked_view,
                "quorum": self.quorum,
                "formed_at": cert["formed_at"],
                "formation_event": {
                    "event_index": cert["formed_at"],
                    "type": "vote",
                    "block_id": locked_block,
                    "view": locked_view,
                    "validator": formation_event["validator"],
                },
                "signers": list(cert["signers"]),
                "forming_votes": forming_votes,
            },
            "parent_chain": chain,
        }

    def _lock_chain_refs(self, locked_block: str) -> list:
        """Continuous certificate references from ``locked_block``'s
        justifying certificate down the proposal parent links to genesis.

        The first hop is the certificate embedded in the locked block's
        proposal; each subsequent hop is the certificate referenced by the
        parent block's own proposal.  Every hop asserts that the proposal's
        parent block equals the block the referenced certificate certifies, so
        the auditor can confirm each parent/certificate pair agrees.
        """
        chain = []
        current = locked_block
        seen = set()
        while current != self.genesis_id:
            if current in seen:
                raise EvidenceError(
                    EVIDENCE_UNAVAILABLE,
                    "parent chain cycles before reaching genesis")
            seen.add(current)
            block = self.blocks.get(current)
            if block is None or block.proposed_at is None:
                raise EvidenceError(
                    EVIDENCE_UNAVAILABLE,
                    f"block {current} on the parent chain is not known")
            if block.proposed_at >= self.events_processed:
                raise EvidenceError(
                    EVIDENCE_UNAVAILABLE,
                    f"block {current} is only proposed beyond the replay "
                    "horizon")
            qc_key = (block.qc_block_id, block.qc_view)
            qc = self.certificates.get(qc_key)
            if qc is None:
                raise EvidenceError(
                    EVIDENCE_UNAVAILABLE,
                    f"referenced certificate ({block.qc_block_id}, view "
                    f"{block.qc_view}) for block {current} never formed")
            if block.parent_id != block.qc_block_id:
                raise EvidenceError(
                    EVIDENCE_UNAVAILABLE,
                    f"block {current} parent does not match its certificate")
            if not qc.get("implicit") and (
                    qc["formed_at"] is None
                    or qc["formed_at"] >= self.events_processed):
                raise EvidenceError(
                    EVIDENCE_UNAVAILABLE,
                    f"certificate for {block.qc_block_id} forms beyond the "
                    "replay horizon")
            is_implicit = bool(qc.get("implicit", False))
            chain.append({
                "block_id": current,
                "block_view": block.view,
                "proposal_event_index": block.proposed_at,
                "proposer": block.proposer,
                "parent_block_id": block.parent_id,
                "certificate": {
                    "block_id": qc["block_id"],
                    "view": qc["view"],
                    "implicit": is_implicit,
                    "formed_at": qc["formed_at"],
                    "signers": list(qc["signers"]),
                },
                "parent_matches_certified_block":
                    block.parent_id == qc["block_id"],
                "reaches_genesis": is_implicit,
            })
            if is_implicit:
                if block.parent_id != self.genesis_id:
                    raise EvidenceError(
                        EVIDENCE_UNAVAILABLE,
                        "implicit genesis certificate cited off genesis")
                break
            current = block.parent_id
        else:  # pragma: no cover - every chain ends via the implicit genesis cert
            raise EvidenceError(
                EVIDENCE_UNAVAILABLE,
                "parent chain reached genesis without its implicit certificate")
        if not chain[-1]["reaches_genesis"] \
                or chain[-1]["parent_block_id"] != self.genesis_id:
            raise EvidenceError(
                EVIDENCE_UNAVAILABLE,
                "parent chain does not run back to genesis")
        return chain

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
