"""Stable evidence chains for a validator's recorded lock.

When a frozen (or accepted) voting trajectory is reopened, a lock summary
(``locked`` block/view) is not enough to judge an unlock: the auditor must be
able to trace a lock back to

1. the captured ``qc_observation`` that moved the validator's lock;
2. the certificate formation that observation relies on — the exact vote
   event at which 2f+1 *distinct* signatures first reached the threshold;
3. every signed vote contributing to that certificate, with its capture
   event index, view, block and validator;
4. the continuous chain of certificate references from the locked block
   back to genesis, so each parent hop can be checked against the
   certificate that justifies it.

Every item is derived *only* from events actually processed by the replay
engine: nothing is inferred from events at or after a freeze violation.
The genesis lock (view 0) is implicit and has no observation or votes.
"""

from __future__ import annotations

from . import consensus


class EvidenceError(Exception):
    """Raised when no evidence chain can be produced.

    ``status`` is the HTTP status the read endpoint must return and
    ``code``/``message`` describe the refusal.
    """

    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def _vote_records(engine: consensus.Engine, block_id: str, view: int) -> list[dict]:
    """Signed votes for a certificate, strictly in capture order."""
    records = engine.votes.get((block_id, view), [])
    return [
        {
            "validator": rec["validator"],
            "event_index": rec["event_index"],
            "block_id": block_id,
            "view": view,
            "signature": rec["signature"],
        }
        for rec in records
    ]


def _certificate_ref(engine: consensus.Engine, block_id: str, view: int) -> dict:
    """Reference to the certificate attesting ``block_id`` at ``view``."""
    cert = engine.certificates[(block_id, view)]
    if cert.get("implicit"):
        return {
            "block_id": block_id,
            "view": 0,
            "implicit": True,
            "formed_at": None,
            "signers": [],
        }
    return {
        "block_id": block_id,
        "view": view,
        "implicit": False,
        "formed_at": cert["formed_at"],
        "signers": list(cert["signers"]),
    }


def _parent_chain(engine: consensus.Engine, locked_block: str,
                  locked_view: int) -> list[dict]:
    """Continuous certificate references from the locked block to genesis.

    Each non-genesis hop records the block, its proposal event, its parent
    and the justifying certificate (which must certify the parent).  The
    final hop is the implicit genesis certificate.  Every block and
    certificate referenced here exists in the processed prefix only.
    """
    chain = []
    current = locked_block
    seen: set[str] = set()
    while current is not None:
        if current in seen:
            raise EvidenceError(
                409, "evidence_cycle",
                f"parent chain from {locked_block} contains a cycle at {current}")
        seen.add(current)
        block = engine.blocks.get(current)
        if block is None:
            raise EvidenceError(
                409, "evidence_incomplete",
                f"block {current} on the parent chain was never observed")
        if current == engine.genesis_id:
            chain.append({
                "block_id": current,
                "view": 0,
                "parent_id": None,
                "proposal_event_index": None,
                "certificate": _certificate_ref(engine, current, 0),
                "genesis": True,
            })
            break
        qc_key = (block.qc_block_id, block.qc_view)
        if qc_key not in engine.certificates:
            raise EvidenceError(
                409, "evidence_incomplete",
                f"certificate ({block.qc_block_id}, view {block.qc_view}) "
                f"justifying {current} is not present in the processed prefix")
        proposal = engine.proposal_events.get(current)
        chain.append({
            "block_id": current,
            "view": block.view,
            "parent_id": block.parent_id,
            "proposal_event_index":
                None if proposal is None else proposal["event_index"],
            "certificate": _certificate_ref(engine, block.qc_block_id,
                                            block.qc_view),
            "genesis": False,
        })
        current = block.parent_id
    return chain


def lock_evidence(engine: consensus.Engine, validator: str,
                  view: int) -> dict:
    """Build the evidence chain for one recorded lock of one validator.

    ``view`` identifies the lock view (0 for the implicit genesis lock).
    Raises :class:`EvidenceError` if the validator, audit or lock view is
    not recorded in the processed prefix.
    """
    if validator not in engine.validator_set:
        raise EvidenceError(
            404, "unknown_validator",
            f"validator {validator} is not part of this audit's validator set")

    history = engine.lock_history[validator]
    recorded_views = [entry["view"] for entry in history]

    lock_entry = None
    if view == 0:
        current_block, current_view = engine.locks[validator]
        # The implicit genesis lock is addressable only while it is still in
        # effect: once the validator has moved, view 0 is not a recorded lock
        # view of the trajectory, and no observation backs it.
        if current_view != 0:
            raise EvidenceError(
                404, "lock_view_not_recorded",
                f"validator {validator} has no recorded lock at view 0; "
                f"recorded lock views: {recorded_views}")
        lock_entry = None
    else:
        for entry in history:
            if entry["view"] == view:
                lock_entry = entry
                break
        if lock_entry is None:
            raise EvidenceError(
                404, "lock_view_not_recorded",
                f"validator {validator} has no recorded lock at view {view}; "
                f"recorded lock views: {[0] + recorded_views}")

    frozen = engine.violation is not None
    result = {
        "audit_id": engine.audit_id,
        "validator": validator,
        "frozen": frozen,
        "queried_lock": {"block_id": None, "view": view},
        "evidence": {},
        "parent_chain": [],
    }
    if frozen:
        result["freeze"] = {
            "event_index": engine.violation["event_index"],
            "type": engine.violation["type"],
        }

    if view == 0:
        genesis_id = engine.genesis_id
        result["queried_lock"] = {"block_id": genesis_id, "view": 0}
        result["evidence"] = {
            "kind": "implicit_genesis",
            "block_id": genesis_id,
            "view": 0,
            "observation": None,
            "certificate": _certificate_ref(engine, genesis_id, 0),
            "votes": [],
        }
        result["parent_chain"] = _parent_chain(engine, genesis_id, 0)
        return result

    obs_index = lock_entry["event_index"]
    locked_block = lock_entry["block_id"]
    locked_view = lock_entry["view"]
    result["queried_lock"] = {"block_id": locked_block, "view": locked_view}

    # Freeze boundary: an observation at or after the violating event was
    # never processed, so such a lock cannot be on record (it would already
    # have been rejected above). Guard explicitly anyway — no evidence may be
    # fabricated from events the replay did not reach.
    if frozen and obs_index >= engine.violation["event_index"]:
        raise EvidenceError(
            409, "lock_after_freeze",
            f"the lock at view {locked_view} only forms at event {obs_index}, "
            f"at or after the freeze at event "
            f"{engine.violation['event_index']}; no evidence can be derived")

    cert_key = (locked_block, locked_view)
    if cert_key not in engine.certificates:
        raise EvidenceError(
            409, "evidence_incomplete",
            f"certificate for observed lock ({locked_block}, view "
            f"{locked_view}) never formed in the processed prefix")
    cert = engine.certificates[cert_key]
    if cert.get("implicit"):
        raise EvidenceError(
            409, "evidence_incomplete",
            "a non-zero lock view cannot be justified by the genesis certificate")
    formed_at = cert["formed_at"]
    if frozen and formed_at >= engine.violation["event_index"]:
        raise EvidenceError(
            409, "lock_after_freeze",
            f"the certificate for view {locked_view} only forms at event "
            f"{formed_at}, at or after the freeze at event "
            f"{engine.violation['event_index']}")

    votes = _vote_records(engine, locked_block, locked_view)
    quorum_votes = votes[:engine.quorum]
    if len(quorum_votes) != engine.quorum \
            or len({v["validator"] for v in quorum_votes}) != engine.quorum:
        raise EvidenceError(
            409, "evidence_incomplete",
            f"certificate for view {locked_view} lacks {engine.quorum} "
            "distinct signers in the processed prefix")

    proposal = engine.proposal_events.get(locked_block)
    result["evidence"] = {
        "kind": "observed_certificate",
        "block_id": locked_block,
        "view": locked_view,
        "proposal": (
            None if proposal is None
            else {
                "event_index": proposal["event_index"],
                "block_id": locked_block,
                "view": locked_view,
                "proposer": proposal["proposer"],
            }
        ),
        "certificate_formation": {
            "block_id": locked_block,
            "view": locked_view,
            "formed_at": formed_at,
            "quorum": engine.quorum,
            "threshold_vote": next(
                (v for v in quorum_votes if v["event_index"] == formed_at),
                None),
        },
        "observation": {
            "event_index": obs_index,
            "validator": validator,
            "block_id": locked_block,
            "view": locked_view,
        },
        "votes": votes,
    }
    result["parent_chain"] = _parent_chain(engine, locked_block, locked_view)
    return result
