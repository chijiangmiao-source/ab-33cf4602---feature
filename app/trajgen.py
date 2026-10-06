"""Deterministic builder for signed audit trajectories.

Used by the unit tests and by the Compose ``verify`` service to produce
commit and reject trajectories with real Ed25519 signatures.
"""

from __future__ import annotations

import hashlib

from . import canonical, ed25519


def validator_seed(index: int) -> bytes:
    """Deterministic 32-byte Ed25519 seed for a synthetic validator."""
    return hashlib.sha256(f"lock-audit validator seed {index}".encode()).digest()


class TrajectoryBuilder:
    def __init__(self, audit_id: str, n_validators: int = 4,
                 genesis_id: str | None = None):
        self.audit_id = audit_id
        self.seeds = [validator_seed(i) for i in range(n_validators)]
        self.pubkeys = [ed25519.publickey(s).hex() for s in self.seeds]
        self.genesis_id = genesis_id or hashlib.sha256(
            f"{audit_id}:genesis".encode("utf-8")).hexdigest()
        self.events: list[dict] = []

    # -- event appenders ------------------------------------------------------

    def propose(self, proposer_index: int, view: int, qc: tuple[str, int],
                payload: str = "") -> str:
        """Append a proposal extending ``qc``; return the new block id."""
        proposer = self.pubkeys[proposer_index]
        qc_block, qc_view = qc
        block_id = canonical.block_id(view, qc_block, qc_block, qc_view,
                                      proposer, payload)
        self.events.append({
            "type": "proposal",
            "proposer": proposer,
            "view": view,
            "block_id": block_id,
            "parent_id": qc_block,
            "qc": {"block_id": qc_block, "view": qc_view},
            "payload": payload,
        })
        return block_id

    def vote(self, voter_index: int, view: int, block_id: str,
             sign: bool = True) -> dict:
        """Append a vote; with ``sign=False`` attach a garbage signature."""
        validator = self.pubkeys[voter_index]
        if sign:
            message = canonical.vote_message(self.audit_id, view, block_id)
            signature = ed25519.sign(self.seeds[voter_index], message).hex()
        else:
            signature = "00" * 64
        event = {
            "type": "vote",
            "validator": validator,
            "view": view,
            "block_id": block_id,
            "signature": signature,
        }
        self.events.append(event)
        return event

    def observe(self, validator_index: int, block_id: str, view: int) -> dict:
        event = {
            "type": "qc_observation",
            "validator": self.pubkeys[validator_index],
            "block_id": block_id,
            "view": view,
        }
        self.events.append(event)
        return event

    # -- assembly ---------------------------------------------------------------

    def submission(self) -> dict:
        return {
            "audit_id": self.audit_id,
            "validators": list(self.pubkeys),
            "genesis": {"id": self.genesis_id, "view": 0},
            "events": list(self.events),
        }


def build_commit_trajectory(audit_id: str, n_validators: int = 4,
                            views: int = 4) -> tuple[TrajectoryBuilder, list[str]]:
    """A fully safe trajectory: ``views`` certified blocks in consecutive
    views, so the 3-chain commit rule fires for the first ``views - 2``.

    Returns the builder and the list of proposed block ids in view order.
    """
    builder = TrajectoryBuilder(audit_id, n_validators)
    quorum = 2 * ((n_validators - 1) // 3) + 1
    qc = (builder.genesis_id, 0)
    blocks = []
    for view in range(1, views + 1):
        block = builder.propose(proposer_index=(view - 1) % n_validators,
                                view=view, qc=qc, payload=f"view-{view}")
        blocks.append(block)
        for voter in range(quorum):
            builder.vote(voter, view, block)
        for observer in range(n_validators):
            builder.observe(observer, block, view)
        qc = (block, view)
    return builder, blocks


def build_unsafe_vote_trajectory(audit_id: str) -> tuple[TrajectoryBuilder, int]:
    """A trajectory that freezes when validator 0, locked on the view-1
    block, votes for a conflicting view-2 branch justified only by the
    genesis certificate.  Returns the builder and the offending event index.
    """
    builder = TrajectoryBuilder(audit_id, 4)
    genesis_qc = (builder.genesis_id, 0)

    block1 = builder.propose(0, 1, genesis_qc, payload="main-1")
    for voter in range(3):
        builder.vote(voter, 1, block1)          # certificate for block1@1
    builder.observe(0, block1, 1)               # validator 0 locks on block1

    rival = builder.propose(1, 2, genesis_qc, payload="rival-2")
    offending_index = len(builder.events)
    builder.vote(0, 2, rival)                   # unsafe: no extension, no unlock
    return builder, offending_index


def build_frozen_trajectory_with_later_lock(
        audit_id: str) -> tuple[TrajectoryBuilder, int, str]:
    """A trajectory frozen by an unsafe view-2 vote, *followed* by events that
    would have locked validator 0 on a certified main-chain view-2 block.

    The post-freeze suffix is a trap for the evidence read path: replaying
    stops at the violation, so validator 0's only recorded lock is view 1 and
    the view-2 lock must never be reconstructed from the later events.
    Returns the builder, the violating event index and the later block id.
    """
    builder, offending_index = build_unsafe_vote_trajectory(audit_id)
    block1 = builder.events[0]["block_id"]

    later = builder.propose(1, 2, (block1, 1), payload="main-2")
    for voter in range(3):
        builder.vote(voter, 2, later)          # certificate for later@2
    builder.observe(0, later, 2)               # would move the lock to view 2
    return builder, offending_index, later
