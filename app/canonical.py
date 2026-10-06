"""Canonical UTF-8 encodings that Ed25519 vote signatures and block
identifiers commit to.

Every signed/hashed structure is a UTF-8 string of ``key:value`` lines with a
fixed field order and a trailing newline.  Free-text fields are embedded via
``json.dumps`` so the encoding stays injective (no newline smuggling).
"""

from __future__ import annotations

import hashlib
import json

DOMAIN = "lock-audit.v1"


def vote_message(audit_id: str, view: int, block_id: str) -> bytes:
    """Canonical UTF-8 byte string covered by a validator's vote signature."""
    return (
        f"{DOMAIN}\n"
        f"vote\n"
        f"audit:{audit_id}\n"
        f"view:{view}\n"
        f"block:{block_id}\n"
    ).encode("utf-8")


def block_id(
    view: int,
    parent_id: str,
    qc_block_id: str,
    qc_view: int,
    proposer: str,
    payload: str,
) -> str:
    """Content-addressed block identifier: sha256 of the canonical block."""
    canonical = (
        f"{DOMAIN}\n"
        f"block\n"
        f"view:{view}\n"
        f"parent:{parent_id}\n"
        f"qc_view:{qc_view}\n"
        f"qc_block:{qc_block_id}\n"
        f"proposer:{proposer}\n"
        f"payload:{json.dumps(payload, ensure_ascii=False)}\n"
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def submission_digest(submission: dict) -> str:
    """Semantic fingerprint of a submission for idempotent replay.

    Key order is normalized (sorted keys, compact separators) so two
    submissions that differ only in JSON object member order hash alike.
    """
    canonical = json.dumps(
        submission, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
