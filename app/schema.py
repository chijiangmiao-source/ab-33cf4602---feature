"""Structural validation of audit submissions.

Everything here is checked *before* any consensus rule runs.  A structurally
invalid submission is rejected with HTTP 400 and produces no verdict; a
structurally valid submission is replayed by the consensus engine, which may
still freeze it at a rule-violating event (verdict ``rejected``).
"""

from __future__ import annotations

import re

MAX_EVENTS = 64
MAX_VIEW = 1_000_000
MAX_PAYLOAD_CHARS = 512
VALIDATOR_COUNTS = (4, 7)

_AUDIT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:\-]{0,127}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_HEX128_RE = re.compile(r"^[0-9a-f]{128}$")


class SchemaError(Exception):
    """Raised when a submission is structurally invalid."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _check_hex(value, pattern, what):
    if not isinstance(value, str) or not pattern.match(value):
        raise SchemaError("invalid_schema", f"{what} must match {pattern.pattern}")
    return value


def _check_view(value, what, minimum):
    if not _is_int(value) or not (minimum <= value <= MAX_VIEW):
        raise SchemaError(
            "invalid_schema",
            f"{what} must be an integer in [{minimum}, {MAX_VIEW}]")
    return value


def _check_keys(obj, allowed, required, what):
    if not isinstance(obj, dict):
        raise SchemaError("invalid_schema", f"{what} must be an object")
    unknown = set(obj) - allowed
    if unknown:
        raise SchemaError("invalid_schema",
                          f"{what} has unknown field(s): {sorted(unknown)}")
    missing = set(required) - set(obj)
    if missing:
        raise SchemaError("invalid_schema",
                          f"{what} is missing field(s): {sorted(missing)}")


def _validate_proposal(ev, i):
    _check_keys(ev,
                allowed={"type", "proposer", "view", "block_id", "parent_id",
                         "qc", "payload"},
                required={"type", "proposer", "view", "block_id", "parent_id",
                          "qc"},
                what=f"events[{i}]")
    _check_hex(ev["proposer"], _HEX64_RE, f"events[{i}].proposer")
    _check_view(ev["view"], f"events[{i}].view", 1)
    _check_hex(ev["block_id"], _HEX64_RE, f"events[{i}].block_id")
    _check_hex(ev["parent_id"], _HEX64_RE, f"events[{i}].parent_id")
    _check_keys(ev["qc"], allowed={"block_id", "view"},
                required={"block_id", "view"}, what=f"events[{i}].qc")
    _check_hex(ev["qc"]["block_id"], _HEX64_RE, f"events[{i}].qc.block_id")
    _check_view(ev["qc"]["view"], f"events[{i}].qc.view", 0)
    if "payload" in ev:
        if not isinstance(ev["payload"], str) \
                or len(ev["payload"]) > MAX_PAYLOAD_CHARS:
            raise SchemaError(
                "invalid_schema",
                f"events[{i}].payload must be a string of at most "
                f"{MAX_PAYLOAD_CHARS} characters")


def _validate_vote(ev, i):
    _check_keys(ev,
                allowed={"type", "validator", "view", "block_id", "signature"},
                required={"type", "validator", "view", "block_id", "signature"},
                what=f"events[{i}]")
    _check_hex(ev["validator"], _HEX64_RE, f"events[{i}].validator")
    _check_view(ev["view"], f"events[{i}].view", 1)
    _check_hex(ev["block_id"], _HEX64_RE, f"events[{i}].block_id")
    _check_hex(ev["signature"], _HEX128_RE, f"events[{i}].signature")


def _validate_observation(ev, i):
    _check_keys(ev, allowed={"type", "validator", "block_id", "view"},
                required={"type", "validator", "block_id", "view"},
                what=f"events[{i}]")
    _check_hex(ev["validator"], _HEX64_RE, f"events[{i}].validator")
    _check_hex(ev["block_id"], _HEX64_RE, f"events[{i}].block_id")
    _check_view(ev["view"], f"events[{i}].view", 0)


def validate_submission(obj) -> dict:
    """Validate the submission envelope; return it unchanged if valid."""
    _check_keys(obj, allowed={"audit_id", "validators", "genesis", "events"},
                required={"audit_id", "validators", "genesis", "events"},
                what="submission")

    audit_id = obj["audit_id"]
    if not isinstance(audit_id, str) or not _AUDIT_ID_RE.match(audit_id):
        raise SchemaError(
            "invalid_audit_id",
            "audit_id must be 1-128 chars of [A-Za-z0-9._:-] and start "
            "alphanumeric")

    validators = obj["validators"]
    if not isinstance(validators, list) or len(validators) not in VALIDATOR_COUNTS:
        raise SchemaError(
            "invalid_validator_set",
            f"validators must be a list of {VALIDATOR_COUNTS} public keys")
    for i, key in enumerate(validators):
        _check_hex(key, _HEX64_RE, f"validators[{i}]")
    if len(set(validators)) != len(validators):
        raise SchemaError("duplicate_identity",
                          "validator list contains a duplicate public key")

    genesis = obj["genesis"]
    _check_keys(genesis, allowed={"id", "view"}, required={"id", "view"},
                what="genesis")
    _check_hex(genesis["id"], _HEX64_RE, "genesis.id")
    if not _is_int(genesis["view"]) or genesis["view"] != 0:
        raise SchemaError("invalid_schema", "genesis.view must be 0")

    events = obj["events"]
    if not isinstance(events, list):
        raise SchemaError("invalid_schema", "events must be a list")
    if len(events) > MAX_EVENTS:
        raise SchemaError("too_many_events",
                          f"at most {MAX_EVENTS} events are allowed")

    handlers = {
        "proposal": _validate_proposal,
        "vote": _validate_vote,
        "qc_observation": _validate_observation,
    }
    for i, ev in enumerate(events):
        if not isinstance(ev, dict):
            raise SchemaError("invalid_schema", f"events[{i}] must be an object")
        etype = ev.get("type")
        if etype not in handlers:
            raise SchemaError(
                "invalid_schema",
                f"events[{i}].type must be one of {sorted(handlers)}")
        handlers[etype](ev, i)
    return obj
