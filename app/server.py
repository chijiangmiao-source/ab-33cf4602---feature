"""HTTP API for the locked-vote trajectory audit service.

Endpoints:
    GET  /health                 liveness probe
    POST /v1/audits              submit a trajectory for audit
    GET  /v1/audits/{audit_id}   fetch the stored verdict for an audit id

The listen port is configurable through the ``PORT`` environment variable
(default 8080).  Only the Python standard library is used.
"""

from __future__ import annotations

import json
import logging
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from . import canonical, consensus, schema, store as store_mod

MAX_BODY_BYTES = 1 << 20  # 1 MiB
_AUDIT_PATH_RE = re.compile(r"^/v1/audits/([A-Za-z0-9][A-Za-z0-9._:\-]{0,127})$")
_LOCK_EVIDENCE_PATH_RE = re.compile(
    r"^/v1/audits/([A-Za-z0-9][A-Za-z0-9._:\-]{0,127})/locks/([0-9a-f]{64})$")

LOG = logging.getLogger("lock-audit")


def _error_body(code: str, message: str) -> bytes:
    return json.dumps(
        {"error": {"code": code, "message": message}},
        ensure_ascii=False,
    ).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    server_version = "LockAudit/1.0"
    protocol_version = "HTTP/1.1"

    # Injected by make_server().
    audit_store: store_mod.AuditStore

    # -- plumbing -----------------------------------------------------------

    def log_message(self, fmt, *args):  # route through logging
        LOG.info("%s - %s", self.address_string(), fmt % args)

    def _send(self, status: int, body: bytes, content_type="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, status: int, obj):
        self._send(status, json.dumps(obj, ensure_ascii=False).encode("utf-8"))

    def _send_error(self, status: int, code: str, message: str):
        self._send(status, _error_body(code, message))

    # -- GET ------------------------------------------------------------------

    def do_GET(self):
        raw_path, _, raw_query = self.path.partition("?")
        path = raw_path
        if path == "/health":
            self._send_json(200, {"status": "ok", "service": "lock-audit"})
            return
        evidence_match = _LOCK_EVIDENCE_PATH_RE.match(path)
        if evidence_match:
            self._handle_lock_evidence(evidence_match, raw_query)
            return
        match = _AUDIT_PATH_RE.match(path)
        if match:
            verdict = self.audit_store.get(match.group(1))
            if verdict is None:
                self._send_error(404, "not_found",
                                 "no verdict stored for this audit_id")
            else:
                self._send_json(200, verdict)
            return
        self._send_error(404, "not_found", "unknown path")

    # -- lock evidence ---------------------------------------------------------

    def _handle_lock_evidence(self, match, raw_query):
        audit_id = match.group(1)
        validator = match.group(2)
        query = parse_qs(raw_query)
        view_values = query.get("view", [])
        if len(view_values) != 1:
            self._send_error(
                400, "invalid_request",
                "lock evidence requires a single integer 'view' query parameter")
            return
        try:
            view = int(view_values[0])
        except ValueError:
            view = -1
        if view < 0:
            self._send_error(
                400, "invalid_request",
                "'view' query parameter must be a non-negative integer")
            return

        verdict = self.audit_store.get(audit_id)
        if verdict is None:
            self._send_error(404, "not_found",
                             "no verdict stored for this audit_id")
            return
        submission = self.audit_store.get_submission(audit_id)
        if submission is None:
            # Stored before evidence retention existed; nothing to replay.
            self._send_error(
                404, "not_found",
                "stored audit carries no replayable submission")
            return

        # Re-derive through the real engine so every cited event, index and
        # signature comes from the actual replay (and never past a freeze).
        engine = consensus.Engine(submission)
        engine.run()
        try:
            evidence = engine.lock_evidence(validator, view)
        except consensus.EvidenceError as exc:
            status = 409 if exc.code == consensus.EVIDENCE_UNAVAILABLE else exc.status
            self._send_error(status, exc.code, exc.message)
            return
        self._send_json(200, evidence)

    # -- POST -----------------------------------------------------------------

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path != "/v1/audits":
            self._send_error(404, "not_found", "unknown path")
            return

        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._send_error(400, "invalid_request", "invalid Content-Length")
            return
        if length <= 0:
            self._send_error(400, "invalid_json", "request body must be JSON")
            return
        if length > MAX_BODY_BYTES:
            self._send_error(413, "too_large", "request body exceeds 1 MiB")
            return
        raw = self.rfile.read(length)
        try:
            submission = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            self._send_error(400, "invalid_json", "request body must be JSON")
            return

        try:
            schema.validate_submission(submission)
        except schema.SchemaError as exc:
            self._send_error(400, exc.code, exc.message)
            return

        audit_id = submission["audit_id"]
        digest = canonical.submission_digest(submission)
        outcome = self.audit_store.check(audit_id, digest)
        if outcome == store_mod.CONFLICT:
            self._send_error(
                409, "conflict",
                f"audit_id {audit_id!r} already has a verdict for different "
                "content")
            return
        if outcome == store_mod.REPLAY:
            verdict = self.audit_store.get(audit_id)
            verdict["replayed"] = True
            self._send_json(200, verdict)
            return

        verdict = consensus.Engine(submission).run()
        self.audit_store.put(audit_id, digest, verdict, submission=submission)
        verdict = dict(verdict)
        verdict["replayed"] = False
        self._send_json(201, verdict)

    # -- other verbs ------------------------------------------------------------

    def _method_not_allowed(self):
        self._send_error(405, "method_not_allowed", "method not allowed")

    do_PUT = _method_not_allowed
    do_DELETE = _method_not_allowed
    do_PATCH = _method_not_allowed


def make_server(port: int, audit_store: store_mod.AuditStore) -> ThreadingHTTPServer:
    handler_cls = type("BoundHandler", (Handler,), {"audit_store": audit_store})
    server = ThreadingHTTPServer(("0.0.0.0", port), handler_cls)
    server.daemon_threads = True
    return server


def main():
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    port = int(os.environ.get("PORT", "8080"))
    store_path = os.environ.get("AUDIT_STORE_FILE") or None
    audit_store = store_mod.AuditStore(store_path)
    server = make_server(port, audit_store)
    LOG.info("lock-audit listening on 0.0.0.0:%d (store: %s)",
             port, store_path or "in-memory")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
