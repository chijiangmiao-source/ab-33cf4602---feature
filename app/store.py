"""Idempotent verdict store.

Maps a stable audit identifier to the digest of the submission and the
verdict it produced.  Retransmitting the same identifier with semantically
identical content replays the original verdict; the same identifier with
different content is an explicit conflict.

Records live in memory; when ``AUDIT_STORE_FILE`` points at a path the store
is also persisted there (atomic rewrite) so a container restart keeps prior
verdicts.
"""

from __future__ import annotations

import json
import os
import threading

NEW = "new"
REPLAY = "replay"
CONFLICT = "conflict"


class AuditStore:
    def __init__(self, path: str | None = None):
        self._lock = threading.Lock()
        self._records: dict[str, dict] = {}
        self._path = path
        if path and os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                if isinstance(data, dict) and isinstance(data.get("records"), dict):
                    self._records = data["records"]
            except (OSError, ValueError):
                # A corrupt store must not take the service down; start empty.
                self._records = {}

    def check(self, audit_id: str, digest: str) -> str:
        """Classify a submission against any stored verdict for its id."""
        with self._lock:
            record = self._records.get(audit_id)
            if record is None:
                return NEW
            return REPLAY if record["digest"] == digest else CONFLICT

    def get(self, audit_id: str):
        with self._lock:
            record = self._records.get(audit_id)
            return None if record is None else dict(record["verdict"])

    def get_submission(self, audit_id: str):
        """Return the original submission for a stored audit (read paths use
        it to re-derive evidence through the real consensus engine)."""
        with self._lock:
            record = self._records.get(audit_id)
            if record is None:
                return None
            submission = record.get("submission")
            return None if submission is None else json.loads(json.dumps(submission))

    def put(self, audit_id: str, digest: str, verdict: dict,
            submission: dict | None = None) -> None:
        with self._lock:
            record = {"digest": digest, "verdict": verdict}
            if submission is not None:
                record["submission"] = submission
            self._records[audit_id] = record
            self._persist_locked()

    def _persist_locked(self) -> None:
        if not self._path:
            return
        tmp = self._path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"records": self._records}, fh, ensure_ascii=False)
        os.replace(tmp, self._path)
