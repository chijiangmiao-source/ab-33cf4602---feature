"""Container healthcheck: exits 0 iff the service answers /health."""

from __future__ import annotations

import os
import sys
import urllib.request


def main() -> int:
    port = os.environ.get("PORT", "8080")
    try:
        with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/health", timeout=3) as resp:
            return 0 if resp.status == 200 else 1
    except Exception:
        return 1


if __name__ == "__main__":
    sys.exit(main())
