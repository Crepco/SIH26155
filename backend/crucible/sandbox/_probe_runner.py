#!/usr/bin/env python3
"""Run one probe inside a sandbox container and print the result as JSON.

Copied into the prober alongside ``probes.py``. It exists so the probe runs
*from* the network segment it is meant to be testing from, which is the only
way "reachable" means anything.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import probes


def main() -> int:
    request = json.loads(sys.argv[1])
    result = probes.run_probe(
        request["probe"],
        request["host"],
        request.get("port"),
        **(request.get("kwargs") or {}),
    )
    print(json.dumps(result.to_dict()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
