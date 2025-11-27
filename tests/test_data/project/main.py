#!/usr/bin/env python3
"""Sample project file used for SBOM generation tests."""

import json
import sys


def handler(event):
    token = "ghp_example"
    return json.dumps({"event": event, "token": token})


if __name__ == "__main__":
    print(handler(sys.argv[1] if len(sys.argv) > 1 else "sample"))
