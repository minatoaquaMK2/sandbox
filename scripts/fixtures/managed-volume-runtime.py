#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path


def main():
    root = Path(sys.argv[1]).resolve()
    args = sys.argv[2:]
    command = [str(root / "bin/cocoon"), "--config", str(root / "cocoon.json"), *args]
    fault_path = root / "cocoon-fault.json"
    try:
        fault = json.loads(fault_path.read_text())
    except FileNotFoundError:
        os.execv(command[0], command)
    if args[: len(fault["prefix"])] != fault["prefix"]:
        os.execv(command[0], command)
    if fault["action"] == "fail_second":
        barrier = root / "artifacts" / "barriers" / fault["id"]
        barrier.mkdir(parents=True, exist_ok=True)
        if fault["first"] in args:
            result = subprocess.run(command)
            if result.returncode == 0:
                (barrier / "first-attached.json").write_text(json.dumps({"argv": args}) + "\n")
            return result.returncode
        if fault["second"] not in args:
            os.execv(command[0], command)
        deadline = time.monotonic() + 60
        while not (barrier / "first-attached.json").exists():
            if time.monotonic() > deadline:
                return 73
            time.sleep(0.01)
        (barrier / "reached.json").write_text(json.dumps({"argv": args, "action": "fail_second"}) + "\n")
        while not (barrier / "continue").exists():
            if time.monotonic() > deadline:
                return 73
            time.sleep(0.01)
        print("owned second disk attach fault reached", file=sys.stderr)
        return 73
    if fault["action"] == "block_after":
        result = subprocess.run(command)
        if result.returncode:
            return result.returncode
    barrier = root / "artifacts" / "barriers" / fault["id"]
    barrier.mkdir(parents=True, exist_ok=True)
    (barrier / "reached.json").write_text(
        json.dumps({"argv": args, "pid": os.getpid(), "action": fault["action"]}) + "\n"
    )
    if fault["action"] in ("block", "block_after"):
        deadline = time.monotonic() + fault.get("timeout_seconds", 60)
        while not (barrier / "continue").exists():
            if time.monotonic() > deadline:
                print("owned verification barrier timed out", file=sys.stderr)
                return 73
            time.sleep(0.01)
        if fault["action"] == "block_after":
            return 0
        os.execv(command[0], command)
    if fault["action"] == "fail_after":
        result = subprocess.run(command)
        if result.returncode:
            return result.returncode
    elif fault["action"] != "fail":
        raise ValueError("unknown verification fault action")
    print("owned verification fault reached", file=sys.stderr)
    return 73


if __name__ == "__main__":
    sys.exit(main())
