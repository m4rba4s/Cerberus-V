#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""
Very small iptables-save importer → DSL v1 (best-effort 80%).
Parses simple -A INPUT/OUTPUT with -s/-d/-p/--dport and translates to policy entries.
"""

from __future__ import annotations
import re
import sys
import json
from typing import Any, Dict, List

RULE_RE = re.compile(r"^-A\s+(?P<chain>\S+)\s+(?P<body>.*)$")
SRC_RE = re.compile(r"-s\s+(?P<src>\S+)")
DST_RE = re.compile(r"-d\s+(?P<dst>\S+)")
PROTO_RE = re.compile(r"-p\s+(?P<proto>tcp|udp|icmp)")
DPORT_RE = re.compile(r"--dport\s+(?P<dport>\d+)")
TARGET_RE = re.compile(r"-j\s+(?P<target>ACCEPT|DROP|REJECT)")


def parse_line(line: str) -> Dict[str, Any] | None:
    m = RULE_RE.match(line.strip())
    if not m:
        return None
    body = m.group("body")
    chain = m.group("chain")
    src = SRC_RE.search(body)
    dst = DST_RE.search(body)
    proto = PROTO_RE.search(body)
    dport = DPORT_RE.search(body)
    target = TARGET_RE.search(body)
    action = {"ACCEPT": "allow", "DROP": "drop", "REJECT": "drop"}.get(
        target.group("target") if target else "ACCEPT", "allow"
    )
    return {
        "chain": chain,
        "src": src.group("src") if src else "any",
        "dst": dst.group("dst") if dst else "any",
        "proto": proto.group("proto") if proto else "any",
        "dport": int(dport.group("dport")) if dport else None,
        "action": action,
    }


def to_dsl(rules: List[Dict[str, Any]]) -> Dict[str, Any]:
    policy = []
    prio = 100
    for idx, r in enumerate(rules, start=1):
        entry = {
            "id": f"ipt_{idx}",
            "action": r["action"],
            "priority": prio + idx,
            "proto": r["proto"],
            "src": r["src"],
            "dst": r["dst"],
        }
        if r.get("dport") is not None:
            entry["service"] = {"proto": r["proto"], "ports": [r["dport"]]}
        policy.append(entry)
    # default drop
    policy.append({"id": "default_drop", "action": "drop", "priority": 65535})
    return {"version": 1, "policy": policy}


def main(argv: List[str]) -> int:
    if len(argv) < 2:
        print("Usage: iptables_import.py <rules.v4>")
        return 2
    with open(argv[1], "r") as f:
        parsed = [p for line in f if (p := parse_line(line))]
    dsl = to_dsl(parsed)
    print(json.dumps(dsl, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))


