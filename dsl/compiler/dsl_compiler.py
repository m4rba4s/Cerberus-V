#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""
Cerberus-V DSL Compiler (v1)
Input: YAML/JSON DSL
Output: materialized structures for eBPF (LPM tries) and VPP ACL entries

Minimal MVP: validate schema, resolve services/zones, build flat rule list with resolved fields.
"""

from __future__ import annotations
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

try:
    import yaml  # type: ignore
except Exception:
    yaml = None


def load_dsl(path: Path) -> Dict[str, Any]:
    text = path.read_text()
    if path.suffix in (".yaml", ".yml"):
        if not yaml:
            raise RuntimeError("PyYAML not installed")
        return yaml.safe_load(text)
    return json.loads(text)


def resolve_service(services: Dict[str, Any], ref: Any) -> Tuple[str, List[int]]:
    if isinstance(ref, str):
        s = services.get(ref, {})
        return s.get("proto", "any"), s.get("ports", [])
    if isinstance(ref, dict):
        return ref.get("proto", "any"), ref.get("ports", [])
    return "any", []


def compile_to_plan(spec: Dict[str, Any]) -> Dict[str, Any]:
    zones = spec.get("zones", {})
    services = spec.get("services", {})
    rules: List[Dict[str, Any]] = []

    for item in spec.get("policy", []):
        proto = item.get("proto")
        srcs = item.get("src") or item.get("from")
        dsts = item.get("dst") or item.get("to")
        sref = item.get("service")
        if sref and not proto:
            proto, ports = resolve_service(services, sref)
            item_ports = {"dst": ports}
        else:
            item_ports = {}

        def expand(endpoint):
            if endpoint is None:
                return ["any"]
            if isinstance(endpoint, str):
                return zones.get(endpoint, [endpoint]) if endpoint in zones else [endpoint]
            if isinstance(endpoint, list):
                out = []
                for e in endpoint:
                    out.extend(zones.get(e, [e]) if e in zones else [e])
                return out
            return ["any"]

        src_list = expand(srcs)
        dst_list = expand(dsts)

        rules.append(
            {
                "id": item.get("id"),
                "action": item.get("action", "allow"),
                "priority": item.get("priority", 100),
                "proto": proto or "any",
                "src": src_list,
                "dst": dst_list,
                "ports": item_ports,
            }
        )

    # Sort by priority asc (lower first)
    rules.sort(key=lambda r: r["priority"]) 

    plan = {
        "lpm_tries": {
            "src": sorted({p for r in rules for p in r["src"] if p != "any"}),
            "dst": sorted({p for r in rules for p in r["dst"] if p != "any"}),
        },
        "vpp_acl": [
            {
                "id": r["id"],
                "action": r["action"],
                "priority": r["priority"],
                "match": {"proto": r["proto"], "src": r["src"], "dst": r["dst"], "ports": r["ports"]},
            }
            for r in rules
        ],
    }
    return plan


def main(argv: List[str]) -> int:
    if len(argv) < 2:
        print("Usage: dsl_compiler.py <policy.{yaml|json}>")
        return 2
    spec = load_dsl(Path(argv[1]))
    plan = compile_to_plan(spec)
    print(json.dumps(plan, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))


