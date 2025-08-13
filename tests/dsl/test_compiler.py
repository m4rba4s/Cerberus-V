import json
from pathlib import Path

from dsl.compiler.dsl_compiler import compile_to_plan


def test_compile_minimal_policy(tmp_path: Path):
    spec = {
        "version": 1,
        "zones": {"web": ["10.0.1.0/24"]},
        "services": {"https": {"proto": "tcp", "ports": [443]}},
        "policy": [
            {"id": "web_to_world_https", "from": "web", "to": "any", "service": "https", "action": "allow", "priority": 100},
            {"id": "default_drop", "action": "drop", "priority": 65535},
        ],
    }
    plan = compile_to_plan(spec)
    assert "lpm_tries" in plan and "vpp_acl" in plan
    assert plan["lpm_tries"]["src"] == ["10.0.1.0/24"]
    rules = {r["id"] for r in plan["vpp_acl"]}
    assert "web_to_world_https" in rules and "default_drop" in rules


