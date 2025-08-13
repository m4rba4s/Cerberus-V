import os
import sys
from pathlib import Path

from fastapi.testclient import TestClient


def _import_app():
    repo_root = Path(__file__).resolve().parents[2]
    backend_dir = repo_root / "gui" / "backend"
    sys.path.insert(0, str(backend_dir))
    from main import app  # type: ignore

    return app


app = _import_app()
client = TestClient(app)


def test_system_status_schema():
    r = client.get("/api/system/status")
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body.get("running"), bool)
    assert "interface" in body
    assert "programs" in body
    assert isinstance(body["programs"], list)


def test_network_interfaces_endpoint():
    r = client.get("/api/network/interfaces")
    assert r.status_code == 200
    body = r.json()
    assert "interfaces" in body
    assert isinstance(body["interfaces"], list)
    # recommended may be empty on minimal envs, but key should exist
    assert "recommended" in body


def test_settings_roundtrip_and_start_stop():
    # get recommended interface (fallback to first or 'lo')
    r_if = client.get("/api/network/interfaces")
    assert r_if.status_code == 200
    interfaces = r_if.json().get("interfaces", [])
    rec = r_if.json().get("recommended") or {}
    iface = rec.get("name") or (interfaces[0]["name"] if interfaces else "lo")

    # fetch current settings
    r0 = client.get("/api/settings")
    assert r0.status_code == 200
    cfg = r0.json().get("config", {}) if "config" in r0.json() else r0.json()
    assert isinstance(cfg, dict)

    # update ebpf.interface
    new_cfg = cfg.copy()
    ebpf = dict(new_cfg.get("ebpf", {}))
    ebpf.update({"interface": iface, "enabled": True})
    new_cfg["ebpf"] = ebpf
    r1 = client.post("/api/settings", json=new_cfg)
    assert r1.status_code == 200

    # start engine
    r2 = client.post("/api/system/start", json={})
    assert r2.status_code == 200

    # verify status reflects interface and running
    r3 = client.get("/api/system/status")
    assert r3.status_code == 200
    body = r3.json()
    assert body.get("running") is True
    assert body.get("interface") == iface
    assert body.get("programs") and body["programs"][0].get("interface") == iface

    # stop engine
    r4 = client.post("/api/system/stop", json={})
    assert r4.status_code == 200
    r5 = client.get("/api/system/status")
    assert r5.status_code == 200
    assert r5.json().get("running") is False


