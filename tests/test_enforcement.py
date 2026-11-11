#!/usr/bin/env python3
"""
Test suite for the enforcement engine (AdvancedFirewallEnforcer).

Two groups of tests:
  * Unit tests (U01-U14): iptables is replaced by a mock that records every
    command, so these run anywhere, without sudo, and never touch the real
    firewall.
  * Integration tests (I01-I03): use the real iptables on this machine.
    They only run when RUN_IPTABLES_TESTS=1 is set, and only ever block
    203.0.113.77, an address from the TEST-NET-3 range reserved for
    documentation (RFC 5737), so no real host can be affected.

Which enforcement module is tested is chosen with ENFORCER_MODULE
(default: src/11_firewall_enforcement_advanced.py).

Run from the project root:
  venv/bin/python3 -m pytest tests/test_enforcement.py -v
  RUN_IPTABLES_TESTS=1 venv/bin/python3 -m pytest tests/test_enforcement.py -v
"""
import importlib.util
import json
import os
import subprocess
from pathlib import Path

import pytest

MODULE_PATH = Path(os.environ.get("ENFORCER_MODULE",
                                  "src/11_firewall_enforcement_advanced.py"))
TEST_IP = "203.0.113.77"


def load_module():
    spec = importlib.util.spec_from_file_location("enforcer_under_test", MODULE_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


enf_mod = load_module()
Enforcer = enf_mod.AdvancedFirewallEnforcer


# --------------------------------------------------------------------------
# Fake iptables: simulates the kernel rule table so tests can check what
# rules would really be left behind, not just which commands were issued.
# --------------------------------------------------------------------------
class FakeIptables:
    def __init__(self):
        self.calls = []        # every iptables argument list, in order
        self.rules = []        # the simulated INPUT chain (list of source IPs)
        self.fail_with = None  # exception to raise on -A, to simulate failures

    def __call__(self, cmd, **kwargs):
        args = cmd[1:] if cmd[0] == "sudo" else cmd
        self.calls.append(args)
        op, ip = args[1], args[4]
        if op == "-A":
            if self.fail_with is not None:
                raise self.fail_with
            self.rules.append(ip)
        elif op == "-D":
            if ip not in self.rules:
                raise subprocess.CalledProcessError(1, cmd)
            self.rules.remove(ip)
        elif op == "-C":
            if ip not in self.rules:
                raise subprocess.CalledProcessError(1, cmd)
        return subprocess.CompletedProcess(cmd, 0, b"", b"")

    def ops(self, op):
        return [a for a in self.calls if a[1] == op]


@pytest.fixture
def fake(monkeypatch):
    f = FakeIptables()
    monkeypatch.setattr(enf_mod.subprocess, "run", f)
    return f


@pytest.fixture
def state(tmp_path):
    return tmp_path / "enforcement_state.json"


def expire_all(enforcer):
    """Move every active block's expiry into the past."""
    for info in enforcer.active_blocks.values():
        info["expires_at"] = "2000-01-01T00:00:00"


# ---------------------------- Unit tests ----------------------------------

def test_U01_block_applies_drop_rule(fake, state):
    e = Enforcer(state_path=state)
    e.block_attack(TEST_IP, 0.98, "f1", "DDoS")
    assert ["iptables", "-A", "INPUT", "-s", TEST_IP, "-j", "DROP"] in fake.calls
    assert fake.rules == [TEST_IP]


def test_U02_block_is_tracked_with_details(fake, state):
    e = Enforcer(state_path=state)
    e.block_attack(TEST_IP, 0.98, "f1", "DDoS")
    info = e.active_blocks[TEST_IP]
    assert info["attack_type"] == "DDoS"
    assert info["confidence"] == 0.98
    assert TEST_IP in e.get_status()["active_blocks"]


def test_U03_metrics_count_blocks(fake, state):
    e = Enforcer(state_path=state)
    e.block_attack("203.0.113.1", 0.9, "f1", "DDoS")
    e.block_attack("203.0.113.2", 0.9, "f2", "PortScan")
    assert e.metrics["blocks"] == 2


def test_U04_state_survives_restart(fake, state):
    Enforcer(state_path=state).block_attack(TEST_IP, 0.9, "f1", "DDoS")
    restarted = Enforcer(state_path=state)
    assert TEST_IP in restarted.active_blocks
    assert restarted.metrics["blocks"] == 1


def test_U05_unexpired_block_is_kept(fake, state):
    e = Enforcer(state_path=state)
    e.block_attack(TEST_IP, 0.9, "f1", "DDoS", ttl_hours=24)
    e.get_status()
    assert TEST_IP in e.active_blocks
    assert fake.rules == [TEST_IP]


def test_U06_expired_block_is_removed(fake, state):
    e = Enforcer(state_path=state)
    e.block_attack(TEST_IP, 0.9, "f1", "DDoS")
    expire_all(e)
    status = e.get_status()
    assert TEST_IP not in status["active_blocks"]
    assert e.metrics["expired"] == 1
    assert fake.rules == []


@pytest.mark.parametrize("error", [
    subprocess.CalledProcessError(1, "iptables"),
    subprocess.TimeoutExpired("iptables", 5),
    FileNotFoundError("iptables"),
], ids=["iptables-error", "timeout", "iptables-missing"])
def test_U07_iptables_failure_does_not_crash(fake, state, error):
    fake.fail_with = error
    e = Enforcer(state_path=state)
    e.block_attack(TEST_IP, 0.9, "f1", "DDoS")   # must not raise
    assert TEST_IP in e.active_blocks
    assert e.metrics["iptables_errors"] == 1


def test_U08_corrupt_state_file_starts_fresh(fake, state):
    state.write_text("{ this is not valid json")
    e = Enforcer(state_path=state)
    assert e.active_blocks == {}


def test_U09_report_export(fake, state, tmp_path):
    e = Enforcer(state_path=state)
    e.block_attack(TEST_IP, 0.9, "f1", "DDoS")
    out = tmp_path / "report.json"
    e.export_report(path=out)
    report = json.loads(out.read_text())
    assert TEST_IP in report["active_blocks"]


# --- Tests for behaviour the design requires but the code may not handle ---

def test_U10_reblocking_same_ip_leaves_no_stale_rule(fake, state):
    """An IP detected twice must not leave a DROP rule behind after expiry."""
    e = Enforcer(state_path=state)
    e.block_attack(TEST_IP, 0.9, "f1", "DDoS")
    e.block_attack(TEST_IP, 0.9, "f2", "DDoS")
    expire_all(e)
    e.get_status()
    assert fake.rules == [], f"stale DROP rules left in the kernel: {fake.rules}"


def test_U11_expiry_is_persisted(fake, state):
    """A block that expired must not come back, or be counted again, after a restart."""
    e = Enforcer(state_path=state)
    e.block_attack(TEST_IP, 0.9, "f1", "DDoS")
    expire_all(e)
    e._save_state()            # expired entry is on disk, as after a normal run
    e.get_status()             # expiry happens here
    saved = json.loads(state.read_text())
    assert TEST_IP not in saved["active_blocks"], "expired block is still in the state file"
    assert saved["metrics"]["expired"] == 1


@pytest.mark.parametrize("bad", ["not-an-ip", "0.0.0.0/0", "203.0.113.0/24", ""])
def test_U12_invalid_address_is_rejected(fake, state, bad):
    """Only a single valid host address may ever reach iptables."""
    e = Enforcer(state_path=state)
    try:
        e.block_attack(bad, 0.9, "f1", "DDoS")
    except ValueError:
        pass
    assert fake.ops("-A") == [], f"iptables was asked to block {bad!r}"


@pytest.mark.parametrize("protected", ["127.0.0.1", "0.0.0.0", "::1"])
def test_U13_protected_address_is_never_blocked(fake, state, protected):
    """Loopback / unspecified addresses must never be blocked."""
    e = Enforcer(state_path=state)
    try:
        e.block_attack(protected, 0.9, "f1", "DDoS")
    except ValueError:
        pass
    assert fake.ops("-A") == []


def test_U14_kernel_rules_restored_after_restart(fake, state):
    """If the kernel rules were lost (e.g. WSL restarted), they must be re-applied."""
    Enforcer(state_path=state).block_attack(TEST_IP, 0.9, "f1", "DDoS")
    fake.rules.clear()                      # simulate a reboot wiping iptables
    Enforcer(state_path=state)
    assert fake.rules == [TEST_IP]


def test_U15_tampered_state_file_cannot_inject_rule(fake, state):
    """An address planted in the state file must be validated before use."""
    state.write_text(json.dumps({
        "active_blocks": {"0.0.0.0/0": {"expires_at": "2999-01-01T00:00:00",
                                        "attack_type": "DDoS", "confidence": 1.0,
                                        "flow_id": "x", "blocked_at": "2026-01-01T00:00:00"}},
        "metrics": {"blocks": 1, "expired": 0, "iptables_errors": 0}}))
    e = Enforcer(state_path=state)
    e.get_status()
    assert fake.ops("-A") == [], "a planted address reached iptables"


# ------------------------- Integration tests ------------------------------

real = pytest.mark.skipif(os.environ.get("RUN_IPTABLES_TESTS") != "1",
                          reason="set RUN_IPTABLES_TESTS=1 to test real iptables")


def rule_exists(ip):
    r = subprocess.run(["sudo", "-n", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                       capture_output=True)
    return r.returncode == 0


def count_rules(ip):
    r = subprocess.run(["sudo", "-n", "iptables", "-S", "INPUT"],
                       capture_output=True, text=True, check=True)
    return sum(1 for line in r.stdout.splitlines() if f"-s {ip}/32" in line and "DROP" in line)


@pytest.fixture
def clean_real():
    def cleanup():
        while rule_exists(TEST_IP):
            subprocess.run(["sudo", "-n", "iptables", "-D", "INPUT", "-s", TEST_IP, "-j", "DROP"],
                           capture_output=True)
    cleanup()
    yield
    cleanup()


@real
def test_I01_real_block_creates_kernel_rule(clean_real, state):
    e = Enforcer(state_path=state)
    e.block_attack(TEST_IP, 0.9, "f1", "DDoS")
    assert rule_exists(TEST_IP)
    assert count_rules(TEST_IP) == 1


@real
def test_I02_real_expiry_removes_kernel_rule(clean_real, state):
    e = Enforcer(state_path=state)
    e.block_attack(TEST_IP, 0.9, "f1", "DDoS")
    expire_all(e)
    e.get_status()
    assert not rule_exists(TEST_IP)


@real
def test_I03_real_reblock_leaves_no_stale_rule(clean_real, state):
    e = Enforcer(state_path=state)
    e.block_attack(TEST_IP, 0.9, "f1", "DDoS")
    e.block_attack(TEST_IP, 0.9, "f2", "DDoS")
    expire_all(e)
    e.get_status()
    assert count_rules(TEST_IP) == 0, f"{count_rules(TEST_IP)} DROP rule(s) left in the kernel"
