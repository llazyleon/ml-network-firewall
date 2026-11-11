#!/usr/bin/env python3
"""
Enforcement engine, version 2.

Same interface as 11_firewall_enforcement_advanced.py, with the defects
found by tests/test_enforcement.py corrected:

  1. Re-blocking an IP that is already blocked extends its expiry instead of
     appending a second, duplicate DROP rule (which was never removed).
  2. Every address is validated before it reaches iptables: it must be one
     valid host address (no ranges such as 0.0.0.0/0), and loopback,
     unspecified, multicast and allow-listed addresses are refused.
  3. Expiry is written to the state file immediately, so an expired block
     does not reappear after a restart.
  4. On start-up, the kernel rule for every restored block is checked with
     `iptables -C` and re-applied if it is missing (e.g. after WSL restarts).
     Restored addresses are validated first, so a tampered state file cannot
     inject a rule such as 0.0.0.0/0.
  5. The state file is written atomically (temporary file, then rename), so
     a crash during a write cannot leave a half-written file.
"""
import ipaddress
import json
import os
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

IPTABLES_ERRORS = (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError)


class AdvancedFirewallEnforcer:

    def __init__(self, state_path='data/enforcement_state.json', allowlist=()):
        self.state_path = Path(state_path)
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        # Networks that must never be blocked (e.g. the gateway, the admin host)
        self.allowlist = [ipaddress.ip_network(n, strict=False) for n in allowlist]
        self.active_blocks = {}
        self.metrics = {'blocks': 0, 'expired': 0, 'iptables_errors': 0, 'rejected': 0}
        self._load_state()
        self._expire_old_blocks()
        self._resync_kernel_rules()

    # ----------------------------------------------------------- state
    def _load_state(self):
        if self.state_path.exists():
            try:
                with open(self.state_path, 'r') as f:
                    saved = json.load(f)
                self.metrics.update(saved.get('metrics', {}))
                # Re-validate every restored address: the state file is outside the
                # engine's control, and a tampered entry must never reach iptables.
                for ip, info in saved.get('active_blocks', {}).items():
                    try:
                        self.active_blocks[self._validate(ip)] = info
                    except ValueError as e:
                        self.metrics['rejected'] += 1
                        print(f"[Enforcer] Ignoring restored entry: {e}")
                print(f"[Enforcer] Restored {len(self.active_blocks)} active blocks from disk")
            except (json.JSONDecodeError, IOError):
                print("[Enforcer] Could not read prior state, starting fresh")

    def _save_state(self):
        tmp = self.state_path.with_suffix('.tmp')
        with open(tmp, 'w') as f:
            json.dump({'active_blocks': self.active_blocks, 'metrics': self.metrics}, f, indent=2)
        os.replace(tmp, self.state_path)

    # -------------------------------------------------------- iptables
    def _iptables(self, op, source_ip):
        subprocess.run(['sudo', 'iptables', op, 'INPUT', '-s', source_ip, '-j', 'DROP'],
                       check=True, capture_output=True, timeout=5)

    def _apply_iptables_block(self, source_ip):
        try:
            self._iptables('-A', source_ip)
            return True
        except IPTABLES_ERRORS as e:
            self.metrics['iptables_errors'] += 1
            print(f"[Enforcer] WARNING: could not apply iptables rule for {source_ip} ({e}). "
                  f"Block is still tracked in software.")
            return False

    def _remove_iptables_block(self, source_ip):
        try:
            self._iptables('-D', source_ip)
        except IPTABLES_ERRORS:
            pass  # rule already gone or iptables unavailable - non-fatal

    def _rule_present(self, source_ip):
        try:
            self._iptables('-C', source_ip)
            return True
        except IPTABLES_ERRORS:
            return False

    def _resync_kernel_rules(self):
        for ip in self.active_blocks:
            if not self._rule_present(ip):
                self._apply_iptables_block(ip)

    # ------------------------------------------------------ validation
    def _validate(self, source_ip):
        """Return the normalised address, or raise ValueError if it must not be blocked."""
        try:
            addr = ipaddress.ip_address(str(source_ip).strip())
        except ValueError:
            raise ValueError(f"not a single valid host address: {source_ip!r}")
        if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
            raise ValueError(f"refusing to block protected address {addr}")
        if any(addr in net for net in self.allowlist):
            raise ValueError(f"refusing to block allow-listed address {addr}")
        return str(addr)

    # ----------------------------------------------------------- logic
    def _expire_old_blocks(self):
        now = datetime.now()
        expired_ips = [ip for ip, info in self.active_blocks.items()
                       if datetime.fromisoformat(info['expires_at']) <= now]
        for ip in expired_ips:
            self._remove_iptables_block(ip)
            del self.active_blocks[ip]
            self.metrics['expired'] += 1
        if expired_ips:
            self._save_state()

    def block_attack(self, source_ip, confidence, flow_id, attack_type, ttl_hours=24):
        """Block source_ip. Returns True if blocked, False if the address was refused."""
        self._expire_old_blocks()
        try:
            ip = self._validate(source_ip)
        except ValueError as e:
            self.metrics['rejected'] += 1
            print(f"[Enforcer] {e}")
            return False

        already_blocked = ip in self.active_blocks
        self.active_blocks[ip] = {
            'expires_at': (datetime.now() + timedelta(hours=ttl_hours)).isoformat(),
            'attack_type': attack_type,
            'confidence': confidence,
            'flow_id': flow_id,
            'blocked_at': datetime.now().isoformat(),
        }
        if not already_blocked:          # re-detection only extends the expiry
            self._apply_iptables_block(ip)
            self.metrics['blocks'] += 1
        self._save_state()
        return True

    def get_status(self):
        self._expire_old_blocks()
        return {'active_blocks': list(self.active_blocks.keys()), 'metrics': self.metrics}

    def export_report(self, path='firewall_report.json'):
        self._expire_old_blocks()
        report = {'generated_at': datetime.now().isoformat(),
                  'active_blocks': self.active_blocks,
                  'metrics': self.metrics}
        with open(path, 'w') as f:
            json.dump(report, f, indent=2)
        return report
