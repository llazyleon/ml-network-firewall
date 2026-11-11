#!/usr/bin/env python3
import json
import subprocess
import time
from datetime import datetime, timedelta
from pathlib import Path


class AdvancedFirewallEnforcer:
    """
    Kernel-level enforcement engine. Translates a positive detection outcome
    into an iptables DROP rule for the offending source IP, with a
    time-to-live (TTL) after which the block automatically expires.

    iptables calls are guarded: in environments where iptables is unavailable
    or the process lacks permission (e.g. inside some WSL configurations
    without elevated privileges), the block is still tracked and reported
    correctly, but the actual kernel rule application is skipped with a
    warning rather than crashing the whole pipeline.
    """

    def __init__(self, state_path='data/enforcement_state.json'):
        self.state_path = Path(state_path)
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.active_blocks = {}   # ip -> {expires_at, attack_type, confidence, flow_id}
        self.metrics = {'blocks': 0, 'expired': 0, 'iptables_errors': 0}
        self._load_state()

    def _load_state(self):
        if self.state_path.exists():
            try:
                with open(self.state_path, 'r') as f:
                    saved = json.load(f)
                self.active_blocks = saved.get('active_blocks', {})
                self.metrics = saved.get('metrics', self.metrics)
                print(f"[Enforcer] Restored {len(self.active_blocks)} active blocks from disk")
            except (json.JSONDecodeError, IOError):
                print("[Enforcer] Could not read prior state, starting fresh")

    def _save_state(self):
        with open(self.state_path, 'w') as f:
            json.dump({'active_blocks': self.active_blocks, 'metrics': self.metrics}, f, indent=2)

    def _apply_iptables_block(self, source_ip):
        try:
            subprocess.run(
                ['sudo', 'iptables', '-A', 'INPUT', '-s', source_ip, '-j', 'DROP'],
                check=True, capture_output=True, timeout=5
            )
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
            self.metrics['iptables_errors'] += 1
            print(f"[Enforcer] WARNING: could not apply iptables rule for {source_ip} ({e}). "
                  f"Block is still tracked in software.")
            return False

    def _remove_iptables_block(self, source_ip):
        try:
            subprocess.run(
                ['sudo', 'iptables', '-D', 'INPUT', '-s', source_ip, '-j', 'DROP'],
                check=True, capture_output=True, timeout=5
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            pass  # rule may already be gone or iptables unavailable - non-fatal

    def _expire_old_blocks(self):
        now = datetime.now()
        expired_ips = [
            ip for ip, info in self.active_blocks.items()
            if datetime.fromisoformat(info['expires_at']) <= now
        ]
        for ip in expired_ips:
            self._remove_iptables_block(ip)
            del self.active_blocks[ip]
            self.metrics['expired'] += 1

    def block_attack(self, source_ip, confidence, flow_id, attack_type, ttl_hours=24):
        self._expire_old_blocks()

        expires_at = datetime.now() + timedelta(hours=ttl_hours)
        self.active_blocks[source_ip] = {
            'expires_at': expires_at.isoformat(),
            'attack_type': attack_type,
            'confidence': confidence,
            'flow_id': flow_id,
            'blocked_at': datetime.now().isoformat(),
        }
        self._apply_iptables_block(source_ip)
        self.metrics['blocks'] += 1
        self._save_state()

    def get_status(self):
        self._expire_old_blocks()
        return {
            'active_blocks': list(self.active_blocks.keys()),
            'metrics': self.metrics,
        }

    def export_report(self, path='firewall_report.json'):
        self._expire_old_blocks()
        report = {
            'generated_at': datetime.now().isoformat(),
            'active_blocks': self.active_blocks,
            'metrics': self.metrics,
        }
        with open(path, 'w') as f:
            json.dump(report, f, indent=2)
        return report
