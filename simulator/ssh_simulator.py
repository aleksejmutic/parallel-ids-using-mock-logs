"""
SSH traffic simulator.
Generates realistic auth.log lines for various scenarios —
both normal background traffic and attack patterns.

Usage:
    python simulator.py                        # run all scenarios in sequence
    python simulator.py --scenario brute_force # run one specific scenario
    python simulator.py --mode background      # run continuous background noise
    python simulator.py --list                 # list available scenarios
"""

import argparse
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

# Make sure shared/ and storage/ are importable
from normalizer.ssh_normalizer import SSHNormalizer
from event_streaming.producer import send_event


# ── Helpers ───────────────────────────────────────────────────────────────────

normalizer = SSHNormalizer()

# Realistic pool of IPs, usernames, hostnames
ATTACKER_IPS  = [f"10.0.0.{i}" for i in range(2, 20)]
LEGIT_IPS     = [f"192.168.1.{i}" for i in range(10, 30)]
USERNAMES     = ["root", "admin", "ubuntu", "pi", "oracle", "test", "guest",
                 "deploy", "git", "postgres", "mysql", "redis", "hadoop"]
LEGIT_USERS   = ["alice", "bob", "carol", "dave"]
HOSTS         = ["web-01", "web-02", "db-01", "bastion"]

def _now() -> str:
    return datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")

def _emit(line: str, host: str, scenario_id: str, delay: float = 0.0):
    """Parse a raw log line, persist to SQLite, and print to console."""
    if delay:
        time.sleep(delay)
    full_line = f"{_now()} {host} {line}"
    event = normalizer.parse(full_line, source_host=host, scenario_id=scenario_id)
    if event:
        send_event(event)
        tag = f"[{scenario_id}]" if scenario_id else "[live]"
        print(f"{tag} {event.event_type:<22} {event.source_ip:<16} {full_line.split('sshd')[-1].strip()[:70]}")
    else:
        print(f"[unparsed] {full_line}")


# ── Scenario implementations ──────────────────────────────────────────────────

def scenario_normal_background(count: int = 20, scenario_id: str = "background"):
    """
    Steady normal traffic: legit logins, occasional wrong password,
    clean disconnects. This trains the anomaly detector's baseline.
    """
    print(f"\n── Normal background traffic ({count} events) ──")
    host = random.choice(HOSTS)

    for _ in range(count):
        ip   = random.choice(LEGIT_IPS)
        user = random.choice(LEGIT_USERS)
        port = random.randint(49152, 65535)

        action = random.choices(
            ["success", "fail", "disconnect"],
            weights=[60, 25, 15]
        )[0]

        if action == "success":
            method = random.choice(["password", "publickey"])
            _emit(f"sshd[{random.randint(1000,9999)}]: Accepted {method} for {user} from {ip} port {port} ssh2",
                  host, scenario_id, delay=random.uniform(0.1, 0.4))

        elif action == "fail":
            _emit(f"sshd[{random.randint(1000,9999)}]: Failed password for {user} from {ip} port {port} ssh2",
                  host, scenario_id, delay=random.uniform(0.1, 0.3))

        else:
            _emit(f"sshd[{random.randint(1000,9999)}]: Disconnected from {ip} port {port} [preauth]",
                  host, scenario_id, delay=random.uniform(0.05, 0.2))


def scenario_brute_force(scenario_id: str = "brute_force"):
    """
    Classic brute force: one attacker IP, rapid repeated failures
    against a single username, then a success.
    Should trigger: BRUTE_FORCE alert within the 60s window.
    """
    print("\n── Brute force attack ──")
    attacker_ip = random.choice(ATTACKER_IPS)
    host        = random.choice(HOSTS)
    pid         = random.randint(1000, 9999)
    target_user = "root"

    # 12 rapid failures
    for i in range(12):
        port = random.randint(49152, 65535)
        _emit(f"sshd[{pid}]: Failed password for {target_user} from {attacker_ip} port {port} ssh2",
              host, scenario_id, delay=random.uniform(0.1, 0.5))

    # Server-side detection kicks in
    port = random.randint(49152, 65535)
    _emit(f"sshd[{pid}]: Too many authentication failures for {target_user} from {attacker_ip} port {port} ssh2",
          host, scenario_id, delay=0.2)

    # Attacker finally gets in (or simulates it)
    _emit(f"sshd[{pid}]: Accepted password for {target_user} from {attacker_ip} port {port} ssh2",
          host, scenario_id, delay=0.3)


def scenario_distributed_brute_force(scenario_id: str = "distributed_brute_force"):
    """
    Distributed attack: many different IPs, each sending only 1-2 attempts.
    Harder to detect — individual IPs stay under the simple threshold.
    Should eventually trigger: DISTRIBUTED_ATTACK alert.
    """
    print("\n── Distributed brute force (low-and-slow) ──")
    host    = random.choice(HOSTS)
    ips     = random.sample(ATTACKER_IPS, 10)
    users   = ["root", "admin", "ubuntu"]

    for ip in ips:
        attempts = random.randint(1, 3)
        user     = random.choice(users)
        for _ in range(attempts):
            port = random.randint(49152, 65535)
            _emit(f"sshd[{random.randint(1000,9999)}]: Failed password for {user} from {ip} port {port} ssh2",
                  host, scenario_id, delay=random.uniform(0.3, 1.2))


def scenario_invalid_user_scan(scenario_id: str = "invalid_user_scan"):
    """
    Attacker probing for valid usernames by trying many non-existent ones.
    Should trigger: AUTH_INVALID_USER spike alert.
    """
    print("\n── Invalid user enumeration ──")
    attacker_ip = random.choice(ATTACKER_IPS)
    host        = random.choice(HOSTS)
    fake_users  = ["deploy", "jenkins", "nagios", "zabbix", "postgres",
                   "tomcat", "hadoop", "spark", "elastic", "kibana",
                   "vagrant", "ansible", "puppet", "chef", "www-data"]

    for user in fake_users:
        port = random.randint(49152, 65535)
        _emit(f"sshd[{random.randint(1000,9999)}]: Invalid user {user} from {attacker_ip} port {port}",
              host, scenario_id, delay=random.uniform(0.1, 0.4))

        # SSH also logs a Failed password line for invalid users
        _emit(f"sshd[{random.randint(1000,9999)}]: Failed password for invalid user {user} "
              f"from {attacker_ip} port {port} ssh2",
              host, scenario_id, delay=0.05)


def scenario_credential_stuffing(scenario_id: str = "credential_stuffing"):
    """
    Credential stuffing: known username/password combos from a breach list.
    Moderate speed, real-looking usernames only.
    Should trigger: BRUTE_FORCE + CREDENTIAL_STUFFING alert.
    """
    print("\n── Credential stuffing ──")
    attacker_ip = random.choice(ATTACKER_IPS)
    host        = random.choice(HOSTS)
    # Realistic breached credentials (username only shown in logs)
    breached_users = ["alice", "bob", "john.doe", "jane.smith", "admin",
                      "carol", "dave", "eve", "frank", "grace"]

    for user in breached_users:
        port = random.randint(49152, 65535)
        # Most fail
        if random.random() < 0.85:
            _emit(f"sshd[{random.randint(1000,9999)}]: Failed password for {user} from {attacker_ip} port {port} ssh2",
                  host, scenario_id, delay=random.uniform(0.5, 1.5))
        else:
            _emit(f"sshd[{random.randint(1000,9999)}]: Accepted password for {user} from {attacker_ip} port {port} ssh2",
                  host, scenario_id, delay=random.uniform(0.5, 1.5))


def scenario_port_scanner_probe(scenario_id: str = "port_scanner_probe"):
    """
    Port scanner hitting the SSH port with malformed/incomplete connections.
    Many connection attempts, instant drops, bad packets.
    """
    print("\n── Port scanner / SSH probe ──")
    attacker_ip = random.choice(ATTACKER_IPS)
    host        = random.choice(HOSTS)

    for _ in range(20):
        port = random.randint(1024, 65535)
        msg_type = random.choices(
            ["connection", "bad_packet", "no_ident"],
            weights=[40, 35, 25]
        )[0]

        if msg_type == "connection":
            _emit(f"sshd[{random.randint(1000,9999)}]: Connection from {attacker_ip} port {port} on 0.0.0.0 port 22",
                  host, scenario_id, delay=random.uniform(0.05, 0.15))
            _emit(f"sshd[{random.randint(1000,9999)}]: Connection closed by {attacker_ip} port {port} [preauth]",
                  host, scenario_id, delay=0.05)

        elif msg_type == "bad_packet":
            _emit(f"sshd[{random.randint(1000,9999)}]: Bad packet length 1349676916 from {attacker_ip}",
                  host, scenario_id, delay=random.uniform(0.05, 0.15))

        else:
            _emit(f"sshd[{random.randint(1000,9999)}]: Did not receive identification string from {attacker_ip} port {port}",
                  host, scenario_id, delay=random.uniform(0.05, 0.15))


def scenario_slow_and_low(scenario_id: str = "slow_and_low"):
    """
    Sophisticated attacker: very slow, only 1 attempt every few seconds,
    randomized usernames. Designed to stay under simple rate thresholds.
    Tests whether the time-window engine catches slow attacks.
    """
    print("\n── Slow-and-low attack (designed to evade simple rules) ──")
    attacker_ip = random.choice(ATTACKER_IPS)
    host        = random.choice(HOSTS)
    users       = ["root", "admin", "ubuntu", "pi", "git", "deploy"]

    for user in users:
        port = random.randint(49152, 65535)
        _emit(f"sshd[{random.randint(1000,9999)}]: Failed password for {user} from {attacker_ip} port {port} ssh2",
              host, scenario_id, delay=random.uniform(2.0, 4.0))  # very slow


# ── Scenario registry ─────────────────────────────────────────────────────────

SCENARIOS: dict[str, Callable] = {
    "background":             scenario_normal_background,
    "brute_force":            scenario_brute_force,
    "distributed_brute":      scenario_distributed_brute_force,
    "invalid_user_scan":      scenario_invalid_user_scan,
    "credential_stuffing":    scenario_credential_stuffing,
    "port_scanner":           scenario_port_scanner_probe,
    "slow_and_low":           scenario_slow_and_low,
}


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="IDS SSH traffic simulator")
    parser.add_argument("--scenario", choices=list(SCENARIOS.keys()),
                        help="Run a specific scenario")
    parser.add_argument("--mode", choices=["background", "all", "attacks"],
                        default="all", help="Run mode")
    parser.add_argument("--list", action="store_true",
                        help="List available scenarios and exit")
    args = parser.parse_args()

    if args.list:
        print("Available scenarios:")
        for name, fn in SCENARIOS.items():
            print(f"  {name:<30} {fn.__doc__.strip().splitlines()[0]}")
        return

    print("[simulator] Starting — sending events to Kafka.\n")

    if args.scenario:
        SCENARIOS[args.scenario]()

    elif args.mode == "background":
        print("Running continuous background traffic. Press Ctrl+C to stop.")
        try:
            while True:
                scenario_normal_background(count=10)
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[simulator] Stopped.")

    elif args.mode == "attacks":
        # Run all attack scenarios without background
        for name, fn in SCENARIOS.items():
            if name != "background":
                fn()
                time.sleep(1)

    else:
        # Full demo: background noise, then each attack
        scenario_normal_background(count=15)
        time.sleep(0.5)
        for name, fn in SCENARIOS.items():
            if name != "background":
                fn()
                time.sleep(0.5)

    print("\n[simulator] Done. Run the detector next to see what was caught.")


if __name__ == "__main__":
    main()
