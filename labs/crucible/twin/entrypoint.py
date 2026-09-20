#!/usr/bin/env python3
"""Render a twin specification into running services, inside the container.

    entrypoint.py run           read /twin/spec.json, start what it says
    entrypoint.py reconfigure   re-read it and restart, after a fix is applied

Deliberately small and readable: this file is part of the evidence. Someone
asking "what exactly did you boot?" should be able to answer it from here in a
couple of minutes.
"""

from __future__ import annotations

import json
import os
import pathlib
import signal
import subprocess
import sys
import time

SPEC = pathlib.Path("/twin/spec.json")
MANAGEMENT_PORTS = (22, 23, 80, 161)


def load() -> dict:
    if not SPEC.exists():
        print("no /twin/spec.json: refusing to guess at a posture", file=sys.stderr)
        raise SystemExit(2)
    return json.loads(SPEC.read_text())


def run(command: list[str], check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(command, check=check, capture_output=True, text=True)


def stop_everything() -> None:
    """Stop every service this twin runs, by reading /proc.

    Not pkill: BusyBox's pkill does not match these processes by name the way
    the GNU one does, and a fix that silently fails to stop a service would
    make the whole verification worthless - the re-test would report a finding
    still open when the fix was never applied.
    """
    wanted = {"sshd", "telnetd", "httpd", "snmpd"}
    for entry in pathlib.Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            comm = (entry / "comm").read_text().strip()
        except OSError:
            continue
        if comm in wanted:
            try:
                os.kill(int(entry.name), signal.SIGKILL)
            except (OSError, ValueError):
                pass
    run(["iptables", "-F", "INPUT"])
    time.sleep(0.3)


def start_ssh(spec: dict) -> None:
    if not spec.get("ssh"):
        return
    kex = ",".join(spec.get("ssh_kex") or []) or "curve25519-sha256"
    ciphers = ",".join(spec.get("ssh_ciphers") or []) or "aes256-gcm@openssh.com"
    config = pathlib.Path("/etc/ssh/sshd_config")
    config.write_text(
        "Port 22\n"
        "PermitRootLogin no\n"
        "UsePAM no\n"
        "PasswordAuthentication yes\n"
        f"KexAlgorithms {kex}\n"
        f"Ciphers {ciphers}\n"
        "HostKeyAlgorithms +ssh-rsa\n"
        "PubkeyAcceptedAlgorithms +ssh-rsa\n"
    )
    run(["/usr/sbin/sshd", "-f", "/etc/ssh/sshd_config"])


def start_telnet(spec: dict) -> None:
    if spec.get("telnet"):
        run(["/usr/sbin/telnetd", "-l", "/bin/login", "-p", "23"])


def start_http(spec: dict) -> None:
    if not spec.get("http"):
        return
    root = pathlib.Path("/twin/www")
    root.mkdir(parents=True, exist_ok=True)
    (root / "index.html").write_text(
        f"<html><title>{spec.get('hostname', 'twin')} management</title>"
        "<body><h1>Device management</h1><p>Unencrypted management interface.</p>"
        "</body></html>\n"
    )
    run(["/usr/sbin/httpd", "-h", str(root), "-p", "80"])


def start_snmp(spec: dict) -> None:
    communities = spec.get("snmp_communities") or []
    if not communities:
        return
    config = pathlib.Path("/etc/snmp/snmpd.conf")
    config.parent.mkdir(parents=True, exist_ok=True)
    body = [
        "sysLocation crucible-sandbox",
        "sysContact none",
        f"sysDescr {spec.get('hostname', 'twin')} crucible twin",
    ]
    for community in communities:
        body.append(f"rocommunity {community} default")
    config.write_text("\n".join(body) + "\n")
    run(["/usr/sbin/snmpd", "-c", str(config), "-Lf", "/dev/null", "udp:161"])


def apply_filter(spec: dict) -> None:
    """The management ACL, as packet filter rules.

    Empty means no restriction, which is exactly what a device with no
    management ACL looks like from the network.
    """
    allow = spec.get("mgmt_allow") or []
    if not allow:
        return
    run(["iptables", "-F", "INPUT"])
    run(["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])
    run(["iptables", "-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
    for prefix in allow:
        for port in MANAGEMENT_PORTS:
            run(["iptables", "-A", "INPUT", "-s", prefix, "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"])
            run(["iptables", "-A", "INPUT", "-s", prefix, "-p", "udp", "--dport", str(port), "-j", "ACCEPT"])
    for port in MANAGEMENT_PORTS:
        run(["iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "REJECT"])
        run(["iptables", "-A", "INPUT", "-p", "udp", "--dport", str(port), "-j", "REJECT"])


def configure() -> dict:
    spec = load()
    stop_everything()
    start_ssh(spec)
    start_telnet(spec)
    start_http(spec)
    start_snmp(spec)
    apply_filter(spec)
    listening = run(["netstat", "-ltnu"]).stdout
    print(json.dumps({"configured": spec, "listening": listening}), flush=True)
    return spec


def main() -> int:
    action = sys.argv[1] if len(sys.argv) > 1 else "run"
    if action in ("run", "reconfigure"):
        configure()
        if action == "reconfigure":
            return 0
        signal.signal(signal.SIGTERM, lambda *_: os._exit(0))
        while True:
            time.sleep(3600)
    print(f"unknown action {action}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
