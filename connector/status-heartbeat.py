#!/usr/bin/env python3
"""Send host health from the connector VM using its existing ingest credential."""

import json
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path


ENV_FILE = Path("/home/mhomolog/PierV/connector/.env")
INDEXER_CA = Path("/home/mhomolog/PierV/connector/certs/indexer-ca.pem")
CONTAINER = "piervuln-wazuh-connector-1"


def environment():
    values = {}
    for line in ENV_FILE.read_text().splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"\'')
    return values


def command(*args):
    return subprocess.run(args, capture_output=True, text=True, timeout=12, check=False)


def memory_percent():
    fields = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, value = line.split(":", 1)
        fields[key] = int(value.strip().split()[0])
    return round(100 * (1 - fields["MemAvailable"] / fields["MemTotal"]), 1)


def main():
    env = environment()
    vpn = command("systemctl", "is-active", "--quiet", "openvpn-client@wazuh").returncode == 0
    connector = command("docker", "inspect", "--format", "{{.State.Running}}", CONTAINER).stdout.strip() == "true"
    route = command("ip", "route", "get", "192.168.100.111").stdout
    vpn = vpn and "tun0" in route
    indexer = command(
        "curl", "--silent", "--show-error", "--output", "/dev/null", "--max-time", "8",
        "--cacert", str(INDEXER_CA), "--write-out", "%{http_code} %{time_total}",
        env["WAZUH_INDEXER_URL"],
    )
    parts = indexer.stdout.strip().split()
    reachable = indexer.returncode == 0 and len(parts) == 2 and parts[0] in {"200", "401", "403"}
    latency = round(float(parts[1]) * 1000) if reachable else None
    total, used, free = shutil.disk_usage("/")
    payload = {
        "vpn_active": vpn,
        "indexer_reachable": reachable,
        "connector_active": connector,
        "uptime_seconds": int(float(Path("/proc/uptime").read_text().split()[0])),
        "load_percent": round(100 * os.getloadavg()[0] / (os.cpu_count() or 1), 1),
        "memory_percent": memory_percent(),
        "disk_percent": round(100 * used / total, 1),
        "indexer_latency_ms": latency,
    }
    request = urllib.request.Request(
        env["SUPABASE_URL"].rstrip("/") + "/functions/v1/connector-status",
        data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json",
            "apikey": env["SUPABASE_PUBLISHABLE_KEY"],
            "Authorization": "Bearer " + env["WAZUH_INGEST_TOKEN"],
            "x-connection-id": env["WAZUH_CONNECTION_ID"],
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        if response.status != 200:
            raise RuntimeError("Status endpoint rejected heartbeat")
    print("Status heartbeat sent")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired, urllib.error.URLError) as exc:
        print(f"Status heartbeat failed: {type(exc).__name__}", file=sys.stderr)
        sys.exit(1)
