import json
import os
import subprocess
import time

SET_NAME = "bh_blocked"
JSON_PATH = "/app/json/blocked_ips.json"
SLEEP_SECONDS = 5


def _run(cmd: list[str]) -> int:
    """Run a command and return its exit code without raising on failure."""
    try:
        result = subprocess.run(cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode != 0:
            # Print minimal error for debugging, but do not crash the sync loop
            print(f"[bh_firewall_sync] Command failed ({result.returncode}): {' '.join(cmd)}", flush=True)
        return result.returncode
    except Exception as exc:  # noqa: BLE001
        print(f"[bh_firewall_sync] Error running command {' '.join(cmd)}: {exc}", flush=True)
        return 1


def ensure_ipset_and_rules() -> None:
    """Ensure the ipset and iptables rules exist on the host.

    Because the container runs with network_mode=host and NET_ADMIN capabilities,
    ipset/iptables here operate on the host network namespace.
    """

    print("[bh_firewall_sync] Initializing ipset and iptables rules...", flush=True)

    # Ensure the ipset exists
    _run(["ipset", "create", SET_NAME, "hash:ip", "-exist"])

    # Ensure iptables rules exist for INPUT and FORWARD (idempotent)
    for chain in ("INPUT", "FORWARD"):
        check_cmd = [
            "iptables",
            "-C",
            chain,
            "-m",
            "set",
            "--match-set",
            SET_NAME,
            "src",
            "-j",
            "DROP",
        ]
        insert_cmd = [
            "iptables",
            "-I",
            chain,
            "-m",
            "set",
            "--match-set",
            SET_NAME,
            "src",
            "-j",
            "DROP",
        ]
        if _run(check_cmd) != 0:
            _run(insert_cmd)

    print("[bh_firewall_sync] ipset and iptables rules ready", flush=True)


def load_blocked_ips() -> set[str]:
    """Load blocked IPs from the Battle-Hardened AI JSON file."""

    if not os.path.exists(JSON_PATH):
        return set()

    try:
        with open(JSON_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:  # noqa: BLE001
        print(f"[bh_firewall_sync] Failed to read {JSON_PATH}: {exc}", flush=True)
        return set()

    ips: set[str] = set()

    # Current schema: {"blocked_ips": [{"ip": "1.2.3.4", ...}, ...]}
    items = data.get("blocked_ips", [])
    if isinstance(items, list):
        for entry in items:
            if isinstance(entry, dict):
                ip = entry.get("ip")
                if isinstance(ip, str) and ip:
                    ips.add(ip)

    return ips


def sync_loop() -> None:
    """Continuously sync blocked_ips.json into the bh_blocked ipset."""

    ensure_ipset_and_rules()

    last_ips: set[str] = set()

    while True:
        try:
            ips = load_blocked_ips()

            # Only apply changes when the set of IPs has changed
            if ips != last_ips:
                print(
                    f"[bh_firewall_sync] Syncing {len(ips)} blocked IPs to ipset '{SET_NAME}'",
                    flush=True,
                )

                # Ensure set still exists, then flush and repopulate
                _run(["ipset", "create", SET_NAME, "hash:ip", "-exist"])
                _run(["ipset", "flush", SET_NAME])

                for ip in sorted(ips):
                    _run(["ipset", "add", SET_NAME, ip, "-exist"])

                last_ips = ips

        except Exception as exc:  # noqa: BLE001
            print(f"[bh_firewall_sync] Unexpected error in sync loop: {exc}", flush=True)

        time.sleep(SLEEP_SECONDS)


if __name__ == "__main__":
    enabled = os.getenv("BH_FIREWALL_SYNC_ENABLED", "false").lower() == "true"
    if not enabled:
        print("[bh_firewall_sync] BH_FIREWALL_SYNC_ENABLED is not 'true'; exiting.", flush=True)
    else:
        print("[bh_firewall_sync] Starting firewall sync daemon...", flush=True)
        sync_loop()
