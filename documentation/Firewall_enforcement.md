# Battle-Hardened AI Firewall Enforcement (Linux & Windows)

Battle-Hardened AI already makes **first-layer decisions** about which IPs are malicious and writes them into structured JSON files (for example, a `blocked_ips.json` file in the JSON directory resolved by the path helpers in AI/path_helper – in a source checkout this is typically `server/json/blocked_ips.json`).

This guide shows how to **turn those decisions into real firewall blocks** on:

- Linux gateway / edge boxes (Docker deployment, host networking)
- Windows hosts (packaged EXE or native Python deployment)

It is written for **enterprise and regulated environments** with change control, GPO/MDM, and third‑party EDR/endpoint firewalls. Treat the concrete scripts here as **reference implementations** of the required ports and rules, not as a replacement for your existing policy tooling.

> **Distribution note:** Customer deployments normally use Linux packages (`.deb`/`.rpm`) or the Windows EXE installer; you do **not** need a Git clone of the repository. Where this guide references paths like `server/docker-compose.yml` or `server/.env.linux`, treat those as **developer/source examples** – packaged appliances run the same Docker image and entrypoint under a managed service as described in INSTALLATION.

> Battle-Hardened AI remains a **first-layer decision node**. These integrations simply push its `blocked_ips` into the OS firewall so port scans and attacks from those IPs are dropped at the network boundary.

### Firewall Ports Summary (Enterprise View)

Use this table as the **authoritative reference** when creating firewall rules via GPO/Intune, on-prem firewalls, or EDR policy consoles.

| Component / Role | Direction | Port(s) / Protocol | Purpose |
|------------------|-----------|--------------------|---------|
| Linux gateway / edge node | Inbound | 60000/TCP | HTTPS dashboard (SOC/administrator access) |
| Linux gateway / edge node | Inbound | 2121, 2222, 2323, 3306, 8080, 2525, 3389/TCP | Honeypot services for attacker interaction and training |
| Linux gateway / edge node | Outbound (optional) | 60001–60002/TCP | Client → relay (WebSocket + HTTPS model API) |
| Windows host / appliance | Inbound | 60000/TCP | HTTPS dashboard on Windows deployments |
| Windows host / appliance | Inbound | 2121, 2222, 2323, 3306, 8080, 2525, 3389/TCP | Windows honeypot services (optional, security lab / decoy) |
| Windows host / appliance | Outbound (optional) | 60001–60002/TCP | Client → relay (WebSocket + HTTPS model API) |
| Relay server (VPS) | Inbound | 60001/TCP | WebSocket relay endpoint (wss://) |
| Relay server (VPS) | Inbound | 60002/TCP | HTTPS model distribution API |

In tightly controlled environments, these ports are normally opened on **security appliances and relay servers only**, not on general-purpose endpoints.

---

## 1. Linux (Docker, Host Networking) — Automatic Mode

On Linux, Battle-Hardened AI runs in a Docker container with:

- `network_mode: host`
- `NET_ADMIN` and related capabilities

The container includes a small daemon that **automatically syncs** Battle-Hardened AI's `blocked_ips.json` into the host firewall when enabled.

### 1.1. Prerequisites

- **Packaged Linux appliance (recommended for customers):** Battle-Hardened AI is installed from a vendor-signed `.deb`/`.rpm` and managed via a systemd service (for example `battle-hardened-ai`). The package internally runs the same Docker Compose stack on the host with `network_mode: host` and `NET_ADMIN`.
- **From source (developers/labs):** You are running from the `server` directory using Docker Compose: `docker compose up -d` and [server/docker-compose.yml](server/docker-compose.yml) is unmodified with respect to:
  - `network_mode: host`
  - `cap_add` including `NET_ADMIN`.
- The Linux box is a **gateway/router** or **edge device** for the traffic you care about.

### 1.2. Enable Automatic Firewall Sync

1. In your Linux environment configuration, enable firewall sync.

  - **Packaged appliance:** Follow the Linux section in INSTALLATION to set `BH_FIREWALL_SYNC_ENABLED=true` in the service’s environment (for example via `/etc/default/battle-hardened-ai` or the package’s `.env` file).
  - **From source:** In [server/.env.linux](server/.env.linux) (or your `.env` on Linux), set:

    ```env
    BH_FIREWALL_SYNC_ENABLED=true
    ```

2. Restart the service or container so the setting is applied:

    - **Packaged appliance (systemd-managed):**

      ```bash
      sudo systemctl restart battle-hardened-ai
      ```

    - **From source (Docker Compose):**

      ```bash
      cd battle-hardened-ai/server
      docker compose build
      docker compose up -d
      ```

3. Inside the Docker image (for both packaged and source-based deployments), the entrypoint script [server/entrypoint.sh](server/entrypoint.sh):
    - Detects `BH_FIREWALL_SYNC_ENABLED=true`.
    - Starts `/app/installation/bh_firewall_sync.py` in the background.

From this point onward:

- You **do not need to run any extra scripts** on Linux.
- Clicking **Unblock** in the dashboard (Section 7) updates `blocked_ips.json`.
- The sync daemon:
  - Reads `/app/json/blocked_ips.json` (the host-side JSON directory as resolved by AI/path_helper; in a source checkout this is [server/json/blocked_ips.json](server/json/blocked_ips.json)).
  - Rebuilds an `ipset` named `bh_blocked` on the host.
  - Ensures `iptables` rules on `INPUT` and `FORWARD` drop traffic from that set.

Unblocking or whitelisting in Section 7 **automatically** removes the IP from `blocked_ips.json`, and the next sync removes it from the Linux firewall as well.

### 1.3. Verify Host Firewall Rules

On the Linux host (not in another container):

```bash
sudo ipset list bh_blocked
sudo iptables -L INPUT -n | grep bh_blocked || echo "no INPUT rule yet"
sudo iptables -L FORWARD -n | grep bh_blocked || echo "no FORWARD rule yet"
```

If `BH_FIREWALL_SYNC_ENABLED=true` and the container is running, you should see:

- A set `bh_blocked` populated with IPs from `blocked_ips.json`.
- DROP rules on INPUT/FORWARD referencing that set.

---

## 2. Windows (EXE or Native Python) — Firewall Integration

On Windows, Battle-Hardened AI runs either as a native Python service or as the packaged Windows EXE and writes to the same logical JSON file (`blocked_ips.json` in the JSON directory resolved via `AI/path_helper`; in a source checkout this is `server/json/blocked_ips.json`).

There are **two layers** of integration with Windows Defender Firewall:

- **Baseline allow rules (ports opened):** Ensure the dashboard and honeypot/relay ports are reachable on the host.
- **Dynamic block rules (malicious IPs):** Sync the `blocked_ips.json` list into a firewall rule so malicious IPs are dropped.

### 2.1. Concept

- Read `server/json/blocked_ips.json` periodically.
- Extract the list of blocked IPs.
- Maintain a **single firewall rule** whose `RemoteAddress` list is updated from that file.

This keeps your firewall configuration simple and centralized.

### 2.2. Example PowerShell Script Locations

The project includes a single ready-to-use script in both **source** and **installed** layouts that configures baseline allow rules **and** syncs blocked IPs into a Windows Defender block rule:

- From a source clone: [server/windows-firewall/configure_bh_windows_firewall.ps1](server/windows-firewall/configure_bh_windows_firewall.ps1)
- From the Windows installer: `{app}\windows-firewall\configure_bh_windows_firewall.ps1` (for example `C:\Program Files\Battle-Hardened AI\windows-firewall\configure_bh_windows_firewall.ps1`)

In **enterprise environments**, baseline rules are usually created centrally via GPO/Intune or your EDR/endpoint firewall console. This script is provided as a **reference** and is suitable for labs, pilots, or controlled security appliances where local rule changes are permitted.

### 2.3. Run Manually

From an elevated PowerShell prompt (Run as Administrator), after starting Battle-Hardened AI (for example `python server\server.py` from a clone, or `BattleHardenedAI.exe` from the install directory):

```powershell
cd C:\Users\YOURUSER\workspace\battle-hardened-ai\server

powershell.exe -ExecutionPolicy Bypass -File .\windows-firewall\configure_bh_windows_firewall.ps1
```

This will:

- Create or update inbound **allow** rules for the dashboard and honeypot ports (unless `-SkipBaselineRules` is used).
- Optionally create an outbound **allow** rule for the relay ports 60001–60002 (unless `-SkipRelayOutbound` is used).
- Read the current `blocked_ips.json` and create or update a **single inbound firewall rule** (by default named `Battle-Hardened AI Blocked IPs`) whose `RemoteAddress` list is populated with the blocked IPs (unless `-SkipBlockSync` is used).

### 2.4. Schedule Automatic Sync (Task Scheduler)

To keep the firewall in sync automatically:

1. Open **Task Scheduler** → **Create Task**.
2. On **General**:
   - Run whether user is logged on or not.
   - Run with highest privileges.
3. On **Triggers**:
   - New → Begin the task: *On a schedule*.
   - Set to run **every 1 minute** (or your preferred interval).
4. On **Actions** (example for an installed EXE under `C:\Program Files\Battle-Hardened AI`):
   - Action: *Start a program*.
   - Program/script:

     ```text
     powershell.exe
     ```

     - Add arguments:

         ```text
         -ExecutionPolicy Bypass -File "C:\Program Files\Battle-Hardened AI\windows-firewall\configure_bh_windows_firewall.ps1" -SkipBaselineRules
         ```

5. Save the task.

Now Windows Defender Firewall will be updated periodically from Battle-Hardened AI's `blocked_ips.json`, and malicious IPs will be blocked at the OS firewall level.

---

## 3. Notes and Limitations

- Battle-Hardened AI remains a **first-layer decision engine**. These integrations only control how those decisions are enforced at the OS/network level.
- For **Linux**:
  - The host must be placed as a **gateway/router or edge device** to protect more than itself.
  - ipset/iptables rules configured by the container affect the host because of `network_mode: host` and granted capabilities.
- For **Windows**:
  - The firewall integration primarily protects the **Windows host itself** and any services directly exposed on that host.
  - It does not automatically protect other devices on the LAN unless Windows is acting as a router.
- Always test new firewall rules carefully to avoid locking yourself out of remote access.

This file is intended as a reference so you can plug Battle-Hardened AI's blocked IP list into the underlying firewall on both Linux and Windows without changing core application code.