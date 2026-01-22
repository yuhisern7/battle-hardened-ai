# Battle-Hardened AI Firewall Enforcement (Linux & Windows)

Battle-Hardened AI already makes **first-layer decisions** about which IPs are malicious and writes them into structured JSON files (for example, `server/json/blocked_ips.json`).

This guide shows how to **turn those decisions into real firewall blocks** on:

- Linux gateway / edge boxes (Docker deployment, host networking)
- Windows hosts (native Python deployment)

> Battle-Hardened AI remains a **first-layer decision node**. These integrations simply push its `blocked_ips` into the OS firewall so port scans and attacks from those IPs are dropped at the network boundary.

---

## 1. Linux (Docker, Host Networking) — Automatic Mode

On Linux, Battle-Hardened AI is designed to run in a Docker container with:

- `network_mode: host`
- `NET_ADMIN` and related capabilities

The container includes a small daemon that **automatically syncs** Battle-Hardened AI's `blocked_ips.json` into the host firewall when enabled.

### 1.1. Prerequisites

- You are running from the `server` directory using Docker Compose: `docker compose up -d`.
- The Linux box is a **gateway/router** or **edge device** for the traffic you care about.
- [server/docker-compose.yml](server/docker-compose.yml) is unmodified with respect to:
  - `network_mode: host`
  - `cap_add` including `NET_ADMIN`.

### 1.2. Enable Automatic Firewall Sync

1. In [server/.env.linux](server/.env.linux) (or your `.env` on Linux), set:

    ```env
    BH_FIREWALL_SYNC_ENABLED=true
    ```

2. Start or restart the container:

    ```bash
    cd battle-hardened-ai/server
    docker compose build
    docker compose up -d
    ```

3. The entrypoint script [server/entrypoint.sh](server/entrypoint.sh):
    - Detects `BH_FIREWALL_SYNC_ENABLED=true`.
    - Starts `/app/installation/bh_firewall_sync.py` in the background.

From this point onward:

- You **do not need to run any extra scripts** on Linux.
- Clicking **Unblock** in the dashboard (Section 7) updates `blocked_ips.json`.
- The sync daemon:
  - Reads `/app/json/blocked_ips.json` (host [server/json/blocked_ips.json](server/json/blocked_ips.json)).
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

## 2. Windows (Native Python or EXE) — PowerShell Integration

On Windows, Battle-Hardened AI runs either as a native Python service or as the packaged Windows EXE and writes to the same JSON file (`server/json/blocked_ips.json`), resolved via the path helpers in `AI/path_helper`. You can use a small PowerShell script to push those IPs into Windows Defender Firewall rules.

### 2.1. Concept

- Read `server/json/blocked_ips.json` periodically.
- Extract the list of blocked IPs.
- Maintain a **single firewall rule** whose `RemoteAddress` list is updated from that file.

This keeps your firewall configuration simple and centralized.

### 2.2. Example PowerShell Script Location

The project includes a ready-to-use script in two common locations:

- From a source clone: [server/windows-firewall/windows_defender_sync.ps1](server/windows-firewall/windows_defender_sync.ps1)
- From the Windows installer: `{app}\windows-firewall\windows_defender_sync.ps1` (for example `C:\Program Files\Battle-Hardened AI\windows-firewall\windows_defender_sync.ps1`)

By default, the script locates `blocked_ips.json` relative to its own directory (it expects a sibling `server\json\blocked_ips.json`), but you can override the `JsonPath` parameter if you have a custom layout.

### 2.3. Run Manually

From an elevated PowerShell prompt (Run as Administrator), after starting Battle-Hardened AI (for example `python server\server.py` from a clone, or `BattleHardenedAI.exe` from the install directory):

```powershell
cd C:\Users\YOURUSER\workspace\battle-hardened-ai\server

powershell.exe -ExecutionPolicy Bypass -File .\windows-firewall\windows_defender_sync.ps1
```

This will:

- Read the current `blocked_ips.json`.
- Create or update a **single inbound firewall rule** named `Battle-Hardened AI Blocked IPs`.
- Populate `RemoteAddress` with the blocked IPs.

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
         -ExecutionPolicy Bypass -File "C:\Program Files\Battle-Hardened AI\windows-firewall\windows_defender_sync.ps1"
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