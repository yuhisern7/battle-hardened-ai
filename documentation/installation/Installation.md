# Battle-Hardened AI - Installation Quick Start

**Minimal installation steps for Debian/Ubuntu (.deb), RHEL-family (.rpm), and Windows (EXE installer).**

> Scope: This guide assumes the OS is already installed and booting correctly (for example, Debian 11/12, Ubuntu 20.04/22.04/24.04, RHEL 8/9, Windows 10/11/Server). It does not explain how to install or harden the operating system itself.

For full deployment scenarios (cloud routing, relay, troubleshooting, FAQs, etc.), see the advanced guide: Installation_advanced.md.

---

## Linux (Debian / Ubuntu) – .deb Package

**Use this for gateway/appliance or host-only installs on Debian/Ubuntu.**

### Prerequisites

- Supported OS: Debian 11/12, Ubuntu 20.04/22.04/24.04 (64-bit)
- Root or sudo access
- iptables/ipset available

### Install

1. Copy the signed .deb package to the server.
2. Install the package and its dependencies (recommended modern apt syntax):

```bash
sudo apt-get install ./battle-hardened-ai_*.deb
```

This will install Battle-Hardened AI, pull in all required Debian packages, and automatically run the post-installation setup script.

3. (Optional) If you ever need to manually re-run the post-install steps (firewall wiring, permissions, health check), you can run:

```bash
sudo bash /opt/battle-hardened-ai/packaging/debian-startup.sh
```

### Basic checks

Quick one-command start + verify (recommended):

```bash
sudo bash /opt/battle-hardened-ai/packaging/debian-start-battle.sh
```

This enables and (re)starts all core services and then runs the health check so you immediately see if everything is green.

You can also check services directly:

```bash
sudo systemctl status battle-hardened-ai
sudo systemctl status battle-hardened-ai-device-scanner
sudo systemctl status battle-hardened-ai-firewall-sync
```

Dashboard (from your admin machine):

```text
https://YOUR_SERVER_IP:60000
```

If you need advanced networking (gateway routing, DHCP, cloud VPC routing, manual firewall overrides), follow the relevant sections in Installation_advanced.md and Firewall_enforcement.md.

---

## Linux (RHEL / Rocky / Alma) – .rpm Package

**Use this for gateway/appliance or host-only installs on RHEL-family systems.**

### Prerequisites

- Supported OS: RHEL 8/9, Rocky 8/9, Alma 8/9 (64-bit)
- Root or sudo access
- firewalld available (for native firewall integration)

### Install

1. Copy the signed .rpm package to the server.
2. Install the package:

```bash
sudo dnf install ./battle-hardened-ai-*.rpm
```

3. Enable and start the services:

```bash
sudo systemctl enable battle-hardened-ai battle-hardened-ai-firewall-sync battle-hardened-ai-device-scanner
sudo systemctl start battle-hardened-ai battle-hardened-ai-firewall-sync battle-hardened-ai-device-scanner
```

4. Ensure firewalld is running so the Linux Firewall Commander can manage ipsets and rich rules:

```bash
sudo systemctl enable firewalld
sudo systemctl start firewalld
```

### Basic checks

```bash
sudo systemctl status battle-hardened-ai
sudo systemctl status battle-hardened-ai-firewall-sync
sudo firewall-cmd --permanent --get-ipsets | grep bh_ || true
```

Dashboard (from your admin machine):

```text
https://YOUR_SERVER_IP:60000
```

For backend auto-detection details, dual-layer firewall rules, and cloud gateway/VPC patterns, see Installation_advanced.md and Firewall_enforcement.md.

---

## Windows – EXE Installer

**Use this for host-only or appliance-style deployments on Windows.**

### Prerequisites

- Supported OS: Windows 10/11, Windows Server (64-bit)
- Local administrator rights

### Install

1. Run the signed installer as an administrator:

```text
BattleHardenedAI-Setup.exe
```

2. Accept the default install path (for example, C:\Program Files\Battle-Hardened AI) unless your policy requires a different location.

### Post-install configuration

1. Edit the installed env file in the install directory:

```text
C:\Program Files\Battle-Hardened AI\.env.windows
```

Set at minimum:

- RELAY_URL (for example, wss://YOUR_VPS_OR_DOMAIN:60001)
- RELAY_API_URL (for example, https://YOUR_VPS_OR_DOMAIN:60002)
- CUSTOMER_ID (your assigned customer identifier)
- PEER_NAME (friendly node name, e.g. branch-office-1)
- BATTLE_HARDENED_SECRET_KEY (long random value you generate and keep secret)

2. Place the shared HMAC key (provided out-of-band) in the crypto directory:

```text
C:\Program Files\Battle-Hardened AI\server\crypto_keys\shared_secret.key
```

3. Create or update the Windows Firewall rules (administrator PowerShell):

```powershell
Remove-NetFirewallRule -DisplayName "Battle-Hardened AI Honeypot" -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName "Battle-Hardened AI Dashboard" -ErrorAction SilentlyContinue

New-NetFirewallRule -DisplayName "Battle-Hardened AI Honeypot" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 2121,2222,2323,3306,8080,2525,3389 `
    -Action Allow `
    -Profile Any `
    -Enabled True

New-NetFirewallRule -DisplayName "Battle-Hardened AI Dashboard" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 60000 `
    -Action Allow `
    -Profile Any `
    -Enabled True
```

This is required for honeypot ports and the HTTPS dashboard to accept inbound connections on Windows, especially on Public networks.

### Start and verify

- Use the Start Menu shortcut created by the installer, or launch BattleHardenedAI.exe from the install directory.
- Then check the dashboard from another machine:

```text
https://YOUR_WINDOWS_IP:60000
```

If you need development-mode commands, advanced honeypot testing, or AV/EDR exception patterns, refer to the Windows sections in Installation_advanced.md and Firewall_enforcement.md.

---

## Updating and Uninstalling (Summary)

### Update – Debian / Ubuntu

```bash
sudo dpkg -i battle-hardened-ai_*.deb
sudo apt-get install -f
```

Configuration in /etc/battle-hardened-ai/.env and runtime data in /var/lib/battle-hardened-ai are preserved.

### Update – RHEL-family

```bash
sudo dnf install ./battle-hardened-ai-*.rpm
```

### Update – Windows

- Run the new BattleHardenedAI-Setup.exe; it upgrades in-place. Verify .env.windows and shared_secret.key remain in the install directory.

### Uninstall – Debian / Ubuntu

```bash
sudo systemctl stop battle-hardened-ai battle-hardened-ai-firewall-sync
sudo apt-get remove battle-hardened-ai
```

Optional cleanup:

```bash
sudo rm -rf /var/lib/battle-hardened-ai /var/log/battle-hardened-ai /etc/battle-hardened-ai
```

### Uninstall – RHEL-family

```bash
sudo systemctl stop battle-hardened-ai battle-hardened-ai-firewall-sync
sudo dnf remove battle-hardened-ai
```

### Uninstall – Windows

- Remove via Apps & Features / Programs and Features.
- Optionally remove custom firewall rules and any residual data directories according to your policy.

---

For anything beyond these minimal steps (cloud gateways, relay topology, quick-attack tests, deep troubleshooting), always jump to Installation_advanced.md and the dedicated docs referenced there.

