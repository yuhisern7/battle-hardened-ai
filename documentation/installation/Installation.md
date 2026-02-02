# Battle-Hardened AI - Complete Installation Guide

**Complete installation instructions for Linux (.deb/.rpm), Windows (EXE installer), and optional Relay Server setup.**

---

## ⚙️ Network Configuration - IP Whitelisting

**If your network uses a different IP segment than the defaults**, you need to whitelist your gateway/router IP to prevent accidental blocking.

### Default Whitelisted IPs (Never Blocked):
- `127.0.0.1`, `localhost`, `::1` - Localhost
- `172.17.0.1`, `172.18.0.1`, `172.19.0.1`, `172.16.0.1` - Docker bridges
- `10.0.0.1` - Common gateway
- `192.168.0.1` - Common home router

### Add Custom IPs (For Different Network Segments):

**Method 1: Edit JSON file directly**
```bash
# Create/edit server/json/whitelist.json
nano server/json/whitelist.json
```

Add your IPs as a JSON array:
```json
[
  "10.0.5.1",
  "172.16.10.1",
  "192.168.1.1",
  "192.168.50.100"
]
```

**Method 2: Use Python API (after installation)**
```python
from AI.pcs_ai import add_to_whitelist

# Add your gateway/trusted IPs
add_to_whitelist("10.0.5.1")
add_to_whitelist("192.168.1.1")
```

**Important:** Only specific IPs are whitelisted, NOT entire ranges. Example: `192.168.0.119` (Kali attacker) WILL be blocked, only `192.168.0.1` (router) is exempt.

---

## 🔐 HMAC Shared Secret Key Required

**To enable encrypted relay communication, obtain the HMAC shared secret key from:**

**Elite Cybersecurity Specialist – 202403184091 (MA0319303)**

**Contact:** Yuhisern Navaratnam  
**WhatsApp:** +60172791717  
**Email:** yuhisern@protonmail.com

Place the `shared_secret.key` file in:
- **Client:** `server/crypto_keys/shared_secret.key`
- **Relay VPS:** `relay/crypto_keys/shared_secret.key`

---

## 🚀 Quick Start - Choose Your Deployment

> **Primary architecture:** Battle-Hardened AI is designed first and foremost for **Linux gateway/edge deployments** (physical or virtual appliances in front of a segment). Windows and macOS installs are supported as **host/appliance** tiers for specific servers or branches, but the canonical 7-stage, 21-layer architecture and firewall enforcement story assume a Linux node at the network boundary.

> **Distribution model:** Production customers normally receive **pre-packaged binaries**, not the GitHub source tree:
> - **Linux gateway/edge nodes:** Installed via a signed **.deb/.rpm package** provided by the vendor.
> - **Windows hosts/appliances:** Installed via the signed **BattleHardenedAI-Setup.exe** installer.
> - **Documentation and helper scripts:** Shipped alongside the packages.
>
> The **`git clone` and source-based commands** in this guide are intended for **development, lab environments, or contributors**. If you have received an official package/installer, follow the **package/installer subsections** for your platform and you can safely ignore any steps that mention cloning from GitHub.

**Who should read what (customers vs developers):**

| Role / Scenario                         | Use these docs primarily                                                                                         |
|-----------------------------------------|-------------------------------------------------------------------------------------------------------------------|
| **Customer operator (Linux appliance)** | This INSTALLATION guide (Linux .deb/.rpm sections), README (high level), FIREWALL_ENFORCEMENT, dashboard docs    |
| **Customer operator (Windows EXE)**     | This INSTALLATION guide (Windows installer/EXE sections), README, FIREWALL_ENFORCEMENT, Windows firewall scripts |
| **Developers / auditors (source)**      | ai-instructions (architecture & pipeline), ARCHITECTURE_COMPLIANCE, dashboard (API details), filepurpose, etc.  |

If you are running the **packaged Linux or Windows builds**, you normally do **not** interact with the full Git source tree; treat the developer/auditor docs as optional deep-dive references rather than required install steps.

---

## 🌐 Deployment Scenarios - Detailed Guide

This section provides step-by-step instructions for the most common deployment scenarios. Choose the scenario that matches your use case.

### Scenario 1: Linux Gateway/Router (Network-Wide Protection - RECOMMENDED)

**Goal:** Protect entire network segment by placing Battle-Hardened AI between internet and internal network.

**When to use:**
- Home/small office networks
- Branch office protection
- Network segment isolation
- Complete visibility and control over all traffic

---

#### 🔧 Equipment Required

**Minimum Hardware:**
- **Linux appliance/server** with 2 network interfaces (NICs):
  - **WAN NIC:** Connects to modem/ONT/upstream router
  - **LAN NIC:** Connects to internal switch/network
- **CPU:** 4 cores (Intel/AMD x64)
- **RAM:** 8 GB minimum, 16 GB recommended
- **Storage:** 32 GB SSD/NVMe minimum, 128 GB recommended
- **Network:** Gigabit Ethernet NICs (Intel i210/i350 recommended for stability)

**Example Hardware Options:**

| Option | Description | Cost Range |
|--------|-------------|------------|
| **Repurposed PC/Server** | Old desktop with dual NICs | $0-200 (reuse) |
| **Mini PC** | Intel NUC, Protectli Vault, Qotom | $200-600 |
| **Dedicated Appliance** | Purpose-built firewall hardware | $300-1000 |
| **VM/Hypervisor** | Proxmox, ESXi with virtual NICs | $0 (software) |

**Network Equipment:**
- **Modem/ONT** in bridge mode (ISP-provided, disable built-in routing)
- **Managed switch** (optional but recommended for VLANs)
- **Wi-Fi access point** in bridge/AP mode (disable router features)

---

#### 📡 Network Topology

```
INTERNET
    │
    │ (WAN connection)
    │
┌───▼────────┐
│ Modem/ONT  │ ← Set to BRIDGE MODE (disable NAT/firewall)
└───┬────────┘
    │
    │ WAN cable (to eth0/enp1s0)
    │
┌───▼─────────────────────────┐
│  Battle-Hardened AI         │ ← Linux Gateway
│  (Ubuntu/Debian Server)     │
│                             │
│  WAN: eth0 (203.0.113.50)   │ ← Public IP from ISP
│  LAN: eth1 (192.168.1.1)    │ ← Gateway for internal network
│                             │
│  Services:                  │
│  - NAT/Routing             │
│  - DHCP server             │
│  - DNS resolver            │
│  - Firewall (iptables)     │
│  - Battle-Hardened AI      │
└───┬─────────────────────────┘
    │
    │ LAN cable (from eth1)
    │
┌───▼──────┐        ┌────────────┐
│ Switch   │───────►│ Wi-Fi AP   │ ← Bridge mode (no DHCP/NAT)
└───┬──────┘        └────────────┘
    │
    ├─── Desktop PC (192.168.1.100)
    ├─── Laptop (192.168.1.101 via Wi-Fi)
    ├─── Server (192.168.1.50)
    └─── IoT devices (192.168.1.200+)
```

---

#### ⚙️ Step-by-Step Setup

**Step 1: Prepare Linux Server**

Install Ubuntu Server 22.04/24.04 or Debian 11/12:

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y net-tools dnsmasq iptables ipset

# Identify network interfaces
ip addr show
# Example output:
# eth0: WAN interface (connected to modem)
# eth1: LAN interface (connected to switch)
```

**Step 2: Configure Network Interfaces**

Edit `/etc/netplan/01-netcfg.yaml` (Ubuntu) or `/etc/network/interfaces` (Debian):

**Ubuntu/Netplan:**
```yaml
network:
  version: 2
  ethernets:
    eth0:  # WAN interface
      dhcp4: true  # Get IP from ISP
      # Or static if ISP provides:
      # addresses: [203.0.113.50/24]
      # gateway4: 203.0.113.1
      # nameservers:
      #   addresses: [8.8.8.8, 8.8.4.4]
    
    eth1:  # LAN interface
      addresses: [192.168.1.1/24]  # Gateway IP for internal network
      dhcp4: no
```

Apply configuration:
```bash
sudo netplan apply
```

**Debian /etc/network/interfaces:**
```
# WAN interface
auto eth0
iface eth0 inet dhcp

# LAN interface
auto eth1
iface eth1 inet static
    address 192.168.1.1
    netmask 255.255.255.0
```

Apply:
```bash
sudo systemctl restart networking
```

**Step 3: Enable IP Forwarding**

```bash
# Enable immediately
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1

# Make permanent
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
echo "net.ipv6.conf.all.forwarding=1" | sudo tee -a /etc/sysctl.conf
```

**Step 4: Configure NAT (Masquerading)**

```bash
# Set up NAT so internal network can access internet via WAN
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Allow forwarding
sudo iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT

# Save rules (Ubuntu/Debian)
sudo apt install iptables-persistent
sudo netfilter-persistent save
```

**Step 5: Configure DHCP Server (dnsmasq)**

Edit `/etc/dnsmasq.conf`:

```bash
# Interface to listen on
interface=eth1

# DHCP range for internal network
dhcp-range=192.168.1.100,192.168.1.250,12h

# Gateway (this server)
dhcp-option=3,192.168.1.1

# DNS servers (this server will forward to ISP or public DNS)
dhcp-option=6,192.168.1.1

# Domain name
domain=local

# Upstream DNS servers
server=8.8.8.8
server=8.8.4.4
```

Enable and start:
```bash
sudo systemctl enable dnsmasq
sudo systemctl start dnsmasq
```

**Step 6: Verify Basic Gateway Functionality**

Connect a test device to LAN switch:

```bash
# From test device (should get 192.168.1.x IP via DHCP)
ip addr show  # Verify IP address
ping 192.168.1.1  # Ping gateway
ping 8.8.8.8  # Ping internet (test NAT)
curl https://google.com  # Test full internet connectivity
```

**Step 7: Install Battle-Hardened AI**

```bash
# Download .deb package (from vendor)
sudo dpkg -i battle-hardened-ai_*.deb
sudo apt-get install -f  # Fix any dependencies

# Configure
sudo nano /etc/battle-hardened-ai/.env

# Set these variables:
RELAY_URL=wss://YOUR_RELAY_VPS:60001
RELAY_API_URL=https://YOUR_RELAY_VPS:60002
CUSTOMER_ID=your-customer-id
PEER_NAME=main-gateway
BATTLE_HARDENED_SECRET_KEY=your-long-random-secret-key
```

**Step 8: Place Shared Secret Key**

```bash
# Obtain shared_secret.key from vendor
# Copy to crypto directory
sudo mkdir -p /etc/battle-hardened-ai/crypto_keys
sudo cp shared_secret.key /etc/battle-hardened-ai/crypto_keys/
sudo chown bhai:bhai /etc/battle-hardened-ai/crypto_keys/shared_secret.key
sudo chmod 600 /etc/battle-hardened-ai/crypto_keys/shared_secret.key
```

**Step 9: Whitelist Gateway IP**

```bash
# Edit whitelist to prevent blocking gateway itself
sudo nano /var/lib/battle-hardened-ai/json/whitelist.json
```

Add:
```json
[
  "192.168.1.1",
  "127.0.0.1"
]
```

**Step 10: Start Services**

```bash
sudo systemctl enable battle-hardened-ai battle-hardened-ai-firewall-sync
sudo systemctl start battle-hardened-ai battle-hardened-ai-firewall-sync

# Check status
sudo systemctl status battle-hardened-ai
sudo journalctl -u battle-hardened-ai -n 50 --no-pager
```

**Step 11: Access Dashboard**

From any device on internal network:
```
https://192.168.1.1:60000
```

Accept self-signed certificate and login.

**Step 12: Final Verification**

```bash
# Check firewall rules are being applied
sudo iptables -L -n -v
sudo ipset list

# Monitor live threats
sudo journalctl -u battle-hardened-ai -f

# Test attack detection from external device
# (e.g., port scan from another network)
```

---

#### 🔒 Firewall Integration

Battle-Hardened AI automatically syncs with iptables via the `battle-hardened-ai-firewall-sync` service:

```bash
# Check firewall sync status
sudo systemctl status battle-hardened-ai-firewall-sync

# View blocked IPs
sudo ipset list battle_hardened_blocklist

# Manual block (for testing)
sudo ipset add battle_hardened_blocklist 1.2.3.4

# Manual unblock
sudo ipset del battle_hardened_blocklist 1.2.3.4
```

For detailed firewall configuration, see [Firewall_enforcement.md](../Firewall_enforcement.md).

---

### Scenario 2: Cloud Gateway with Virtual NICs (AWS/Azure/GCP)

**Goal:** Deploy Battle-Hardened AI as a virtual gateway in cloud environment protecting VPC/VNet resources.

**When to use:**
- Cloud-hosted infrastructure (AWS, Azure, GCP)
- Hybrid cloud deployments
- Multi-region protection
- Testing before on-premises deployment

---

#### ☁️ Cloud Architecture Overview

```
INTERNET
    │
    │ (Public IP/Elastic IP)
    │
┌───▼─────────────────────────────────────────┐
│  Cloud VPC/VNet (10.0.0.0/16)               │
│                                             │
│  ┌─────────────────────────────────────┐   │
│  │ Battle-Hardened AI Gateway VM      │   │
│  │                                     │   │
│  │ Virtual NIC 1 (Public)              │   │
│  │   - Public IP: 203.0.113.50        │   │
│  │   - Subnet: 10.0.1.0/24 (DMZ)      │   │
│  │                                     │   │
│  │ Virtual NIC 2 (Private)             │   │
│  │   - Private IP: 10.0.10.1          │   │
│  │   - Subnet: 10.0.10.0/24 (App tier)│   │
│  │                                     │   │
│  │ Services:                           │   │
│  │   - NAT Gateway                     │   │
│  │   - Security Groups/NSG             │   │
│  │   - Battle-Hardened AI              │   │
│  └───┬─────────────────────────────────┘   │
│      │                                      │
│      │ (Internal routing)                   │
│      │                                      │
│  ┌───▼──────────┐  ┌──────────────┐       │
│  │ Web Servers  │  │ App Servers  │       │
│  │ 10.0.10.10   │  │ 10.0.10.20   │       │
│  └──────────────┘  └──────────────┘       │
│                                             │
│  ┌──────────────┐  ┌──────────────┐       │
│  │ Databases    │  │ Storage      │       │
│  │ 10.0.20.10   │  │ 10.0.30.x    │       │
│  └──────────────┘  └──────────────┘       │
│                                             │
└─────────────────────────────────────────────┘
```

---

#### 🔧 Equipment Required

**Cloud Resources:**
- **VM Instance:**
  - Type: e2-standard-4 (GCP), t3.xlarge (AWS), Standard_B4ms (Azure)
  - vCPUs: 4 cores minimum, 8 recommended
  - RAM: 8 GB minimum, 16 GB recommended
  - Storage: 50 GB SSD minimum, 128 GB recommended
- **Virtual NICs:** 2 network interfaces
  - NIC 1: External/public subnet (WAN equivalent)
  - NIC 2: Internal/private subnet (LAN equivalent)
- **Public IP:** Elastic IP (AWS), Static IP (GCP), Public IP (Azure)
- **Operating System:** Ubuntu 22.04/24.04 LTS or Debian 11/12

**Network Configuration:**
- **VPC/VNet:** 10.0.0.0/16 (example)
- **Public Subnet:** 10.0.1.0/24 (for NIC 1)
- **Private Subnet:** 10.0.10.0/24 (for NIC 2 and backend services)
- **Route Tables:** Custom routes pointing to Battle-Hardened AI
- **Security Groups/NSGs:** Allow necessary ports

---

#### ⚙️ AWS Deployment (Step-by-Step)

**Step 1: Create VPC and Subnets**

```bash
# Create VPC
aws ec2 create-vpc --cidr-block 10.0.0.0/16 --tag-specifications 'ResourceType=vpc,Tags=[{Key=Name,Value=BattleHardenedAI-VPC}]'

# Note the VPC ID from output
VPC_ID=vpc-xxxxxxxxx

# Create public subnet (for external NIC)
aws ec2 create-subnet --vpc-id $VPC_ID --cidr-block 10.0.1.0/24 --availability-zone us-east-1a --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=Public-Subnet}]'

# Note subnet ID
PUBLIC_SUBNET_ID=subnet-xxxxxxxxx

# Create private subnet (for internal NIC)
aws ec2 create-subnet --vpc-id $VPC_ID --cidr-block 10.0.10.0/24 --availability-zone us-east-1a --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=Private-Subnet}]'

PRIVATE_SUBNET_ID=subnet-yyyyyyyyy

# Create Internet Gateway
aws ec2 create-internet-gateway --tag-specifications 'ResourceType=internet-gateway,Tags=[{Key=Name,Value=BH-AI-IGW}]'
IGW_ID=igw-xxxxxxxxx

# Attach to VPC
aws ec2 attach-internet-gateway --vpc-id $VPC_ID --internet-gateway-id $IGW_ID
```

**Step 2: Launch EC2 Instance with Dual NICs**

```bash
# Create Security Groups
# External SG (allow dashboard, SSH)
aws ec2 create-security-group --group-name BH-AI-External-SG --description "Battle-Hardened AI External" --vpc-id $VPC_ID

EXTERNAL_SG_ID=sg-xxxxxxxxx

aws ec2 authorize-security-group-ingress --group-id $EXTERNAL_SG_ID --protocol tcp --port 22 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --group-id $EXTERNAL_SG_ID --protocol tcp --port 60000 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --group-id $EXTERNAL_SG_ID --protocol tcp --port 443 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --group-id $EXTERNAL_SG_ID --protocol tcp --port 80 --cidr 0.0.0.0/0

# Internal SG (allow all from private subnet)
aws ec2 create-security-group --group-name BH-AI-Internal-SG --description "Battle-Hardened AI Internal" --vpc-id $VPC_ID

INTERNAL_SG_ID=sg-yyyyyyyyy

aws ec2 authorize-security-group-ingress --group-id $INTERNAL_SG_ID --protocol -1 --cidr 10.0.0.0/16

# Launch instance with two network interfaces
aws ec2 run-instances \
  --image-id ami-0c55b159cbfafe1f0 \
  --instance-type t3.xlarge \
  --key-name your-key-pair \
  --network-interfaces \
    "DeviceIndex=0,SubnetId=$PUBLIC_SUBNET_ID,Groups=$EXTERNAL_SG_ID" \
    "DeviceIndex=1,SubnetId=$PRIVATE_SUBNET_ID,Groups=$INTERNAL_SG_ID" \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=BattleHardened-AI-Gateway}]'

INSTANCE_ID=i-xxxxxxxxx
```

**Step 3: Allocate and Assign Elastic IP**

```bash
# Allocate Elastic IP
aws ec2 allocate-address --domain vpc

EIP_ALLOCATION_ID=eipalloc-xxxxxxxxx

# Associate with primary network interface
aws ec2 associate-address --instance-id $INSTANCE_ID --allocation-id $EIP_ALLOCATION_ID
```

**Step 4: Configure Source/Dest Check (Critical for NAT)**

```bash
# Disable source/destination check (allows NAT/routing)
aws ec2 modify-instance-attribute --instance-id $INSTANCE_ID --no-source-dest-check
```

**Step 5: SSH to Instance and Configure**

```bash
# SSH using Elastic IP
ssh -i your-key.pem ubuntu@YOUR_ELASTIC_IP

# Once connected:
sudo apt update && sudo apt upgrade -y

# Identify NICs
ip addr show
# Example:
# eth0: 10.0.1.x (public subnet - WAN equivalent)
# eth1: 10.0.10.1 (private subnet - LAN equivalent)
```

**Step 6: Configure Network Interfaces**

```bash
# Edit netplan
sudo nano /etc/netplan/50-cloud-init.yaml
```

Add/modify:
```yaml
network:
  version: 2
  ethernets:
    eth0:  # Public NIC
      dhcp4: true
    eth1:  # Private NIC
      addresses: [10.0.10.1/24]
      dhcp4: no
```

Apply:
```bash
sudo netplan apply
```

**Step 7: Enable IP Forwarding and NAT**

```bash
# Enable forwarding
sudo sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf

# Configure NAT (masquerade private subnet through public NIC)
sudo iptables -t nat -A POSTROUTING -s 10.0.10.0/24 -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT

# Save rules
sudo apt install iptables-persistent -y
sudo netfilter-persistent save
```

**Step 8: Update Route Tables**

In AWS Console or via CLI:

```bash
# Get private route table
PRIVATE_RT_ID=$(aws ec2 describe-route-tables --filters "Name=vpc-id,Values=$VPC_ID" "Name=association.subnet-id,Values=$PRIVATE_SUBNET_ID" --query 'RouteTables[0].RouteTableId' --output text)

# Add route: all internet traffic from private subnet goes through Battle-Hardened AI
aws ec2 create-route --route-table-id $PRIVATE_RT_ID --destination-cidr-block 0.0.0.0/0 --network-interface-id $(aws ec2 describe-instances --instance-ids $INSTANCE_ID --query 'Reservations[0].Instances[0].NetworkInterfaces[1].NetworkInterfaceId' --output text)
```

**Step 9: Install Battle-Hardened AI**

```bash
# Download and install .deb package
wget https://your-vendor-url/battle-hardened-ai_*.deb
sudo dpkg -i battle-hardened-ai_*.deb
sudo apt-get install -f

# Configure
sudo nano /etc/battle-hardened-ai/.env
```

Set:
```
RELAY_URL=wss://YOUR_RELAY_VPS:60001
RELAY_API_URL=https://YOUR_RELAY_VPS:60002
CUSTOMER_ID=aws-vpc-gateway-1
PEER_NAME=aws-us-east-1a
BATTLE_HARDENED_SECRET_KEY=your-secret-key
```

**Step 10: Start Services**

```bash
sudo systemctl enable battle-hardened-ai battle-hardened-ai-firewall-sync
sudo systemctl start battle-hardened-ai battle-hardened-ai-firewall-sync

# Verify
sudo systemctl status battle-hardened-ai
```

**Step 11: Launch Backend Servers**

Launch web/app servers in private subnet (10.0.10.0/24). They will automatically route through Battle-Hardened AI gateway.

**Step 12: Test**

From backend server:
```bash
curl https://google.com  # Should work through NAT
# Check logs on Battle-Hardened AI to see traffic
```

Access dashboard:
```
https://YOUR_ELASTIC_IP:60000
```

---

#### ☁️ Azure Deployment (Quick Guide)

**Resources Needed:**
- **Virtual Network (VNet):** 10.0.0.0/16
- **Subnets:**
  - External: 10.0.1.0/24
  - Internal: 10.0.10.0/24
- **VM:** Standard_B4ms (4 vCPU, 16GB RAM)
  - OS: Ubuntu 22.04 LTS
  - Network Interfaces: 2 NICs
- **Public IP:** Static
- **NSG:** Network Security Groups for external/internal

**Key Configuration:**
```bash
# Disable source/dest check on NIC
az network nic update --name bh-ai-nic-internal --resource-group BH-AI-RG --ip-forwarding true

# Create route table
az network route-table create --name BH-AI-Routes --resource-group BH-AI-RG

# Add route (all traffic to internal NIC)
az network route-table route create --name ToInternet --resource-group BH-AI-RG --route-table-name BH-AI-Routes --address-prefix 0.0.0.0/0 --next-hop-type VirtualAppliance --next-hop-ip-address 10.0.10.1

# Associate route table with private subnet
az network vnet subnet update --resource-group BH-AI-RG --vnet-name BH-AI-VNet --name Private-Subnet --route-table BH-AI-Routes
```

---

#### ☁️ GCP Deployment (Quick Guide)

**Resources Needed:**
- **VPC Network:** Custom mode
- **Subnets:**
  - External: 10.0.1.0/24 (us-central1)
  - Internal: 10.0.10.0/24 (us-central1)
- **VM Instance:** e2-standard-4
  - OS: Ubuntu 22.04 LTS
  - Network Interfaces: 2 NICs
- **External IP:** Static
- **Firewall Rules:** Allow ingress/egress

**Key Configuration:**
```bash
# Create instance with two NICs
gcloud compute instances create bh-ai-gateway \
  --zone=us-central1-a \
  --machine-type=e2-standard-4 \
  --network-interface=subnet=external-subnet,address=EXTERNAL_IP \
  --network-interface=subnet=internal-subnet,no-address \
  --can-ip-forward \
  --image-family=ubuntu-2204-lts \
  --image-project=ubuntu-os-cloud

# Create route (direct private subnet traffic through BH-AI)
gcloud compute routes create to-internet \
  --network=bh-ai-network \
  --priority=100 \
  --destination-range=0.0.0.0/0 \
  --next-hop-instance=bh-ai-gateway \
  --next-hop-instance-zone=us-central1-a
```

---

### Scenario 3: Web Server / Reverse Proxy Protection

**Coming Soon:** Detailed Nginx/Apache integration patterns for protecting web applications.

### Scenario 4: Transparent Bridge Mode (No Routing Changes)

**Coming Soon:** Step-by-step guide for inline transparent bridge deployment.

---

## Troubleshooting

### Common Issues (Packaged Installs)

#### 1. Linux: Service fails to start

```bash
sudo systemctl status battle-hardened-ai
sudo journalctl -u battle-hardened-ai -n 100 --no-pager
```

Common causes:
- Missing dependencies – run `sudo apt-get install -f` after `dpkg -i`.
- Misconfigured `/etc/battle-hardened-ai/.env` – revert recent edits and restart.
- Permission issues on `/var/lib/battle-hardened-ai` or `/var/log/battle-hardened-ai` – ensure they are owned by the `bhai` user.

#### 2. Linux: Dashboard not reachable on 60000

```bash
# From the gateway
sudo ss -ltnp | grep 60000 || sudo netstat -ltnp | grep 60000

# Check host firewall (ufw example)
sudo ufw status
```

Ensure:
- `battle-hardened-ai.service` is running.
- Host firewall allows inbound TCP 60000 from your admin network.

#### 3. Windows: Telnet shows "Trying..." forever

Most often this is Windows Firewall blocking inbound honeypot ports.

```powershell
# Run as Administrator
Get-NetFirewallRule -DisplayName "*Battle-Hardened*"

# If not found, add rules (example)
New-NetFirewallRule -DisplayName "Battle-Hardened AI Honeypot" `
   -Direction Inbound `
   -Protocol TCP `
   -LocalPort 2121,2222,2323,3306,8080,2525,3389 `
   -Action Allow `
   -Profile Any

New-NetFirewallRule -DisplayName "Battle-Hardened AI Dashboard" `
   -Direction Inbound `
   -Protocol TCP `
   -LocalPort 60000 `
   -Action Allow `
   -Profile Any
```

Also check router AP/client isolation settings if testing from another device.

#### 4. Port 60000 already in use

```bash
# Linux: Find process using port 60000
sudo lsof -i :60000 || sudo ss -ltnp | grep 60000

# Windows: Find process
netstat -ano | Select-String "60000"
```

Stop or reconfigure any conflicting service before starting Battle-Hardened AI.
**Integration Points:**
- **Docker:** Automatically runs via `entrypoint.sh`
- **Native:** Automatically runs on `server.py` startup
- **Manual:** Run `python installation/init_json_files.py` anytime

**Note:** All Python dependencies (including Flask, Flask-CORS, scikit-learn, numpy, cryptography, websockets, etc.) are listed in `server/requirements.txt` and must be installed before starting the server.

### Step 4: Configure Windows Firewall

**⚠️ CRITICAL - Run PowerShell as Administrator (Required)**

**Understanding Windows Network Profiles:**
- Windows has 3 network profiles: **Public**, **Private**, **Domain**
- **Public networks** (most Wi-Fi) block ALL inbound connections by default for security
- Firewall rules MUST include `-Profile Any` to work on Public networks
- This is NOT a bug - it's Windows security by design

**Add Firewall Rules (Administrator PowerShell):**

```powershell
# Delete old rules if they exist (in case you created them without -Profile Any)
Remove-NetFirewallRule -DisplayName "Battle-Hardened AI Honeypot" -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName "Battle-Hardened AI Dashboard" -ErrorAction SilentlyContinue

# Create NEW rules with -Profile Any (works on ALL network types including Public)
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

# Verify rules are created with correct profile
Get-NetFirewallRule -DisplayName "*Battle-Hardened*" | Select-Object DisplayName, Profile, Enabled
```

**Expected output:**
```
DisplayName                      Profile Enabled
-----------                      ------- -------
Battle-Hardened AI Dashboard     Any        True
Battle-Hardened AI Honeypot      Any        True
```

**⚠️ If you already created the rules earlier (without -Profile Any):**

```powershell
# Update existing rules to work on ALL profiles including Public
Set-NetFirewallRule -DisplayName "Battle-Hardened AI Honeypot" -Profile Any -Enabled True
Set-NetFirewallRule -DisplayName "Battle-Hardened AI Dashboard" -Profile Any -Enabled True

# Verify the fix
Get-NetFirewallRule -DisplayName "*Battle-Hardened*" | Select-Object DisplayName, Profile, Enabled
# Profile should now show "Any"
```

**Why `-Profile Any` is Required:**

Without `-Profile Any`, the firewall rule defaults to Domain + Private profiles only.

| Scenario | Without `-Profile Any` | With `-Profile Any` |
|----------|----------------------|---------------------|
| **Public Wi-Fi** (coffee shop, home) | ❌ BLOCKED | ✅ ALLOWED |
| **Private network** | ✅ ALLOWED | ✅ ALLOWED |
| **Domain network** (enterprise) | ✅ ALLOWED | ✅ ALLOWED |

**For ENTERPRISE/ORGANIZATIONAL environments:**

Organizations typically use Domain or Private network profiles, so `-Profile Any` rules work without issues. However:

1. **Security Review Required** - IT/Security must approve inbound ports:
   - Honeypot ports (2121, 2222, 2323, etc.) accept external connections
   - Document purpose: Network intrusion detection system (NIDS)
   - Show this is a security monitoring tool, not a production service

2. **Best Practice - Deploy on Dedicated Security Appliance:**
   - Windows Server VM or physical security device
   - Connected to network SPAN/mirror port (passive monitoring)
   - Isolated from production network
   - Managed by Security Operations Center (SOC)

3. **Alternative - Use Linux Instead:**
   - No Public/Private network profile restrictions
   - Full Docker support with host networking
   - Better eBPF support (100% capability vs Windows 98%)
   - Industry standard for network security appliances

**Why Honeypot Ports Must Accept Inbound:**
- Honeypot services **intentionally** accept connections from attackers
- This is how the system detects and logs attack attempts
- Without inbound access, honeypot cannot function (no attacks logged)
- Similar to how Intrusion Detection Systems (IDS) work

**Why firewall rules are required:**
- Honeypot services must accept **incoming connections from external attackers**
- Windows Firewall **blocks inbound connections by default**
- Without these rules, external telnet/nmap attempts will hang on "Trying..."

**Honeypot Ports (must accept inbound traffic):**
- **2121** (FTP), **2222** (SSH), **2323** (Telnet)
- **3306** (MySQL), **8080** (HTTP), **2525** (SMTP), **3389** (RDP)

### Handling Antivirus / EDR False Positives (Windows)

Battle-Hardened AI for Windows is designed to run **with** enterprise security controls enabled. You should **not** disable antivirus or EDR during installation or runtime.

If a particular AV/EDR product flags `BattleHardenedAI-Setup.exe` (installer) or the installed `BattleHardenedAI.exe` as a false positive:

1. **Keep protection enabled** – Do not turn off AV/EDR for the entire host.
2. Add narrow allowlist/exception rules for the signed binaries and paths only.

#### 2) In an enterprise EDR/AV console (generic steps)

In your EDR/AV management portal (Defender for Endpoint, CrowdStrike, SentinelOne, Cortex XDR, etc.):

- Go to the **policy** or **exclusions/allowlist** section.
- Add an exception by:
   - **File hash** (recommended for production builds), and/or
   - **Path**: `C:\Program Files\Battle-Hardened AI\BattleHardenedAI.exe` and the installer filename you distribute (for example, `BattleHardenedAI-Setup.exe`).
- Apply the policy to the relevant device group(s).
- Keep protection enabled; only this signed binary and path are allowed.

This pattern keeps AV/EDR fully active for the rest of the system, while explicitly authorizing the Battle-Hardened AI binaries used as a first-layer defense node.

### Windows .exe Installer – Post-Install Configuration

If you install Battle-Hardened AI using the **Windows GUI installer** (`BattleHardenedAI-Setup.exe`), complete these steps **after** the setup finishes:

1. **Locate the install directory**  
   Default path: `C:\Program Files\Battle-Hardened AI\`

2. **Edit the installed `.env.windows` file** in that directory and set at minimum:
   - `RELAY_URL` – your relay WebSocket endpoint, e.g. `wss://YOUR_VPS_OR_DOMAIN:60001`  
   - `RELAY_API_URL` – your relay HTTPS API endpoint, e.g. `https://YOUR_VPS_OR_DOMAIN:60002`  
   - `CUSTOMER_ID` – the unique customer identifier provided to you  
   - `PEER_NAME` – a friendly node name (e.g. `branch-office-1`, `dc-core-01`)  
   - `BATTLE_HARDENED_SECRET_KEY` – replace `CHANGE_ME_TO_A_LONG_RANDOM_VALUE` with a long, random string; keep it secret and consistent across restarts (and across nodes, if you cluster).

   Optionally, adjust:
   - `TZ` – your timezone (e.g. `Asia/Kuala_Lumpur`)  
   - `DASHBOARD_PORT` / `P2P_PORT` – only if your environment requires different ports.

3. **Obtain the HMAC shared secret key (relay authentication)**  
   Follow the instructions in **“HMAC Shared Secret Key Required”** at the top of this document and request the key from the Cybersecurity Specialist. You will receive a file named `shared_secret.key` **out-of-band** (it is **not** included in the installer).

4. **Place `shared_secret.key` in the crypto directory**  
   - Create the directory `server\crypto_keys\` under the install path if it does not exist.  
   - Copy the key file to:  
     `C:\Program Files\Battle-Hardened AI\server\crypto_keys\shared_secret.key`

   This path matches the default `MESSAGE_SECURITY_KEY_DIR=server/crypto_keys` used by the Windows build.

Once `.env.windows` is configured and `shared_secret.key` is in place, you can start Battle-Hardened AI either via the Start Menu shortcut created by the installer or by launching `BattleHardenedAI.exe` directly from the install directory.

### Step 5: Run Battle-Hardened AI

**⚠️ Must run PowerShell as Administrator**

#### 🧪 Development Mode (Testing Only - Single Process)

**Use for:** Quick testing with 1-10 concurrent connections

**⚠️ WARNING**: Will crash under load - DO NOT use in production

```powershell
cd C:\Users\YOUR_USERNAME\workspace\battle-hardened-ai\server
python server.py
```

**Limitations:**
- Single-threaded (no multi-worker)
- Crashes with 50+ concurrent connections
- No auto-restart on crash
- No memory leak protection
- Use ONLY for development/debugging

---

#### 🛡️ Production Mode (Recommended - Multi-Worker with Crash Protection)

**Use for:** Real production environments, handling hundreds of concurrent connections

**✅ Features:**
- **Multi-worker processes** - Auto-scaled based on your CPU cores
- **Auto-restart on crash** - Workers respawn automatically
- **Memory leak protection** - Workers recycle after 1,000 requests
- **Timeout protection** - Kills slow attacks (Slowloris defense)
- **Connection queue** - 2,048 pending connections before dropping
- **Graceful shutdown** - 30-second grace period for existing requests

**Run Production Server (from a clone, development-style):**
```powershell
cd C:\Users\YOUR_USERNAME\workspace\battle-hardened-ai\server
python installation\watchdog.py
```

**Run Production Server (from the Windows installer, recommended for production):**
- Use the Start Menu shortcut created by the installer, or
- Launch `BattleHardenedAI.exe` directly from `C:\Program Files\Battle-Hardened AI` (or your chosen install path).

**What Happens Automatically:**

1. **CPU Detection**: System detects your CPU cores (e.g., 8 cores)
2. **Worker Calculation**: Formula: `(8 × 2) + 1 = 17 workers`
3. **Thread Allocation**: 17 workers × 4 threads = 68 concurrent threads
4. **Capacity**: ~500-1,000 concurrent connections
5. **Crash Protection**: If worker crashes, watchdog respawns it automatically
6. **Memory Recycling**: Each worker restarts after 1,000 requests

**Your Actual Capacity (Based on Your CPU):**

Your system will show something like this on startup:

```
[WATCHDOG] 👁️  Server watchdog started
[WATCHDOG] 📊 Detected 8 CPU cores
[WATCHDOG] 🚀 Starting 17 workers (formula: 8 × 2 + 1)
[WATCHDOG] 💪 Capacity: ~500-1,000 concurrent connections
[WATCHDOG] 🔄 Max restarts per hour: 10
```

**Expected output:**
```
[SSL] ✅ SSL certificates generated (auto-created: ssl_cert.pem, ssl_key.pem)
[CRYPTO] ✅ Lineage signing key generated (auto-created: json/lineage_signing_key.pem)
[HONEYPOT] Starting 7 honeypot services...
[HONEYPOT] ✅ SSH honeypot listening on port 2222
[HONEYPOT] ✅ FTP honeypot listening on port 2121
[HONEYPOT] ✅ Telnet honeypot listening on port 2323
[NETWORK] Starting promiscuous mode monitoring (NETWORK-WIDE PROTECTION)
[AI] ✅ All 20 detection signals initialized
[DASHBOARD] HTTPS server running on https://0.0.0.0:60000
```

**🔐 Auto-Generated Security Files (DO NOT SHARE):**

On first run (whether via `installation\watchdog.py` or the packaged `BattleHardenedAI.exe`), the server automatically creates:
- `server/crypto_keys/ssl_cert.pem` - SSL certificate for HTTPS dashboard (self-signed)
- `server/crypto_keys/ssl_key.pem` - SSL private key (KEEP SECRET)
- `server/json/lineage_signing_key.pem` - Cryptographic lineage signing key (KEEP SECRET)

**These files are auto-generated and already in .gitignore - never commit them to Git.**

**Note:** The relay server encryption keys (for VPS communication) must be manually shared between your client and VPS relay server. See [relay/RELAY_SETUP.md](relay/RELAY_SETUP.md) for details.

### Step 6: Access Dashboard

Open browser: **https://localhost:60000**

Accept self-signed SSL certificate warning.

### Step 7: Test Honeypot

**From another device on your network (e.g., Kali Linux):**

```bash
# Get Windows IP address first
# From Windows PowerShell: ipconfig | Select-String "IPv4"
# Example: 192.168.1.100 (YOUR_WINDOWS_IP)

# Test FTP honeypot (should show "220 FTP Server Ready" banner)
telnet YOUR_WINDOWS_IP 2121

# Test SSH honeypot (should show "SSH-2.0-OpenSSH" banner)
telnet YOUR_WINDOWS_IP 2222

# Full TCP connection scan (use -sT for full connect, not SYN scan)
nmap -sT -p 2121,2222,2323 YOUR_WINDOWS_IP
```

**Check attack logs on Windows:**
- `server\json\honeypot_attacks.json` - Full attack details
- `server\json\honeypot_patterns.json` - Attack patterns
- Dashboard → Section 15: Honeypot Attacks

**⚠️ Troubleshooting "Trying..." Connection Hangs:**

**MOST COMMON ISSUE: Firewall Rules Missing `-Profile Any`**

Windows "Public" networks block ALL inbound connections by default - UNLESS the firewall rule has `-Profile Any`.

**Step 1: Check Your Network Profile**
```powershell
Get-NetConnectionProfile | Select-Object Name, NetworkCategory
```

**Step 2: Check Firewall Rule Profile (Administrator PowerShell)**
```powershell
Get-NetFirewallRule -DisplayName "Battle-Hardened AI Honeypot" | Select-Object DisplayName, Profile, Enabled
```

**If Profile shows "Domain, Private" (NOT "Any") - THIS IS THE PROBLEM:**

```powershell
# FIX: Update existing rules to work on ALL profiles including Public
Set-NetFirewallRule -DisplayName "Battle-Hardened AI Honeypot" -Profile Any -Enabled True
Set-NetFirewallRule -DisplayName "Battle-Hardened AI Dashboard" -Profile Any -Enabled True

# Verify fix
Get-NetFirewallRule -DisplayName "*Battle-Hardened*" | Select-Object DisplayName, Profile, Enabled
# Profile should now show "Any"
```

**After Fixing Firewall, Test Connection:**
```powershell
# Test locally from Windows
Test-NetConnection -ComputerName 127.0.0.1 -Port 2222
# TcpTestSucceeded should be True

# Test from your Windows IP
Test-NetConnection -ComputerName 192.168.68.111 -Port 2222
# TcpTestSucceeded should be True
```

**From Kali Linux:**
```bash
telnet 192.168.68.111 2222
# Should connect immediately and show SSH banner
```

**Other Checks If Still Not Working:**

1. **Check ports are listening:**
   ```powershell
   netstat -an | Select-String "2121|2222|2323"
   # Should show: 0.0.0.0:2121 LISTENING
   ```

2. **Check server is running:**
   ```powershell
   Get-Process python
   # Should show python.exe process
   ```

3. **Check Wi-Fi Router AP Isolation:**
   - Some routers have "AP Isolation" or "Client Isolation" enabled
   - This blocks device-to-device communication on same network
   - Log into router admin panel → Wireless → Advanced → Disable AP Isolation

**✅ Installation Complete!**

---

## Relay Server Setup (Optional)

### Why Use a Relay Server?

**Problem: Local-Only Training**
- Each customer trains AI on their own attacks only
- Customer A: 100 attacks → AI knows 100 patterns
- Customer B: 200 attacks → AI knows 200 patterns
- **Result:** INCONSISTENT protection ❌

**Solution: Centralized Relay Training**
- Deploy relay server on VPS with ExploitDB (43,971 exploits)
- ALL customers download same centrally-trained models
- Customer A (Day 1): Downloads 43,971 patterns ✅
- Customer B (Month 3): Downloads 43,971 + real-world attacks ✅
- **Result:** EVERYONE protected equally (or better) ✅

### Architecture

```
Customer A (Japan)  ─┐
Customer B (USA)    ─┼─→  Relay Server (VPS)  ←─ ExploitDB (43,971 exploits)
Customer C (Europe) ─┘         │
                               ↓
                     Centralized AI Models
                     (Everyone downloads same models)
```

### Relay Server Deployment

**For detailed relay server setup, see: [relay/RELAY_SETUP.md](relay/RELAY_SETUP.md)**

**Quick Setup:**

```bash
# SSH into your VPS
ssh root@YOUR_VPS_IP

# Clone repository
git clone https://github.com/YOUR_USERNAME/battle-hardened-ai.git
cd battle-hardened-ai/relay

# Start relay server (downloads 43,971 ExploitDB exploits)
docker compose up -d

# Monitor ExploitDB download (takes 5-10 minutes)
docker compose logs -f | grep "ExploitDB"

# Verify relay is ready
curl -k https://YOUR_VPS_IP:60002/health
# Should return: {"status": "healthy", "exploits": 43971}
```

**VPS Requirements:**
- Ubuntu/Debian recommended
- Public IP address
- Ports 60001 (WebSocket), 60002 (API) open
- 4 GB RAM, 2 CPU cores
- 5 GB disk space (for ExploitDB)

---

## Client-Relay Configuration

### Connect Clients to Relay Server

**Option A: Environment Variables (Recommended)**

Create `.env` file in `server/` directory:

```bash
# server/.env
RELAY_ENABLED=true
RELAY_URL=wss://YOUR_VPS_IP:60001
RELAY_API_URL=https://YOUR_VPS_IP:60002
CUSTOMER_ID=customer-unique-id-here
PEER_NAME=customer-location-name
```

**Option B: Docker Compose (Linux)**

Edit `server/docker-compose.yml`:

```yaml
environment:
  - RELAY_ENABLED=true
  - RELAY_URL=wss://YOUR_VPS_IP:60001
  - RELAY_API_URL=https://YOUR_VPS_IP:60002
  - CUSTOMER_ID=customer-123
  - PEER_NAME=japan-office
```

**Restart Client:**

```bash
# Docker
docker compose down && docker compose up -d

# Native Python
# Restart server.py (Ctrl+C then rerun)
```

### Verify Relay Connection

**Check Client Logs:**

```bash
# Docker
docker compose logs --tail=100 | grep "AI\|RELAY"

# Native
# Check terminal output where server.py is running
```

**SUCCESS indicators:**
```
[AI] 🌐 Requesting training from relay server (43,971 ExploitDB exploits)...
[AI] ✅ Relay trained models using 43971 exploits
[AI] 📥 Downloading trained models from relay...
[AI] ✅ Downloaded anomaly detector (280 KB)
[AI] ✅ Downloaded threat classifier (280 KB)
[AI] ✅ Downloaded IP reputation model (280 KB)
[RELAY] ✅ Connected to relay server wss://YOUR_VPS_IP:60001
```

**FAILURE indicators (relay not configured):**
```
[AI] ⚠️  Relay training failed, falling back to local training
[AI] 🎓 AUTO-TRAINING locally with 100 historical threat events...
```

### Dashboard Verification

Open: **https://localhost:60000**

**Section 1 - AI Training Network – Shared Machine Learning:**
- Connection: ✅ Connected
- Last Sync: < 1 second ago
- Shared Attacks: 43,971+ patterns
- Model Version: v1.x.x

**Section 4 - Real AI/ML Models – Machine Learning Intelligence:**
- Training Data Size: Should show **43,971+** (not 100-1000)
- Last Trained: Recent timestamp
- Models Status: All showing "TRAINED ✅"

### Training & Synchronization

#### How Training Works

**Without Relay (Default):**
```
1. Client starts → No models exist
2. Loads threat_log.json (100-1000 local attacks)
3. Trains models locally (30 seconds)
4. Result: AI knows 100-1000 patterns
```

**With Relay (Configured):**
```
1. Client starts → No models exist
2. Calls RELAY_API_URL/train
3. Relay trains using 43,971 ExploitDB exploits (3-5 min)
4. Client downloads 3 model files (280 KB each)
5. Result: AI knows 43,971+ patterns ✅
```

#### Model Update Frequency

**Automatic Updates:**
- Client checks relay every **24 hours**
- Downloads new models if relay version is newer
- No downtime during update

**Manual Retrain:**
```bash
# Force immediate retrain from relay
curl -k -X POST https://localhost:60000/inspector/ai-monitoring/retrain-ml
```

#### Training Data Growth

**Month 1:**
- Relay: 43,971 ExploitDB + 0 real attacks = 43,971 patterns
- New customer downloads 43,971 patterns

**Month 6:**
- Customer A experienced 5,000 attacks
- Customer B experienced 3,000 attacks
- Relay: 43,971 + 8,000 = 51,971 patterns
- New customer downloads 51,971 patterns ✅

**Year 1:**
- 100 customers, avg 1,000 attacks each
- Relay: 43,971 + 100,000 = 143,971 patterns
- New customer downloads 143,971 patterns ✅ (INSTANT EXPERT!)

#### Troubleshooting Relay Training

**Issue: "Relay training failed, falling back to local"**

**Cause:** Can't connect to RELAY_API_URL

**Fix:**
```bash
# Test connection from client machine
curl -k https://YOUR_VPS_IP:60002/health

# If fails, check:
# 1. VPS firewall allows port 60002
# 2. Docker container running on VPS: docker compose ps
# 3. RELAY_API_URL correct in .env file
```

**Issue: Training Data Shows 100-1000 (not 43,971)**

**Cause:** Using local training, relay not connected

**Fix:**
```bash
# Check environment variables (Docker)
docker compose exec battle-hardened-ai env | grep RELAY

# Should show:
# RELAY_ENABLED=true
# RELAY_API_URL=https://YOUR_VPS_IP:60002

# If empty, update .env and restart
docker compose down && docker compose up -d
```

**Issue: Fresh Installation Has 0 Threat Data**

**Cause:** No attacks detected yet, threat_log.json empty

**Solution:**
- **With Relay:** Training uses ExploitDB (43,971 patterns) - no local data needed ✅
- **Without Relay:** Generate attacks to populate threat_log.json:
  ```bash
  # From another machine (e.g., Kali Linux)
  curl -k "https://CLIENT_IP:60000/test?id=1'%20OR%20'1'='1"
  curl -k "https://CLIENT_IP:60000/test?name=<script>alert(1)</script>"
  nmap -sS CLIENT_IP
  # Repeat 10-20 times to build training data
  ```

## Detection Capability Comparison

### Platform Capabilities Summary

| Platform | Signal #1 (Kernel) | Signals #2-20 | Total Capability | Network-Wide | Deployment Method |
|----------|-------------------|---------------|------------------|--------------|-------------------|
| **Linux** | ✅ eBPF (100%) | ✅ Full (100%) | **100%** | ✅ Yes | .deb/.rpm package (gateway/appliance) |
| **Windows** | ⚠️ Scapy (98%) | ✅ Full (100%) | **~99%** | ✅ Yes | Windows EXE installer |

### Signal #1 Differences: Linux eBPF vs Windows/macOS Scapy

| Capability | Linux (eBPF) | Windows (Scapy) |
|------------|-------------|----------------------|
| **Packet capture** | ✅ Kernel-level | ✅ Userland (Npcap/libpcap) |
| **Syscall correlation** | ✅ Process→network mapping | ❌ Limited |
| **Process integrity** | ✅ Kernel verification | ⚠️ Userland only |
| **Attack detection** | 100% | ~98% |

**Practical Impact:**
- **99%+ of attacks are still detected** (Signals #2-20 handle most threats)
- Lost capabilities mainly affect:
  - Advanced rootkit detection (rare)
  - Kernel-level tampering (Signal #18 still works at userland level)
  - Process injection mapping (Signal #4 Privilege Escalation still works)
- **For network-based attacks** (vast majority): No difference in detection

**Bottom Line:** Windows/macOS users get 98-99% detection capability vs Linux 100%.

---

## Post-Installation

### Verify Everything Works

**Linux (Docker):**
```bash
# Check container status
docker ps
# Expected: battle-hardened-ai Up (healthy)

# Check logs
docker logs battle-hardened-ai --tail 50

# Access dashboard
curl -k https://localhost:60000
```

**Windows/macOS (Native):**
```powershell
# Check server is running
Get-Process python  # Windows
ps aux | grep python  # macOS

# Check logs in terminal where server is running

# Access dashboard
curl -k https://localhost:60000  # macOS
curl.exe -k https://localhost:60000  # Windows
```

### Dashboard Sections

Navigate to **https://localhost:60000** and verify all sections:

1. **Threat Overview** - Should show 0 threats initially
2. **20 Detection Signals** - All should be green/active
3. **ML Model Status** - All 5 models trained
4. **Network Statistics** - Live packet capture stats
5. **Top Threats** - Initially empty
6. **Recent Alerts** - Initially empty
7. **Geographic Threat Map** - World map visualization
8. **Attack Timeline** - Initially empty
9. **Blocked IPs** - Initially empty
10. **MITRE ATT&CK Coverage** - 98 techniques covered
11. **Compliance Status** - Regulatory framework compliance
12. **System Resources** - CPU, RAM, disk usage
13. **Relay Status** - Connected (if relay enabled) or Disabled
14. **Explainability Log** - AI decision explanations
15. **Honeypot Attacks** - Attack logs (Windows/macOS only)

### Test Attack Detection

**Simulate attacks from another machine:**

```bash
# Port scan (should trigger Signal #10 Graph Intelligence)
nmap -sS 192.168.X.X

# SQL injection attempt (should trigger multiple signals)
curl "http://192.168.X.X/login?user=admin'--"

# SSH brute force simulation (should trigger Signal #7 LSTM Sequences)
# (requires SSH service running on target)
```

Check dashboard for detected threats.

---

## Troubleshooting

### Common Issues

#### 1. Docker: "Cannot connect to Docker daemon"

**Linux:**
```bash
# Start Docker service
sudo systemctl start docker

# Enable on boot
sudo systemctl enable docker

# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker
```

**Windows/macOS:**
- Start Docker Desktop application
- Wait for "Docker is running" notification

#### 2. Windows: "Npcap not found" or Scapy errors

```powershell
# Reinstall Npcap from: https://npcap.com/#download
# Ensure "WinPcap API-compatible mode" is checked

## Post-Installation

### Verify Everything Works

**Linux (.deb/.rpm appliance):**
```bash
# Check systemd service status
sudo systemctl status battle-hardened-ai
sudo systemctl status battle-hardened-ai-firewall-sync

# Check recent logs for the main service
sudo journalctl -u battle-hardened-ai -n 50 --no-pager

# From an admin workstation, verify dashboard is reachable
curl -k https://YOUR_GATEWAY_IP:60000 || echo "curl failed"
```

**Windows (EXE installer):**
```powershell
# Verify the Battle-Hardened AI Windows service is running
Get-Service | Where-Object { $_.DisplayName -like "*Battle-Hardened AI*" }

# From the Windows host, verify dashboard is reachable
curl.exe -k https://localhost:60000
```

### Service Control and Shutdown (Linux appliances)

To safely stop Battle-Hardened AI on a Debian/Ubuntu gateway:

```bash
sudo systemctl stop battle-hardened-ai battle-hardened-ai-firewall-sync
```

To prevent automatic start on boot:

```bash
sudo systemctl disable battle-hardened-ai battle-hardened-ai-firewall-sync
```

To fully shut down the Linux gateway after stopping services:

```bash
sudo shutdown now    # or: sudo poweroff
```
# Linux: Find process using port 60000
sudo lsof -i :60000
sudo kill -9 <PID>

# Windows: Find and kill process
netstat -ano | Select-String "60000"
Stop-Process -Id <PID> -Force
```

#### 5. ML Models not training

```bash
# Check logs for training errors
docker logs battle-hardened-ai | grep -E "ML|TRAINED|synthetic"

# Rebuild container (fix should be in latest code)
cd battle-hardened-ai/server
git pull
docker compose down
docker compose up -d --build
```

#### 6. SSL Certificate errors

**Expected:** Self-signed certificates show browser warnings

**Solution:** Click "Advanced" → "Proceed to localhost (unsafe)"

**For production:** Replace with real certificates:
```bash
# Place certificates in server/crypto_keys/
server/crypto_keys/ssl_cert.pem
server/crypto_keys/ssl_key.pem
```

---

## Updating

For production customers, updates should follow your normal package/installer process.

### Linux (.deb/.rpm)

- Obtain the new signed package from the vendor.
- On Debian/Ubuntu:

```bash
sudo dpkg -i battle-hardened-ai_*.deb
sudo apt-get install -f
```

- On RHEL/CentOS/Rocky/Alma:

```bash
sudo dnf install ./battle-hardened-ai-*.rpm
```

Runtime data under `/var/lib/battle-hardened-ai` and configuration under `/etc/battle-hardened-ai/.env` are preserved across upgrades.

### Windows (EXE installer)

- Download the latest `BattleHardenedAI-Setup.exe` from the vendor.
- Run the installer on the target host; it will upgrade the existing installation in-place.
- Verify that your `.env.windows` and `shared_secret.key` are still present in the install directory; re-apply only if the vendor release notes indicate format changes.

---

## Uninstallation

### Linux (.deb/.rpm)

```bash
sudo systemctl stop battle-hardened-ai battle-hardened-ai-firewall-sync
sudo apt-get remove battle-hardened-ai        # Debian/Ubuntu
# or
sudo dnf remove battle-hardened-ai            # RHEL-family
```

Optionally remove residual data and logs:

```bash
sudo rm -rf /var/lib/battle-hardened-ai /var/log/battle-hardened-ai /etc/battle-hardened-ai
```

### Windows (EXE installer)

- Use **Apps & Features** / **Programs and Features** in Windows to uninstall "Battle-Hardened AI".
- This removes the installed binaries and Windows service. If you created any additional firewall rules or data directories, clean them up according to your local policy.

---

docker compose up -d
docker compose down
docker compose restart
docker logs -f battle-hardened-ai
git pull && docker compose up -d --build
docker exec -it battle-hardened-ai bash
git pull
## Support & Resources

### Documentation
- [README.md](README.md) - Features, architecture, MITRE ATT&CK coverage
- [relay/RELAY_SETUP.md](relay/RELAY_SETUP.md) - VPS relay server setup (detailed guide)
- [testconnection.md](testconnection.md) - Client relay troubleshooting
- [Dashboard.md](Dashboard.md) - Dashboard features and usage
- [Ai-instructions.md](documentation/Ai-instructions.md) - AI capabilities and detection logic

### Quick Commands Reference (Packaged Installs)

**Linux (.deb/.rpm):**
```bash
# Start / stop services
sudo systemctl start battle-hardened-ai battle-hardened-ai-firewall-sync
sudo systemctl stop battle-hardened-ai battle-hardened-ai-firewall-sync

# Check status and logs
sudo systemctl status battle-hardened-ai
sudo journalctl -u battle-hardened-ai -n 50 --no-pager
```

**Windows (EXE installer):**
```powershell
# Check Windows service
Get-Service | Where-Object { $_.DisplayName -like "*Battle-Hardened AI*" }

# Start/stop via Services MMC or:
Start-Service -Name "BattleHardenedAI" -ErrorAction SilentlyContinue
Stop-Service -Name "BattleHardenedAI" -ErrorAction SilentlyContinue
```

### Getting Help

**Before asking for help, collect this information:**

1. **Platform:** Linux (.deb/.rpm) or Windows (EXE)
2. **Package/installer version:** As reported by the vendor or OS package manager
3. **Logs:**
   ```bash
   # Linux packaged service
   sudo journalctl -u battle-hardened-ai -n 200 --no-pager > bhai-linux-logs.txt
   ```
   On Windows, capture relevant Windows Event Viewer entries and any application logs referenced by support.

**Submit Issues:**
- GitHub Repository: https://github.com/yuhisern7/battle-hardened-ai
- Include logs, platform info, and steps to reproduce

---

**Last Updated:** January 11, 2026  
**Version:** 3.0  
**Compatibility:**
- Docker 20.10+, Docker Compose v2.0+
- Python 3.10+, Npcap 1.70+ (Windows), libpcap (macOS)
