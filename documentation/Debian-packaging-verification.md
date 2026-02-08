# Debian Package Build Verification Checklist

This checklist ensures the **entire packaging system** works end-to-end, not just individual files.

## 1. File Structure Verification

### Required Files Exist
- [ ] `packaging/health-check.sh` (263 lines)
- [ ] `packaging/debian-startup.sh` (264 lines)
- [ ] `packaging/debian-uninstall.sh`
- [ ] `packaging/debian/battle-hardened-ai.postinst` (201 lines)
- [ ] `packaging/debian/battle-hardened-ai.prerm`
- [ ] `packaging/debian/battle-hardened-ai.postrm`
- [ ] `packaging/debian/rules` (Makefile)
- [ ] `packaging/debian/control`
- [ ] `packaging/debian/changelog`
- [ ] `packaging/debian/source/format`
- [ ] `packaging/build-deb.sh`

### No Duplicate Files
- [ ] Only ONE postinst file exists: `battle-hardened-ai.postinst` (NOT plain `postinst`)
- [ ] No orphaned debian/ files

## 2. debian/rules Verification (Makefile Format)

### All Directories Copied
```makefile
cp -a ../AI ../server ../policies ../assets $(DESTDIR)/opt/battle-hardened-ai/
```
- [ ] `AI/` directory will be copied
- [ ] `server/` directory will be copied
- [ ] `policies/` directory will be copied
- [ ] `assets/` directory will be copied

### packaging/ Directory Handled Correctly
```makefile
mkdir -p debian/battle-hardened-ai/opt/battle-hardened-ai/packaging
cp -a health-check.sh debian-startup.sh debian-uninstall.sh ...
cp -a systemd debian/battle-hardened-ai/opt/battle-hardened-ai/packaging/systemd
```
- [ ] `packaging/health-check.sh` will be copied
- [ ] `packaging/debian-startup.sh` will be copied
- [ ] `packaging/debian-uninstall.sh` will be copied
- [ ] `packaging/systemd/` directory will be copied

### Systemd Units Installed
```makefile
mkdir -p debian/battle-hardened-ai/lib/systemd/system
cp -a systemd/battle-hardened-ai.service debian/battle-hardened-ai/lib/systemd/system/
cp -a systemd/firewall-sync.service debian/battle-hardened-ai/lib/systemd/system/
```
- [ ] `battle-hardened-ai.service` will be installed to `/lib/systemd/system/`
- [ ] `firewall-sync.service` will be installed to `/lib/systemd/system/`

### Configuration Directories Created
- [ ] `/etc/battle-hardened-ai/policies/step21/` created
- [ ] `/etc/battle-hardened-ai/.env.template` installed
- [ ] `/var/log/battle-hardened-ai/` directory created

## 3. battle-hardened-ai.postinst Verification

### Script Integration
```bash
#!/bin/bash
set -e

# ... user creation, directories, JSON seeding ...
# ... Python venv creation ...
# ... Crypto key generation ...

# CRITICAL: Call debian-startup.sh for firewall + health check
if [ -f /opt/battle-hardened-ai/packaging/debian-startup.sh ]; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "📋 Post-Install Setup"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    /opt/battle-hardened-ai/packaging/debian-startup.sh
```
- [ ] postinst calls `debian-startup.sh` after Python venv creation
- [ ] postinst displays installation status banner
- [ ] postinst captures exit code from debian-startup.sh
- [ ] postinst only enables services (doesn't restart - debian-startup.sh handles that)

## 4. build-deb.sh Verification

### Line Ending Normalization
```bash
FILES_TO_NORMALIZE="debian/rules debian/control debian/changelog debian/compat debian/battle-hardened-ai.* debian/source/format health-check.sh debian-startup.sh debian-uninstall.sh"
```
- [ ] All debian/ packaging files normalized to Unix line endings
- [ ] `health-check.sh` normalized
- [ ] `debian-startup.sh` normalized
- [ ] `debian-uninstall.sh` normalized

### Execute Permissions Set
```bash
chmod +x debian/rules
chmod +x health-check.sh
chmod +x debian-startup.sh
chmod +x debian-uninstall.sh
chmod +x debian/battle-hardened-ai.postinst
```
- [ ] `debian/rules` is executable
- [ ] `health-check.sh` is executable
- [ ] `debian-startup.sh` is executable
- [ ] `debian-uninstall.sh` is executable
- [ ] `battle-hardened-ai.postinst` is executable

## 5. debian/control Dependencies

### Required Packages Listed
```
Depends: python3, python3-venv, systemd, iptables, iptables-persistent, ipset, curl, adduser
```
- [ ] `python3` (for Python 3.11+)
- [ ] `python3-venv` (for virtualenv)
- [ ] `systemd` (service management)
- [ ] `iptables` (firewall rules)
- [ ] `iptables-persistent` (save/restore rules)
- [ ] `ipset` (IP set management)
- [ ] `curl` (health checks)
- [ ] `adduser` (create bhai user)

## 6. debian/source/format

- [ ] File exists at `packaging/debian/source/format`
- [ ] Contains: `3.0 (quilt)`
- [ ] Fixes build warning: "no source format specified"

## 7. Code Quality Verification

### health-check.sh (263 lines)
- [ ] Uses `#!/bin/bash` shebang
- [ ] **NO `set -e`** (would exit on first error - we need to check ALL issues)
- [ ] Returns proper exit codes (0 = healthy, 1 = issues found)
- [ ] Color codes defined (GREEN, RED, YELLOW, BLUE, NC)
- [ ] Check functions: `check_service()`, `check_port()`, `check_path()`
- [ ] 7-step comprehensive checks:
  1. Firewall components (ipset, iptables rules)
  2. Services (battle-hardened-ai.service, firewall-sync.service)
  3. Network ports (60000, 2121, 2222, 2323)
  4. Python dependencies (requirements.txt)
  5. File permissions (/opt, /etc, /var/log)
  6. Log files (server.log, firewall.log)
  7. Dashboard accessibility (curl localhost:60000)

### debian-startup.sh (264 lines)
- [ ] Uses `#!/bin/bash` shebang
- [ ] Uses `set -o pipefail` (NOT `set -e` - too aggressive for installation)
- [ ] Returns proper exit codes via `exit $HEALTH_EXIT`
- [ ] Windows installer-style output: [1/8] through [8/8]
- [ ] Color-coded feedback (✅ green, ❌ red, ⚠️ yellow)
- [ ] 8-step installation process:
  1. Dependency check (auto-install if missing)
  2. Fix permissions (/opt, /etc, /var/log)
  3. Check .env template (warns if missing, NOT fatal)
  4. Install iptables-persistent
  5. Create ipsets (bh_whitelist, bh_blocked)
  6. Install iptables rules (INPUT, FORWARD, OUTPUT chains)
  7. Start services (systemctl start + enable)
  8. Run health-check.sh for verification
- [ ] Missing .env template is WARNING only (line 95 - NOT exit 1)
- [ ] Calls health-check.sh at end and captures exit code

### server.py API Endpoints
- [ ] `/api/health/status` endpoint exists (lines 2124-2209)
- [ ] Uses `shutil.which('ipset')` NOT deprecated `which` command (line 2152)
- [ ] Checks systemd services and ipsets
- [ ] Returns JSON: `{ healthy: bool, issues: [], issue_count: int }`
- [ ] `/api/health/check` endpoint exists (lines 2211-2249)
- [ ] Executes `/opt/battle-hardened-ai/packaging/health-check.sh`
- [ ] 30-second timeout
- [ ] Returns stdout, stderr, exit_code

### inspector_ai_monitoring.html Dashboard
- [ ] Health check banner HTML (lines 730-788) - hidden by default
- [ ] Health details modal (lines 790-820)
- [ ] `checkSystemHealth()` function (lines 12843-12869)
- [ ] Calls `/api/health/status` on page load (line 12967)
- [ ] Auto-refreshes health every 30 seconds (line 12975)
- [ ] Shows installation issues with severity indicators
- [ ] Dismissible banner with localStorage persistence

## 8. Build Output Verification

### Expected Build Warnings (ACCEPTABLE)
```
dpkg-buildpackage: warning: debian/changelog(l5): found eof where expected more change data or trailer
dpkg-shlibdeps: warning: can't extract name and version from library name 'libpython3.so'
dpkg-gencontrol: warning: Depends field of package battle-hardened-ai: substitution variable ${shlibs:Depends} used, but is not defined
dpkg-source: warning: no source format specified in debian/source/format, see dpkg-source(1)
```
- [ ] changelog warning is acceptable (single-version package)
- [ ] libpython3.so warning is acceptable (system Python)
- [ ] ${shlibs:Depends} warning is acceptable (no compiled libraries)
- [ ] ~~Source format warning~~ → **FIXED** (debian/source/format now exists)

### Build Must Succeed
```
dpkg-deb: building package 'battle-hardened-ai' in '../battle-hardened-ai_1.0.0_amd64.deb'.
 dpkg-genbuildinfo --build=binary -O../battle-hardened-ai_1.0.0_amd64.buildinfo
 dpkg-genchanges --build=binary -O../battle-hardened-ai_1.0.0_amd64.changes
dpkg-buildpackage: info: binary-only upload (no source included)
```
- [ ] `.deb` file created successfully
- [ ] No fatal errors during build

## 9. Package Contents Verification

### Extract and Verify (After Build)
```bash
dpkg -c ../battle-hardened-ai_1.0.0_amd64.deb | grep -E "(health-check|debian-startup|postinst)"
```
- [ ] `/opt/battle-hardened-ai/packaging/health-check.sh` is in package
- [ ] `/opt/battle-hardened-ai/packaging/debian-startup.sh` is in package
- [ ] `/opt/battle-hardened-ai/packaging/debian-uninstall.sh` is in package
- [ ] `/opt/battle-hardened-ai/packaging/systemd/` directory is in package
- [ ] `postinst` maintainer script exists (will be battle-hardened-ai.postinst)

### Directory Structure
```bash
dpkg -c ../battle-hardened-ai_1.0.0_amd64.deb
```
- [ ] `/opt/battle-hardened-ai/AI/` directory
- [ ] `/opt/battle-hardened-ai/server/` directory
- [ ] `/opt/battle-hardened-ai/policies/` directory
- [ ] `/opt/battle-hardened-ai/assets/` directory
- [ ] `/opt/battle-hardened-ai/packaging/` directory
- [ ] `/lib/systemd/system/battle-hardened-ai.service`
- [ ] `/lib/systemd/system/firewall-sync.service`
- [ ] `/etc/battle-hardened-ai/.env.template`

## 10. Installation Simulation Test

### Install Package
```bash
sudo dpkg -i ../battle-hardened-ai_1.0.0_amd64.deb
```
- [ ] Package installs without errors
- [ ] postinst displays: "📋 Post-Install Setup"
- [ ] debian-startup.sh shows [1/8] through [8/8] progress
- [ ] health-check.sh runs automatically at [8/8]
- [ ] Services start: battle-hardened-ai.service, firewall-sync.service
- [ ] Final status shows ✅ or ❌ for each step

### Post-Installation Verification
```bash
sudo systemctl status battle-hardened-ai.service
sudo systemctl status firewall-sync.service
sudo ipset list bh_whitelist
sudo ipset list bh_blocked
sudo iptables -L INPUT -n | grep "battle-hardened"
curl http://localhost:60000
```
- [ ] battle-hardened-ai.service is active (running)
- [ ] firewall-sync.service is active (running)
- [ ] ipset bh_whitelist exists (hash:ip)
- [ ] ipset bh_blocked exists (hash:ip)
- [ ] iptables rules installed (DROP chain, ACCEPT chain)
- [ ] Dashboard accessible on port 60000

### Manual Health Check
```bash
sudo /opt/battle-hardened-ai/packaging/health-check.sh
```
- [ ] Script executes without errors
- [ ] Shows 7-step comprehensive diagnostics
- [ ] Returns exit code 0 (healthy) or 1 (issues found)
- [ ] Output has color codes and symbols (✅❌⚠️)

## 11. Dashboard Integration Test

1. Open dashboard: `http://<debian-ip>:60000`
2. Check for installation issues banner
3. Click "View Details" to see full health check output
4. Click "Run Health Check" to re-run diagnostics
5. Verify banner dismisses and persists in localStorage

- [ ] Dashboard loads successfully
- [ ] Health check banner appears if issues detected
- [ ] Modal shows full health-check.sh output
- [ ] "Run Health Check" button works
- [ ] Banner dismissal persists across page reloads

## Checklist Summary

- **File Structure**: 11 required files, no duplicates
- **debian/rules**: Copies AI/, server/, policies/, assets/, packaging/
- **postinst**: Calls debian-startup.sh, displays status
- **build-deb.sh**: Normalizes line endings, sets execute permissions
- **debian/control**: All 8 dependencies listed
- **Code Quality**: No set -e in health scripts, proper exit codes
- **Build Output**: Expected warnings acceptable, .deb created
- **Package Contents**: All directories and scripts present
- **Installation**: Services start, firewall configured, health verified
- **Dashboard**: Banner shows issues, modal displays details

**All 11 sections must pass before claiming "packaging quality verified".**

---

## Lessons Learned

### What "Quality Check" Means for Packaging Systems:

1. **End-to-End Verification** - Not just individual files, but the ENTIRE BUILD → INSTALL → RUN chain
2. **Integration Points** - Verify debian/rules copies files, postinst calls scripts, services start
3. **Build Output Analysis** - Read build warnings to catch missing files, format issues
4. **Package Extraction Test** - Verify .deb contains expected files before installation
5. **Installation Simulation** - Test on clean system to catch missing dependencies, permission issues

### Common Packaging Mistakes to Avoid:

- ❌ Creating files but not updating debian/rules to copy them
- ❌ Writing postinst but not integrating it with existing postinst
- ❌ Forgetting to normalize line endings (Windows → Unix)
- ❌ Missing execute permissions on scripts
- ❌ Duplicate maintainer scripts (postinst vs package-name.postinst)
- ❌ Missing debian/source/format (causes build warnings)
- ❌ Using `set -e` in installation scripts (too aggressive, aborts on minor issues)
- ❌ Hard-coding exit 1 for non-fatal conditions (missing .env template)

**Quality = Code Quality + Integration + Build + Installation + Runtime Verification**
