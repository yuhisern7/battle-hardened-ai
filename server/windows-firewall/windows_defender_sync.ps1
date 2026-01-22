param(
    [string]$JsonPath,
    [string]$RuleName = "Battle-Hardened AI Blocked IPs"
)

# If no JSON path is provided, default to the standard location
# used by the Windows EXE install:
#   <InstallDir>\server\json\blocked_ips.json
if (-not $JsonPath -or $JsonPath.Trim() -eq "") {
    try {
        $baseDir = Split-Path -Parent $PSScriptRoot
        $serverDir = Join-Path $baseDir "server"
        $JsonPath = Join-Path $serverDir "json\blocked_ips.json"
    }
    catch {
        Write-Host "[windows_defender_sync] Failed to resolve default JsonPath from script location: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

function Get-BlockedIpsFromJson {
    param([string]$Path)

    if (-not (Test-Path -Path $Path)) {
        Write-Host "[windows_defender_sync] JSON file not found at '$Path' (no IPs synced)" -ForegroundColor Yellow
        return @()
    }

    try {
        $json = Get-Content -Path $Path -Raw | ConvertFrom-Json
    }
    catch {
        Write-Host "[windows_defender_sync] Failed to parse JSON: $($_.Exception.Message)" -ForegroundColor Yellow
        return @()
    }

    if (-not $json.blocked_ips) {
        return @()
    }

    $ips = @()
    foreach ($entry in $json.blocked_ips) {
        if ($entry.ip -and ($entry.ip -is [string])) {
            $ips += $entry.ip
        }
    }
    return $ips | Sort-Object -Unique
}

function Set-BhFirewallRule {
    param(
        [string]$Name,
        [string[]]$RemoteAddresses
    )

    # Windows firewall does not allow an empty RemoteAddress list, so we use a harmless placeholder
    $addresses = if ($RemoteAddresses -and $RemoteAddresses.Count -gt 0) { $RemoteAddresses } else { "0.0.0.0" }

    $rule = Get-NetFirewallRule -DisplayName $Name -ErrorAction SilentlyContinue
    if (-not $rule) {
        New-NetFirewallRule \
            -DisplayName $Name \
            -Direction Inbound \
            -Action Block \
            -Profile Any \
            -RemoteAddress $addresses \
            -Enabled True | Out-Null
    }
    else {
        Set-NetFirewallRule -DisplayName $Name -Enabled True | Out-Null
        Set-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -RemoteAddress $addresses | Out-Null
    }
}

$ips = Get-BlockedIpsFromJson -Path $JsonPath
Write-Host "[windows_defender_sync] Syncing $($ips.Count) blocked IPs into firewall rule '$RuleName'" -ForegroundColor Cyan
Set-BhFirewallRule -Name $RuleName -RemoteAddresses $ips
