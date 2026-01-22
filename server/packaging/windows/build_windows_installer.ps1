<#
Build script for Battle-Hardened AI Windows installer.

Steps:
1. Ensures a fresh PyInstaller build of BattleHardenedAI.exe in server/dist
   (uses server/BattleHardenedAI.spec).
2. Runs Inno Setup (ISCC.exe) against BattleHardenedAI.iss to produce
   BattleHardenedAI-Setup.exe in server\packaging\windows.
3. Cleans up the temporary PyInstaller exe if this script created it, so
   you only care about the Inno installer output.
#>

param(
    [string]$InnoSetupCompiler = "ISCC.exe",
    [string]$Python = "python"
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$repoRoot = Resolve-Path (Join-Path $scriptDir "..\..\..")

# Prefer the project virtualenv's python.exe if available and no Python
# override was explicitly passed.
if (-not $PSBoundParameters.ContainsKey('Python')) {
    $venvPython = Join-Path $repoRoot ".venv\Scripts\python.exe"
    if (Test-Path $venvPython) {
        $Python = $venvPython
    }
}

# Paths for PyInstaller build
$serverDir = Join-Path $repoRoot "server"
$specPath  = Join-Path $serverDir "BattleHardenedAI.spec"
# PyInstaller by default writes dist/ at the current working directory
# (the repo root for this script), so expect the exe at <repoRoot>/dist.
$distDir   = Join-Path $repoRoot "dist"
$exePath   = Join-Path $distDir "BattleHardenedAI.exe"

if (-not (Test-Path $specPath)) {
    Write-Error "PyInstaller spec file not found at $specPath."
    exit 1
}

$pyInstallerBuiltHere = $false

if (-not (Test-Path $exePath)) {
    Write-Host "[build_windows_installer] BattleHardenedAI.exe not found, building with PyInstaller from spec: $specPath" -ForegroundColor Cyan

    & $Python "-m" "PyInstaller" $specPath

    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $exePath)) {
        Write-Error "PyInstaller build failed or BattleHardenedAI.exe was not created at $exePath."
        exit 1
    }

    $pyInstallerBuiltHere = $true
}

$issPath = Join-Path $scriptDir "BattleHardenedAI.iss"
if (-not (Test-Path $issPath)) {
    Write-Error "Inno Setup script not found at $issPath."
    exit 1
}

Write-Host "[build_windows_installer] Using Inno Setup compiler: $InnoSetupCompiler" -ForegroundColor Cyan
Write-Host "[build_windows_installer] Repository root: $repoRoot" -ForegroundColor Cyan

& $InnoSetupCompiler $issPath

if ($LASTEXITCODE -ne 0) {
    Write-Error "Inno Setup compilation failed with exit code $LASTEXITCODE."
    exit $LASTEXITCODE
}

Write-Host "[build_windows_installer] Installer build complete. Check BattleHardenedAI-Setup.exe in $scriptDir" -ForegroundColor Green
