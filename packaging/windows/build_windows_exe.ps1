# Build Battle-Hardened AI Windows EXE
# Outputs to packaging/windows/dist to keep all Windows artifacts together

param(
  [switch]$Clean
)

$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$repoRoot  = Resolve-Path (Join-Path $scriptDir "..\..")
$serverDir = Join-Path $repoRoot "server"
$specPath  = Join-Path $serverDir "BattleHardenedAI.spec"

# For Windows builds, keep all EXE artifacts local to this windows packaging folder
$distDir   = Join-Path $scriptDir "dist"
$buildDir  = Join-Path $scriptDir "build"

Push-Location $repoRoot
try {
  if ($Clean) {
    if (Test-Path $buildDir) { Remove-Item $buildDir -Recurse -Force }
    if (Test-Path $distDir)  { Remove-Item $distDir  -Recurse -Force }
  }

  if (-not (Test-Path $distDir)) { New-Item -ItemType Directory -Path $distDir | Out-Null }
  if (-not (Test-Path $buildDir)) { New-Item -ItemType Directory -Path $buildDir | Out-Null }

  pyinstaller $specPath -y `
    --distpath $distDir `
    --workpath $buildDir

  Write-Host "Build complete: $(Resolve-Path (Join-Path $distDir 'BattleHardenedAI.exe'))"
}
finally {
  Pop-Location
}
