[CmdletBinding()]
param(
    [switch]$SelfTest,
    [switch]$NoSuppressMappedKeys,
    [switch]$StartReleased
)

$ErrorActionPreference = 'Stop'

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$toolRoot = Join-Path $repoRoot 'out\toolchain\gamepad-bridge'
$vendorRoot = Join-Path $toolRoot 'vendor'
$archive = Join-Path $vendorRoot 'vgamepad-0.1.0.tar.gz'
$packageRoot = Join-Path $vendorRoot 'vgamepad-0.1.0'
$packageEntryPoint = Join-Path $packageRoot 'vgamepad\__init__.py'
$expectedHash = '57F6BD01AEC0C172947517FB782D150EF9B285F7F4D524C317374FA5C24A89DE'
$configPath = Join-Path $repoRoot 'data\ResidentEvilRevelations2.FusionFix\gamepad-bridge.ini'
$bridgeScript = Join-Path $PSScriptRoot 'gamepad_bridge.py'

$python = Get-Command python.exe -ErrorAction SilentlyContinue
if (-not $python) {
    throw 'Python 3 was not found on PATH.'
}

if (-not (Test-Path -LiteralPath $packageEntryPoint)) {
    New-Item -ItemType Directory -Path $vendorRoot -Force | Out-Null
    if (-not (Test-Path -LiteralPath $archive)) {
        Write-Host 'Downloading the pinned vgamepad 0.1.0 source package...'
        & $python.Source -m pip download --disable-pip-version-check --no-deps --no-binary=:all: `
            --dest $vendorRoot 'vgamepad==0.1.0'
        if ($LASTEXITCODE -ne 0) {
            throw 'Unable to download vgamepad 0.1.0 from PyPI.'
        }
    }

    $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash
    if ($actualHash -ne $expectedHash) {
        throw "Unexpected vgamepad archive hash: $actualHash"
    }

    Write-Host 'Extracting the repo-local vgamepad client (no driver installation)...'
    & tar.exe -xzf $archive -C $vendorRoot
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $packageEntryPoint)) {
        throw 'Unable to extract the vgamepad client package.'
    }
}

$env:PYTHONPATH = $packageRoot
$arguments = @($bridgeScript, '--config', $configPath)
if ($SelfTest) {
    $arguments += '--self-test'
}
if ($NoSuppressMappedKeys) {
    $arguments += '--no-suppress'
}
if ($StartReleased) {
    $arguments += '--start-released'
}

& $python.Source @arguments
exit $LASTEXITCODE
