[CmdletBinding()]
param(
    [ValidateSet('Release', 'Debug')]
    [string]$Configuration = 'Release',

    [string]$GamePath,

    [switch]$OverwriteIni,

    [switch]$InstallLoader,

    [switch]$IncludeSymbols
)

$ErrorActionPreference = 'Stop'

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$configKey = $Configuration.ToLowerInvariant()
$packageDir = Join-Path $repoRoot "out\packages\rerev2\$configKey"

if ([string]::IsNullOrWhiteSpace($GamePath)) {
    $GamePath = [System.Environment]::GetEnvironmentVariable('REREV2_GAME_DIR')
}

if ([string]::IsNullOrWhiteSpace($GamePath)) {
    throw 'Specify -GamePath or set REREV2_GAME_DIR.'
}

$gameRoot = [System.IO.Path]::GetFullPath($GamePath)
if (-not (Test-Path -LiteralPath $gameRoot -PathType Container)) {
    throw "Game directory does not exist: $gameRoot"
}
if (-not (Test-Path -LiteralPath $packageDir -PathType Container)) {
    throw "Package not found: $packageDir. Run tools\build.ps1 first."
}

$packageScripts = Join-Path $packageDir 'scripts'
$gameScripts = Join-Path $gameRoot 'scripts'
New-Item -ItemType Directory -Path $gameScripts -Force | Out-Null

function Backup-FileBeforeOverwrite([string]$SourceFile, [string]$DestinationFile) {
    if (-not (Test-Path -LiteralPath $DestinationFile -PathType Leaf)) {
        return
    }

    $sourceHash = (Get-FileHash -LiteralPath $SourceFile -Algorithm SHA256).Hash
    $destinationHash = (Get-FileHash -LiteralPath $DestinationFile -Algorithm SHA256).Hash
    if ($sourceHash -eq $destinationHash) {
        return
    }

    $backupDir = Join-Path $gameScripts '.fusionfix-backups'
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
    $backupName = "{0}.{1}.bak" -f ([System.IO.Path]::GetFileName($DestinationFile)), $timestamp
    $backupPath = Join-Path $backupDir $backupName
    Copy-Item -LiteralPath $DestinationFile -Destination $backupPath
    Write-Host "Backed up: $backupPath"
}

$asiFiles = Get-ChildItem -LiteralPath $packageScripts -Filter '*.asi' -File
if ($asiFiles.Count -ne 1) {
    throw "Expected exactly one ASI file in $packageScripts, found $($asiFiles.Count)."
}
$asiDestination = Join-Path $gameScripts $asiFiles[0].Name
Backup-FileBeforeOverwrite $asiFiles[0].FullName $asiDestination
Copy-Item -LiteralPath $asiFiles[0].FullName -Destination $asiDestination -Force
Write-Host "Deployed: $($asiFiles[0].Name)"

$iniFiles = Get-ChildItem -LiteralPath $packageScripts -Filter '*.ini' -File
foreach ($ini in $iniFiles) {
    $destination = Join-Path $gameScripts $ini.Name
    if ($OverwriteIni -or -not (Test-Path -LiteralPath $destination)) {
        Backup-FileBeforeOverwrite $ini.FullName $destination
        Copy-Item -LiteralPath $ini.FullName -Destination $destination -Force
        Write-Host "Deployed: $($ini.Name)"
    } else {
        Write-Host "Kept existing INI: $destination"
    }
}

if ($IncludeSymbols) {
    Get-ChildItem -LiteralPath $packageScripts -Filter '*.pdb' -File | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $gameScripts $_.Name) -Force
        Write-Host "Deployed symbols: $($_.Name)"
    }
}

if ($InstallLoader) {
    $loaderMarker = Join-Path $packageDir 'dinput8.ual'
    $loaderDestination = Join-Path $gameRoot 'dinput8.ual'
    if (-not (Test-Path -LiteralPath $loaderMarker)) {
        throw "Loader marker not found in package: $loaderMarker"
    }
    if (-not (Test-Path -LiteralPath $loaderDestination)) {
        Copy-Item -LiteralPath $loaderMarker -Destination $loaderDestination
        Write-Host 'Installed dinput8.ual marker.'
    } else {
        Write-Host "Kept existing loader marker: $loaderDestination"
    }
}

Write-Host "Deployment complete: $gameRoot"
