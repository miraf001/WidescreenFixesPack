[CmdletBinding()]
param(
    [string]$Contains = '',
    [string[]]$AddressRange = @(),
    [string[]]$PointerTable = @(),
    [ValidateRange(1, 900)]
    [int]$TimeoutSeconds = 180
)

$ErrorActionPreference = 'Stop'

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$fridaRoot = Join-Path $repoRoot 'out\toolchain\frida-17.17.0'
if (-not (Test-Path -LiteralPath (Join-Path $fridaRoot 'frida\__init__.py'))) {
    throw 'Pinned Frida 17.17.0 is not installed under out/toolchain.'
}

$game = @(Get-Process -Name 'rerev2' -ErrorAction Stop)
if ($game.Count -ne 1) {
    throw "Expected exactly one rerev2 process, found $($game.Count)."
}

$module = $game[0].Modules | Where-Object { $_.ModuleName -eq 'rerev2.exe' }
$functionAddress = $module.BaseAddress.ToInt64() + 0x554B40

$python = Get-Command python.exe -ErrorAction Stop
$previousPythonPath = $env:PYTHONPATH
try {
    $env:PYTHONPATH = if ($previousPythonPath) {
        "$fridaRoot;$previousPythonPath"
    } else {
        $fridaRoot
    }
    $arguments = @(
        (Join-Path $PSScriptRoot 'trace-rerev2-localization.py'),
        '--pid', $game[0].Id,
        '--function', ('0x{0:X}' -f $functionAddress),
        '--timeout-seconds', $TimeoutSeconds
    )
    if (-not [string]::IsNullOrEmpty($Contains)) {
        $arguments += @('--contains', $Contains)
    }
    foreach ($range in $AddressRange) {
        $arguments += @('--address-range', $range)
    }
    foreach ($table in $PointerTable) {
        $arguments += @('--pointer-table', $table)
    }
    & $python.Source @arguments
    exit $LASTEXITCODE
}
finally {
    $env:PYTHONPATH = $previousPythonPath
}
