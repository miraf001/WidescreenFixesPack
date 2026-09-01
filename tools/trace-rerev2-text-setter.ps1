[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Contains,
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
# Verified against runtime instructions: this shared text-copy wrapper begins at
# 0xE5E5B0 for the current Steam executable. ECX is the destination object and
# its second stack argument is the source UTF-8 string pointer.
$functionAddress = $module.BaseAddress.ToInt64() + 0xA5E5B0

$python = Get-Command python.exe -ErrorAction Stop
$previousPythonPath = $env:PYTHONPATH
try {
    $env:PYTHONPATH = if ($previousPythonPath) {
        "$fridaRoot;$previousPythonPath"
    } else {
        $fridaRoot
    }
    & $python.Source (Join-Path $PSScriptRoot 'trace-rerev2-text-setter.py') `
        --pid $game[0].Id `
        --function ('0x{0:X}' -f $functionAddress) `
        --contains $Contains `
        --timeout-seconds $TimeoutSeconds
    exit $LASTEXITCODE
}
finally {
    $env:PYTHONPATH = $previousPythonPath
}
