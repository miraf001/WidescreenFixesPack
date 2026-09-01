[CmdletBinding()]
param(
    [ValidateRange(1, 120)]
    [int]$TimeoutSeconds = 30,
    [UInt32]$Owner = 0
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

$python = Get-Command python.exe -ErrorAction Stop
$previousPythonPath = $env:PYTHONPATH
try {
    $env:PYTHONPATH = if ($previousPythonPath) {
        "$fridaRoot;$previousPythonPath"
    } else {
        $fridaRoot
    }
    & $python.Source (Join-Path $PSScriptRoot 'diff-rerev2-gui-traversal.py') `
        --pid $game[0].Id `
        --timeout-seconds $TimeoutSeconds `
        --owner ('0x{0:X8}' -f $Owner)
    exit $LASTEXITCODE
}
finally {
    $env:PYTHONPATH = $previousPythonPath
}
