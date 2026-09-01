[CmdletBinding()]
param(
    [Parameter(Mandatory, ValueFromRemainingArguments)]
    [string[]]$Address,
    [ValidateSet('r', 'w', 'rw')]
    [string]$Access = 'r',
    [ValidateRange(1, 300)]
    [int]$TimeoutSeconds = 30
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
    $arguments = @(
        (Join-Path $PSScriptRoot 'watch-rerev2-pointer-access.py'),
        '--pid', $game[0].Id,
        '--access', $Access,
        '--timeout-seconds', $TimeoutSeconds
    )
    foreach ($item in $Address) {
        $arguments += @('--address', $item)
    }
    & $python.Source @arguments
    exit $LASTEXITCODE
}
finally {
    $env:PYTHONPATH = $previousPythonPath
}
