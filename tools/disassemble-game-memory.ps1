[CmdletBinding()]
param(
    [Parameter(Mandatory, ValueFromRemainingArguments)]
    [string[]]$Address,
    [ValidateRange(1, 65536)]
    [int]$Size = 512
)

$ErrorActionPreference = 'Stop'

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$capstoneRoot = Join-Path $repoRoot 'out\toolchain\capstone-5.0.9'
if (-not (Test-Path -LiteralPath (Join-Path $capstoneRoot 'capstone\__init__.py'))) {
    throw 'Pinned Capstone 5.0.9 is not installed under out/toolchain.'
}

$game = Get-Process -Name 'rerev2' -ErrorAction Stop
if ($game.Count -ne 1) {
    throw "Expected exactly one rerev2 process, found $($game.Count)."
}

$python = Get-Command python.exe -ErrorAction Stop
$previousPythonPath = $env:PYTHONPATH
try {
    $env:PYTHONPATH = if ($previousPythonPath) {
        "$capstoneRoot;$previousPythonPath"
    } else {
        $capstoneRoot
    }
    $arguments = @(
        (Join-Path $PSScriptRoot 'disassemble-process-memory.py'),
        '--pid', $game.Id,
        '--size', $Size
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
