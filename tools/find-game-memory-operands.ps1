[CmdletBinding()]
param(
    [Parameter(Mandatory, ValueFromRemainingArguments)]
    [string[]]$Displacement
)

$ErrorActionPreference = 'Stop'
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$capstoneRoot = Join-Path $repoRoot 'out\toolchain\capstone-5.0.9'
$game = @(Get-Process -Name 'rerev2' -ErrorAction Stop)
if ($game.Count -ne 1) {
    throw "Expected exactly one rerev2 process, found $($game.Count)."
}

$previousPythonPath = $env:PYTHONPATH
try {
    $env:PYTHONPATH = if ($previousPythonPath) {
        "$capstoneRoot;$previousPythonPath"
    } else {
        $capstoneRoot
    }
    $arguments = @(
        (Join-Path $PSScriptRoot 'find-process-memory-operands.py'),
        '--pid', $game[0].Id,
        '--base', '0x00401000',
        '--size', '0x00E3E000'
    )
    foreach ($item in $Displacement) {
        $arguments += @('--displacement', $item)
    }
    & (Get-Command python.exe -ErrorAction Stop).Source @arguments
    exit $LASTEXITCODE
}
finally {
    $env:PYTHONPATH = $previousPythonPath
}
