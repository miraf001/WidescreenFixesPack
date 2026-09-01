[CmdletBinding()]
param(
    [Parameter(Mandatory, ValueFromRemainingArguments)]
    [string[]]$MatchAddress,
    [ValidateRange(1, 900)]
    [int]$TimeoutSeconds = 300
)

$ErrorActionPreference = 'Stop'

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$fridaRoot = Join-Path $repoRoot 'out\toolchain\frida-17.17.0'
if (-not (Test-Path -LiteralPath (Join-Path $fridaRoot 'frida\__init__.py'))) {
    throw 'Pinned Frida 17.17.0 is not installed under out/toolchain.'
}

$game = Get-Process -Name 'rerev2' -ErrorAction Stop
if ($game.Count -ne 1) {
    throw "Expected exactly one rerev2 process, found $($game.Count)."
}
$module = $game.Modules | Where-Object { $_.ModuleName -eq 'rerev2.exe' }
# Runtime disassembly confirms that RVA 0x569E40 is the start of the
# direct-string setter. RVA 0x569E3E is the final immediate byte of the
# preceding `ret 8` instruction and must never be used as a hook boundary.
$functionAddress = $module.BaseAddress.ToInt64() + 0x569E40

$python = Get-Command python.exe -ErrorAction Stop
$previousPythonPath = $env:PYTHONPATH
try {
    $env:PYTHONPATH = if ($previousPythonPath) {
        "$fridaRoot;$previousPythonPath"
    } else {
        $fridaRoot
    }
    $arguments = @(
        (Join-Path $PSScriptRoot 'trace-process-call.py'),
        '--pid', $game.Id,
        '--function', ('0x{0:X}' -f $functionAddress),
        '--argument-index', 1,
        '--timeout-seconds', $TimeoutSeconds
    )
    foreach ($item in $MatchAddress) {
        $arguments += @('--match-address', $item)
    }
    & $python.Source @arguments
    exit $LASTEXITCODE
}
finally {
    $env:PYTHONPATH = $previousPythonPath
}
