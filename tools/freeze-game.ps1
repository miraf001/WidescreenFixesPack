[CmdletBinding()]
param(
    [ValidateRange(1, 1000)]
    [int]$PulseMilliseconds = 50
)

$ErrorActionPreference = 'Stop'

$game = Get-Process -Name 'rerev2' -ErrorAction Stop
if ($game.Count -ne 1) {
    throw "Expected exactly one rerev2 process, found $($game.Count)."
}

$python = Get-Command python.exe -ErrorAction Stop
& $python.Source (Join-Path $PSScriptRoot 'freeze-process.py') `
    --pid $game.Id --pulse-ms $PulseMilliseconds
exit $LASTEXITCODE
