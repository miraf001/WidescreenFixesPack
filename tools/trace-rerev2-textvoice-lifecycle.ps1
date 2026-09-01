[CmdletBinding()]
param(
    [ValidateRange(1, 120)]
    [int]$WaitSeconds = 30,
    [ValidateRange(1, 120)]
    [int]$TraceSeconds = 35
)

$ErrorActionPreference = 'Stop'
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$fridaRoot = Join-Path $repoRoot 'out\toolchain\frida-17.17.0'
if (-not (Test-Path -LiteralPath (Join-Path $fridaRoot 'frida\__init__.py'))) {
    throw 'Pinned Frida 17.17.0 is not installed under out/toolchain.'
}

$python = Get-Command python.exe -ErrorAction Stop
$previousPythonPath = $env:PYTHONPATH
try {
    $env:PYTHONPATH = if ($previousPythonPath) {
        "$fridaRoot;$previousPythonPath"
    } else {
        $fridaRoot
    }
    & $python.Source (Join-Path $PSScriptRoot 'trace-rerev2-textvoice-lifecycle.py') `
        --wait-seconds $WaitSeconds `
        --trace-seconds $TraceSeconds
    exit $LASTEXITCODE
}
finally {
    $env:PYTHONPATH = $previousPythonPath
}
