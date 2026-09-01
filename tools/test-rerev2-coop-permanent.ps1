[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$testRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$testOut = Join-Path $testRoot 'out\tests\coop-permanent'
New-Item -ItemType Directory -Path $testOut -Force | Out-Null
$testPython = Get-Command python.exe -ErrorAction SilentlyContinue
if (-not $testPython) { throw 'Python 3 was not found' }
foreach ($dependency in @(
    @{ Name = 'unicorn'; Version = '2.1.3' },
    @{ Name = 'capstone'; Version = '5.0.9' }
)) {
    $target = Join-Path $testRoot "out\toolchain\$($dependency.Name)-$($dependency.Version)"
    $module = Join-Path $target $dependency.Name
    if (-not (Test-Path -LiteralPath $module)) {
        New-Item -ItemType Directory -Path $target -Force | Out-Null
        & $testPython.Source -m pip install --disable-pip-version-check --only-binary=:all: `
            --no-deps --target $target "$($dependency.Name)==$($dependency.Version)"
        if ($LASTEXITCODE -ne 0) { throw "Unable to install $($dependency.Name) test dependency" }
    }
}
$testVswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
$testVs = @(& $testVswhere -all -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath) |
    Where-Object { $_ -and (Test-Path -LiteralPath (Join-Path $_.Trim() 'Common7\Tools\VsDevCmd.bat')) } |
    Select-Object -Last 1
if (-not $testVs) { throw 'MSVC build tools not found' }
$testDev = Join-Path $testVs.Trim() 'Common7\Tools\VsDevCmd.bat'
$testSource = Join-Path $testRoot 'source\ResidentEvilRevelations2.FusionFix\tests\coop_native_dump.cpp'
$testExe = Join-Path $testOut 'coop-native-dump.exe'
$testObj = Join-Path $testOut 'coop-native-dump.obj'
$testCommand = "call `"$testDev`" -no_logo -arch=x86 -host_arch=x64 >nul && cl /nologo /std:c++17 /EHsc /O2 /MT /W4 `"$testSource`" /Fo`"$testObj`" /Fe`"$testExe`""
& $env:ComSpec /d /s /c $testCommand
if ($LASTEXITCODE -ne 0) { throw 'Offline C++ code-generator build failed' }
& $testPython.Source (Join-Path $PSScriptRoot 'test-rerev2-coop-permanent.py') --dump-exe $testExe
if ($LASTEXITCODE -ne 0) { throw 'Offline permanent co-op tests failed' }
