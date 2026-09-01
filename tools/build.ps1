[CmdletBinding()]
param(
    [ValidateSet('Release', 'Debug')]
    [string]$Configuration = 'Release',

    [switch]$Clean,

    [switch]$UseInstalledStl
)

$ErrorActionPreference = 'Stop'

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$outRoot = [System.IO.Path]::GetFullPath((Join-Path $repoRoot 'out'))
$configKey = $Configuration.ToLowerInvariant()
$buildDir = [System.IO.Path]::GetFullPath((Join-Path $outRoot "build\rerev2-$configKey"))
$packageDir = [System.IO.Path]::GetFullPath((Join-Path $outRoot "packages\rerev2\$configKey"))

function Assert-PathUnderOutRoot([string]$PathToCheck) {
    $normalizedRoot = $outRoot.TrimEnd('\') + '\'
    $normalizedPath = [System.IO.Path]::GetFullPath($PathToCheck)
    if (-not $normalizedPath.StartsWith($normalizedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to modify a path outside $outRoot`: $normalizedPath"
    }
}

if ($Clean) {
    foreach ($target in @($buildDir, $packageDir)) {
        Assert-PathUnderOutRoot $target
        if (Test-Path -LiteralPath $target) {
            Remove-Item -LiteralPath $target -Recurse -Force
        }
    }
}

$requiredSubmodules = @(
    'external\hooking\Hooking.Patterns.cpp',
    'external\injector\safetyhook\src\mid_hook.cpp',
    'external\inireader\IniReader.h',
    'external\minidx9\Lib\x86\d3dx9.lib'
)
foreach ($relativePath in $requiredSubmodules) {
    if (-not (Test-Path -LiteralPath (Join-Path $repoRoot $relativePath))) {
        throw "Missing dependency '$relativePath'. Run: git submodule update --init --recursive"
    }
}

$vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) {
    throw 'Visual Studio Installer (vswhere.exe) was not found.'
}

$vsCandidates = @(& $vswhere -all -products * `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
    -property installationPath)
$vsInstall = $vsCandidates |
    Where-Object {
        $_ -and (Test-Path -LiteralPath (Join-Path $_.Trim() 'Common7\Tools\VsDevCmd.bat'))
    } |
    Select-Object -Last 1
if ([string]::IsNullOrWhiteSpace($vsInstall)) {
    throw 'A Visual Studio installation with the MSVC x86/x64 tools was not found.'
}
$vsInstall = $vsInstall.Trim()

$vsDevCmd = Join-Path $vsInstall 'Common7\Tools\VsDevCmd.bat'
$ninja = Join-Path $vsInstall 'Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe'
$cmakeCommand = Get-Command cmake.exe -ErrorAction SilentlyContinue
$cmake = if ($cmakeCommand) {
    $cmakeCommand.Source
} else {
    Join-Path $vsInstall 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
}

foreach ($tool in @($vsDevCmd, $cmake)) {
    if (-not (Test-Path -LiteralPath $tool)) {
        throw "Required build tool was not found: $tool"
    }
}

$generator = 'Ninja'
$makeProgramArgument = "-DCMAKE_MAKE_PROGRAM=`"$ninja`""
$clangCl = 'C:\Program Files\AMD\ROCm\6.1\bin\clang-cl.exe'
$useClangCl = $vsInstall -match '\\2019\\' -and (Test-Path -LiteralPath $clangCl)
if (-not (Test-Path -LiteralPath $ninja)) {
    # Standalone Build Tools installations do not necessarily bundle Ninja.
    # VsDevCmd exposes NMake together with cl.exe, so keep the build entirely
    # local instead of requiring the Visual Studio IDE installation.
    $generator = 'NMake Makefiles'
    $makeProgramArgument = $null
    $buildDir = [System.IO.Path]::GetFullPath(
        (Join-Path $outRoot "build\rerev2-$configKey-nmake"))
}
if ($useClangCl) {
    $buildDir = [System.IO.Path]::GetFullPath(
        (Join-Path $outRoot "build\rerev2-$configKey-clang-nmake"))
}
if ($Clean) {
    Assert-PathUnderOutRoot $buildDir
    if (Test-Path -LiteralPath $buildDir) {
        Remove-Item -LiteralPath $buildDir -Recurse -Force
    }
}

New-Item -ItemType Directory -Path $outRoot -Force | Out-Null

$gitCommand = Get-Command git.exe -ErrorAction SilentlyContinue
if (-not $gitCommand) {
    throw 'Git is required to prepare the pinned build dependencies.'
}

$stlConfigureArgument = '-DFOCUSED_MSVC_STL_INCLUDE='
if (-not $UseInstalledStl -and $vsInstall -match '\\2022\\') {
    # VS 2022 17.14 is installed on this machine, but at least one of its STL
    # headers is corrupt. Keep an exact, clean header mirror in generated output
    # instead of changing the system-wide Visual Studio installation.
    $stlTag = 'vs-2022-17.14'
    $stlCommit = '1f6e5b16ec02216665624c1e762f3732605cf2b4'
    $stlRoot = [System.IO.Path]::GetFullPath((Join-Path $outRoot "toolchain\microsoft-stl-$stlTag"))
    $stlInclude = Join-Path $stlRoot 'stl\inc'
    $stlRequiredFiles = @(
        (Join-Path $stlInclude 'yvals_core.h'),
        (Join-Path $stlInclude 'xlocnum')
    )
    if ($stlRequiredFiles.Where({ -not (Test-Path -LiteralPath $_) }).Count -gt 0) {
        Assert-PathUnderOutRoot $stlRoot
        if (Test-Path -LiteralPath $stlRoot) {
            Remove-Item -LiteralPath $stlRoot -Recurse -Force
        }

        Write-Host "Caching clean Microsoft STL headers ($stlTag)..."
        & $gitCommand.Source clone --quiet --depth 1 --branch $stlTag --filter=blob:none --sparse `
            https://github.com/microsoft/STL.git $stlRoot
        if ($LASTEXITCODE -ne 0) {
            throw "Unable to clone Microsoft STL tag $stlTag."
        }
        & $gitCommand.Source -C $stlRoot sparse-checkout set stl/inc
        if ($LASTEXITCODE -ne 0) {
            throw 'Unable to populate the Microsoft STL header cache.'
        }
    }

    $cachedCommit = (& $gitCommand.Source -C $stlRoot rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $cachedCommit -ne $stlCommit) {
        throw "Unexpected Microsoft STL cache revision '$cachedCommit'; expected $stlCommit."
    }
    $stlConfigureArgument = "-DFOCUSED_MSVC_STL_INCLUDE=`"$stlInclude`""
}

$expectedConfigureArgument = '-DFOCUSED_EXPECTED_INCLUDE='
if ($vsInstall -match '\\2019\\') {
    $expectedTag = 'v1.1.0'
    $expectedCommit = '292eff8bd8ee230a7df1d6a1c00c4ea0eb2f0362'
    $expectedRoot = [System.IO.Path]::GetFullPath(
        (Join-Path $outRoot "toolchain\tl-expected-$expectedTag"))
    $expectedInclude = Join-Path $expectedRoot 'include'
    $expectedHeader = Join-Path $expectedInclude 'tl\expected.hpp'

    if (-not (Test-Path -LiteralPath $expectedHeader)) {
        Assert-PathUnderOutRoot $expectedRoot
        if (Test-Path -LiteralPath $expectedRoot) {
            Remove-Item -LiteralPath $expectedRoot -Recurse -Force
        }
        Write-Host "Caching tl::expected compatibility headers ($expectedTag)..."
        & $gitCommand.Source clone --quiet --depth 1 --branch $expectedTag `
            https://github.com/TartanLlama/expected.git $expectedRoot
        if ($LASTEXITCODE -ne 0) {
            throw "Unable to clone tl::expected tag $expectedTag."
        }
    }

    $cachedExpectedCommit = (& $gitCommand.Source -C $expectedRoot rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $cachedExpectedCommit -ne $expectedCommit) {
        throw "Unexpected tl::expected cache revision '$cachedExpectedCommit'; expected $expectedCommit."
    }
    $expectedConfigureArgument = "-DFOCUSED_EXPECTED_INCLUDE=`"$expectedInclude`""
}

$compilerConfigureArguments = @()
if ($useClangCl) {
    $compilerConfigureArguments = @(
        "-DCMAKE_C_COMPILER=`"$clangCl`"",
        "-DCMAKE_CXX_COMPILER=`"$clangCl`"",
        '-DCMAKE_C_COMPILER_TARGET=i686-pc-windows-msvc',
        '-DCMAKE_CXX_COMPILER_TARGET=i686-pc-windows-msvc'
    )
}

$configure = @(
    "`"$cmake`"",
    '-S', "`"$repoRoot`"",
    '-B', "`"$buildDir`"",
    '-G', "`"$generator`"",
    $makeProgramArgument,
    "-DCMAKE_BUILD_TYPE=$Configuration",
    "-DFOCUSED_PACKAGE_DIR=`"$packageDir`"",
    $stlConfigureArgument,
    $expectedConfigureArgument
) + $compilerConfigureArguments + @(
    '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON'
) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
$configure = $configure -join ' '

$build = "`"$cmake`" --build `"$buildDir`" --parallel"
$commandLine = "call `"$vsDevCmd`" -no_logo -arch=x86 -host_arch=x64 >nul && $configure && $build"

Write-Host "Building Resident Evil Revelations 2 ($Configuration) with CMake + $generator..."
& $env:ComSpec /d /s /c $commandLine
if ($LASTEXITCODE -ne 0) {
    throw "Build failed with exit code $LASTEXITCODE."
}

$asi = Get-ChildItem -LiteralPath (Join-Path $packageDir 'scripts') -Filter '*.asi' -File | Select-Object -First 1
if (-not $asi) {
    throw "Build completed but no ASI file was found in $packageDir\scripts."
}

Write-Host "Built: $($asi.FullName)"
Write-Host "Package: $packageDir"
