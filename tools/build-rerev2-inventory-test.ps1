$ErrorActionPreference = 'Stop'
$inventoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$inventoryOut = Join-Path $inventoryRoot 'out\tests\inventory'
New-Item -ItemType Directory -Path $inventoryOut -Force | Out-Null
$inventoryVswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
$inventoryVs = @(& $inventoryVswhere -all -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath) |
    Where-Object { $_ -and (Test-Path -LiteralPath (Join-Path $_.Trim() 'Common7\Tools\VsDevCmd.bat')) } | Select-Object -Last 1
if (-not $inventoryVs) { throw 'MSVC build tools not found' }
$inventoryDev = Join-Path $inventoryVs.Trim() 'Common7\Tools\VsDevCmd.bat'
$inventorySource = Join-Path $inventoryRoot 'source\ResidentEvilRevelations2.FusionFix\InventoryPreviewLive.asm'
$inventoryObj = Join-Path $inventoryOut 'InventoryPreviewLive.obj'
$inventoryCommand = "call `"$inventoryDev`" -no_logo -arch=x86 -host_arch=x64 >nul && ml /nologo /c /coff /Fo`"$inventoryObj`" `"$inventorySource`""
& $env:ComSpec /d /s /c $inventoryCommand
if ($LASTEXITCODE -ne 0) { throw 'Inventory test assembly failed' }
Write-Host "Built: $inventoryObj"
