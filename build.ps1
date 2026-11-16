$ErrorActionPreference = 'Stop'
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compiler)) { throw 'Requires Windows x64 with .NET Framework 4.8.' }
$assemblies = @('UIAutomationClient', 'UIAutomationTypes', 'WindowsBase')
$references = @('/reference:System.Windows.Forms.dll', '/reference:System.Drawing.dll', '/reference:System.Security.dll', '/reference:System.Web.Extensions.dll')
foreach ($assembly in $assemblies) {
    $base = Join-Path $env:WINDIR ('Microsoft.NET\assembly\GAC_MSIL\' + $assembly)
    $dll = Get-ChildItem -LiteralPath $base -Filter ($assembly + '.dll') -Recurse | Select-Object -First 1
    if (-not $dll) { throw ('Missing framework assembly: ' + $assembly) }
    $references += '/reference:' + $dll.FullName
}
New-Item -ItemType Directory -Path (Join-Path $PSScriptRoot 'bin') -Force | Out-Null
$outputExe = Join-Path $PSScriptRoot 'bin\VALO.exe'
$sourceFile = Join-Path $PSScriptRoot 'src\Manager.cs'
$manifestFile = Join-Path $PSScriptRoot 'src\app.manifest'
& $compiler /nologo /target:winexe /platform:x64 /optimize+ ('/out:' + $outputExe) ('/win32manifest:' + $manifestFile) ('/win32icon:' + (Join-Path $PSScriptRoot 'assets\VALO.ico')) @references $sourceFile
if ($LASTEXITCODE -ne 0) { throw 'Build failed.' }
Write-Output $outputExe
