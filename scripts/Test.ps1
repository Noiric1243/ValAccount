$ErrorActionPreference = 'Stop'
$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
& (Join-Path $projectRoot 'build.ps1')
$testRoot = Join-Path $projectRoot 'test-output'
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null
$executable = Join-Path $projectRoot 'bin\VALO.exe'
$process = Start-Process -FilePath $executable -ArgumentList @('--self-test', ('"' + $testRoot + '"')) -WindowStyle Hidden -Wait -PassThru
Get-Content -LiteralPath (Join-Path $testRoot 'test-results.txt')
if ($process.ExitCode -ne 0) { throw 'Self-test failed.' }

$englishRoot = Join-Path $testRoot "english"
New-Item -ItemType Directory -Path $englishRoot -Force | Out-Null
$englishProcess = Start-Process -FilePath $executable -ArgumentList @("--self-test-en", ('"' + $englishRoot + '"')) -WindowStyle Hidden -Wait -PassThru
Get-Content -LiteralPath (Join-Path $englishRoot "test-results.txt")
if ($englishProcess.ExitCode -ne 0) { throw "English self-test failed." }
