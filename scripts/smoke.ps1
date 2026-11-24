#Requires -RunAsAdministrator
<#
  Smoke test: installs and loads the driver, runs the client for a few seconds,
  counts the events it received, unloads, and fails if no events arrived or if the
  machine recorded a new bugcheck.
#>
param(
    [string]$ClientPath = (Join-Path $PSScriptRoot 'ramon-client.exe'),
    [string]$DriverPath = (Join-Path $PSScriptRoot 'ramon.sys'),
    [string]$ServiceName = 'ramon',
    [int]$Seconds = 5,
    [int]$MinEvents = 1
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $ClientPath)) {
    throw "client not found: $ClientPath (pass -ClientPath)"
}

function Get-LastBugcheck {
    (Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 1001 } -MaxEvents 1 -ErrorAction SilentlyContinue).TimeCreated
}

$bugcheckBefore = Get-LastBugcheck

& (Join-Path $PSScriptRoot 'install.ps1') -DriverPath $DriverPath -ServiceName $ServiceName

$log = Join-Path $env:TEMP ("ramon-smoke-{0}.log" -f ([guid]::NewGuid().ToString('N')))
$err = "$log.err"
$client = Start-Process -FilePath $ClientPath -ArgumentList 'all' `
    -RedirectStandardOutput $log -RedirectStandardError $err -PassThru
Start-Sleep -Seconds $Seconds
Stop-Process -Id $client.Id -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

fltmc unload $ServiceName | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "fltmc unload $ServiceName failed: $LASTEXITCODE"
}

$events = @(Get-Content -LiteralPath $log -ErrorAction SilentlyContinue).Count
$errors = @(Get-Content -LiteralPath $err -ErrorAction SilentlyContinue).Count
$bugcheckAfter = Get-LastBugcheck

Write-Host "events received: $events"
Write-Host "client stderr lines: $errors"
Write-Host "log: $log"

if ($bugcheckAfter -ne $bugcheckBefore) {
    throw "a new bugcheck was recorded ($bugcheckAfter)"
}
if ($events -lt $MinEvents) {
    throw "expected at least $MinEvents event(s), got $events"
}

Write-Host 'SMOKE TEST PASSED'
