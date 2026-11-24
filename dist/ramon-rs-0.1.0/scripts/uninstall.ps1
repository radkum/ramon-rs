#Requires -RunAsAdministrator
<#
  Unloads and removes the ramon service and its driver file.
#>
param([string]$ServiceName = 'ramon')

$ErrorActionPreference = 'Continue'

fltmc unload $ServiceName 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "$ServiceName was not loaded"
}
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    sc.exe delete $ServiceName | Out-Null
}
Remove-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\drivers\ramon.sys') -Force -ErrorAction SilentlyContinue
Write-Host "removed: $ServiceName"
