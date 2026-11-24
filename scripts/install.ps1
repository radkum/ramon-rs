#Requires -RunAsAdministrator
<#
  Installs ramon as a demand-start minifilter service and loads it.
  The driver must be test-signed and trusted by this machine (testsigning on).
#>
param(
    [string]$DriverPath = (Join-Path $PSScriptRoot 'ramon.sys'),
    [string]$ServiceName = 'ramon',
    [string]$Altitude = '345102'
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $DriverPath)) {
    throw "driver not found: $DriverPath (pass -DriverPath)"
}
$signature = Get-AuthenticodeSignature -LiteralPath $DriverPath
if ($signature.Status -ne 'Valid') {
    Write-Warning "signature: $($signature.Status) - the driver will not load unless testsigning is on and the certificate is trusted"
}
if (-not (bcdedit /enum '{current}' | Select-String -Pattern 'testsigning\s+Yes')) {
    throw "test signing is off: run 'bcdedit /set testsigning on', reboot, then retry"
}

# WFP callouts cannot be re-registered safely in the same boot yet: refuse a second load
$marker = Join-Path $env:ProgramData 'ramon\last-load.txt'
$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString('o')
if (Test-Path -LiteralPath $marker) {
    $last = (Get-Content -LiteralPath $marker -Raw).Trim()
    if ($last -eq $boot) {
        throw "ramon was already loaded once in this boot. The WFP callout cannot be registered a second time safely yet - reboot and retry."
    }
}

$destination = Join-Path $env:SystemRoot 'System32\drivers\ramon.sys'
try {
    Copy-Item -LiteralPath $DriverPath -Destination $destination -Force
} catch {
    throw "cannot replace $destination ($($_.Exception.Message)). A previously loaded image can stay mapped until reboot - reboot and retry."
}

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
}
sc.exe create $ServiceName type= filesys start= demand error= normal `
    binPath= '\SystemRoot\System32\drivers\ramon.sys' group= 'FSFilter Activity Monitor' | Out-Null
if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
    throw "service $ServiceName was not created"
}

$base = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
$instance = "$base\Instances\Ramon Instance"
New-Item -Path $instance -Force | Out-Null
New-ItemProperty -Path "$base\Instances" -Name DefaultInstance -Value 'Ramon Instance' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $instance -Name Altitude -Value $Altitude -PropertyType String -Force | Out-Null
New-ItemProperty -Path $instance -Name Flags -Value 0 -PropertyType DWord -Force | Out-Null

fltmc load $ServiceName
if ($LASTEXITCODE -ne 0) {
    throw "fltmc load $ServiceName failed: $LASTEXITCODE"
}
New-Item -ItemType Directory -Force (Split-Path -Parent $marker) | Out-Null
Set-Content -LiteralPath $marker -Value $boot
Write-Host "loaded: $ServiceName"
