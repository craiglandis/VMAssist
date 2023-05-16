<#
t -setprofile
t -blockwireserver
t -unblockwireserver
t -blockimds
t -unblockimds

\\tsclient\c\src\Get-VMHealth\Test-GetVMHealth.ps1 -setprofile
\\tsclient\c\src\Get-VMHealth\Test-GetVMHealth.ps1 -blockwireserver
\\tsclient\c\src\Get-VMHealth\Test-GetVMHealth.ps1 -unblockwireserver
\\tsclient\c\src\Get-VMHealth\Test-GetVMHealth.ps1 -blockimds
\\tsclient\c\src\Get-VMHealth\Test-GetVMHealth.ps1 -unblockimds
#>
param(
    [switch]$setprofile,
    [switch]$blockwireserver,
    [switch]$blockimds,
    [switch]$unblockwireserver,
    [switch]$unblockimds
)

if ($setprofile)
{
    Set-ExecutionPolicy Bypass -Force
    New-Item -Path $profile -ItemType File -Force | Out-Null
    Add-Content -Path $profile -Value "Set-Alias g '\\tsclient\c\src\get-vmhealth\Get-VMHealth.ps1'" -Force
    Add-Content -Path $profile -Value "Set-Alias t '\\tsclient\c\src\get-vmhealth\Test-GetVMHealth.ps1'" -Force
    Add-Content -Path $profile -Value "Set-Alias w '\\tsclient\c\onedrive\my\Set-Wallpaper.ps1'" -Force
    Add-Content -Path $profile -Value "Set-Location -Path C:\" -Force
    Add-Content -Path $profile -Value "Clear-Host" -Force
}

if ($blockwireserver)
{
    New-NetFirewallRule -DisplayName 'Block outbound traffic to 168.63.129.16' -Direction Outbound -LocalPort Any -Protocol TCP -Action Block -RemoteAddress 168.63.129.16
}

if ($unblockwireserver)
{
    Remove-NetFirewallRule -DisplayName 'Block outbound traffic to 168.63.129.16'
}

if ($blockimds)
{
    New-NetFirewallRule -DisplayName 'Block outbound traffic to 169.254.169.254' -Direction Outbound -LocalPort Any -Protocol TCP -Action Block -RemoteAddress 169.254.169.254
}

if ($unblockimds)
{
    Remove-NetFirewallRule -DisplayName 'Block outbound traffic to 169.254.169.254'
}