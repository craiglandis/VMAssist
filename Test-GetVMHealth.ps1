Set-ExecutionPolicy Bypass -Force
New-Item -Path $profile -ItemType File -Force | Out-Null
Add-Content -Path $profile -Value "Set-Alias g '\\tsclient\c\src\get-vmhealth\get-vmhealth.ps1'" -Force
Add-Content -Path $profile -Value "Set-Alias w '\\tsclient\c\onedrive\my\Set-Wallpaper.ps1'" -Force
Add-Content -Path $profile -Value "Set-Location -Path C:\" -Force
Add-Content -Path $profile -Value "Clear-Host" -Force

New-NetFirewallRule -DisplayName 'Block outbound traffic to 168.63.129.16' -Direction Outbound –LocalPort Any -Protocol TCP -Action Block -RemoteAddress 168.63.129.16
New-NetFirewallRule -DisplayName 'Block outbound traffic to 169.254.169.254' -Direction Outbound –LocalPort Any -Protocol TCP -Action Block -RemoteAddress 169.254.169.254
