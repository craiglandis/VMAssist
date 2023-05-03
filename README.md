# Azure VM Health Check Script

https://raw.githubusercontent.com/craiglandis/Get-VMHealth/main/Get-VMHealth.ps1

```
Set-AzVMCustomScriptExtension -Location westus2 -ResourceGroupName rg -VMName win11 -Name cse -FileUri https://raw.githubusercontent.com/craiglandis/Get-VMHealth/main/Get-VMHealth.ps1 -Run Get-VMHealth.ps1 -TypeHandlerVersion 1.10 -ForceRerun (Get-Date).Ticks
```

```
Get-AzVMExtension -ResourceGroupName rg -VMName win11 -Name cse -Status
```

```
Remove-AzVMExtension -ResourceGroupName rg -VMName win11 -Name cse -Force
```

```
[version]$version = Get-AzVMExtensionImage -Location westus2 -PublisherName Microsoft.Compute -Type CustomScriptExtension | Sort-Object {[version]$_.Version} | Select-Object -ExpandProperty Version -Last 1
[string]$version = "$($version.Major).$($version.Minor)"
```

```
Get-AzVMExtension -ResourceGroupName rg -VMName win11 -Name cse -Status | select -ExpandProperty SubStatuses | where code -match 'stdout' | select -ExpandProperty Message
```

```
Get-AzVMExtension -ResourceGroupName rg -VMName win11 -Name cse -Status | select -ExpandProperty SubStatuses | where code -match 'stderr' | select -ExpandProperty Message
```
