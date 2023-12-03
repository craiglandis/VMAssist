# Get-VMHealth

Get-VMHealth is a PowerShell script you run within the guest operating system of an Azure virtual machine to diagnose common health and configuration issues with the Azure VM agent.

Azure VM agent health is critical to the proper functioning of Azure VM agent extensions.

Running Get-VMHealth generates a report showing the results of health checks it performed and suggested mitigation steps for issues it finds.

## Table of Contents

- [Background](#background)
- [Prerequisites](#prerequisites)
- [Usage](#usage)
  - [Remote Desktop](#remote-desktop)
  - [Custom Script Extension (Azure PowerShell)](#custom-script-extension-azure-powershell)
  - [Custom Script Extension (Azure CLI)](#custom-script-extension-azure-cli)
  - [Managed Run Command (Azure PowerShell)](#managed-run-command-azure-powershell)
  - [Managed Run Command (Azure CLI)](#managed-run-command-azure-cli)
  - [Action Run Command (Azure PowerShell)](#action-run-command-azure-powershell)
  - [Action Run Command (Azure CLI)](#action-run-command-azure-cli)
  - [Serial Console](#serial-console)
- [Example Readmes](#example-readmes)
- [Maintainers](#maintainers)
- [Contributing](#contributing)
- [License](#license)

https://raw.githubusercontent.com/craiglandis/Get-VMHealth/main/Get-VMHealth.ps1

## Prerequisites

## Usage

### Remote Desktop

### Custom Script Extension (Azure PowerShell)

```powershell
Set-AzVMCustomScriptExtension -Location westus2 -ResourceGroupName rg -VMName win11 -Name cse -FileUri https://raw.githubusercontent.com/craiglandis/Get-VMHealth/main/Get-VMHealth.ps1 -Run Get-VMHealth.ps1 -TypeHandlerVersion 1.10 -ForceRerun (Get-Date).Ticks
```

```powershell
Get-AzVMExtension -ResourceGroupName rg -VMName win11 -Name cse -Status
```

```powershell
Remove-AzVMExtension -ResourceGroupName rg -VMName win11 -Name cse -Force
```

```powershell
[version]$version = Get-AzVMExtensionImage -Location westus2 -PublisherName Microsoft.Compute -Type CustomScriptExtension | Sort-Object {[version]$_.Version} | Select-Object -ExpandProperty Version -Last 1
[string]$version = "$($version.Major).$($version.Minor)"
```

```powershell
Get-AzVMExtension -ResourceGroupName rg -VMName win11 -Name cse -Status | select -ExpandProperty SubStatuses | where code -match 'stdout' | select -ExpandProperty Message
```

```powershell
Get-AzVMExtension -ResourceGroupName rg -VMName win11 -Name cse -Status | select -ExpandProperty SubStatuses | where code -match 'stderr' | select -ExpandProperty Message
```
