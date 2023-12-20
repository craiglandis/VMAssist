# Get-VMAgentHealth

Get-VMAgentHealth is a PowerShell script you run within the guest operating system of an Azure virtual machine to diagnose common health and configuration issues with the Azure VM agent.

Azure VM agent health is critical to the proper functioning of Azure VM agent extensions.

Running Get-VMAgentHealth generates a report showing the results of health checks it performed and suggested mitigation steps for issues it finds.

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
- [License](#license)

https://raw.githubusercontent.com/craiglandis/Get-VMAgentHealth/main/Get-VMAgentHealth.ps1

## Prerequisites

## Usage

### Remote Desktop

### Custom Script Extension (Azure PowerShell)

## Using Set-AzVMCustomScriptExtension
```powershell
$resourceGroupName = 'myrg'
$vmName = 'myvm'
$location = Get-AzVM -resourceGroupName $resourceGroupName -name $vmName | Select-Object -ExpandProperty Location
$publisher = 'Microsoft.Compute'
$extensionType = 'CustomScriptExtension'
$name = "$publisher.$extensionType"
$versions = Get-AzVMExtensionImage -Location $location -PublisherName $publisherName -Type $type
[version]$version = $versions | Sort-Object {[version]$_.Version} | Select-Object -ExpandProperty Version -Last 1
$typeHandlerVersion = "$($version.Major).$($version.Minor)"

$name = 'CustomScriptExtension'
$fileUri = 'https://raw.githubusercontent.com/craiglandis/Get-VMAgentHealth/main/Get-VMAgentHealth.ps1'
$run = $fileUri -split '/' | Select-Object -Last 1
Set-AzVMCustomScriptExtension -Location $location -ResourceGroupName $resourceGroupName -VMName $vmName -Name $name -FileUri $fileUri -Run $run -TypeHandlerVersion $typeHandlerVersion -ForceRerun (Get-Date).Ticks

$status = Get-AzVMCustomScriptExtension -ResourceGroupName $resourceGroupName -VMName $vmName -Name $name -Status
$stdOut = $status.SubStatuses | Where-Object {$_.Code -match 'StdOut'} | Select-Object -ExpandProperty Message
$stdErr = $status.SubStatuses | Where-Object {$_.Code -match 'StdErr'} | Select-Object -ExpandProperty Message

Get-AzVM -resourceGroupName $resourceGroupName -name $vmName | select-object -expandproperty Extensions | where {$_.Publisher -eq $publisherName -and $_.VirtualMachineExtensionType -eq $name}

Remove-AzVMCustomScriptExtension -ResourceGroupName $resourceGroupName -VMName $vmName -Name $name -Force

## Using Set-AzVMExtension
```powershell
$resourceGroupName = 'myrg'
$vmName = 'myvm'
$location = Get-AzVM -resourceGroupName $resourceGroupName -name $vmName | Select-Object -ExpandProperty Location
$publisher = 'Microsoft.Compute'
$extensionType = 'CustomScriptExtension'
$name = "$publisher.$extensionType"
[version]$version = (Get-AzVMExtensionImage -Location $location -PublisherName $publisher -Type $extensionType | Sort-Object {[Version]$_.Version} -Desc | Select-Object Version -First 1).Version
$typeHandlerVersion = "$($version.Major).$($version.Minor)"
$scriptUrl = 'https://raw.githubusercontent.com/craiglandis/Get-VMAgentHealth/main/Get-VMAgentHealth.ps1'
$scriptFileName = $scriptUrl -split '/' | Select-Object -Last 1
$settings = @{
	'fileUris'         = @($scriptUrl)
	'commandToExecute' = "powerShell -ExecutionPolicy Bypass -Nologo -NoProfile -File $scriptFileName"
	'timestamp'        = (Get-Date).Ticks
}
Set-AzVMExtension -Location $location -ResourceGroupName $resourceGroupName -VMName $vmName -Name $name -Publisher $publisher -ExtensionType $extensionType -TypeHandlerVersion $typeHandlerVersion -Settings $settings
$status = Get-AzVMExtension -ResourceGroupName $resourceGroupName -VMName $vmName -Name $name -Status
$status.Statuses.Message
Remove-AzVMExtension -ResourceGroupName $resourceGroupName -VMName $vmName -Name $name -Force
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

### Custom Script Extension (Azure CLI)

```
'{"fileUris": ["https://raw.githubusercontent.com/craiglandis/Get-VMAgentHealth/main/Get-VMAgentHealth.ps1"],"commandToExecute": "./health.sh"}' > settings.json

az vm extension set --resource-group myrg --vm-name myvm --name customScript --publisher Microsoft.Azure.Extensions --settings ./settings.json

```

### Managed Run Command (Azure PowerShell)

```powershell
$resourceGroupName = 'myrg'
$vmName = 'myvm'
$sourceScriptUri = 'https://raw.githubusercontent.com/craiglandis/Get-VMAgentHealth/main/Get-VMAgentHealth.ps1'
Set-AzVMRunCommand -ResourceGroupName $resourceGroupName -VMName $vmName -RunCommandName RunPowerShellScript -SourceScriptUri $sourceScriptUri
Get-AzVMRunCommand -ResourceGroupName $resourceGroupName -VMName $vmName -RunCommandName RunPowerShellScript -Expand InstanceView | Select-Object -ExpandProperty InstanceView
```

### Managed Run Command (Azure CLI)

```
az vm run-command create --name Get-VMAgentHealth --vm-name ws12r2 --resource-group rg --script-uri 'https://raw.githubusercontent.com/craiglandis/Get-VMAgentHealth/main/Get-VMAgentHealth.ps1'

$result = az vm run-command show --name Get-VMAgentHealth --vm-name ws12r2 --resource-group rg --expand instanceView
$result = $result | ConvertFrom-Json
$result.instanceView.output
```

### Action Run Command (Azure PowerShell)

```powershell
$resourceGroupName = 'myrg'
$vmName = 'myvm'
Invoke-WebRequest -Uri https://raw.githubusercontent.com/craiglandis/Get-VMAgentHealth/main/Get-VMAgentHealth.ps1 -OutFile Get-VMAgentHealth.ps1
Invoke-AzVMRunCommand -ResourceGroupName $resourceGroupName -Name $vmName -CommandId RunPowerShellScript -ScriptPath Get-VMAgentHealth.ps1
```

### Action Run Command (Azure CLI)

```
curl https://raw.githubusercontent.com/craiglandis/Get-VMAgentHealth/main/Get-VMAgentHealth.ps1 -o Get-VMAgentHealth.ps1
az vm run-command invoke -g rg -n ws12r2 --command-id RunPowerShellScript --scripts @{Get-VMAgentHealth.ps1}

```

### Serial Console

## Maintainers

## Contributing

## License
