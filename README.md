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

https://aka.ms/vmhealth

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
$type = 'CustomScriptExtension'
$name = "$publisher.$type"
$versions = Get-AzVMExtensionImage -Location $location -PublisherName $publisher -Type $type
[version]$version = $versions | Sort-Object {[version]$_.Version} | Select-Object -ExpandProperty Version -Last 1
$typeHandlerVersion = "$($version.Major).$($version.Minor)"

$name = 'CustomScriptExtension'
$fileUri = 'https://aka.ms/vmhealth'
$run = $fileUri -split '/' | Select-Object -Last 1
Set-AzVMCustomScriptExtension -Location $location -ResourceGroupName $resourceGroupName -VMName $vmName -Name $name -FileUri $fileUri -Run $run -TypeHandlerVersion $typeHandlerVersion -ForceRerun (Get-Date).Ticks

$status = Get-AzVMCustomScriptExtension -ResourceGroupName $resourceGroupName -VMName $vmName -Name $name -Status
$stdOut = $status.SubStatuses | Where-Object {$_.Code -match 'StdOut'} | Select-Object -ExpandProperty Message
$stdErr = $status.SubStatuses | Where-Object {$_.Code -match 'StdErr'} | Select-Object -ExpandProperty Message

Get-AzVM -resourceGroupName $resourceGroupName -name $vmName | Select-Object -ExpandProperty Extensions | Where-Object {$_.Publisher -eq $publisher -and $_.VirtualMachineExtensionType -eq $name}

Remove-AzVMCustomScriptExtension -ResourceGroupName $resourceGroupName -VMName $vmName -Name $name -Force

## Using Set-AzVMExtension
```powershell
$resourceGroupName = 'myrg'
$vmName = 'myvm'
$location = Get-AzVM -resourceGroupName $resourceGroupName -name $vmName | Select-Object -ExpandProperty Location
$publisher = 'Microsoft.Compute'
$type = 'CustomScriptExtension'
$name = "$publisher.$type"
[version]$version = (Get-AzVMExtensionImage -Location $location -PublisherName $publisher -Type $type | Sort-Object {[Version]$_.Version} -Desc | Select-Object Version -First 1).Version
$typeHandlerVersion = "$($version.Major).$($version.Minor)"
$scriptUrl = 'https://aka.ms/vmhealth'
$scriptFileName = $scriptUrl -split '/' | Select-Object -Last 1
$settings = @{
	'fileUris'         = @($scriptUrl)
	'commandToExecute' = "powerShell -ExecutionPolicy Bypass -Nologo -NoProfile -File $scriptFileName"
	'timestamp'        = (Get-Date).Ticks
}
Set-AzVMExtension -Location $location -ResourceGroupName $resourceGroupName -VMName $vmName -Name $name -Publisher $publisher -ExtensionType $type -TypeHandlerVersion $typeHandlerVersion -Settings $settings
$status = Get-AzVMExtension -ResourceGroupName $resourceGroupName -VMName $vmName -Name $name -Status
$status.Statuses.Message
Remove-AzVMExtension -ResourceGroupName $resourceGroupName -VMName $vmName -Name $name -Force
```

```powershell
Get-AzVMExtension -ResourceGroupName $resourceGroupName -VMName $vmName -Name $name -Status
```

```powershell
Remove-AzVMExtension -ResourceGroupName $resourceGroupName -VMName $vmName -Name $name -Force
```

```powershell
[version]$version = Get-AzVMExtensionImage -Location $location -PublisherName $pubisher -Type $type | Sort-Object {[version]$_.Version} | Select-Object -ExpandProperty Version -Last 1
[string]$version = "$($version.Major).$($version.Minor)"
```

```powershell
Get-AzVMExtension -ResourceGroupName $resourceGroupName -VMName $vmName -Name $name -Status | Select-Object -ExpandProperty SubStatuses | Where-Object code -match 'stdout' | Select-Object -ExpandProperty Message
```

```powershell
Get-AzVMExtension -ResourceGroupName $resourceGroupName -VMName $vmName -Name $name -Status | Select-Object -ExpandProperty SubStatuses | Where-Object code -match 'stderr' | Select-Object -ExpandProperty Message
```

### Custom Script Extension (Azure CLI)

```
'{"fileUris": ["https://aka.ms/vmhealth"],"commandToExecute": "./health.sh"}' > settings.json

az vm extension set --resource-group myrg --vm-name myvm --name customScript --publisher Microsoft.Azure.Extensions --settings ./settings.json

```

### Managed Run Command (Azure PowerShell)

```powershell
$resourceGroupName = 'myrg'
$vmName = 'myvm'
$sourceScriptUri = 'https://aka.ms/vmhealth'
Set-AzVMRunCommand -ResourceGroupName $resourceGroupName -VMName $vmName -RunCommandName RunPowerShellScript -SourceScriptUri $sourceScriptUri
Get-AzVMRunCommand -ResourceGroupName $resourceGroupName -VMName $vmName -RunCommandName RunPowerShellScript -Expand InstanceView | Select-Object -ExpandProperty InstanceView
```

### Managed Run Command (Azure CLI)

```
resourceGroupName=rg
vmName=ws22
az vm run-command create --name Get-VMAgentHealth --vm-name ws12r2 --resource-group rg --script-uri 'https://aka.ms/vmhealth'

$result = az vm run-command show --name Get-VMAgentHealth --vm-name ws12r2 --resource-group rg --expand instanceView
$result = $result | ConvertFrom-Json
$result.instanceView.output
```

### Action Run Command (Azure PowerShell)

```powershell
$resourceGroupName = 'myrg'
$vmName = 'myvm'
Invoke-WebRequest -Uri https://aka.ms/vmhealth -OutFile Get-VMAgentHealth.ps1
Invoke-AzVMRunCommand -ResourceGroupName $resourceGroupName -Name $vmName -CommandId RunPowerShellScript -ScriptPath Get-VMAgentHealth.ps1
```

### Action Run Command (Azure CLI)

```
curl https://aka.ms/vmhealth -o Get-VMAgentHealth.ps1
az vm run-command invoke -g rg -n ws12r2 --command-id RunPowerShellScript --scripts @{Get-VMAgentHealth.ps1}

```

### Serial Console

## Maintainers

## Contributing

## License
