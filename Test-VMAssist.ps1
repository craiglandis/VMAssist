<#
Test-VMAssist.ps1 -stopRdagent
Test-VMAssist.ps1 -stopWindowsAzureGuestAgent
Test-VMAssist.ps1 -blockwireserver
Test-VMAssist.ps1 -blockimds
Test-VMAssist.ps1 -enableProxy
Test-VMAssist.ps1 -setNonDefaultMachineKeysAcl
Test-VMAssist.ps1 -setNonDefaultWindowsAzureAcl
Test-VMAssist.ps1 -setNonDefaultPackagesAcl

t -setprofile
t -blockwireserver
t -unblockwireserver
t -blockimds
t -unblockimds

\\tsclient\c\src\VMAssist\Test-VMAssist.ps1 -setprofile
\\tsclient\c\src\VMAssist\Test-VMAssist.ps1 -blockwireserver
\\tsclient\c\src\VMAssist\Test-VMAssist.ps1 -unblockwireserver
\\tsclient\c\src\VMAssist\Test-VMAssist.ps1 -blockimds
\\tsclient\c\src\VMAssist\Test-VMAssist.ps1 -unblockimds
\\tsclient\c\src\VMAssist\Test-VMAssist.ps1 -enableProxy
\\tsclient\c\src\VMAssist\Test-VMAssist.ps1 -disableProxy

#>
param(
    [switch]$setprofile,
    [switch]$enableStaticIp,
    [switch]$enableDhcp,
    [switch]$enableWcfDebugging,
    [switch]$disableWcfDebugging,
    [switch]$setNonDefaultMachineKeysAcl,
    [switch]$setDefaultMachineKeysAcl,
    [switch]$setNonDefaultWindowsAzureAcl,
    [switch]$setDefaultWindowsAzureAcl,
    [switch]$setNonDefaultPackagesAcl,
    [switch]$setDefaultPackagesAcl,
    [switch]$stopRdagent,
    [switch]$startRdagent,
    [switch]$disableRdagent,
    [switch]$enableRdagent,
    [switch]$stopWindowsAzureGuestAgent,
    [switch]$startWindowsAzureGuestAgent,
    [switch]$disableWindowsAzureGuestAgent,
    [switch]$enableWindowsAzureGuestAgent,
    [switch]$stopGAServices,
    [switch]$startGAServices,
    [switch]$disableGAServices,
    [switch]$enableGAServices,
    [switch]$blockwireserver,
    [switch]$blockimds,
    [switch]$unblockwireserver,
    [switch]$unblockimds,
    [switch]$enableProxy,
    [switch]$disableProxy,
    [switch]$enableWinmgmt,
    [switch]$disableWinmgmt,
    [switch]$loadModule, # https://chat.openai.com/share/cc75e85d-da52-455e-a945-a826af4d3866
    [switch]$unloadModule,
    [switch]$testCSEWithCommand,
    [switch]$testCSEWithScript,
    [switch]$removeCSE,
    [string]$resourceGroupName,
    [string]$vmName,
    [switch]$parameters
)

function Out-Log
{
    param(
        [string]$text,
        [switch]$verboseOnly,
        [switch]$sameline,
        [ValidateSet('timespan', 'both')]
        [string]$prefix = 'both',
        [ValidateSet('hours', 'minutes', 'seconds')]
        [string]$timespanFormat = 'minutes',
        [ValidateSet('condensedTime', 'time', 'datetime')]
        [string]$timestampFormat = 'time',
        [switch]$dateCondensed = $true,
        [switch]$milliseconds,
        [switch]$raw,
        [switch]$logonly,
        # [ValidateSet('Black', 'DarkBlue', 'DarkGreen', 'DarkCyan', 'DarkRed', 'DarkMagenta', 'DarkYellow', 'Gray', 'DarkGray', 'Blue', 'Green', 'Cyan', 'Red', 'Magenta', 'Yellow', 'White')]
        [string]$color = 'White'
    )

    if ($timestampFormat -eq 'condensedTime')
    {
        $dateFormat = 'ddhhmmss'
    }
    elseif ($timestampFormat -eq 'time')
    {
        $dateFormat = 'hh:mm:ss'
    }
    elseif ($timestampFormat -eq 'datetime')
    {
        $dateFormat = 'yyyy-MM-dd hh:mm:ss'
    }
    else
    {
        $dateFormat = 'yyyy-MM-dd hh:mm:ss'
    }

    if ($verboseOnly)
    {
        $global:callstack = Get-PSCallStack
        $caller = $callstack | Select-Object -First 1 -Skip 1
        $caller = $caller.InvocationInfo.MyCommand.Name
        if ($caller -eq 'Invoke-ExpressionWithLogging')
        {
            $caller = $callstack | Select-Object -First 1 -Skip 2
            $caller = $caller.InvocationInfo.MyCommand.Name
        }
        $caller = "$yellow$caller$reset"
        # Write-Host "$scriptName `$verboseOnly: $verboseOnly `$global:verbose: $global:verbose" -ForegroundColor Magenta
        if ($global:verbose)
        {
            $outputNeeded = $true
            $foreGroundColor = 'Yellow'
        }
        else
        {
            $outputNeeded = $false
        }
    }
    else
    {
        $outputNeeded = $true
        $foreGroundColor = 'White'
    }

    if ($outputNeeded)
    {
        if ($raw)
        {
            if ($logonly)
            {
                if ($logFilePath)
                {
                    $text | Out-File $logFilePath -Append
                }
            }
            else
            {
                Write-Host $text -ForegroundColor $color
                if ($logFilePath)
                {
                    $text | Out-File $logFilePath -Append
                }
            }
        }
        else
        {
            if (!$script:scriptStartTime)
            {
                $script:scriptStartTime = Get-Date
            }

            if ($prefix -eq 'timespan' -and $script:scriptStartTime)
            {
                $timespan = New-TimeSpan -Start $script:scriptStartTime -End (Get-Date)
                if ($timespanFormat -eq 'hours')
                {
                    $format = '{0:hh}:{0:mm}:{0:ss}'
                    #$prefixString = '{0:hh}:{0:mm}:{0:ss}.{0:ff}' -f $timespan
                }
                elseif ($timespanFormat -eq 'minutes')
                {
                    $format = '{0:mm}:{0:ss}'
                    #$prefixString = '{0:mm}:{0:ss}.{0:ff}' -f $timespan
                }
                elseif ($timespanFormat -eq 'seconds')
                {
                    $format = '{0:ss}'
                    #$prefixString = '{0:ss}.{0:ff}' -f $timespan
                }
                if ($milliseconds)
                {
                    $format = "$($format).{0:ff}"
                }
                $prefixString = $format -f $timespan
                # $prefixString = "[$prefixString]"
                $prefixString = $prefixString
            }
            # elseif ($prefix -eq 'both' -and $script:scriptStartTime)
            elseif ($prefix -eq 'both' -and $script:scriptStartTime)
            {
                $timestamp = Get-Date -Format $dateFormat
                # $timespan = New-TimeSpan -Start $script:scriptStartTime -End (Get-Date)
                $timespan = New-TimeSpan -Start $script:scriptStartTime -End (Get-Date)

                if ($timespanFormat -eq 'hours')
                {
                    $format = '{0:hh}:{0:mm}:{0:ss}'
                    #$prefixString = '{0:hh}:{0:mm}:{0:ss}.{0:ff}' -f $timespan
                }
                elseif ($timespanFormat -eq 'minutes')
                {
                    $format = '{0:mm}:{0:ss}'
                    #$prefixString = '{0:mm}:{0:ss}.{0:ff}' -f $timespan
                }
                elseif ($timespanFormat -eq 'seconds')
                {
                    $format = '{0:ss}'
                    #$prefixString = '{0:ss}.{0:ff}' -f $timespan
                }
                if ($milliseconds)
                {
                    $format = "$($format).{0:ff}"
                }
                $prefixString = $format -f $timespan
                # $prefixString = "$cyan$timestamp$reset $blue$prefixString$reset"
                $prefixString = "$gray$timestamp$reset $gray$prefixString$reset"
            }
            else
            {
                $prefixString = Get-Date -Format $dateFormat
            }

            if ($logonly -or $global:quiet)
            {
                if ($logFilePath)
                {
                    $prefixString = $prefixString.Replace("$cyan", '').Replace("$blue", '').Replace("$reset", '')
                    "$prefixString $text" | Out-File $logFilePath -Append
                }
            }
            else
            {
                #<#
                switch ($color)
                {
                    'Gray' {$color = $gray}
                    'Red' {$color = $red}
                    'Green' {$color = $green}
                    'Yellow' {$color = $yellow}
                    'Blue' {$color = $blue}
                    'Magenta' {$color = $magenta}
                    'Cyan' {$color = $cyan}
                    'White' {$color = $white}
                    Default {$white}
                }
                #>

                if ($verboseOnly)
                {
                    $prefixString = "$prefixString [$caller]"
                }

                if ($sameline)
                {
                    $script:lastCallWasSameLine = $true
                    Write-Host "`r$cyan$prefixString$reset $text" -NoNewline
                    #Write-Host "`r$prefixString $cyan$text$reset" -NoNewline
                    #Write-Host "`r$prefixString" -NoNewline -ForegroundColor Cyan
                    #Write-Host "`r $text" -ForegroundColor $color -NoNewline
                }
                else
                {
                    if ($script:lastCallWasSameLine)
                    {
                        Write-Host ''
                        $script:lastCallWasSameLine = $null
                    }
                    Write-Host $prefixString -NoNewline -ForegroundColor Gray
                    Write-Host " $text"  #-ForegroundColor $color
                    # Write-Host "$cyan$prefixString$reset $color$text$reset"
                }

                if ($logFilePath)
                {
                    # $prefixString = $prefixString.Replace("$cyan", '').Replace("$blue", '').Replace("$reset", '')
                    "$prefixString $text" | Out-File $logFilePath -Append
                }
            }
        }
    }
}

function Invoke-ExpressionWithLogging
{
    param(
        [string]$command,
        [switch]$raw,
        [switch]$verboseOnly
    )

    if ($verboseOnly)
    {
        if ($verbose)
        {
            if ($raw)
            {
                Out-Log $command -verboseOnly -raw
            }
            else
            {
                Out-Log $command -verboseOnly
            }
        }
    }
    else
    {
        if ($raw)
        {
            Out-Log $command -raw
        }
        else
        {
            Out-Log $command
        }
    }

    <# This results in error:

    Cannot convert argument "newChar", with value: "", for "Replace" to type "System.Char": "Cannot convert value "" to
    type "System.Char". Error: "String must be exactly one character long.""

    $command = $command.Replace($green, '').Replace($reset, '')
    #>

    try
    {
        Invoke-Expression -Command $command
    }
    catch
    {
        $global:errorRecordObject = $PSItem
        Out-Log "`n$command`n" -raw -color Red
        Out-Log "$global:errorRecordObject" -raw -color Red
        if ($LASTEXITCODE)
        {
            Out-Log "`$LASTEXITCODE: $LASTEXITCODE`n" -raw -color Red
        }
    }
}

$scriptStartTime = Get-Date
$scriptStartTimeString = Get-Date -Date $scriptStartTime -Format yyyyMMddHHmmss
$scriptFullName = $MyInvocation.MyCommand.Path
$scriptFolderPath = Split-Path -Path $scriptFullName
$scriptName = Split-Path -Path $scriptFullName -Leaf
$scriptBaseName = $scriptName.Split('.')[0]

$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'
$PSDefaultParameterValues['*:WarningAction'] = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'

$verbose = [bool]$PSBoundParameters['verbose']
$debug = [bool]$PSBoundParameters['debug']

if ($parameters)
{
    $script = Get-Command -Name $scriptFullName
    $parameterNames = $script.ParameterSets.Parameters.Name | Sort-Object -Unique
    $parameterNames = $parameterNames | Where-Object {$_ -notin 'verbose', 'whatif', 'warningaction', 'warningvariable', 'PipelineVariable', 'ProgressAction', 'OutBuffer', 'OutVariable', 'InformationAction', 'InformationVariable', 'ErrorAction', 'ErrorVariable', 'Debug', 'Confirm'}
    $parameterNames | Format-Column
    exit
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')
if ($isAdmin -eq $false)
{
    Write-Host 'Script must be run from an elevated PowerShell session' -ForegroundColor Cyan
    exit
}

if ($outputPath)
{
    $logFolderPath = $outputPath
}
else
{
    $logFolderParentPath = $env:TEMP
    $logFolderPath = "$logFolderParentPath\$scriptBaseName"
}
if ((Test-Path -Path $logFolderPath -PathType Container) -eq $false)
{
    Invoke-ExpressionWithLogging "New-Item -Path $logFolderPath -ItemType Directory -Force | Out-Null" -verboseOnly
}
$computerName = $env:COMPUTERNAME.ToUpper()

if ((Get-Service -Name winmgmt).Status -eq 'Running') {$invokeWmiMethodResult = Invoke-WmiMethod -Path "Win32_Directory.Name='$logFolderPath'" -Name Compress}
# $invokeWmiMethodResult = Invoke-WmiMethod -Path "Win32_Directory.Name='$logFolderPath'" -Name Compress
$logFilePath = "$logFolderPath\$($scriptBaseName)_$($computerName)_$($scriptStartTimeString).log"
if ((Test-Path -Path $logFilePath -PathType Leaf) -eq $false)
{
    New-Item -Path $logFilePath -ItemType File -Force | Out-Null
}
Out-Log "Log file: $logFilePath"

if ($testCSEWithCommand -or $testCSEWithScript)
{
    $vm = Get-AzVM -resourceGroupName $resourceGroupName -Name $vmName -ErrorAction Stop
    $location = $vm.Location
    $publisher = 'Microsoft.Compute'
    $extensionType = 'CustomScriptExtension'
    $name = "$publisher.$extensionType"
    [version]$version = (Get-AzVMExtensionImage -Location $location -PublisherName $publisher -Type $extensionType | Sort-Object {[Version]$_.Version} -Desc | Select-Object Version -First 1).Version
    $typeHandlerVersion = "$($version.Major).$($version.Minor)" #'1.10'
    $timestamp = Get-Date -Format yyyy-MM-ddTHH:mm:ss

    if ($testCSEWithCommand)
    {
        $settingString = "'{`"commandToExecute`": `"powershell.exe -ExecutionPolicy Unrestricted -command write-host HelloWorld $timestamp`"}'"
        $result = Invoke-ExpressionWithLogging "Set-AzVMExtension -Location $location -ResourceGroupName $resourceGroupName -VMName $vmName -Name $name -Publisher $publisher -ExtensionType $extensionType -TypeHandlerVersion $typeHandlerVersion -SettingString $settingString"
    }
    elseif ($testCSEWithScript)
    {
        $scriptUrl = 'https://raw.githubusercontent.com/Azure/azure-support-scripts/master/VMAgent/Test-CustomScriptExtension.ps1'
        $scriptFileName = $scriptUrl.Split('/')[-1]
        $settings = @{
            'fileUris'         = @($scriptUrl)
            'commandToExecute' = "powerShell -ExecutionPolicy Bypass -Nologo -NoProfile -File $scriptFileName"
            'ticks'            = (Get-Date).Ticks
        }
        $command = "Set-AzVMExtension -Location $location -ResourceGroupName $resourceGroupName -VMName $vmName -Name $name -Publisher $publisher -ExtensionType $extensionType -TypeHandlerVersion $typeHandlerVersion -Settings `$settings"
        Out-Log $command
        $result = Set-AzVMExtension -Location $location -ResourceGroupName $resourceGroupName -VMName $vmName -Name $name -Publisher $publisher -ExtensionType $extensionType -TypeHandlerVersion $typeHandlerVersion -Settings $settings
    }
    Out-Log ($result | Out-String) -raw

    $extensionStatus = Get-AzVMExtension -ResourceGroupName $resourceGroupName -VMName $vmName -Name $name -Status
    $statuses = $extensionStatus.Statuses
    $subStatuses = $extensionStatus.SubStatuses
    $subStatusesStdOut = ($subStatuses | where Code -match 'StdOut').Message
    $subStatusesStdErr = ($subStatuses | where Code -match 'StdErr').Message
    Out-Log "STDOUT: $($subStatusesStdOut.Trim())" -raw
    Out-Log "STDERR: $($subStatusesStdErr.Trim())" -raw
}

if ($enableStaticIp -or $enableDhcp)
{

$enableStaticIpScriptContents = @'
$scriptStartTime = Get-Date
$scriptFullName = $MyInvocation.MyCommand.Path
$scriptFolderPath = Split-Path -Path $scriptFullName
$scriptName = Split-Path -Path $scriptFullName -Leaf
$scriptBaseName = $scriptName.Split('.')[0]
$logFileNameSuffix = Get-Date $scriptStartTime -Format yyyyMMddHHmmssff
$logFilePath = "$scriptFolderPath\$($scriptBaseName)_$($logFileNameSuffix).log"
$scriptStartString = "$scriptFullName $(Get-Date $scriptStartTime -Format yyyy-MM-ddTHH:mm:ss.ff)"
Write-Output $scriptStartString
$scriptStartString | Out-File -FilePath $logFilePath

$addressFamily = 'IPv4'
$ipconfig = Get-NetIPConfiguration
$interfaceAlias = $ipconfig.InterfaceAlias
$interfaceIndex = $ipconfig.InterfaceIndex
$ipV4Address = $ipconfig.IPv4Address.IPAddress
$ipV4DefaultGateway = $ipconfig.IPv4DefaultGateway.NextHop
$dnsServer = $ipconfig.DNSServer
$adapter = Get-NetAdapter -InterfaceIndex $interfaceIndex -Physical
$netIPAddress = Get-NetIPAddress -InterfaceIndex $interfaceIndex -AddressFamily $addressFamily
$prefixLength = $netIPAddress.PrefixLength
$interface = Get-NetIPInterface -InterfaceIndex $interfaceIndex -AddressFamily $addressFamily
$dnsServerAddresses = Get-DnsClientServerAddress -InterfaceIndex $interfaceIndex -AddressFamily $addressFamily | Select-Object -ExpandProperty ServerAddresses
$adapter | Remove-NetIPAddress -AddressFamily $addressFamily -Confirm:$false
$adapter | Remove-NetRoute -AddressFamily $IPType -Confirm:$false
New-NetIPAddress -InterfaceIndex $interfaceIndex -AddressFamily $addressFamily -IPAddress $ipV4Address -PrefixLength $prefixLength -DefaultGateway $ipV4DefaultGateway
Set-DnsClientServerAddress -InterfaceIndex $interfaceIndex -ServerAddresses $dnsServerAddresses
$adapter | Restart-NetAdapter

$scriptTimespan = New-TimeSpan -Start $scriptStartTime -End (Get-Date)
$scriptSeconds = [Math]::Round($scriptTimespan.TotalSeconds,0)
$scriptDuration = '{0:hh}:{0:mm}:{0:ss}.{0:ff}' -f $scriptTimespan
$scriptEndString = "$scriptName duration $scriptDuration ($scriptSeconds seconds)"
Write-Output $scriptEndString
$scriptEndString | Out-File -FilePath $logFilePath -Append
'@

$enableDhcpScriptContents = @'
$scriptStartTime = Get-Date
$scriptFullName = $MyInvocation.MyCommand.Path
$scriptFolderPath = Split-Path -Path $scriptFullName
$scriptName = Split-Path -Path $scriptFullName -Leaf
$scriptBaseName = $scriptName.Split('.')[0]
$logFileNameSuffix = Get-Date $scriptStartTime -Format yyyyMMddHHmmssff
$logFilePath = "$scriptFolderPath\$($scriptBaseName)_$($logFileNameSuffix).log"
$scriptStartString = "$scriptFullName $(Get-Date $scriptStartTime -Format yyyy-MM-ddTHH:mm:ss.ff)"
Write-Output $scriptStartString
$scriptStartString | Out-File -FilePath $logFilePath

$addressFamily = 'IPv4'
$ipconfig = Get-NetIPConfiguration
$interfaceIndex = $ipconfig.InterfaceIndex
$adapter = Get-NetAdapter -InterfaceIndex $interfaceIndex -Physical
$interface = Get-NetIPInterface -InterfaceIndex $interfaceIndex -AddressFamily $addressFamily
$interface | Remove-NetRoute -Confirm:$false
$interface | Set-NetIPInterface -DHCP Enabled
$interface | Set-DnsClientServerAddress -ResetServerAddresses
$adapter | Restart-NetAdapter

$scriptTimespan = New-TimeSpan -Start $scriptStartTime -End (Get-Date)
$scriptSeconds = [Math]::Round($scriptTimespan.TotalSeconds,0)
$scriptDuration = '{0:hh}:{0:mm}:{0:ss}.{0:ff}' -f $scriptTimespan
$scriptEndString = "$scriptName duration $scriptDuration ($scriptSeconds seconds)"
Write-Output $scriptEndString
$scriptEndString | Out-File -FilePath $logFilePath -Append
'@

    $myFolderPath = 'c:\my'

    $enableStaticIpScriptFilePath = "$myFolderPath\Enable-StaticIp.ps1"
    New-Item -Path $enableStaticIpScriptFilePath -ItemType File -Force
    Set-Content -Path $enableStaticIpScriptFilePath -Value $enableStaticIpScriptContents -Force

    $enableDhcpScriptFilePath = "$myFolderPath\Enable-DHCP.ps1"
    New-Item -Path $enableDhcpScriptFilePath -ItemType File -Force
    Set-Content -Path $enableDhcpScriptFilePath -Value $enableDhcpScriptContents -Force

    # Adds a startup task to enable DHCP so regardless the state it's left in,
    # restarting the VM will enable DHCP again
    $TASK_TRIGGER_BOOT = 8
    $taskName = 'EnableDHCP'
    $execute = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $argument = "-NoLogo -NoProfile -File $enableDhcpScriptFilePath"
    $action = New-ScheduledTaskAction -Execute $execute -Argument $argument
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -RunLevel Highest -LogonType ServiceAccount
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Compatibility 'Win8'
    $task = New-ScheduledTask -Action $action -Principal $principal -Trigger $trigger -Settings $settings
    Register-ScheduledTask -TaskName $taskName -InputObject $task -Force | Out-Null

    if ($enableStaticIp)
    {
        powershell -NoLogo -NoProfile -File $enableStaticIpScriptFilePath
    }
    elseif ($enableDhcp)
    {
        powershell -NoLogo -NoProfile -File $enableDhcpScriptFilePath
    }
}

if ($setNonDefaultMachineKeysAcl -or $setDefaultMachineKeysAcl)
{
    $machineKeysPath = 'C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys'
    $machineKeysAcl = Get-Acl -Path $machineKeysPath

    if ($setNonDefaultMachineKeysAcl)
    {
        $identity = "Everyone"
        $fileSystemRights = "FullControl"
        $type = "Deny"
        $fileSystemAccessRuleArgumentList = $identity, $fileSystemRights, $type
        $fileSystemAccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $fileSystemAccessRuleArgumentList
        $machineKeysAcl.SetAccessRule($fileSystemAccessRule)
    }

    if ($setDefaultMachineKeysAcl)
    {
        $machineKeysDefaultSddl = 'O:SYG:SYD:PAI(A;;0x12019f;;;WD)(A;;FA;;;BA)'
        $machineKeysAcl.SetSecurityDescriptorSddlForm($machineKeysDefaultSddl)
    }

    Set-Acl -Path $machineKeysPath -AclObject $machineKeysAcl
    Out-Log ((Get-Acl -Path $machineKeysPath).Access | Format-Table -AutoSize | Out-String) -raw
}

if ($setNonDefaultWindowsAzureAcl -or $setDefaultWindowsAzureAcl)
{
    $windowsAzurePath = 'C:\WindowsAzure'
    $windowsAzureAcl = Get-Acl -Path $windowsAzurePath

    if ($setNonDefaultWindowsAzureAcl)
    {
        $identity = "Everyone"
        $fileSystemRights = "FullControl"
        $type = "Deny"
        $fileSystemAccessRuleArgumentList = $identity, $fileSystemRights, $type
        $fileSystemAccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $fileSystemAccessRuleArgumentList
        $windowsAzureAcl.SetAccessRule($fileSystemAccessRule)
    }

    if ($setDefaultWindowsAzureAcl)
    {
        $windowsAzureDefaultSddl = 'O:SYG:SYD:PAI(A;OICI;0x1200a9;;;WD)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
        $windowsAzureAcl.SetSecurityDescriptorSddlForm($windowsAzureDefaultSddl)
    }

    Set-Acl -Path $windowsAzurePath -AclObject $windowsAzureAcl
    Out-Log ((Get-Acl -Path $windowsAzurePath).Access | Format-Table -AutoSize | Out-String) -raw
}

if ($setNonDefaultPackagesAcl -or $setDefaultPackagesAcl)
{
    $packagesPath = 'C:\Packages'
    $packagesAcl = Get-Acl -Path $packagesPath

    if ($setNonDefaultPackagesAcl)
    {
        $identity = "Everyone"
        $fileSystemRights = "FullControl"
        $type = "Deny"
        $fileSystemAccessRuleArgumentList = $identity, $fileSystemRights, $type
        $fileSystemAccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $fileSystemAccessRuleArgumentList
        $packagesAcl.SetAccessRule($fileSystemAccessRule)
    }

    if ($setDefaultPackagesAcl)
    {
        $packagesDefaultSddl = 'O:BAG:SYD:PAI(A;OICI;0x1200a9;;;WD)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
        $packagesAcl.SetSecurityDescriptorSddlForm($packagesDefaultSddl)
    }

    Set-Acl -Path $packagesPath -AclObject $packagesAcl
    Out-Log ((Get-Acl -Path $packagesPath).Access | Format-Table -AutoSize | Out-String) -raw
}

if ($removeCSE)
{
    Import-Module Az.Compute
    $publisher = 'Microsoft.Compute'
    $extensionType = 'CustomScriptExtension'
    $name = "$publisher.$extensionType"
    $result = Invoke-ExpressionWithLogging "Remove-AzVMExtension -ResourceGroupName $resourceGroupName -VMName $vmName -Name $name -Force"
    Out-Log ($result | Out-String) -raw
}

if ($enableWcfDebugging)
{
    # VS22 17.8+ have MSFT_VSInstance class in root/cimv2/vs namespace
    # <VS22 17.8 the MSFT_VSInstance class is in root/cimv2 namespace

    if (Get-CimClass -ClassName 'MSFT_VSInstance' -Namespace 'root/cimv2/vs' -ErrorAction SilentlyContinue)
    {
        $productLocation = Invoke-ExpressionWithLogging "Get-CimInstance -ClassName 'MSFT_VSInstance' -Namespace 'root/cimv2/vs' -Property ProductLocation -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProductLocation"
    }
    elseif (Get-CimClass -ClassName 'MSFT_VSInstance' -Namespace 'root/cimv2' -ErrorAction SilentlyContinue)
    {
        $productLocation = Invoke-ExpressionWithLogging "Get-CimInstance -ClassName 'MSFT_VSInstance' -Namespace 'root/cimv2' -Property ProductLocation -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProductLocation"
    }
    else
    {
        Out-Log "Visual Studio is not installed."
        Out-Log "The vsdiag_regwcf.exe tool is installed by the Windows Communication Framework component of Visual Studio. It cannot run as a standalone EXE."
        Out-Log "To install Visual Studio: https://aka.ms/vs/17/release/vs_enterprise.exe"
        exit
    }

    if (Test-Path -Path $productLocation -PathType Leaf)
    {
        $vsdiagRegwcfFilePath = "$(Split-Path -Path $productLocation)\vsdiag_regwcf.exe"
        if (Test-Path -Path $vsdiagRegwcfFilePath -PathType Leaf)
        {
            $timestamp = Get-Date -Format 'yyyyMMddHHmmss'
            $machineConfigx64FilePath = "$env:SystemRoot\Microsoft.NET\Framework64\v4.0.30319\config\machine.config"
            Invoke-ExpressionWithLogging "Copy-Item -Path $machineConfigx64FilePath $machineConfigx64FilePath.$timestamp"
            Invoke-ExpressionWithLogging "& '$vsdiagRegwcfFilePath' -i"
            $result = Invoke-ExpressionWithLogging "& '$vsdiagRegwcfFilePath' -s" | Out-String -Width 4096
            Out-Log $result -raw
        }
        else
        {
            Out-Log "File not found: $vsdiagRegwcfFilePath"
            exit 2
        }
    }
    else
    {
        Out-Log "File not found: $productLocation"
        exit 2
    }
}

if ($disableWcfDebugging)
{
    # VS22 17.8+ have MSFT_VSInstance class in root/cimv2/vs namespace
    # <VS22 17.8 the MSFT_VSInstance class is in root/cimv2 namespace

    if (Get-CimClass -ClassName 'MSFT_VSInstance' -Namespace 'root/cimv2/vs' -ErrorAction SilentlyContinue)
    {
        $productLocation = Invoke-ExpressionWithLogging "Get-CimInstance -ClassName 'MSFT_VSInstance' -Namespace 'root/cimv2/vs' -Property ProductLocation -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProductLocation"
    }
    elseif (Get-CimClass -ClassName 'MSFT_VSInstance' -Namespace 'root/cimv2' -ErrorAction SilentlyContinue)
    {
        $productLocation = Invoke-ExpressionWithLogging "Get-CimInstance -ClassName 'MSFT_VSInstance' -Namespace 'root/cimv2' -Property ProductLocation -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProductLocation"
    }
    else
    {
        Out-Log "Visual Studio is not installed."
        Out-Log "The vsdiag_regwcf.exe tool is installed by the Windows Communication Framework component of Visual Studio. It cannot run as a standalone EXE."
        Out-Log "To install Visual Studio: https://aka.ms/vs/17/release/vs_enterprise.exe"
        exit
    }

    if (Test-Path -Path $productLocation -PathType Leaf)
    {
        $vsdiagRegwcfFilePath = "$(Split-Path -Path $productLocation)\vsdiag_regwcf.exe"
        if (Test-Path -Path $vsdiagRegwcfFilePath -PathType Leaf)
        {
            $timestamp = Get-Date -Format 'yyyyMMddHHmmss'
            $machineConfigx64FilePath = "$env:SystemRoot\Microsoft.NET\Framework64\v4.0.30319\config\machine.config"
            Invoke-ExpressionWithLogging "Copy-Item -Path $machineConfigx64FilePath $machineConfigx64FilePath.$timestamp"
            Invoke-ExpressionWithLogging "& '$vsdiagRegwcfFilePath' -u"
            $result = Invoke-ExpressionWithLogging "& '$vsdiagRegwcfFilePath' -s" | Out-String -Width 4096
            Out-Log $result -raw
        }
        else
        {
            Out-Log "File not found: $vsdiagRegwcfFilePath"
            exit 2
        }
    }
    else
    {
        Out-Log "File not found: $productLocation"
        exit 2
    }
}


if ($setprofile)
{
    Set-ExecutionPolicy Bypass -Force
    New-Item -Path $profile -ItemType File -Force | Out-Null
    Add-Content -Path $profile -Value "Set-Alias g '\\tsclient\c\src\VMAssist\VMAssist.ps1'" -Force
    Add-Content -Path $profile -Value "Set-Alias t '\\tsclient\c\src\VMAssist\Test-VMAssist.ps1'" -Force
    Add-Content -Path $profile -Value "Set-Alias w '\\tsclient\c\onedrive\my\Set-Wallpaper.ps1'" -Force
    Add-Content -Path $profile -Value "Set-Location -Path C:\" -Force
    Add-Content -Path $profile -Value "Clear-Host" -Force
}

if ($enableWinmgmt)
{
    Invoke-ExpressionWithLogging 'Get-Service -Name winmgmt | Format-Table -Autosize Name,ServiceName,Status,StartType'
    Invoke-ExpressionWithLogging 'Set-Service -Name winmgmt -StartupType Automatic -Status Running'
    # Invoke-ExpressionWithLogging 'Start-Service -Name winmgmt'
    Invoke-ExpressionWithLogging 'Get-Service -Name winmgmt | Format-Table -Autosize Name,ServiceName,Status,StartType'
}

if ($disableWinmgmt)
{
    Invoke-ExpressionWithLogging 'Stop-Service -Name winmgmt -Force'
    Invoke-ExpressionWithLogging 'Set-Service -Name winmgmt -StartupType Disabled'
    Invoke-ExpressionWithLogging 'Get-Service -Name winmgmt | Format-Table -Autosize Name,ServiceName,Status,StartType'
}

if ($stopRdagent -or $startRdagent -or $disableRdagent -or $enableRdagent -or $stopWindowsAzureGuestAgent -or $startWindowsAzureGuestAgent -or $disableWindowsAzureGuestAgent -or $enableWindowsAzureGuestAgent -or $stopGAServices -or $startGAServices -or $disableGAServices -or $enableGAServices)
{
    if ($stopRdagent)
    {
        Invoke-ExpressionWithLogging 'Stop-Service -Name rdagent'
    }

    if ($startRdagent)
    {
        Invoke-ExpressionWithLogging 'Start-Service -Name rdagent'
    }

    if ($disableRdagent)
    {
        Invoke-ExpressionWithLogging 'Set-Service -Name rdagent -StartupType Disabled'
    }

    if ($enableRdagent)
    {
        Invoke-ExpressionWithLogging 'Set-Service -Name rdagent -StartupType Automatic'
    }

    if ($stopWindowsAzureGuestAgent)
    {
        Invoke-ExpressionWithLogging 'Stop-Service -Name WindowsAzureGuestAgent'
    }

    if ($startWindowsAzureGuestAgent)
    {
        Invoke-ExpressionWithLogging 'Start-Service -Name WindowsAzureGuestAgent'
    }

    if ($disableWindowsAzureGuestAgent)
    {
        Invoke-ExpressionWithLogging 'Set-Service -Name WindowsAzureGuestAgent -StartupType Disabled'
    }

    if ($enableWindowsAzureGuestAgent)
    {
        Invoke-ExpressionWithLogging 'Set-Service -Name WindowsAzureGuestAgent -StartupType Automatic'
    }

    if ($stopGAServices)
    {
        Invoke-ExpressionWithLogging 'Stop-Service -Name rdagent,WindowsAzureGuestAgent'
    }

    if ($startGAServices)
    {
        Invoke-ExpressionWithLogging 'Start-Service -Name rdagent,WindowsAzureGuestAgent'
    }

    if ($disableGAServices)
    {
        Invoke-ExpressionWithLogging 'Set-Service -Name rdagent -StartupType Disabled'
        Invoke-ExpressionWithLogging 'Set-Service -Name WindowsAzureGuestAgent -StartupType Disabled'
    }

    if ($enableGAServices)
    {
        Invoke-ExpressionWithLogging 'Set-Service -Name rdagent -StartupType Automatic'
        Invoke-ExpressionWithLogging 'Set-Service -Name WindowsAzureGuestAgent -StartupType Automatic'
    }

    $result = Invoke-ExpressionWithLogging "Get-Service -Name ('rdagent','WindowsAzureGuestAgent') | Format-Table -Autosize Name,ServiceName,Status,StartType | Out-String"
    Out-Log $result.Trim() -raw
}

if ($blockwireserver)
{
    $result = Invoke-ExpressionWithLogging "New-NetFirewallRule -DisplayName 'Block outbound traffic to 168.63.129.16' -Direction Outbound -LocalPort Any -Protocol TCP -Action Block -RemoteAddress 168.63.129.16"
    Out-Log ($result | Out-String) -raw
}

if ($unblockwireserver)
{
    $result = Invoke-ExpressionWithLogging "Remove-NetFirewallRule -DisplayName 'Block outbound traffic to 168.63.129.16'"
    Out-Log ($result | Out-String) -raw
}

if ($blockimds)
{
    $result = Invoke-ExpressionWithLogging "New-NetFirewallRule -DisplayName 'Block outbound traffic to 169.254.169.254' -Direction Outbound -LocalPort Any -Protocol TCP -Action Block -RemoteAddress 169.254.169.254"
    Out-Log ($result | Out-String) -raw
}

if ($unblockimds)
{
    $result = Invoke-ExpressionWithLogging "Remove-NetFirewallRule -DisplayName 'Block outbound traffic to 169.254.169.254'"
    Out-Log ($result | Out-String) -raw
}

if ($enableProxy)
{
    $result = Invoke-ExpressionWithLogging "netsh winhttp set proxy proxy-server='http=192.168.0.1:8080;https=192.168.0.1:8080'"
    Out-Log ($result | Out-String) -raw
    $result = Invoke-ExpressionWithLogging "netsh winhttp show proxy"
    Out-Log ($result | Out-String) -raw
}

if ($disableProxy)
{
    $result = Invoke-ExpressionWithLogging "netsh winhttp reset proxy"
    Out-Log ($result | Out-String) -raw
    $result = Invoke-ExpressionWithLogging "netsh winhttp show proxy"
    Out-Log ($result | Out-String) -raw
}
