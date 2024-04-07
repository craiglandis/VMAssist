<#
.SYNOPSIS
    Assists in diagnosing Azure VM issues
.DESCRIPTION
    Assists in diagnosing Azure VM issues
.NOTES
    Supported on Windows Server 2012 R2 and later versions of Windows.
    Supported in Windows PowerShell 4.0+ and PowerShell 6.0+.
    Not supported on Linux.
.LINK
    https://github.com/craiglandis/VMAssist/blob/main/README.md
.EXAMPLE
    RDP to Azure VM
    Launch an elevated PowerShell prompt
    Download VMAssist.ps1 with the following command

    VMAssist.ps1
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [string]$outputPath = 'C:\logs',
    [switch]$showReport,
    [switch]$fakeFinding,
    [switch]$skipFirewall,
    [switch]$skipFilters,
    [switch]$useDotnetForNicDetails
)

trap
{
    $trappedError = $PSItem
    $global:trappedError = $trappedError
    $scriptLineNumber = $trappedError.InvocationInfo.ScriptLineNumber
    $line = $trappedError.InvocationInfo.Line.Trim()
    $exceptionMessage = $trappedError.Exception.Message
    $trappedErrorString = $trappedError.Exception.ErrorRecord | Out-String -ErrorAction SilentlyContinue
    Out-Log "[ERROR] $exceptionMessage Line $scriptLineNumber $line" -color Red
    $properties = @{
        vmId  = $vmId
        error = $trappedErrorString
    }
    Send-Telemetry -properties $properties
    continue
}

<#
Add check to compare file hashes of machine.config and machine.config.default - if they differ we know they changed machine.config
(Get-FileHash -Path C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\machine.config -Algorithm SHA256 | Select-Object -ExpandProperty Hash) -eq (Get-FileHash -Path C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\machine.config.default -Algorithm SHA256 | Select-Object -ExpandProperty Hash)
#>
function Get-WCFConfig
{
    <#
    Microsoft.VisualStudio.Diagnostics.ServiceModelSink.dll must be present for the related machine.config settings to work
    C:\Windows\Microsoft.NET\assembly\GAC_MSIL\Microsoft.VisualStudio.Diagnostics.ServiceModelSink\v4.0_4.0.0.0__b03f5f7f11d50a3a\Microsoft.VisualStudio.Diagnostics.ServiceModelSink.dll
    C:\Windows\assembly\GAC_MSIL\Microsoft.VisualStudio.Diagnostics.ServiceModelSink\3.0.0.0__b03f5f7f11d50a3a\Microsoft.VisualStudio.Diagnostics.ServiceModelSink.dll
    vsdiag_regwcf.exe is the tool to use to enable/disable WCF debugging. It does the machine.config edits.
    It is installed as part of the Windows Communication Framework component of Visual Studio, up-to-and-including VS2022:
    C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\IDE\vsdiag_regwcf.exe
    C:\OneDrive\tools\vsdiag_regwcf.exe -i
    gc C:\Windows\Microsoft.NET\Framework64\v4.0.30319\config\machine.config | findstr /i servicemodelsink
                <add name="Microsoft.VisualStudio.Diagnostics.ServiceModelSink.Behavior" type="Microsoft.VisualStudio.Diagnostics.ServiceModelSink.Behavior, Microsoft.VisualStudio.Diagnostics.ServiceModelSink, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"/></behaviorExtensions>
        <commonBehaviors><endpointBehaviors><Microsoft.VisualStudio.Diagnostics.ServiceModelSink.Behavior/></endpointBehaviors><serviceBehaviors><Microsoft.VisualStudio.Diagnostics.ServiceModelSink.Behavior/></serviceBehaviors></commonBehaviors></system.serviceModel>
    C:\OneDrive\tools\vsdiag_regwcf.exe -u
    gc C:\Windows\Microsoft.NET\Framework64\v4.0.30319\config\machine.config | findstr /i servicemodelsink
    #>
    Out-Log 'WCF debugging enabled:' -startLine
    $machineConfigx64FilePath = "$env:SystemRoot\Microsoft.NET\Framework64\v4.0.30319\config\machine.config"
    $matches = Get-Content -Path $machineConfigx64FilePath | Select-String -SimpleMatch 'Microsoft.VisualStudio.Diagnostics.ServiceModelSink'
    if ($matches)
    {
        $serviceModelSinkDllParentPath1 = 'C:\Windows\Microsoft.NET\assembly\GAC_MSIL\Microsoft.VisualStudio.Diagnostics.ServiceModelSink'
        $serviceModelSinkDllParentPath2 = 'C:\Windows\assembly\GAC_MSIL\Microsoft.VisualStudio.Diagnostics.ServiceModelSink'
        $serviceModelSinkDllPath1 = Get-ChildItem -Path $ServiceModelSinkDllParentPath1 -Filter 'Microsoft.VisualStudio.Diagnostics.ServiceModelSink.dll' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
        $serviceModelSinkDllPath2 = Get-ChildItem -Path $ServiceModelSinkDllParentPath2 -Filter 'Microsoft.VisualStudio.Diagnostics.ServiceModelSink.dll' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName

        if (Get-CimClass -ClassName 'MSFT_VSInstance' -Namespace 'root/cimv2/vs' -ErrorAction SilentlyContinue)
        {
            $vsInstance = Invoke-ExpressionWithLogging "Get-CimInstance -ClassName 'MSFT_VSInstance' -Namespace 'root/cimv2/vs' -ErrorAction SilentlyContinue" -verboseOnly
        }
        elseif (Get-CimClass -ClassName 'MSFT_VSInstance' -Namespace 'root/cimv2' -ErrorAction SilentlyContinue)
        {
            $vsInstance = Invoke-ExpressionWithLogging "Get-CimInstance -ClassName 'MSFT_VSInstance' -Namespace 'root/cimv2' -ErrorAction SilentlyContinue" -verboseOnly
        }

        if ($vsInstance)
        {
            $productLocation = $vsInstance | Select-Object -ExpandProperty ProductLocation -ErrorAction SilentlyContinue
        }
        else
        {
            Out-Log "Visual Studio is not installed."
            Out-Log "The vsdiag_regwcf.exe tool is installed by the Windows Communication Framework component of Visual Studio. It cannot run as a standalone EXE."
            Out-Log "To install Visual Studio: https://aka.ms/vs/17/release/vs_enterprise.exe"
        }

        if ($productLocation -and (Test-Path -Path $productLocation -PathType Leaf))
        {
            $vsdiagRegwcfFilePath = "$(Split-Path -Path $productLocation)\vsdiag_regwcf.exe"
            if (Test-Path -Path $vsdiagRegwcfFilePath -PathType Leaf)
            {
                $vsdiagRegwcfExists = $true
                Out-Log "Found $vsdiagRegwcfExists" -verboseOnly
            }
            else
            {
                $vsdiagRegwcfExists = $false
                Out-Log "File not found: $vsdiagRegwcfExists" -verboseOnly
            }
        }
        else
        {
            Out-Log "File not found: $productLocation"
            $vsdiagRegwcfExists = $false
        }

        $machineConfigStrings = $matches.ToString()
        $matchesString = $matches.Line.Replace('<','&lt;').Replace('>','&gt;')
        #$matchesString = "<div class='box'><pre><code>$matchesString</code></pre></div>"
        #$matchesString = $matches.Line

        $global:dbgMatchesString = $matchesString
        $wcfDebuggingEnabled = $true
        Out-Log $wcfDebuggingEnabled -color Red -endLine
        New-Check -name 'WCF debugging config' -result 'FAILED' -details 'WCF debugging is enabled'
        $global:dbgMachineConfigStrings = $machineConfigStrings
        $description = "$machineConfigx64FilePath shows WCF debugging is enabled:<p>$matchesString<p>"
        $global:dbgDescription = $description
        New-Finding -type Critical -name 'WCF debugging enabled' -description $description
    }
    else
    {
        $wcfDebuggingEnabled = $false
        Out-Log $wcfDebuggingEnabled -color Green -endLine
        New-Check -name 'WCF debugging config' -result 'OK' -details 'WCF debugging not enabled'
    }
}

function Confirm-HyperVGuest
{
    # SystemManufacturer/SystemProductName valus are in different locations depending if Gen1 vs Gen2
    $systemManufacturer = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SystemManufacturer
    $systemProductName = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SystemProductName
    if ([string]::IsNullOrEmpty($systemManufacturer) -and [string]::IsNullOrEmpty($systemProductName))
    {
        $systemManufacturer = Get-ItemProperty "HKLM:\HARDWARE\DESCRIPTION\System\BIOS" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SystemManufacturer
        $systemProductName = Get-ItemProperty "HKLM:\HARDWARE\DESCRIPTION\System\BIOS" -ErrorAction SilentlyContinue| Select-Object -ExpandProperty SystemProductName
        if ([string]::IsNullOrEmpty($systemManufacturer) -and [string]::IsNullOrEmpty($systemProductName))
        {
            $systemManufacturer = Get-ItemProperty "HKLM:\SYSTEM\HardwareConfig\Current" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SystemManufacturer
            $systemProductName = Get-ItemProperty "HKLM:\SYSTEM\HardwareConfig\Current" -ErrorAction SilentlyContinue| Select-Object -ExpandProperty SystemProductName
        }
    }

    if ($systemManufacturer -eq 'Microsoft Corporation' -and $systemProductName -eq 'Virtual Machine')
    {
        # Deterministic for being a Hyper-V guest, but not for if it's in Azure or local
        $isHyperVGuest = $true
    }
    else
    {
        $isHyperVGuest = $false
    }
    return $isHyperVGuest
}

function Get-ApplicationErrors
{
    param(
        [string]$name
    )
    Out-Log "$name process errors:" -startLine
    $applicationErrors = Get-WinEvent -FilterHashtable @{ProviderName = 'Application Error';Id = 1000; StartTime = ((Get-Date).AddDays(-7))} -ErrorAction SilentlyContinue | Where-Object {$_.Message -match $name}
    if ($applicationErrors)
    {
        $applicationErrorsCount = $applicationErrors | Measure-Object | Select-Object -ExpandProperty Count
        $latestApplicationError = $applicationErrors | Sort-Object TimeCreated | Select-Object -Last 1
        $timeCreated = Get-Date $latestApplicationError.TimeCreated -Format 'yyyy-MM-ddTHH:mm:ss'
        $id = $latestApplicationError.Id
        $message = $latestApplicationError.Message
        $description = "$applicationErrorsCount $name process errors in the last 1 day. Most recent: $timeCreated $id $message"
        New-Finding -type 'Critical' -name "$name application error" -description $description -mitigation ''
        New-Check -name "$name process errors" -result 'FAILED' -details ''
        Out-Log $false -color Red -endLine
    }
    else
    {
        New-Check -name "$name process errors" -result 'OK' -details "No $name process errors in last 1 day"
        Out-Log $true -color Green -endLine
    }
}

function Get-ServiceCrashes
{
    param(
        [string]$name
    )
    Out-Log "$name service crashes:" -startLine
    $serviceCrashes = Get-WinEvent -FilterHashtable @{ProviderName = 'Service Control Manager'; Id = 7031,7034; StartTime = ((Get-Date).AddDays(-1))} -ErrorAction SilentlyContinue | Where-Object {$_.Message -match $name}
    if ($serviceCrashes)
    {
        $serviceCrashesCount = $serviceCrashes | Measure-Object | Select-Object -ExpandProperty Count
        $latestCrash = $serviceCrashes | Sort-Object TimeCreated | Select-Object -Last 1
        $timeCreated = Get-Date $latestCrash.TimeCreated -Format 'yyyy-MM-ddTHH:mm:ss'
        $id = $latestCrash.Id
        $message = $latestCrash.Message
        $description = "$serviceCrashesCount $name service crashes in the last 1 day. Most recent: $timeCreated $id $message"
        New-Finding -type 'Critical' -name "$name service terminated unexpectedly" -description $description -mitigation ''
        New-Check -name "$name service crashes" -result 'FAILED' -details ''
        Out-Log $true -color Red -endLine
    }
    else
    {
        New-Check -name "$name service crashes" -result 'OK' -details "No $name service crashes in last 1 day"
        Out-Log $false -color Green -endLine
    }
}

function Get-WfpFilters
{
    Out-Log "Getting WFP filters:" -startLine

    $wireserverWfpFiltersPath = "$scriptFolderPath\wireserverFilters.xml"
    $result = Invoke-ExpressionWithLogging "netsh wfp show filters dir=OUT remoteaddr=168.63.129.16 file=$wireserverWfpFiltersPath" -verboseOnly
    [xml]$wireserverWfpFilters = Get-Content -Path $wireserverWfpFiltersPath

    $wfpFiltersPath = "$scriptFolderPath\wfpFilters.xml"
    $result = Invoke-ExpressionWithLogging "netsh wfp show filters file=$wfpFiltersPath" -verboseOnly
    [xml]$wfpFilters = Get-Content -Path $wfpFiltersPath

    $displayDataName = @{Name = 'displayData.name'; Expression = {$_.displayData.name}}
    $displayDataDescription = @{Name = 'displayData.description'; Expression = {$_.displayData.description}}
    $flagsNumItems = @{Name = 'flags.numItems'; Expression = {$_.flags.numItems}}
    $providerDataData = @{Name = 'providerData.data'; Expression = {$_.providerData.data}}
    $providerDataAsString = @{Name = 'providerData.asString'; Expression = {$_.providerData.asString}}
    $weightType = @{Name = 'weight.type'; Expression = {$_.weight.type}}
    $weightUint8 = @{Name = 'weight.uint8'; Expression = {$_.weight.uint8}}
    $filterConditionNumItems = @{Name = 'filterCondition.numItems'; Expression = {$_.filterCondition.numItems}}
    $actionType = @{Name = 'action.type'; Expression = {$_.action.type}}
    $actionFilterType = @{Name = 'action.filterType'; Expression = {$_.action.filterType}}
    $effectiveWeightType = @{Name = 'effectiveWeight.type'; Expression = {$_.effectiveWeight.type}}
    $effectiveWeightUint64 = @{Name = 'effectiveWeight.uint64'; Expression = {$_.effectiveWeight.uint64}}

    $providers = $wfpFilters.wfpdiag.providers.Item | Select-Object serviceName,providerKey,$displayDataName,$displayDataDescription,$flagsNumItems
    $filters = $wfpFilters.wfpdiag.filters.item | Select-Object $actionType,$displayDataName,$displayDataDescription,filterKey,providerKey,layerKey,subLayerKey,providerContextKey,filterId,reserved,$flagsNumItems,$providerDataData,$providerDataAsString,$weightType,$weightUint8,$filterConditionNumItems,$actionFilterType,$effectiveWeightType,$effectiveWeightUint64
    $filters = $filters | Sort-Object 'effectiveWeight.uint64'
    $wireserverFilters = $wireserverWfpFilters.wfpdiag.filters.item | Select-Object $actionType,$displayDataName,$displayDataDescription,filterKey,providerKey,layerKey,subLayerKey,providerContextKey,filterId,reserved,$flagsNumItems,$providerDataData,$providerDataAsString,$weightType,$weightUint8,$filterConditionNumItems,$actionFilterType,$effectiveWeightType,$effectiveWeightUint64
    $wireserverFilters = $wireserverFilters | Sort-Object 'effectiveWeight.uint64'

    $result = [PSCustomObject]@{
        Providers = $providers
        Filters = $filters
        WireserverFilters = $wireserverFilters
    }

    $filtersCount = $filters | Measure-Object | Select-Object -ExpandProperty Count
    Out-Log "$filtersCount WPF filters" -endLine
    return $result
}

function Get-EnabledFirewallRules
{
    Out-Log "Getting enabled Windows firewall rules: " -startLine
    $getNetFirewallRuleDuration = Measure-Command {$enabledRules = Get-NetFirewallRule -Enabled True | Where-Object {$_.Direction -eq 'Inbound'}}

    $getNetFirewallPortFilterStartTime = Get-Date

    foreach ($enabledRule in $enabledRules)
    {
        $portFilter = $enabledRule | Get-NetFirewallPortFilter
        $enabledRule | Add-Member -MemberType NoteProperty -Name Protocol -Value $portFilter.Protocol
        $enabledRule | Add-Member -MemberType NoteProperty -Name LocalPort -Value $portFilter.LocalPort
        $enabledRule | Add-Member -MemberType NoteProperty -Name RemotePort -Value $portFilter.RemotePort
        $enabledRule | Add-Member -MemberType NoteProperty -Name IcmpType -Value $portFilter.IcmpType
        $enabledRule | Add-Member -MemberType NoteProperty -Name DynamicTarget -Value $portFilter.DynamicTarget
    }
    $getNetFirewallPortFilterEndTime = Get-Date
    $getNetFirewallPortFilterDuration = '{0:hh}:{0:mm}:{0:ss}.{0:ff}' -f (New-TimeSpan -Start $getNetFirewallPortFilterStartTime -End $getNetFirewallPortFilterEndTime)

    $enabledInboundFirewallRules = $enabledRules | Where-Object {$_.Direction -eq 'Inbound'} | Select-Object DisplayName,Profile,Action,Protocol,LocalPort,RemotePort,IcmpType,DynamicTarget | Sort-Object DisplayName
    $enabledOutboundFirewallRules = $enabledRules | Where-Object {$_.Direction -eq 'Outbound'} | Select-Object DisplayName,Profile,Action,Protocol,LocalPort,RemotePort,IcmpType,DynamicTarget | Sort-Object DisplayName
    $enabledFirewallRules = [PSCustomObject]@{
        Inbound = $enabledInboundFirewallRules
        Outbound = $enabledOutboundFirewallRules
    }

    $enabledFirewallRulesCount = $enabledRules | Measure-Object | Select-Object -ExpandProperty Count
    $enabledInboundFirewallRulesCount = $enabledInboundFirewallRules | Measure-Object | Select-Object -ExpandProperty Count
    $enabledOutboundFirewallRulesCount = $enabledOutboundFirewallRules | Measure-Object | Select-Object -ExpandProperty Count
    Out-Log "$enabledFirewallRulesCount enabled Windows firewall rules ($enabledInboundFirewallRulesCount inbound, $enabledOutboundFirewallRulesCount outbound)" -endLine
    Out-Log "Get-NetFirewallRule duration: $('{0:hh}:{0:mm}:{0:ss}.{0:ff}' -f $getNetFirewallRuleDuration)" -verboseOnly
    Out-Log "Get-NetFirewallPortFilter duration: $getNetFirewallPortFilterDuration" -verboseOnly
    return $enabledFirewallRules
}

function Get-Counters
{
    $counters = @(
        "\System\Processor Queue Length",
        "\Memory\Pages/sec",
        "\Memory\Available MBytes",
        "\Processor(*)\% Processor Time",
        "\Network Interface(*)\Bytes Received/sec",
        "\Network Interface(*)\Bytes Sent/sec",
        "\LogicalDisk(C:)\% Free Space",
        "\LogicalDisk(*)\Avg. Disk Queue Length"
    )
    $counterValues = Get-Counter -Counter $counters -SampleInterval 5 -MaxSamples 5
    $counterSamples = $counterValues.CounterSamples
    $readings = $counterValues.Readings
}

function Get-FirewallProfiles
{
    $firewallProfiles = Get-NetFirewallProfile
    return $firewallProfiles
}

function Get-ThirdPartyLoadedModules
{
    param(
        [string]$processName
    )
    $microsoftWindowsProductionPCA2011 = 'CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
    Out-Log "Third-party modules in $($processName):" -startLine
    if ($isVMAgentInstalled)
    {
        $process = Get-Process -Name WaAppAgent -ErrorAction SilentlyContinue
        if ($process)
        {
            $processThirdPartyModules = $process | Select-Object -ExpandProperty modules | Where-Object Company -NE 'Microsoft Corporation' | Select-Object ModuleName, company, description, product, filename, @{Name = 'Version'; Expression = {$_.FileVersionInfo.FileVersion}} | Sort-Object company
            if ($processThirdPartyModules)
            {
                foreach ($processThirdPartyModule in $processThirdPartyModules)
                {
                    $filePath = $processThirdPartyModule.FileName
                    $signature = Invoke-ExpressionWithLogging "Get-AuthenticodeSignature -FilePath '$filePath' -ErrorAction SilentlyContinue" -verboseOnly
                    $issuer = $signature.SignerCertificate.Issuer
                    if ($issuer -eq $microsoftWindowsProductionPCA2011)
                    {
                        $processThirdPartyModules = $processThirdPartyModules | Where-Object {$_.FileName -ne $filePath}
                    }
                }
                if ($processThirdPartyModules)
                {
                    $details = "$($($processThirdPartyModules.ModuleName -join ',').TrimEnd(','))"
                    New-Check -name "Third-party modules in $processName" -result 'Info' -details $details
                    Out-Log $true -endLine -color Cyan
                    New-Finding -type Information -name "Third-party modules in $processName" -description $details -mitigation ''
                }
                else
                {
                    New-Check -name "Third-party modules in $processName" -result 'OK' -details "No third-party modules in $processName"
                    Out-Log $false -endLine -color Green
                }
            }
            else
            {
                New-Check -name "Third-party modules in $processName" -result 'OK' -details "No third-party modules in $processName"
                Out-Log $false -endLine -color Green
            }
        }
        else
        {
            $details = "$processName process not running"
            New-Check -name "Third-party modules in $processName" -result 'Info' -details $details
            Out-Log $details -color Cyan -endLine
        }
    }
    else
    {
        New-Check -name "Third-party modules in $processName" -result 'SKIPPED' -details "Skipped (VM agent installed: $isVMAgentInstalled)"
        Out-Log "Skipped (VM agent installed: $isVMAgentInstalled)" -endLine
    }
}

function Get-Services
{
    $services = Get-CimInstance -Query 'SELECT DisplayName,Description,ErrorControl,ExitCode,Name,PathName,ProcessId,StartMode,StartName,State,ServiceSpecificExitCode,ServiceType FROM Win32_Service' -ErrorAction SilentlyContinue
    if ($services)
    {
        foreach ($service in $services)
        {
            #[int32]$exitCode = $service.ExitCode
            [double]$exitCode = $service.ExitCode
            $exitCodeMessage = [ComponentModel.Win32Exception]$exitCode | Select-Object -ExpandProperty Message
            #[int32]$serviceSpecificExitCode = $service.ServiceSpecificExitCode
            [double]$serviceSpecificExitCode = $service.ServiceSpecificExitCode
            $serviceSpecificExitCodeMessage = [ComponentModel.Win32Exception]$serviceSpecificExitCode | Select-Object -ExpandProperty Message
            $service | Add-Member -MemberType NoteProperty -Name ExitCode -Value "$exitCode ($exitCodeMessage)" -Force
            $service | Add-Member -MemberType NoteProperty -Name ServiceSpecificExitCode -Value "$serviceSpecificExitCode ($serviceSpecificExitCodeMessage)" -Force
        }
        $services = $services | Select-Object DisplayName,Name,State,StartMode,StartName,ErrorControl,ExitCode,ServiceSpecificExitCode,ServiceType,ProcessId,PathName | Sort-Object DisplayName
    }
    else
    {
        $services = Get-Service -ErrorAction SilentlyContinue
        foreach ($service in $services)
        {
            if ($service.ServiceHandle)
            {
                $statusExt = [Win32.Service.Ext]::QueryServiceStatus($service.ServiceHandle)
                $win32ExitCode = $statusExt | Select-Object -ExpandProperty Win32ExitCode
                $win32ExitCodeMessage = [ComponentModel.Win32Exception]$win32ExitCode | Select-Object -ExpandProperty Message
                $serviceSpecificExitCode = $statusExt | Select-Object -ExpandProperty ServiceSpecificExitCode
                $serviceSpecificExitCodeMessage = [ComponentModel.Win32Exception]$serviceSpecificExitCode | Select-Object -ExpandProperty Message
                $service | Add-Member -MemberType NoteProperty -Name Win32ExitCode -Value "$win32ExitCode ($win32ExitCodeMessage)"
                $service | Add-Member -MemberType NoteProperty -Name ServiceSpecificExitCode -Value "$serviceSpecificExitCode ($serviceSpecificExitCodeMessage)"
            }
            else
            {
                $service | Add-Member -MemberType NoteProperty -Name Win32ExitCode -Value $null
                $service | Add-Member -MemberType NoteProperty -Name ServiceSpecificExitCode -Value $null
            }
        }
        $services = $services | Select-Object DisplayName,Name,Status,StartType,Win32ExitCode,ServiceSpecificExitCode | Sort-Object DisplayName
    }
    return $services
}

function Get-ServiceChecks
{
    param(
        [string]$name,
        [string]$expectedStatus,
        [string]$expectedStartType
    )

    <#
    $serviceKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
    $serviceKey = Invoke-ExpressionWithLogging "Get-ItemProperty -Path '$serviceKeyPath' -ErrorAction SilentlyContinue" -verboseOnly
    if ($serviceKey)
    {
        $serviceKeyExists = $true

        $serviceKeyStartValue = $serviceKey.Start
        $serviceKeyErrorControlValue = $serviceKey.ErrorControl
        $serviceKeyImagePathValue = $serviceKey.ImagePath
        $serviceKeyObjectNameValue = $serviceKey.ObjectName
    }
    else
    {
        $serviceKeyExists = $false
    }

    $scExe = "$env:SystemRoot\System32\sc.exe"

    $scQueryExOutput = Invoke-ExpressionWithLogging "& $scExe queryex $name" -verboseOnly
    $scQueryExExitCode = $LASTEXITCODE

    $scQcOutput = Invoke-ExpressionWithLogging "& $scExe qc $name" -verboseOnly
    $scQcExitCode = $LASTEXITCODE
    #>

    Out-Log "$name service:" -startLine
    $regKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
    $imagePath = Invoke-ExpressionWithLogging "Get-ItemProperty -Path '$regKeyPath' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ImagePath" -verboseOnly
    if ($imagePath)
    {
        Out-Log "ImagePath: $imagePath" -verboseOnly
        $fullName = Get-Item -Path $imagePath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
        if ($fullName -or $imagePath -match 'svchost')
        {
            if ($fullName)
            {
                Out-Log "Service binary location $fullName matches ImagePath value in the registry" -verboseOnly
            }

            $service = Invoke-ExpressionWithLogging "Get-Service -Name '$name' -ErrorAction SilentlyContinue" -verboseOnly
            if ($service)
            {
                $isInstalled = $true

                $win32Service = Invoke-ExpressionWithLogging "Get-CimInstance -Query `"SELECT * from Win32_Service WHERE Name='$name'`" -ErrorAction SilentlyContinue" -verboseOnly
                if ($win32Service)
                {
                    $processId = $win32Service.ProcessId
                    $startName = $win32Service.StartName
                    $pathName = $win32Service.PathName
                    $exitCode = $win32Service.ExitCode
                    $serviceSpecificExitCode = $win32Service.ServiceSpecificExitCode
                    $errorControl = $win32Service.ErrorControl
                    if ($processId)
                    {
                        $process = Invoke-ExpressionWithLogging "Get-Process -Id $processId -ErrorAction SilentlyContinue" -verboseOnly

                        if ($process)
                        {
                            $startTime = $process.StartTime
                            $uptime = '{0:dd}:{0:hh}:{0:mm}:{0:ss}' -f (New-Timespan -Start $process.StartTime -End (Get-Date))
                        }
                    }
                }

                $displayName = $service.DisplayName
                $binaryPathName = $service.BinaryPathName
                $userName = $service.UserName
                $status = $service.Status
                $startType = $service.StartType
                $requiredServices = $service.RequiredServices
                $dependentServices = $service.DependentServices
                $servicesDependedOn = $service.ServicesDependedOn

                $statusExt = [Win32.Service.Ext]::QueryServiceStatus($service.ServiceHandle)
                $win32ExitCode = $statusExt | Select-Object -ExpandProperty Win32ExitCode
                $serviceSpecificExitCode = $statusExt | Select-Object -ExpandProperty ServiceSpecificExitCode

                if ($status -eq $expectedStatus)
                {
                    $isExpectedStatus = $true
                }
                else
                {
                    $isExpectedStatus = $false
                }
                if ($startType -eq $expectedStartType)
                {
                    $isExpectedStartType = $true
                }
                else
                {
                    $isExpectedStartType = $false
                }

                if ($startName -and $uptime)
                {
                    $details = "Status: $status StartType: $startType Startname: $startName Uptime: $uptime"
                }
                else
                {
                    $details = "Status: $status StartType: $startType"
                }
            }
            else
            {
                $isInstalled = $false
            }

            if ($isInstalled -eq $false)
            {
                New-Check -name "$name service" -result 'FAILED' -details "$name service is not installed"
                New-Finding -type 'Critical' -name "$name service is not installed" -description '' -mitigation ''
                Out-Log 'Not Installed' -color Red -endLine
            }
            elseif ($isInstalled -eq $true -and $isExpectedStatus -eq $true -and $isExpectedStartType -eq $true)
            {
                New-Check -name "$name service" -result 'OK' -details $details
                Out-Log "Status: $status StartType: $startType StartName: $startName" -color Green -endLine
            }
            elseif ($isInstalled -eq $true -and $isExpectedStatus -eq $true -and $isExpectedStartType -eq $false)
            {
                New-Check -name "$name service" -result 'FAILED' -details $details
                New-Finding -type 'Warning' -name "$name service start type $startType (expected: $expectedStartType)" -description '' -mitigation ''
                Out-Log "Status: $status (expected $expectedStatus) StartType: $startType (expected $expectedStartType)" -color Red -endLine
            }
            elseif ($isInstalled -eq $true -and $isExpectedStatus -eq $false -and $isExpectedStartType -eq $true)
            {
                New-Check -name "$name service" -result 'FAILED' -details $details
                New-Finding -type 'Critical' -name "$name service status $status (expected: $expectedStatus)" -description '' -mitigation ''
                Out-Log "Status: $status (expected $expectedStatus) StartType: $startType (expected $expectedStartType)" -color Red -endLine
            }
            elseif ($isInstalled -eq $true -and $isExpectedStatus -eq $false -and $isExpectedStartType -eq $false)
            {
                New-Check -name "$name service" -result 'FAILED' -details $details
                New-Finding -type 'Critical' -name "$name service status $status (expected: $expectedStatus)" -description '' -mitigation ''
                Out-Log "Status: $status (expected $expectedStatus) StartType: $startType (expected $expectedStartType)" -color Red -endLine
            }

            return $service
        }
        else
        {
            $imageName = Split-Path -Path $imagePath -Leaf
            $actualImagePath = Get-ChildItem -Path "$env:SystemDrive\WindowsAzure" -Filter $imageName -Recurse -File -ErrorAction SilentlyContinue
            if ($actualImagePath)
            {
                $details = "ImagePath registry value is incorrect"
                New-Check -name "$name service" -result 'FAILED' -details $details
                $description = "HKLM:\SYSTEM\CurrentControlSet\Services\$name\ImagePath is '$imagePath' but actual location of $imageName is '$actualImagePath'"
                New-Finding -type 'Critical' -name "$name service ImagePath registry value is incorrect" -description $description -mitigation ''
                Out-Log 'Not Installed' -color Red -endLine
            }
            else
            {
                New-Check -name "$name service" -result 'FAILED' -details "$name service is not installed"
                New-Finding -type 'Critical' -name "$name service is not installed" -description '' -mitigation ''
                Out-Log 'Not Installed' -color Red -endLine
            }
        }
    }
    else
    {
        New-Check -name "$name service" -result 'FAILED' -details "$name service is not installed"
        New-Finding -type 'Critical' -name "$name service is not installed" -description '' -mitigation ''
        Out-Log 'Not Installed' -color Red -endLine
    }
}

function Get-RegKey
{
    <#
    'HKLM:\SOFTWARE\Microsoft\GuestAgent'
    'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest'
    'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Auto'
    'HKLM:\SOFTWARE\Microsoft\Windows Azure'
    'HKLM:\SOFTWARE\Microsoft\Windows Azure\GuestAgentUpdateState'
    'HKLM:\SOFTWARE\Microsoft\Windows Azure\HandlerState'

    REG_DWORD     System.Int32
    REG_SZ        System.String
    REG_QWORD     System.Int64
    REG_BINARY    System.Byte[]
    REG_MULTI_SZ  System.String[]
    REG_EXPAND_SZ System.String
    #>

    param(
        [string]$path,
        [switch]$recurse
    )

    $regKeyValues = New-Object System.Collections.Generic.List[Object]

    if ($recurse)
    {
        $regKeys = Get-ChildItem -Path $path -Recurse
    }
    else
    {
        $regKeys = Get-Item -Path $path
    }

    foreach ($regKey in $regKeys)
    {
        $valueNames = $regKey.GetValueNames()
        foreach ($valueName in $valueNames)
        {
            $valueData = $regKey.GetValue($valueName)
            $valueType = $regKey.GetValueKind($valueName)
            $regKeyValue = [PSCustomObject]@{
                SubkeyName = $regKey.Name
                ValueName = $valueName
                ValueData = $valueData
                ValueType = $valueType
            }
            $regKeyValues.Add($regKeyValue)
        }
    }
    $regKeyValues = $regKeyValues | Sort-Object -Property Name
    return $regKeyValues
}

function Out-Log
{
    param(
        [string]$text,
        [switch]$verboseOnly,
        [switch]$startLine,
        [switch]$endLine,
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
        [ValidateSet('Black', 'DarkBlue', 'DarkGreen', 'DarkCyan', 'DarkRed', 'DarkMagenta', 'DarkYellow', 'Gray', 'DarkGray', 'Blue', 'Green', 'Cyan', 'Red', 'Magenta', 'Yellow', 'White')]
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
        $callstack = Get-PSCallStack
        $caller = $callstack | Select-Object -First 1 -Skip 1
        $caller = $caller.InvocationInfo.MyCommand.Name
        if ($caller -eq 'Invoke-ExpressionWithLogging')
        {
            $caller = $callstack | Select-Object -First 1 -Skip 2
            $caller = $caller.InvocationInfo.MyCommand.Name
        }
        # Write-Host "$scriptName `$verboseOnly: $verboseOnly `$global:verbose: $global:verbose `$verbose: $verbose" -ForegroundColor Magenta
        if ($verbose)
        {
            $outputNeeded = $true
        }
        else
        {
            $outputNeeded = $false
        }
    }
    else
    {
        $outputNeeded = $true
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
                }
                elseif ($timespanFormat -eq 'minutes')
                {
                    $format = '{0:mm}:{0:ss}'
                }
                elseif ($timespanFormat -eq 'seconds')
                {
                    $format = '{0:ss}'
                }
                if ($milliseconds)
                {
                    $format = "$($format).{0:ff}"
                }
                $prefixString = $format -f $timespan
            }
            elseif ($prefix -eq 'both' -and $script:scriptStartTime)
            {
                $timestamp = Get-Date -Format $dateFormat
                $timespan = New-TimeSpan -Start $script:scriptStartTime -End (Get-Date)

                if ($timespanFormat -eq 'hours')
                {
                    $format = '{0:hh}:{0:mm}:{0:ss}'
                }
                elseif ($timespanFormat -eq 'minutes')
                {
                    $format = '{0:mm}:{0:ss}'
                }
                elseif ($timespanFormat -eq 'seconds')
                {
                    $format = '{0:ss}'
                }
                if ($milliseconds)
                {
                    $format = "$($format).{0:ff}"
                }
                $prefixString = $format -f $timespan
                $prefixString = "$timestamp $prefixString"
            }
            else
            {
                $prefixString = Get-Date -Format $dateFormat
            }

            $prefixString = "$prefixString "

            if ($logonly -or $global:quiet)
            {
                if ($logFilePath)
                {
                    "$prefixString $text" | Out-File $logFilePath -Append
                }
            }
            else
            {
                if ($verboseOnly)
                {
                    $prefixString = "$prefixString[$caller] "
                }

                if ($startLine)
                {
                    $script:startLineText = $text
                    Write-Host $prefixString -NoNewline -ForegroundColor DarkGray
                    Write-Host "$text " -NoNewline -ForegroundColor $color
                }
                elseif ($endLine)
                {
                    Write-Host $text -ForegroundColor $color
                    if ($logFilePath)
                    {
                        "$prefixString $script:startLineText $text" | Out-File $logFilePath -Append
                    }
                }
                else
                {
                    Write-Host $prefixString -NoNewline -ForegroundColor DarkGray
                    Write-Host $text -ForegroundColor $color
                    if ($logFilePath)
                    {
                        "$prefixString $text" | Out-File $logFilePath -Append
                    }
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

function Test-Port
{
    param(
        [string]$ipAddress,
        [int]$port,
        [int]$timeout = 1000
    )
    <#
    Use TCPClient .NET class since Test-NetConnection cmdlet does not support setting a timeout
    Equivalent Test-NetConnection command (but doesn't support timeouts):
    Test-NetConnection -ComputerName $wireServer -Port 80 -InformationLevel Quiet -WarningAction SilentlyContinue
    #>
    $tcpClient = New-Object System.Net.Sockets.TCPClient
    $connect = $tcpClient.BeginConnect($ipAddress, $port, $null, $null)
    $wait = $connect.AsyncWaitHandle.WaitOne($timeout, $false)

    $result = [PSCustomObject]@{
        Succeeded = $null
        Error     = $null
    }

    if ($wait)
    {
        try
        {
            $tcpClient.EndConnect($connect)
        }
        catch [System.Net.Sockets.SocketException]
        {
            $testPortError = $_
            $result.Succeeded = $false
            $result.Error = $testPortError
            #$result | Add-Member -MemberType NoteProperty -Name Succeeded -Value $false -Force
            #$result | Add-Member -MemberType NoteProperty -Name Error -Value $testPortError -Force
            return $result
        }

        if ([bool]$testPortError -eq $false)
        {
            $result.Succeeded = $true
            return $result
        }
    }
    else
    {
        $result.Succeeded = $false
        return $result
    }
    $tcpClient.Close()
    $tcpClient.Dispose()
}

function New-Check
{
    param(
        [string]$name,
        [ValidateSet('OK','FAILED','INFO','SKIPPED')]
        [string]$result,
        [string]$details
    )

    $date = Get-Date
    $date = $date.ToUniversalTime()
    $timeCreated = Get-Date -Date $date -Format yyyy-MM-ddTHH:mm:ss.ffZ

    $check = [PSCustomObject]@{
        TimeCreated = $timeCreated
        Name        = $name
        Result      = $result
        Details     = $details
    }
    $checks.Add($check)

}

function New-Finding
{
    param(
        [ValidateSet('Information', 'Warning', 'Critical')]
        [string]$type,
        [string]$name,
        [string]$description,
        [string]$mitigation
    )

    $date = Get-Date
    $date = $date.ToUniversalTime()
    $timeCreated = Get-Date -Date $date -Format yyyy-MM-ddTHH:mm:ss.ffZ

    $finding = [PSCustomObject]@{
        TimeCreated = $timeCreated
        Type        = $type
        Name        = $name
        Description = $description
        Mitigation  = $mitigation
    }
    $findings.Add($finding)
    $global:dbgFinding = $finding
}

function Send-Telemetry
{
    param(
        $properties
    )

    $ingestionDnsName = 'dc.services.visualstudio.com'
    $dnsRecord = Resolve-DnsName -Name $ingestionDnsName -QuickTimeout -TcpOnly -Type A -ErrorAction SilentlyContinue
    if ($dnsRecord)
    {
        $ip4Address = $dnsRecord.IP4Address
        if ($ip4Address)
        {
            Out-Log "Sending telemetry to $ingestionDnsName ($ip4Address):" -startLine
            $ingestionEndpointReachable = Test-Port -ipAddress $ip4Address -Port 443
            $global:dbgingestionEndpointReachable = $ingestionEndpointReachable
            if ($ingestionEndpointReachable.Succeeded)
            {
                $ingestionEndpoint = 'https://dc.services.visualstudio.com/v2/track'
                $instrumentationKey = '82048970-8bf5-4f69-88d2-1951be268160'
                $body = [PSCustomObject]@{
                    'name' = "Microsoft.ApplicationInsights.$instrumentationKey.Event"
                    'time' = ([System.dateTime]::UtcNow.ToString('o'))
                    'iKey' = $instrumentationKey
                    'data' = [PSCustomObject]@{
                        'baseType' = 'EventData'
                        'baseData' = [PSCustomObject]@{
                            'ver'        = '2'
                            'name'       = $scriptBaseName
                            'properties' = $properties
                        }
                    }
                }
                $body = $body | ConvertTo-Json -Depth 10 -Compress
                $headers = @{'Content-Type' = 'application/x-json-stream';}
                try
                {
                    $result = Invoke-RestMethod -Uri $ingestionEndpoint -Method Post -Headers $headers -Body $body -ErrorAction SilentlyContinue
                }
                catch
                {
                    $trappedError = $PSItem
                    $global:trappedError = $trappedError
                    $scriptLineNumber = $trappedError.InvocationInfo.ScriptLineNumber
                    $line = $trappedError.InvocationInfo.Line.Trim()
                    $exceptionMessage = $trappedError.Exception.Message
                    $trappedErrorString = $trappedError.Exception.ErrorRecord | Out-String -ErrorAction SilentlyContinue
                    Out-Log "[ERROR] $exceptionMessage Line $scriptLineNumber $line" -color Red
                }
                if ($result)
                {
                    $itemsReceived = $result | Select-Object -ExpandProperty itemsReceived
                    $itemsAccepted = $result | Select-Object -ExpandProperty itemsAccepted
                    $errors = $result | Select-Object -ExpandProperty errors
                    $message = "Received: $itemsReceived Accepted: $itemsAccepted"
                    if ($errors)
                    {
                        $message = "$message Errors: $errors"
                        Out-Log $message -color Red -endLine
                    }
                    else
                    {
                        Out-Log $message -color Green -endLine
                    }
                }
            }
            else
            {
                Out-Log "Ingestion endpoint $($ip4Address):443 not reachable" -endLine
            }
        }
        else
        {
            Out-Log "Could not resolve $ingestionDnsName to an IP address" -endLine
        }
    }
}

function Get-Drivers
{
    # Both Win32_SystemDriver and Driverquery.exe use WMI, and Win32_SystemDriver is faster
    # So no benefit to using Driverquery.exe
<#
CN=Microsoft Windows Third Party Component CA 2012, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
CN=Microsoft Windows Third Party Component CA 2013, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
CN=Microsoft Windows Third Party Component CA 2014, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
#>

    $microsoftIssuers = @'
CN=Microsoft Code Signing PCA 2010, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
CN=Microsoft Code Signing PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
CN=Microsoft Code Signing PCA, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
CN=Microsoft Windows Verification PCA, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
'@

    $microsoftIssuers = $microsoftIssuers.Split("`n").Trim()

    $drivers = Get-CimInstance -Query 'SELECT * FROM Win32_SystemDriver'

    foreach ($driver in $drivers)
    {
        $driverPath = $driver.PathName.Replace('\??\', '')
        $driverFile = Get-Item -Path $driverPath -ErrorAction SilentlyContinue
        if ($driverFile)
        {
            $driver | Add-Member -MemberType NoteProperty -Name Path -Value $driverPath
            $driver | Add-Member -MemberType NoteProperty -Name Version -Value $driverFile.VersionInfo.FileVersionRaw
            $driver | Add-Member -MemberType NoteProperty -Name CompanyName -Value $driverFile.VersionInfo.CompanyName
        }

        # TODO: PS4.0 shows OS file as not signed, this was fixed in PS5.1
        # Need to handle the PS4.0 scenario
        $driverFileSignature = Invoke-ExpressionWithLogging "Get-AuthenticodeSignature -FilePath '$driverPath' -ErrorAction SilentlyContinue" -verboseOnly
        if ($driverFileSignature)
        {
            $driver | Add-Member -MemberType NoteProperty -Name Issuer -Value $driverFileSignature.Signercertificate.Issuer
            $driver | Add-Member -MemberType NoteProperty -Name Subject -Value $driverFileSignature.Signercertificate.Subject
        }
    }

    $microsoftRunningDrivers = $drivers | Where-Object {$_.State -eq 'Running' -and $_.Issuer -in $microsoftIssuers}
    $thirdPartyRunningDrivers = $drivers | Where-Object {$_.State -eq 'Running' -and $_.Issuer -notin $microsoftIssuers}

    $microsoftRunningDrivers = $microsoftRunningDrivers | Select-Object -Property Name,Description,Path,Version,CompanyName,Issuer
    $thirdPartyRunningDrivers = $thirdPartyRunningDrivers | Select-Object -Property Name,Description,Path,Version,CompanyName,Issuer

    $runningDrivers = [PSCustomObject]@{
        microsoftRunningDrivers = $microsoftRunningDrivers
        thirdPartyRunningDrivers = $thirdPartyRunningDrivers
    }

    return $runningDrivers
}

function Get-JoinInfo
{
$netApi32MemberDefinition = @'
using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
public class NetAPI32{
    public enum DSREG_JOIN_TYPE {
    DSREG_UNKNOWN_JOIN,
    DSREG_DEVICE_JOIN,
    DSREG_WORKPLACE_JOIN
    }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct DSREG_USER_INFO {
        [MarshalAs(UnmanagedType.LPWStr)] public string UserEmail;
        [MarshalAs(UnmanagedType.LPWStr)] public string UserKeyId;
        [MarshalAs(UnmanagedType.LPWStr)] public string UserKeyName;
    }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct CERT_CONTEX {
        public uint   dwCertEncodingType;
        public byte   pbCertEncoded;
        public uint   cbCertEncoded;
        public IntPtr pCertInfo;
        public IntPtr hCertStore;
    }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct DSREG_JOIN_INFO
    {
        public int joinType;
        public IntPtr pJoinCertificate;
        [MarshalAs(UnmanagedType.LPWStr)] public string DeviceId;
        [MarshalAs(UnmanagedType.LPWStr)] public string IdpDomain;
        [MarshalAs(UnmanagedType.LPWStr)] public string TenantId;
        [MarshalAs(UnmanagedType.LPWStr)] public string JoinUserEmail;
        [MarshalAs(UnmanagedType.LPWStr)] public string TenantDisplayName;
        [MarshalAs(UnmanagedType.LPWStr)] public string MdmEnrollmentUrl;
        [MarshalAs(UnmanagedType.LPWStr)] public string MdmTermsOfUseUrl;
        [MarshalAs(UnmanagedType.LPWStr)] public string MdmComplianceUrl;
        [MarshalAs(UnmanagedType.LPWStr)] public string UserSettingSyncUrl;
        public IntPtr pUserInfo;
    }
    [DllImport("netapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern void NetFreeAadJoinInformation(
            IntPtr pJoinInfo);
    [DllImport("netapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern int NetGetAadJoinInformation(
            string pcszTenantId,
            out IntPtr ppJoinInfo);
}
'@

    if ($buildNumber -ge 10240)
    {
        if ([bool]([System.Management.Automation.PSTypeName]'NetAPI32').Type -eq $false)
        {
            $netApi32 = Add-Type -TypeDefinition $netApi32MemberDefinition -ErrorAction SilentlyContinue
        }

        if ([bool]([System.Management.Automation.PSTypeName]'NetAPI32').Type -eq $true)
        {
            $netApi32 = Add-Type -TypeDefinition $netApi32MemberDefinition -ErrorAction SilentlyContinue
            $pcszTenantId = $null
            $ptrJoinInfo = [IntPtr]::Zero

            # https://docs.microsoft.com/en-us/windows/win32/api/lmjoin/nf-lmjoin-netgetaadjoininformation
            # [NetAPI32]::NetFreeAadJoinInformation([IntPtr]::Zero);
            $retValue = [NetAPI32]::NetGetAadJoinInformation($pcszTenantId, [ref]$ptrJoinInfo)

            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/18d8fbe8-a967-4f1c-ae50-99ca8e491d2d
            if ($retValue -eq 0)
            {
                # https://support.microsoft.com/en-us/help/2909958/exceptions-in-windows-powershell-other-dynamic-languages-and-dynamical
                $ptrJoinInfoObject = New-Object NetAPI32+DSREG_JOIN_INFO
                $joinInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ptrJoinInfo, [System.Type] $ptrJoinInfoObject.GetType())

                $ptrUserInfo = $joinInfo.pUserInfo
                $ptrUserInfoObject = New-Object NetAPI32+DSREG_USER_INFO
                $userInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ptrUserInfo, [System.Type] $ptrUserInfoObject.GetType())

                switch ($joinInfo.joinType)
                {
                    ([NetAPI32+DSREG_JOIN_TYPE]::DSREG_DEVICE_JOIN.value__) {$joinType = 'Joined to Azure AD (DSREG_DEVICE_JOIN)'}
                    ([NetAPI32+DSREG_JOIN_TYPE]::DSREG_UNKNOWN_JOIN.value__) {$joinType = 'Unknown (DSREG_UNKNOWN_JOIN)'}
                    ([NetAPI32+DSREG_JOIN_TYPE]::DSREG_WORKPLACE_JOIN.value__) {$joinType = 'Azure AD work account is added on the device (DSREG_WORKPLACE_JOIN)'}
                }
            }
            else
            {
                $joinType = 'Not Azure Joined'
            }
        }
    }
    else
    {
        $joinType = 'N/A'
    }

    $productType = Invoke-ExpressionWithLogging "Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions' | Select-Object -ExpandProperty ProductType" -verboseOnly

    $joinInfo = [PSCustomObject]@{
        JoinType = $joinType
        ProductType = $productType
    }

    return $joinInfo
}

function Confirm-AzureVM
{
    $typeDefinition = @'
using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.Net.NetworkInformation;

namespace Microsoft.WindowsAzure.Internal
{
    /// <summary>
    /// A simple DHCP client.
    /// </summary>
    public class DhcpClient : IDisposable
    {
        public DhcpClient()
        {
            uint version;
            int err = NativeMethods.DhcpCApiInitialize(out version);
            if (err != 0)
                throw new Win32Exception(err);
        }

        public void Dispose()
        {
            NativeMethods.DhcpCApiCleanup();
        }

        /// <summary>
        /// Gets the available interfaces that are enabled for DHCP.
        /// </summary>
        /// <remarks>
        /// The operational status of the interface is not assessed.
        /// </remarks>
        /// <returns></returns>
        public static IEnumerable<NetworkInterface> GetDhcpInterfaces()
        {
            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.NetworkInterfaceType != NetworkInterfaceType.Ethernet) continue;
                if (!nic.Supports(NetworkInterfaceComponent.IPv4)) continue;
                IPInterfaceProperties props = nic.GetIPProperties();
                if (props == null) continue;
                IPv4InterfaceProperties v4props = props.GetIPv4Properties();
                if (v4props == null) continue;
                if (!v4props.IsDhcpEnabled) continue;

                yield return nic;
            }
        }

        /// <summary>
        /// Requests DHCP parameter data.
        /// </summary>
        /// <remarks>
        /// Windows serves the data from a cache when possible.
        /// With persistent requests, the option is obtained during boot-time DHCP negotiation.
        /// </remarks>
        /// <param name="optionId">the option to obtain.</param>
        /// <param name="isVendorSpecific">indicates whether the option is vendor-specific.</param>
        /// <param name="persistent">indicates whether the request should be persistent.</param>
        /// <returns></returns>
        public byte[] DhcpRequestParams(string adapterName, uint optionId)
        {
            uint bufferSize = 1024;
        Retry:
            IntPtr buffer = Marshal.AllocHGlobal((int)bufferSize);
            try
            {
                NativeMethods.DHCPCAPI_PARAMS_ARRAY sendParams = new NativeMethods.DHCPCAPI_PARAMS_ARRAY();
                sendParams.nParams = 0;
                sendParams.Params = IntPtr.Zero;

                NativeMethods.DHCPCAPI_PARAMS recv = new NativeMethods.DHCPCAPI_PARAMS();
                recv.Flags = 0x0;
                recv.OptionId = optionId;
                recv.IsVendor = false;
                recv.Data = IntPtr.Zero;
                recv.nBytesData = 0;

                IntPtr recdParamsPtr = Marshal.AllocHGlobal(Marshal.SizeOf(recv));
                try
                {
                    Marshal.StructureToPtr(recv, recdParamsPtr, false);

                    NativeMethods.DHCPCAPI_PARAMS_ARRAY recdParams = new NativeMethods.DHCPCAPI_PARAMS_ARRAY();
                    recdParams.nParams = 1;
                    recdParams.Params = recdParamsPtr;

                    NativeMethods.DhcpRequestFlags flags = NativeMethods.DhcpRequestFlags.DHCPCAPI_REQUEST_SYNCHRONOUS;

                    int err = NativeMethods.DhcpRequestParams(
                        flags,
                        IntPtr.Zero,
                        adapterName,
                        IntPtr.Zero,
                        sendParams,
                        recdParams,
                        buffer,
                        ref bufferSize,
                        null);

                    if (err == NativeMethods.ERROR_MORE_DATA)
                    {
                        bufferSize *= 2;
                        goto Retry;
                    }

                    if (err != 0)
                        throw new Win32Exception(err);

                    recv = (NativeMethods.DHCPCAPI_PARAMS)
                        Marshal.PtrToStructure(recdParamsPtr, typeof(NativeMethods.DHCPCAPI_PARAMS));

                    if (recv.Data == IntPtr.Zero)
                        return null;

                    byte[] data = new byte[recv.nBytesData];
                    Marshal.Copy(recv.Data, data, 0, (int)recv.nBytesData);
                    return data;
                }
                finally
                {
                    Marshal.FreeHGlobal(recdParamsPtr);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        ///// <summary>
        ///// Unregisters a persistent request.
        ///// </summary>
        //public void DhcpUndoRequestParams()
        //{
        //    int err = NativeMethods.DhcpUndoRequestParams(0, IntPtr.Zero, null, this.ApplicationID);
        //    if (err != 0)
        //        throw new Win32Exception(err);
        //}

        #region Native Methods
    }

    internal static partial class NativeMethods
    {
        public const uint ERROR_MORE_DATA = 124;

        [DllImport("dhcpcsvc.dll", EntryPoint = "DhcpRequestParams", CharSet = CharSet.Unicode, SetLastError = false)]
        public static extern int DhcpRequestParams(
            DhcpRequestFlags Flags,
            IntPtr Reserved,
            string AdapterName,
            IntPtr ClassId,
            DHCPCAPI_PARAMS_ARRAY SendParams,
            DHCPCAPI_PARAMS_ARRAY RecdParams,
            IntPtr Buffer,
            ref UInt32 pSize,
            string RequestIdStr
            );

        [DllImport("dhcpcsvc.dll", EntryPoint = "DhcpUndoRequestParams", CharSet = CharSet.Unicode, SetLastError = false)]
        public static extern int DhcpUndoRequestParams(
            uint Flags,
            IntPtr Reserved,
            string AdapterName,
            string RequestIdStr);

        [DllImport("dhcpcsvc.dll", EntryPoint = "DhcpCApiInitialize", CharSet = CharSet.Unicode, SetLastError = false)]
        public static extern int DhcpCApiInitialize(out uint Version);

        [DllImport("dhcpcsvc.dll", EntryPoint = "DhcpCApiCleanup", CharSet = CharSet.Unicode, SetLastError = false)]
        public static extern int DhcpCApiCleanup();

        [Flags]
        public enum DhcpRequestFlags : uint
        {
            DHCPCAPI_REQUEST_PERSISTENT = 0x01,
            DHCPCAPI_REQUEST_SYNCHRONOUS = 0x02,
            DHCPCAPI_REQUEST_ASYNCHRONOUS = 0x04,
            DHCPCAPI_REQUEST_CANCEL = 0x08,
            DHCPCAPI_REQUEST_MASK = 0x0F
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct DHCPCAPI_PARAMS_ARRAY
        {
            public UInt32 nParams;
            public IntPtr Params;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct DHCPCAPI_PARAMS
        {
            public UInt32 Flags;
            public UInt32 OptionId;
            [MarshalAs(UnmanagedType.Bool)]
            public bool IsVendor;
            public IntPtr Data;
            public UInt32 nBytesData;
        }
        #endregion
    }
}
'@

    $isAzureVM = $false

    $assemblies = [System.AppDomain]::CurrentDomain.GetAssemblies()
    $isAssemblyLoaded = [bool]($assemblies.ExportedTypes -match 'Microsoft.WindowsAzure.Internal')
    if ($isAssemblyLoaded -eq $false)
    {
        Add-Type -TypeDefinition $typeDefinition
    }

    $vmbus = Get-Service -Name vmbus
    if ($vmbus.Status -eq 'Running')
    {
        $client = New-Object Microsoft.WindowsAzure.Internal.DhcpClient
        try
        {
            [Microsoft.WindowsAzure.Internal.DhcpClient]::GetDhcpInterfaces() | ForEach-Object {
                $val = $client.DhcpRequestParams($_.Id, 245)
                if ($val -And $val.Length -eq 4)
                {
                    $isAzureVM = $true
                }
            }
        }
        finally
        {
            $client.Dispose()
        }
    }

    return $isAzureVM
}

$psVersion = $PSVersionTable.PSVersion
$psVersionString = $psVersion.ToString()
if ($psVersion -lt [version]'4.0' -or $psVersion -ge [version]'6.0')
{
    Write-Error "You are using PowerShell $psVersionString. This script requires PowerShell version 5.1, 5.0, or 4.0."
    exit 1
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
if ($debug)
{
    $DebugPreference = 'Continue'
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
$logFilePath = "$logFolderPath\$($scriptBaseName)_$($computerName)_$($scriptStartTimeString).log"
if ((Test-Path -Path $logFilePath -PathType Leaf) -eq $false)
{
    New-Item -Path $logFilePath -ItemType File -Force | Out-Null
}
Out-Log "Log file: $logFilePath"

$result = New-Object System.Collections.Generic.List[Object]
$checks = New-Object System.Collections.Generic.List[Object]
$findings = New-Object System.Collections.Generic.List[Object]
$vm = New-Object System.Collections.Generic.List[Object]

$ErrorActionPreference = 'SilentlyContinue'
$version = [environment]::osversion.version.ToString()
$buildNumber = [environment]::osversion.version.build
$currentVersionKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$currentVersionKey = Invoke-ExpressionWithLogging "Get-ItemProperty -Path '$currentVersionKeyPath' -ErrorAction SilentlyContinue" -verboseOnly
if ($currentVersionKey)
{
    $productName = $currentVersionKey.ProductName
    if ($productName -match 'Windows 10' -and $buildNumber -ge 22000)
    {
        $productName = $productName.Replace('Windows 10', 'Windows 11')
    }
    $ubr = $currentVersionKey.UBR
    # Starting with Win10/WS16, InstallDate is when the last cumulative update was installed, not when Windows itself was installed
    # $installDate = $currentVersionKey.InstallDate
    # $installDateString = Get-Date -Date ([datetime]'1/1/1970').AddSeconds($installDate) -Format yyyy-MM-ddTHH:mm:ss
    if ($buildNumber -ge 14393)
    {
        $releaseId = $currentVersionKey.ReleaseId
        $displayVersion = $currentVersionKey.DisplayVersion
    }
}
$ErrorActionPreference = 'Continue'

$installationType = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion' -Name InstallationType | Select-Object -ExpandProperty InstallationType

if ($displayVersion)
{
    if ($installationType -eq 'Server Core')
    {
        $osVersion = "$productName $installationType $displayVersion $releaseId $version"
    }
    else
    {
        $osVersion = "$productName $displayVersion $releaseId $version"
    }
}
else
{
    if ($installationType -eq 'Server Core')
    {
        $osVersion = "$productName $installationType $version"
    }
    else
    {
        $osVersion = "$productName $version"
    }
}

Out-Log $osVersion -color Cyan
$timeZone = Get-TimeZone | Select-Object -ExpandProperty DisplayName
$isHyperVGuest = Confirm-HyperVGuest
Out-Log "Hyper-V Guest: $isHyperVGuest"
if ($isHyperVGuest)
{
    $isAzureVM = Confirm-AzureVM
    Out-Log "Azure VM: $isAzureVM"
}
else
{
    $isAzureVM = $false
    Out-Log "Azure VM: $isAzureVM"
}

$uuidFromWMI = Get-CimInstance -Query 'SELECT UUID FROM Win32_ComputerSystemProduct' | Select-Object -ExpandProperty UUID
$lastConfig = Get-ItemProperty -Path 'HKLM:\SYSTEM\HardwareConfig' -ErrorAction SilentlyContinue | Select-Object -Expandproperty LastConfig
if ($lastConfig)
{
    $uuidFromRegistry = $lastConfig.ToLower().Replace('{','').Replace('}','')
}
if ($isAzureVM)
{
    $vmId = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Azure' -ErrorAction SilentlyContinue | Select-Object -Expandproperty VmId
}

$windowsAzureFolderPath = "$env:SystemDrive\WindowsAzure"
if ($isAzureVM)
{
    Out-Log "$windowsAzureFolderPath folder exists:" -startLine
    if (Test-Path -Path $windowsAzureFolderPath -PathType Container)
    {
        $windowsAzureFolderExists = $true
        Out-Log $windowsAzureFolderExists -color Green -endLine
        New-Check -name "$windowsAzureFolderPath folder exists" -result 'OK' -details ''
        $windowsAzureFolder = Invoke-ExpressionWithLogging "Get-ChildItem -Path $windowsAzureFolderPath -Recurse -ErrorAction SilentlyContinue" -verboseOnly
        Out-Log 'WindowsAzureGuestAgent.exe exists:' -startLine
        $windowsAzureGuestAgentExe = $windowsAzureFolder | Where-Object {$_.Name -eq 'WindowsAzureGuestAgent.exe'}
        if ($windowsAzureGuestAgentExe)
        {
            New-Check -name "WindowsAzureGuestAgent.exe exists in $windowsAzureFolderPath" -result 'OK' -details ''
            $windowsAzureGuestAgentExeExists = $true
            $windowsAzureGuestAgentExeFileVersion = $windowsAzureGuestAgentExe | Select-Object -ExpandProperty VersionInfo | Select-Object -ExpandProperty FileVersion
            Out-Log "$windowsAzureGuestAgentExeExists (version $windowsAzureGuestAgentExeFileVersion)" -color Green -endLine
        }
        else
        {
            New-Check -name "WindowsAzureGuestAgent.exe exists in $windowsAzureFolderPath" -result 'FAILED' -details ''
            $windowsAzureGuestAgentExe = $false
            Out-Log $windowsAzureGuestAgentExeExists -color Red -endLine
        }

        Out-Log 'WaAppAgent.exe exists:' -startLine
        $waAppAgentExe = $windowsAzureFolder | Where-Object {$_.Name -eq 'WaAppAgent.exe'}
        if ($waAppAgentExe)
        {
            New-Check -name "WaAppAgent.exe exists in $windowsAzureFolderPath" -result 'OK' -details ''
            $waAppAgentExeExists = $true
            $waAppAgentExeFileVersion = $waAppAgentExe | Select-Object -ExpandProperty VersionInfo | Select-Object -ExpandProperty FileVersion
            Out-Log "$waAppAgentExeExists (version $waAppAgentExeFileVersion)" -color Green -endLine
        }
        else
        {
            New-Check -name "WaAppAgent.exe exists in $windowsAzureFolderPath" -result 'FAILED' -details ''
            $waAppAgentExeExists = $false
            Out-Log $waAppAgentExeExists -color Red -endLine
        }
    }
    else
    {
        $windowsAzureFolderExists = $false
        New-Check -name "$windowsAzureFolderPath folder exists" -result 'FAILED' -details ''
        Out-Log $windowsAzureFolderExists -color Red -endLine
    }
}
else
{
    $windowsAzureFolderExists = $false
    Out-Log "$windowsAzureFolderPath folder exists: Skipped (Azure VM: $isAzureVM)"
    New-Check -name "$windowsAzureFolderPath folder exists" -result 'Skipped' -details "Azure VM: $isAzureVM"

    $windowsAzureGuestAgentExe = $false
    Out-Log "WindowsAzureGuestAgent.exe exists in $($windowsAzureFolderPath): Skipped (Azure VM: $isAzureVM)"
    New-Check -name "WindowsAzureGuestAgent.exe exists in $windowsAzureFolderPath" -result 'Skipped' -details "Azure VM: $isAzureVM"

    $waAppAgentExeExists = $false
    Out-Log "WaAppAgent.exe exists in $($windowsAzureFolderPath): Skipped (Azure VM: $isAzureVM)"
    New-Check -name "WaAppAgent.exe exists in $windowsAzureFolderPath" -result 'Skipped' -details "Azure VM: $isAzureVM"
}

Add-Type -TypeDefinition @'
using Microsoft.Win32.SafeHandles;
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Win32.Service
{
    public static class Ext
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct SERVICE_STATUS
        {
            public int ServiceType;
            public int CurrentState;
            public int ControlsAccepted;
            public int Win32ExitCode;
            public int ServiceSpecificExitCode;
            public int CheckPoint;
            public int WaitHint;
        }

        [DllImport("Advapi32.dll", EntryPoint = "QueryServiceStatus")]
        private static extern bool NativeQueryServiceStatus(
            SafeHandle hService,
            out SERVICE_STATUS lpServiceStatus);

        public static SERVICE_STATUS QueryServiceStatus(SafeHandle serviceHandle)
        {
            SERVICE_STATUS res;
            if (!NativeQueryServiceStatus(serviceHandle, out res))
            {
                throw new Win32Exception();
            }

            return res;
        }
    }
}
'@

if ($isAzureVM)
{
    $rdagent = Get-ServiceChecks -name 'RdAgent' -expectedStatus 'Running' -expectedStartType 'Automatic'
    if ($rdagent)
    {
        $rdAgentServiceExists = $true
    }
    $windowsAzureGuestAgent = Get-ServiceChecks -name 'WindowsAzureGuestAgent' -expectedStatus 'Running' -expectedStartType 'Automatic'
    if ($windowsAzureGuestAgent)
    {
        $windowsAzureGuestAgentServiceExists = $true
    }
}
else
{
    Out-Log "RdAgent service: Skipped (Azure VM: $isAzureVM)"
    New-Check -name "RdAgent service" -result 'Skipped' -details "Azure VM: $isAzureVM"

    Out-Log "WindowsAzureGuestAgent service: Skipped (Azure VM: $isAzureVM)"
    New-Check -name "WindowsAzureGuestAgent service" -result 'Skipped' -details "Azure VM: $isAzureVM"
}
$winmgmt = Get-ServiceChecks -name 'Winmgmt' -expectedStatus 'Running' -expectedStartType 'Automatic'
$keyiso = Get-ServiceChecks -name 'Keyiso' -expectedStatus 'Running' -expectedStartType 'Manual'

if ($isAzureVM)
{
    Get-ServiceCrashes -Name 'RdAgent'
    Get-ServiceCrashes -Name 'Windows Azure Guest Agent'
    Get-ApplicationErrors -Name 'WaAppagent'
    Get-ApplicationErrors -Name 'WindowsAzureGuestAgent'
}
else
{
    Out-Log "RdAgent service crashes: Skipped (Azure VM: $isAzureVM)"
    New-Check -name 'RdAgent service crashes' -result 'Skipped' -details "Azure VM: $isAzureVM"

    Out-Log "Windows Azure Guest Agent service crashes: Skipped (Azure VM: $isAzureVM)"
    New-Check -name 'Windows Azure Guest Agent service crashes' -result 'Skipped' -details "Azure VM: $isAzureVM"

    Out-Log "WaAppAgent application errors: Skipped (Azure VM: $isAzureVM)"
    New-Check -name 'WaAppAgent application errors' -result 'Skipped' -details "Azure VM: $isAzureVM"

    Out-Log "WindowsAzureGuestAgent application errors: Skipped (Azure VM: $isAzureVM)"
    New-Check -name 'WindowsAzureGuestAgent application errors' -result 'Skipped' -details "Azure VM: $isAzureVM"
}

Out-Log 'StdRegProv WMI class:' -startLine
if ($winmgmt.Status -eq 'Running')
{
    if ($fakeFinding)
    {
        # Using intentionally wrong class name NOTStdRegProv in order to generate a finding on-demand without having to change any config
        $stdRegProv = Invoke-ExpressionWithLogging "wmic /namespace:\\root\default Class NOTStdRegProv Call GetDWORDValue hDefKey='&H80000002' sSubKeyName='SYSTEM\CurrentControlSet\Services\Winmgmt' sValueName=Start 2>`$null" -verboseOnly
    }
    else
    {
        $stdRegProv = Invoke-ExpressionWithLogging "wmic /namespace:\\root\default Class StdRegProv Call GetDWORDValue hDefKey='&H80000002' sSubKeyName='SYSTEM\CurrentControlSet\Services\Winmgmt' sValueName=Start 2>`$null" -verboseOnly
    }

    $wmicExitCode = $LASTEXITCODE
    if ($wmicExitCode -eq 0)
    {
        $stdRegProvQuerySuccess = $true
        Out-Log $stdRegProvQuerySuccess -color Green -endLine
        New-Check -name 'StdRegProv WMI class' -result 'OK' -details ''
    }
    else
    {
        $stdRegProvQuerySuccess = $false
        Out-Log $stdRegProvQuerySuccess -color Red -endLine
        New-Check -name 'StdRegProv WMI class' -result 'FAILED' -details ''
        $description = "StdRegProv WMI class query failed with error code $wmicExitCode"
        New-Finding -type Critical -name 'StdRegProv WMI class query failed' -description $description -mitigation ''
    }
}
else
{
    $details = 'Skipped (Winmgmt service not running)'
    New-Check -name 'StdRegProv WMI class' -result 'Skipped' -details $details
    Out-Log $details -endLine
}

if ($isAzureVM)
{
    Out-Log 'VM Agent installed:' -startLine
    # $detailsSuffix = "(windowsAzureFolderExists:$windowsAzureFolderExists rdAgentServiceExists:$rdAgentServiceExists windowsAzureGuestAgentServiceExists:$windowsAzureGuestAgentServiceExists rdAgentKeyExists:$rdAgentKeyExists windowsAzureGuestAgentKeyExists:$windowsAzureGuestAgentKeyExists waAppAgentExeExists:$waAppAgentExeExists windowsAzureGuestAgentExeExists:$windowsAzureGuestAgentExeExists)"
    # if ($windowsAzureFolderExists -and $rdAgentServiceExists -and $windowsAzureGuestAgentServiceExists -and $rdAgentKeyExists -and $windowsAzureGuestAgentKeyExists -and $waAppAgentExeExists -and $windowsAzureGuestAgentExeExists -and $windowsAzureGuestAgentKeyExists -and $windowsAzureGuestAgentKeyExists)
    $detailsSuffix = "$windowsAzureFolderPath exists: $([bool]$windowsAzureFolder), WaAppAgent.exe in $($windowsAzureFolderPath): $([bool]$waAppAgentExe), WindowsAzureGuestAgent.exe in $($windowsAzureFolderPath): $([bool]$windowsAzureGuestAgentExe), RdAgent service installed: $([bool]$rdagent), WindowsAzureGuestAgent service installed: $([bool]$windowsAzureGuestAgent)"
    if ([bool]$windowsAzureFolder -and [bool]$rdagent -and [bool]$windowsAzureGuestAgent -and [bool]$waAppAgentExe -and [bool]$windowsAzureGuestAgentExe)
    {
        $isVMAgentInstalled = $true
        $details = "VM agent is installed ($detailsSuffix)"
        New-Check -name 'VM agent installed' -result 'OK' -details $details
        Out-Log $isVMAgentInstalled -color Green -endLine
    }
    else
    {
        $isVMAgentInstalled = $false
        $details = "VM agent is not installed ($detailsSuffix)"
        New-Check -name 'VM agent installed' -result 'FAILED' -details $details
        Out-Log $isVMAgentInstalled -color Red -endLine
        New-Finding -type Critical -Name 'VM agent not installed' -description $details -mitigation ''
    }

    if ($isVMAgentInstalled)
    {
        Out-Log 'VM agent installed by provisioning agent or Windows Installer package (MSI):' -startLine
        $uninstallKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        $uninstallKey = Invoke-ExpressionWithLogging "Get-Item -Path '$uninstallKeyPath' -ErrorAction SilentlyContinue" -verboseOnly
        $agentUninstallKey = $uninstallkey.GetSubKeyNames() | ForEach-Object {Get-ItemProperty -Path $uninstallKeyPath\$_ | Where-Object {$_.Publisher -eq 'Microsoft Corporation' -and $_.DisplayName -match 'Windows Azure VM Agent'}}
        $agentUninstallKeyDisplayName = $agentUninstallKey.DisplayName
        $agentUninstallKeyDisplayVersion = $agentUninstallKey.DisplayVersion
        $agentUninstallKeyInstallDate = $agentUninstallKey.InstallDate

        if ($agentUninstallKey)
        {
            New-Check -name 'VM agent installed by provisioning agent' -result 'OK' -details ''
            Out-Log 'MSI: MSI' -color Green -endLine
        }
        else
        {
            New-Check -name 'VM agent installed by provisioning agent' -result 'OK' -details ''
            Out-Log 'Provisioning agent' -color Green -endLine
        }
    }
}
else
{
    $isVMAgentInstalled = $false

    Out-Log "VM agent installed: Skipped (Azure VM: $isAzureVM)"
    New-Check -name 'VM agent installed' -result 'Skipped' -details "Azure VM: $isAzureVM"

    Out-Log "VM agent installed by provisioning agent or Windows Installer package (MSI): Skipped (Azure VM: $isAzureVM)"
    New-Check -name 'VM agent installed by provisioning agent' -result 'Skipped' -details "Azure VM: $isAzureVM"
}

Out-Log 'VM agent is supported version:' -startLine
if ($isVMAgentInstalled)
{
    $guestKeyPath = 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest'
    $guestKey = Invoke-ExpressionWithLogging "Get-ItemProperty -Path '$guestKeyPath' -ErrorAction SilentlyContinue" -verboseOnly
    if ($guestKey)
    {
        $guestKeyDHCPStatus = $guestKey.DHCPStatus
        $guestKeyDhcpWithFabricAddressTime = $guestKey.DhcpWithFabricAddressTime
        $guestKeyGuestAgentStartTime = $guestKey.GuestAgentStartTime
        $guestKeyGuestAgentStatus = $guestKey.GuestAgentStatus
        $guestKeyGuestAgentVersion = $guestKey.GuestAgentVersion
        $guestKeyOsVersion = $guestKey.OsVersion
        $guestKeyRequiredDotNetVersionPresent = $guestKey.RequiredDotNetVersionPresent
        $guestKeyTransparentInstallerStartTime = $guestKey.TransparentInstallerStartTime
        $guestKeyTransparentInstallerStatus = $guestKey.TransparentInstallerStatus
        $guestKeyWireServerStatus = $guestKey.WireServerStatus

        $minSupportedGuestAgentVersion = '2.7.41491.1010'
        if ($guestKeyGuestAgentVersion -and [version]$guestKeyGuestAgentVersion -ge [version]$minSupportedGuestAgentVersion)
        {
            New-Check -name 'VM agent is supported version' -result 'OK' -details "Installed version: $guestKeyGuestAgentVersion, minimum supported version: $minSupportedGuestAgentVersion"
            $isAtLeastMinSupportedVersion = $true
            Out-Log "$isAtLeastMinSupportedVersion (installed: $guestKeyGuestAgentVersion, minimum supported: $minSupportedGuestAgentVersion)" -color Green -endLine
        }
        else
        {
            New-Check -name 'VM agent is supported version' -result 'FAILED' -details "Installed version: $guestKeyGuestAgentVersion, minimum supported version: $minSupportedGuestAgentVersion"
            Out-Log "$isAtLeastMinSupportedVersion (installed: $guestKeyGuestAgentVersion, minimum supported: $minSupportedGuestAgentVersion)" -color Red -endLine
        }
    }
}
else
{
    $details = "Skipped (VM agent installed: $isVMAgentInstalled)"
    New-Check -name 'VM agent is supported version' -result 'Skipped' -details $details
    $isAtLeastMinSupportedVersion = $false
    Out-Log $details -endLine
}

if ($isVMAgentInstalled)
{
    $guestAgentKeyPath = 'HKLM:\SOFTWARE\Microsoft\GuestAgent'
    $guestAgentKey = Invoke-ExpressionWithLogging "Get-ItemProperty -Path '$guestAgentKeyPath' -ErrorAction SilentlyContinue" -verboseOnly
    if ($guestAgentKey)
    {
        $guestAgentKeyContainerId = $guestAgentKey.ContainerId
        $guestAgentKeyDirectoryToDelete = $guestAgentKey.DirectoryToDelete
        $guestAgentKeyHeartbeatLastStatusUpdateTime = $guestAgentKey.HeartbeatLastStatusUpdateTime
        $guestAgentKeyIncarnation = $guestAgentKey.Incarnation
        $guestAgentKeyInstallerRestart = $guestAgentKey.InstallerRestart
        $guestAgentKeyManifestTimeStamp = $guestAgentKey.ManifestTimeStamp
        $guestAgentKeyMetricsSelfSelectionSelected = $guestAgentKey.MetricsSelfSelectionSelected
        $guestAgentKeyUpdateNewGAVersion = $guestAgentKey.'Update-NewGAVersion'
        $guestAgentKeyUpdatePreviousGAVersion = $guestAgentKey.'Update-PreviousGAVersion'
        $guestAgentKeyUpdateStartTime = $guestAgentKey.'Update-StartTime'
        $guestAgentKeyVmProvisionedAt = $guestAgentKey.VmProvisionedAt
        if ($guestAgentKeyVmProvisionedAt)
        {
            $guestAgentKeyVmProvisionedAt = `Get-Date -Date $guestAgentKeyVmProvisionedAt -Format 'yyyy-MM-ddTHH:mm:ss'
        }
    }

    $vm.Add([PSCustomObject]@{Property = "ContainerId"; Value = $guestAgentKeyContainerId; Type = 'Agent'})
    $vm.Add([PSCustomObject]@{Property = "DirectoryToDelete"; Value = $guestAgentKeyDirectoryToDelete; Type = 'Agent'})
    $vm.Add([PSCustomObject]@{Property = "HeartbeatLastStatusUpdateTime"; Value = $guestAgentKeyHeartbeatLastStatusUpdateTime; Type = 'Agent'})
    $vm.Add([PSCustomObject]@{Property = "Incarnation"; Value = $guestAgentKeyIncarnation; Type = 'Agent'})
    $vm.Add([PSCustomObject]@{Property = "InstallerRestart"; Value = $guestAgentKeyInstallerRestart; Type = 'Agent'})
    $vm.Add([PSCustomObject]@{Property = "ManifestTimeStamp"; Value = $guestAgentKeyManifestTimeStamp; Type = 'Agent'})
    $vm.Add([PSCustomObject]@{Property = "MetricsSelfSelectionSelected"; Value = $guestAgentKeyMetricsSelfSelectionSelected; Type = 'Agent'})
    $vm.Add([PSCustomObject]@{Property = "UpdateNewGAVersion"; Value = $guestAgentKeyUpdateNewGAVersion; Type = 'Agent'})
    $vm.Add([PSCustomObject]@{Property = "UpdatePreviousGAVersion"; Value = $guestAgentKeyUpdatePreviousGAVersion; Type = 'Agent'})
    $vm.Add([PSCustomObject]@{Property = "UpdateStartTime"; Value = $guestAgentKeyUpdateStartTime; Type = 'Agent'})
    $vm.Add([PSCustomObject]@{Property = "VmProvisionedAt"; Value = $guestAgentKeyVmProvisionedAt; Type = 'Agent'})

    $windowsAzureKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows Azure'
    $windowsAzureKey = Invoke-ExpressionWithLogging "Get-ItemProperty -Path '$windowsAzureKeyPath' -ErrorAction SilentlyContinue" -verboseOnly
    if ($windowsAzureKey)
    {
        $vmId = $windowsAzureKey.vmId
        if ($vmId)
        {
            $vmId = $vmId.ToLower()
        }
    }

    $guestAgentUpdateStateKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows Azure\GuestAgentUpdateState'
    $guestAgentUpdateStateKey = Invoke-ExpressionWithLogging "Get-Item -Path '$guestAgentUpdateStateKeyPath' -ErrorAction SilentlyContinue" -verboseOnly
    if ($guestAgentUpdateStateKey)
    {
        $guestAgentUpdateStateSubKeyName = $guestAgentUpdateStateKey.GetSubKeyNames() | Sort-Object {[Version]$_} | Select-Object -Last 1
        $guestAgentUpdateStateSubKey = Invoke-ExpressionWithLogging "Get-ItemProperty -Path '$guestAgentUpdateStateKeyPath\$guestAgentUpdateStateSubKeyName' -ErrorAction SilentlyContinue" -verboseOnly
        if ($guestAgentUpdateStateSubKey)
        {
            $guestAgentUpdateStateCode = $guestAgentUpdateStateSubKey.Code
            $guestAgentUpdateStateMessage = $guestAgentUpdateStateSubKey.Message
            $guestAgentUpdateStateState = $guestAgentUpdateStateSubKey.State
        }
    }

    $handlerStateKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows Azure\HandlerState'
    $handlerStateKey = Invoke-ExpressionWithLogging "Get-Item -Path '$handlerStateKeyPath' -ErrorAction SilentlyContinue" -verboseOnly
    if ($handlerStateKey)
    {
        $handlerNames = $handlerStateKey.GetSubKeyNames()
        if ($handlerNames)
        {
            $handlerStates = New-Object System.Collections.Generic.List[Object]
            foreach ($handlerName in $handlerNames)
            {
                $handlerState = Invoke-ExpressionWithLogging "Get-ItemProperty -Path '$handlerStateKeyPath\$handlerName' -ErrorAction SilentlyContinue" -verboseOnly
                if ($handlerState)
                {
                    $handlerStates.Add($handlerState)
                    $handlerState = $null
                }
            }
        }
    }
}

# The ProxyEnable key controls the proxy settings.
# 0 disables them, and 1 enables them.
# If you are using a proxy, you will get its value under the ProxyServer key.
# This gets the same settings as running "netsh winhttp show proxy"
$proxyConfigured = $false
Out-Log 'Proxy configured:' -startLine
$netshWinhttpShowProxyOutput = netsh winhttp show proxy
Out-Log "`$netshWinhttpShowProxyOutput: $netshWinhttpShowProxyOutput" -verboseOnly
$proxyServers = $netshWinhttpShowProxyOutput | Select-String -SimpleMatch 'Proxy Server(s)' | Select-Object -ExpandProperty Line
if ([string]::IsNullOrEmpty($proxyServers) -eq $false)
{
    $proxyServers = $proxyServers.Trim()
    Out-Log "`$proxyServers: $proxyServers" -verboseOnly
    Out-Log "`$proxyServers.Length: $($proxyServers.Length)" -verboseOnly
    Out-Log "`$proxyServers.GetType(): $($proxyServers.GetType())" -verboseOnly
}
$connectionsKeyPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections'
$connectionsKey = Get-ItemProperty -Path $connectionsKeyPath -ErrorAction SilentlyContinue
$winHttpSettings = $connectionsKey | Select-Object -ExpandProperty WinHttpSettings -ErrorAction SilentlyContinue
$winHttpSettings = ($winHttpSettings | ForEach-Object {'{0:X2}' -f $_}) -join ''
# '1800000000000000010000000000000000000000' is the default if nothing was ever configured
# '2800000000000000010000000000000000000000' is the default after running "netsh winhttp reset proxy"
# So either of those equate to "Direct access (no proxy server)." being returned by "netsh winhttp show proxy"
$defaultWinHttpSettings = @('1800000000000000010000000000000000000000', '2800000000000000010000000000000000000000')
if ($winHttpSettings -notin $defaultWinHttpSettings)
{
    $proxyConfigured = $true
}

# [System.Net.WebProxy]::GetDefaultProxy() works on Windows PowerShell but not PowerShell Core
$defaultProxy = Invoke-ExpressionWithLogging '[System.Net.WebProxy]::GetDefaultProxy()' -verboseOnly
$defaultProxyAddress = $defaultProxy.Address
$defaultProxyBypassProxyOnLocal = $defaultProxy.BypassProxyOnLocal
$defaultProxyBypassList = $defaultProxy.BypassList
$defaultProxyCredentials = $defaultProxy.Credentials
$defaultProxyUseDefaultCredentials = $defaultProxy.UseDefaultCredentials
$defaultProxyBypassArrayList = $defaultProxy.BypassArrayList

if ($defaultProxyAddress)
{
    $proxyConfigured = $true
}
Out-Log "Address: $defaultProxyAddress" -verboseOnly
Out-Log "BypassProxyOnLocal: $defaultProxyBypassProxyOnLocal" -verboseOnly
Out-Log "BypassList: $defaultProxyBypassList" -verboseOnly
Out-Log "Credentials: $defaultProxyCredentials" -verboseOnly
Out-Log "UseDefaultCredentials: $defaultProxyUseDefaultCredentials" -verboseOnly
Out-Log "BypassArrayList: $defaultProxyBypassArrayList" -verboseOnly

<#
HTTP_PROXY  : proxy server used on HTTP requests.
HTTPS_PROXY : proxy server used on HTTPS requests.
ALL_PROXY   : proxy server used on HTTP and/or HTTPS requests in case HTTP_PROXY and/or HTTPS_PROXY are not defined.
NO_PROXY    : comma-separated list of hostnames that should be excluded from proxying.
#>
Out-Log 'Proxy environment variables:' -verboseOnly
Out-Log "HTTP_PROXY : $env:HTTP_PROXY" -verboseOnly
Out-Log "HTTPS_PROXY : $env:HTTP_PROXY" -verboseOnly
Out-Log "ALL_PROXY : $env:HTTP_PROXY" -verboseOnly
Out-Log "NO_PROXY : $env:HTTP_PROXY" -verboseOnly
if ($env:HTTP_PROXY -or $env:HTTPS_PROXY -or $env:ALL_PROXY)
{
    $proxyConfigured = $true
}

$userInternetSettingsKeyPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$userInternetSettingsKey = Invoke-ExpressionWithLogging "Get-ItemProperty -Path $userInternetSettingsKeyPath -ErrorAction SilentlyContinue" -verboseOnly
$userProxyEnable = $userInternetSettingsKey | Select-Object -ExpandProperty ProxyEnable -ErrorAction SilentlyContinue
$userProxyServer = $userInternetSettingsKey | Select-Object -ExpandProperty ProxyServer -ErrorAction SilentlyContinue
$userProxyOverride = $userInternetSettingsKey | Select-Object -ExpandProperty ProxyOverride -ErrorAction SilentlyContinue
$userAutoDetect = $userInternetSettingsKey | Select-Object -ExpandProperty AutoDetect -ErrorAction SilentlyContinue
Out-Log "$userInternetSettingsKeyPath\ProxyEnable: $userProxyEnable" -verboseOnly
Out-Log "$userInternetSettingsKeyPath\ProxyServer: $userProxyServer" -verboseOnly
Out-Log "$userInternetSettingsKeyPath\ProxyOverride: $userProxyOverride" -verboseOnly
Out-Log "$userInternetSettingsKeyPath\AutoDetect: $userAutoDetect" -verboseOnly
if ($userProxyEnable -and $userProxyServer)
{
    $proxyConfigured = $true
}

$machineInternetSettingsKeyPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$machineInternetSettingsKey = Invoke-ExpressionWithLogging "Get-ItemProperty -Path $machineInternetSettingsKeyPath -ErrorAction SilentlyContinue" -verboseOnly
$machineProxyEnable = $machineInternetSettingsKey | Select-Object -ExpandProperty ProxyEnable -ErrorAction SilentlyContinue
$machineProxyServer = $machineInternetSettingsKey | Select-Object -ExpandProperty ProxyServer -ErrorAction SilentlyContinue
$machineProxyOverride = $machineInternetSettingsKey | Select-Object -ExpandProperty ProxyOverride -ErrorAction SilentlyContinue
$machineAutoDetect = $machineInternetSettingsKey | Select-Object -ExpandProperty AutoDetect -ErrorAction SilentlyContinue
Out-Log "$machineInternetSettingsKeyPath\ProxyEnable: $machineProxyEnable" -verboseOnly
Out-Log "$machineInternetSettingsKeyPath\ProxyServer: $machineProxyServer" -verboseOnly
Out-Log "$machineInternetSettingsKeyPath\ProxyOverride: $machineProxyOverride" -verboseOnly
Out-Log "$machineInternetSettingsKeyPath\Autodetect: $machineAutoDetect" -verboseOnly
if ($machineProxyEnable -and $machineProxyServer)
{
    $proxyConfigured = $true
}

$machinePoliciesInternetSettingsKeyPath = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
$machinePoliciesInternetSettingsKey = Invoke-ExpressionWithLogging "Get-ItemProperty -Path $machinePoliciesInternetSettingsKeyPath -ErrorAction SilentlyContinue" -verboseOnly
$proxySettingsPerUser = $machinePoliciesInternetSettingsKey | Select-Object -ExpandProperty ProxySettingsPerUser -ErrorAction SilentlyContinue
Out-Log "$machinePoliciesInternetSettingsKeyPath\ProxySettingsPerUser: $proxySettingsPerUser" -verboseOnly

if ($proxyConfigured)
{
    New-Check -name 'Proxy configured' -result 'Info' -details $proxyServers
    Out-Log $proxyConfigured -color Cyan -endLine
    $mitigation = '<a href="https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/windows-azure-guest-agent#solution-3-enable-dhcp-and-make-sure-that-the-server-isnt-blocked-by-firewalls-proxies-or-other-sources">Check proxy settings</a>'
    New-Finding -type Information -name 'Proxy configured' -description $proxyServers -mitigation $mitigation
}
else
{
    New-Check -name 'Proxy configured' -result 'OK' -details 'No proxy configured'
    Out-Log $proxyConfigured -color Green -endLine
}

Out-Log 'TenantEncryptionCert installed:' -startLine
if ($isVMAgentInstalled)
{
    $tenantEncryptionCert = Get-ChildItem -Path 'Cert:\LocalMachine\My' | Where-Object {$_.FriendlyName -eq 'TenantEncryptionCert' -and $_.Issuer -eq 'DC=Windows Azure CRP Certificate Generator' -and $_.Subject -eq 'DC=Windows Azure CRP Certificate Generator'}
    if ($tenantEncryptionCert)
    {
        $tenantEncryptionCertInstalled = $true
        Out-Log $tenantEncryptionCertInstalled -color Green -endLine
        $subject = $tenantEncryptionCert.Subject
        $issuer =  $tenantEncryptionCert.Issuer
        $effective = Get-Date -Date $tenantEncryptionCert.NotBefore.ToUniversalTime() -Format 'yyyy-MM-ddTHH:mm:ssZ'
        $expires = Get-Date -Date $tenantEncryptionCert.NotAfter.ToUniversalTime() -Format 'yyyy-MM-ddTHH:mm:ssZ'
        $now = Get-Date -Date (Get-Date).ToUniversalTime() -Format 'yyyy-MM-ddTHH:mm:ssZ'
        New-Check -name 'TenantEncryptionCert installed' -result 'OK' -details "Subject: $subject Issuer: $issuer"

        Out-Log 'TenantEncryptionCert within validity period:' -startLine
        if ($tenantEncryptionCert.NotBefore -le [System.DateTime]::Now -and $tenantEncryptionCert.NotAfter -gt [System.DateTime]::Now)
        {
            $tenantEncryptionCertWithinValidityPeriod = $true
            Out-Log $tenantEncryptionCertWithinValidityPeriod -color Green -endLine
            New-Check -name 'TenantEncryptionCert within validity period' -result 'OK' -details "Now: $now Effective: $effective Expires: $expires"
        }
        else
        {
            $tenantEncryptionCertWithinValidityPeriod = $false
            Out-Log $tenantEncryptionCertWithinValidityPeriod -color Red -endLine
            New-Check -name 'TenantEncryptionCert within validity period' -result 'FAILED' -details "Now: $now Effective: $effective Expires: $expires"
            New-Finding -type Critical -name 'TenantEncryptionCert not within validity period' -description "Now: $now Effective: $effective Expires: $expires" -mitigation $mitigation
        }
    }
    else
    {
        New-Check -name 'TenantEncryptionCert installed' -result 'FAILED' -details ''
        New-Finding -type Critical -name 'TenantEncryptionCert not installed' -description '' -mitigation ''
        Out-Log $false -color Red -endLine
    }
}
else
{
    $details = "Skipped (VM agent installed: $isVMAgentInstalled)"
    New-Check -name 'TenantEncryptionCert installed' -result 'Skipped' -details $details
    Out-Log $details -endLine
}

Get-WCFConfig

if ($isAzureVM)
{
    # wireserver doesn't listen on 8080 even though it creates a BFE filter for it
    # Test-NetConnection -ComputerName 168.63.129.16 -Port 80 -InformationLevel Quiet -WarningAction SilentlyContinue
    # Test-NetConnection -ComputerName 168.63.129.16 -Port 32526 -InformationLevel Quiet -WarningAction SilentlyContinue
    # Test-NetConnection -ComputerName 169.254.169.254 -Port 80 -InformationLevel Quiet -WarningAction SilentlyContinue
    Out-Log 'Wireserver endpoint 168.63.129.16:80 reachable:' -startLine
    $wireserverPort80Reachable = Test-Port -ipAddress '168.63.129.16' -port 80 -timeout 1000
    $description = "Wireserver endpoint 168.63.129.16:80 reachable: $($wireserverPort80Reachable.Succeeded) $($wireserverPort80Reachable.Error)"
    $mitigation = '<a href="https://learn.microsoft.com/en-us/azure/virtual-network/what-is-ip-address-168-63-129-16">What is IP address 168.63.129.16?</a>'
    if ($wireserverPort80Reachable.Succeeded)
    {
        New-Check -name 'Wireserver endpoint 168.63.129.16:80 reachable' -result 'OK' -details ''
        Out-Log "$($wireserverPort80Reachable.Succeeded) $($wireserverPort80Reachable.Error)" -color Green -endline
    }
    else
    {
        New-Check -name 'Wireserver endpoint 168.63.129.16:80 reachable' -result 'FAILED' -details ''
        Out-Log $wireserverPort80Reachable.Succeeded -color Red -endLine
        New-Finding -type Critical -name 'Wireserver endpoint 168.63.129.16:80 not reachable' -description $description -mitigation $mitigation
    }

    Out-Log 'Wireserver endpoint 168.63.129.16:32526 reachable:' -startLine
    $wireserverPort32526Reachable = Test-Port -ipAddress '168.63.129.16' -port 32526 -timeout 1000
    $description = "Wireserver endpoint 168.63.129.16:32526 reachable: $($wireserverPort32526Reachable.Succeeded) $($wireserverPort80Reachable.Error)"
    if ($wireserverPort32526Reachable.Succeeded)
    {
        New-Check -name 'Wireserver endpoint 168.63.129.16:32526 reachable' -result 'OK' -details ''
        Out-Log $wireserverPort32526Reachable.Succeeded -color Green -endLine
    }
    else
    {
        New-Check -name 'Wireserver endpoint 168.63.129.16:32526 reachable' -result 'FAILED' -details ''
        Out-Log "$($wireserverPort32526Reachable.Succeeded) $($wireserverPort80Reachable.Error)" -color Red -endLine
        New-Finding -type Critical -name 'Wireserver endpoint 168.63.129.16:32526 not reachable' -description $description -mitigation $mitigation
    }

    Out-Log 'IMDS endpoint 169.254.169.254:80 reachable:' -startLine
    $imdsReachable = Test-Port -ipAddress '169.254.169.254' -port 80 -timeout 1000
    $description = "IMDS endpoint 169.254.169.254:80 reachable: $($imdsReachable.Succeeded) $($imdsReachable.Error)"
    if ($imdsReachable.Succeeded)
    {
        New-Check -name 'IMDS endpoint 169.254.169.254:80 reachable' -result 'OK' -details ''
        Out-Log $imdsReachable.Succeeded -color Green -endLine
    }
    else
    {
        New-Check -name 'IMDS endpoint 169.254.169.254:80 reachable' -result 'FAILED' -details ''
        Out-Log "$($imdsReachable.Succeeded) $($imdsReachable.Error)" -color Red -endLine
        New-Finding -type Information -name 'IMDS endpoint 169.254.169.254:80 not reachable' -description $description
    }

    if ($imdsReachable.Succeeded)
    {
        Out-Log 'IMDS endpoint 169.254.169.254:80 returned expected result:' -startLine
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072
        # Below three lines have it use a null proxy, bypassing any configured proxy
        # See also https://github.com/microsoft/azureimds/blob/master/IMDSSample.ps1
        $proxy = New-Object System.Net.WebProxy
        $webSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        $webSession.Proxy = $proxy
        $apiVersions = Invoke-RestMethod -Headers @{'Metadata' = 'true'} -Method GET -Uri 'http://169.254.169.254/metadata/versions' -WebSession $webSession | Select-Object -ExpandProperty apiVersions
        $apiVersion = $apiVersions | Select-Object -Last 1
        $metadata = Invoke-RestMethod -Headers @{'Metadata' = 'true'} -Method GET -Uri "http://169.254.169.254/metadata/instance?api-version=$apiVersion" -WebSession $webSession
        $compute = $metadata | Select-Object -ExpandProperty compute -ErrorAction SilentlyContinue

        if ($compute)
        {
            $imdReturnedExpectedResult = $true
            Out-Log $imdReturnedExpectedResult -color Green -endLine
            New-Check -name 'IMDS endpoint 169.254.169.254:80 returned expected result' -result 'OK' -details ''

            $global:dbgMetadata = $metadata

            $azEnvironment = $metadata.compute.azEnvironment
            $vmName = $metadata.compute.name
            $vmId = $metadata.compute.vmId
            $resourceId = $metadata.compute.resourceId
            $licenseType = $metadata.compute.licenseType
            $planPublisher = $metadata.compute.plan.publisher
            $planProduct = $metadata.compute.plan.product
            $planName = $metadata.compute.plan.name
            $osDiskDiskSizeGB = $metadata.compute.storageProfile.osDisk.diskSizeGB
            $osDiskManagedDiskId = $metadata.compute.storageProfile.osDisk.managedDisk.id
            $osDiskManagedDiskStorageAccountType = $metadata.compute.storageProfile.osDisk.managedDisk.storageAccountType
            $osDiskCreateOption = $metadata.compute.storageProfile.osDisk.createOption
            $osDiskCaching = $metadata.compute.storageProfile.osDisk.caching
            $osDiskDiffDiskSettingsOption = $metadata.compute.storageProfile.osDisk.diffDiskSettings.option
            $osDiskEncryptionSettingsEnabled = $metadata.compute.storageProfile.osDisk.encryptionSettings.enabled
            $osDiskImageUri = $metadata.compute.storageProfile.osDisk.image.uri
            $osDiskName = $metadata.compute.storageProfile.osDisk.name
            $osDiskOsType = $metadata.compute.storageProfile.osDisk.osType
            $osDiskVhdUri = $metadata.compute.storageProfile.osDisk.vhd.uri
            $osDiskWriteAcceleratorEnabled = $metadata.compute.storageProfile.osDisk.writeAcceleratorEnabled
            $encryptionAtHost = $metadata.compute.securityProfile.encryptionAtHost
            $secureBootEnabled = $metadata.compute.securityProfile.secureBootEnabled
            $securityType = $metadata.compute.securityProfile.securityType
            $virtualTpmEnabled = $metadata.compute.securityProfile.virtualTpmEnabled
            $virtualMachineScaleSetId = $metadata.compute.virtualMachineScaleSet.id
            $vmScaleSetName = $metadata.compute.vmScaleSetName
            $zone = $metadata.compute.zone
            $dataDisks = $metadata.compute.storageProfile.dataDisks
            $priority = $metadata.compute.priority
            $platformFaultDomain = $metadata.compute.platformFaultDomain
            $platformSubFaultDomain = $metadata.compute.platformSubFaultDomain
            $platformUpdateDomain = $metadata.compute.platformUpdateDomain
            $placementGroupId = $metadata.compute.placementGroupId
            $extendedLocationName = $metadata.compute.extendedLocationName
            $extendedLocationType = $metadata.compute.extendedLocationType
            $evictionPolicy = $metadata.compute.evictionPolicy
            $hostId = $metadata.compute.hostId
            $hostGroupId = $metadata.compute.hostGroupId
            $isHostCompatibilityLayerVm = $metadata.compute.isHostCompatibilityLayerVm
            $hibernationEnabled = $metadata.compute.additionalCapabilities.hibernationEnabled
            $subscriptionId = $metadata.compute.subscriptionId
            $resourceGroupName = $metadata.compute.resourceGroupName
            $location = $metadata.compute.location
            $vmSize = $metadata.compute.vmSize
            $vmIdFromImds = $metadata.compute.vmId
            $publisher = $metadata.compute.publisher
            $offer = $metadata.compute.offer
            $sku = $metadata.compute.sku
            $version = $metadata.compute.version
            $imageReferenceId = $metadata.compute.storageProfile.imageReference.id
            if ($publisher)
            {
                $imageReference = "$publisher|$offer|$sku|$version"
            }
            else
            {
                if ($imageReferenceId)
                {
                    $imageReference = "$($imageReferenceId.Split('/')[-1]) (custom image)"
                }
            }
            $interfaces = $metadata.network.interface
            $macAddress = $metadata.network.interface.macAddress
            $privateIpAddress = $metadata.network.interface | Select-Object -First 1 | Select-Object -ExpandProperty ipv4 -First 1 | Select-Object -ExpandProperty ipAddress -First 1 | Select-Object -ExpandProperty privateIpAddress -First 1
            $publicIpAddress = $metadata.network.interface | Select-Object -First 1 | Select-Object -ExpandProperty ipv4 -First 1 | Select-Object -ExpandProperty ipAddress -First 1 | Select-Object -ExpandProperty publicIpAddress -First 1
            $publicIpAddressReportedFromAwsCheckIpService = Invoke-RestMethod -Uri https://checkip.amazonaws.com -WebSession $webSession
            if ($publicIpAddressReportedFromAwsCheckIpService)
            {
                $publicIpAddressReportedFromAwsCheckIpService = $publicIpAddressReportedFromAwsCheckIpService.Trim()
            }
        }
        else
        {
            $imdReturnedExpectedResult = $false
            Out-Log $imdReturnedExpectedResult -color Red -endLine
            New-Check -name 'IMDS endpoint 169.254.169.254:80 returned expected result' -result 'FAILED' -details ''
        }
    }

    <#  Moved "isAzureVM" check earlier so it can be used as a conditional for other checks
    if ($imdsReachable.Succeeded -eq $false)
    {
        Out-Log 'DHCP request returns option 245:' -startLine
        $dhcpReturnedOption245 = Confirm-AzureVM
        if ($dhcpReturnedOption245)
        {
            Out-Log $dhcpReturnedOption245 -color Green -endLine
        }
        else
        {
            Out-Log $dhcpReturnedOption245 -color Yellow -endLine
        }
    }
    #>

    if ($wireserverPort80Reachable.Succeeded -and $wireserverPort32526Reachable.Succeeded)
    {
        Out-Log 'Getting status from aggregatestatus.json' -verboseOnly
        $aggregateStatusJsonFilePath = $windowsAzureFolder | Where-Object {$_.Name -eq 'aggregatestatus.json'} | Select-Object -ExpandProperty FullName
        $aggregateStatus = Get-Content -Path $aggregateStatusJsonFilePath
        $aggregateStatus = $aggregateStatus -replace '\0' | ConvertFrom-Json

        $aggregateStatusGuestAgentStatusVersion = $aggregateStatus.aggregateStatus.guestAgentStatus.version
        $aggregateStatusGuestAgentStatusStatus = $aggregateStatus.aggregateStatus.guestAgentStatus.status
        $aggregateStatusGuestAgentStatusMessage = $aggregateStatus.aggregateStatus.guestAgentStatus.formattedMessage.message
        $aggregateStatusGuestAgentStatusLastStatusUploadMethod = $aggregateStatus.aggregateStatus.guestAgentStatus.lastStatusUploadMethod
        $aggregateStatusGuestAgentStatusLastStatusUploadTime = $aggregateStatus.aggregateStatus.guestAgentStatus.lastStatusUploadTime

        Out-Log "Version: $aggregateStatusGuestAgentStatusVersion" -verboseOnly
        Out-Log "Status: $aggregateStatusGuestAgentStatusStatus" -verboseOnly
        Out-Log "Message: $aggregateStatusGuestAgentStatusMessage" -verboseOnly
        Out-Log "LastStatusUploadMethod: $aggregateStatusGuestAgentStatusLastStatusUploadMethod" -verboseOnly
        Out-Log "LastStatusUploadTime: $aggregateStatusGuestAgentStatusLastStatusUploadTime" -verboseOnly

        $headers = @{'x-ms-version' = '2012-11-30'}
        $proxy = New-Object System.Net.WebProxy
        $webSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        $webSession.Proxy = $proxy

        $goalState = Invoke-RestMethod -Method GET -Uri 'http://168.63.129.16/machine?comp=goalstate' -Headers $headers -WebSession $webSession | Select-Object -ExpandProperty GoalState

        $hostingEnvironmentConfigUri = $goalState.Container.RoleInstanceList.RoleInstance.Configuration.HostingEnvironmentConfig
        $sharedConfigUri = $goalState.Container.RoleInstanceList.RoleInstance.Configuration.SharedConfig
        $extensionsConfigUri = $goalState.Container.RoleInstanceList.RoleInstance.Configuration.ExtensionsConfig
        $fullConfigUri = $goalState.Container.RoleInstanceList.RoleInstance.Configuration.FullConfig
        $certificatesUri = $goalState.Container.RoleInstanceList.RoleInstance.Configuration.Certificates
        $configName = $goalState.Container.RoleInstanceList.RoleInstance.Configuration.ConfigName

        $hostingEnvironmentConfig = Invoke-RestMethod -Method GET -Uri $hostingEnvironmentConfigUri -Headers $headers -WebSession $webSession | Select-Object -ExpandProperty HostingEnvironmentConfig
        $sharedConfig = Invoke-RestMethod -Method GET -Uri $sharedConfigUri -Headers $headers -WebSession $webSession | Select-Object -ExpandProperty SharedConfig
        $extensions = Invoke-RestMethod -Method GET -Uri $extensionsConfigUri -Headers $headers -WebSession $webSession | Select-Object -ExpandProperty Extensions
        $rdConfig = Invoke-RestMethod -Method GET -Uri $fullConfigUri -Headers $headers -WebSession $webSession | Select-Object -ExpandProperty RDConfig
        $storedCertificate = $rdConfig.StoredCertificates.StoredCertificate | Where-Object {$_.name -eq 'TenantEncryptionCert'}
        $tenantEncryptionCertThumbprint = $storedCertificate.certificateId -split ':' | Select-Object -Last 1
        $tenantEncryptionCert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.Thumbprint -eq $tenantEncryptionCertThumbprint}

        $statusUploadBlobUri = $extensions.StatusUploadBlob.'#text'
        $inVMGoalStateMetaData = $extensions.InVMGoalStateMetaData
    }

    if ($isVMAgentInstalled)
    {
        Get-ThirdPartyLoadedModules -processName 'WaAppAgent'
        Get-ThirdPartyLoadedModules -processName 'WindowsAzureGuestAgent'
    }
}
else
{
    New-Check -name "Third-party modules in WaAppAgent" -result 'SKIPPED' -details "Skipped (VM agent installed: $isVMAgentInstalled)"
    Out-Log "Third-party modules in WaAppAgent: Skipped (VM agent installed: $isVMAgentInstalled)"

    New-Check -name "Third-party modules in WindowsAzureGuestAgent" -result 'SKIPPED' -details "Skipped (VM agent installed: $isVMAgentInstalled)"
    Out-Log "Third-party modules in WindowsAzureGuestAgent: Skipped (VM agent installed: $isVMAgentInstalled)"

    Out-Log "Wireserver endpoint 168.63.129.16:80 reachable: Skipped (Azure VM: $isAzureVM)"
    New-Check -name 'Wireserver endpoint 168.63.129.16:80 reachable' -result 'Skipped' -details "Azure VM: $isAzureVM"

    Out-Log "Wireserver endpoint 168.63.129.16:32526 reachable: Skipped (Azure VM: $isAzureVM)"
    New-Check -name 'Wireserver endpoint 168.63.129.16:32526 reachable' -result 'Skipped' -details "Azure VM: $isAzureVM"

    Out-Log "IMDS endpoint 169.254.169.254:80 reachable: Skipped (Azure VM: $isAzureVM)"
    New-Check -name 'IMDS endpoint 169.254.169.254:80 reachable' -result 'Skipped' -details "Azure VM: $isAzureVM"

    Out-Log "IMDS endpoint 169.254.169.254:80 returned expected result: Skipped (Azure VM: $isAzureVM)"
    New-Check -name 'IMDS endpoint 169.254.169.254:80 returned expected result' -result 'Skipped' -details "Azure VM: $isAzureVM"
}

if ($skipFirewall -eq $false)
{
    $enabledFirewallRules = Get-EnabledFirewallRules
}
if ($skipFilters -eq $false)
{
    $wfpFilters = Get-WfpFilters
}

$machineKeysDefaultSddl = 'O:SYG:SYD:PAI(A;;0x12019f;;;WD)(A;;FA;;;BA)'
Out-Log 'MachineKeys folder has default permissions:' -startLine
$machineKeysPath = 'C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys'
$machineKeysAcl = Get-Acl -Path $machineKeysPath
$machineKeysSddl = $machineKeysAcl | Select-Object -ExpandProperty Sddl
$machineKeysAccess = $machineKeysAcl | Select-Object -ExpandProperty Access
$machineKeysAccessString = $machineKeysAccess | ForEach-Object {"$($_.IdentityReference) $($_.AccessControlType) $($_.FileSystemRights)"}
$machineKeysAccessString = $machineKeysAccessString -join '<br>'

if ($machineKeysSddl -eq $machineKeysDefaultSddl)
{
    $machineKeysHasDefaultPermissions = $true
    Out-Log $machineKeysHasDefaultPermissions -color Green -endLine
    $details = "$machineKeysPath folder has default NTFS permissions" # <br>SDDL: $machineKeysSddl<br>$machineKeysAccessString"
    New-Check -name 'MachineKeys folder permissions' -result 'OK' -details $details
}
else
{
    $machineKeysHasDefaultPermissions = $false
    Out-Log $machineKeysHasDefaultPermissions -color Cyan -endLine
    $details = "$machineKeysPath folder does not have default NTFS permissions<br>SDDL: $machineKeysSddl<br>$machineKeysAccessString"
    New-Check -name 'MachineKeys folder permissions' -result 'Info' -details $details
    $mitigation = '<a href="https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/troubleshoot-extension-certificates-issues-windows-vm#solution-2-fix-the-access-control-list-acl-in-the-machinekeys-or-systemkeys-folders">Troubleshoot extension certificates</a>'
    New-Finding -type Information -name 'Non-default MachineKeys permissions' -description $details -mitigation $mitigation
}

# Permissions on $env:SystemDrive\WindowsAzure and $env:SystemDrive\Packages folder during startup.
# It first removes all user/groups and then sets the following permission
# (Read & Execute: Everyone, Full Control: SYSTEM & Local Administrators only) to these folders.
# If GA fails to remove/set the permission, it can't proceed further.
Out-Log "$windowsAzureFolderPath folder has default permissions:" -startLine
if ($isVMAgentInstalled)
{
    $windowsAzureDefaultSddl = 'O:SYG:SYD:PAI(A;OICI;0x1200a9;;;WD)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
    $windowsAzureAcl = Get-Acl -Path $windowsAzureFolderPath
    $windowsAzureSddl = $windowsAzureAcl | Select-Object -ExpandProperty Sddl
    $windowsAzureAccess = $windowsAzureAcl | Select-Object -ExpandProperty Access
    $windowsAzureAccessString = $windowsAzureAccess | ForEach-Object {"$($_.IdentityReference) $($_.AccessControlType) $($_.FileSystemRights)"}
    $windowsAzureAccessString = $windowsAzureAccessString -join '<br>'
    if ($windowsAzureSddl -eq $windowsAzureDefaultSddl)
    {
        $windowsAzureHasDefaultPermissions = $true
        Out-Log $windowsAzureHasDefaultPermissions -color Green -endLine
        $details = "$windowsAzureFolderPath folder has default NTFS permissions" # <br>SDDL: $windowsAzureSddl<br>$windowsAzureAccessString"
        New-Check -name "$windowsAzureFolderPath permissions" -result 'OK' -details $details
    }
    else
    {
        $windowsAzureHasDefaultPermissions = $false
        Out-Log $windowsAzureHasDefaultPermissions -color Cyan -endLine
        $details = "$windowsAzureFolderPath does not have default NTFS permissions<br>SDDL: $windowsAzureSddl<br>$windowsAzureAccessString"
        New-Check -name "$windowsAzureFolderPath permissions" -result 'Info' -details $details
        $mitigation = '<a href="https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/troubleshoot-extension-certificates-issues-windows-vm#solution-2-fix-the-access-control-list-acl-in-the-machinekeys-or-systemkeys-folders">Troubleshoot extension certificates</a>'
        New-Finding -type Information -name "Non-default $windowsAzureFolderPath permissions" -description $details -mitigation $mitigation
    }
}
else
{
    $details = "Skipped (VM agent installed: $isVMAgentInstalled)"
    New-Check -name "$windowsAzureFolderPath permissions" -result 'Skipped' -details $details
    Out-Log $details -endLine
}

$packagesFolderPath = "$env:SystemDrive\Packages"
Out-Log "$packagesFolderPath folder has default permissions:" -startLine
if ($isVMAgentInstalled)
{
    $packagesDefaultSddl = 'O:BAG:SYD:PAI(A;OICI;0x1200a9;;;WD)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
    $packagesAcl = Get-Acl -Path $packagesFolderPath
    $packagesSddl = $packagesAcl | Select-Object -ExpandProperty Sddl
    $packagesAccess = $packagesAcl | Select-Object -ExpandProperty Access
    $packagessAccessString = $packagesAccess | ForEach-Object {"$($_.IdentityReference) $($_.AccessControlType) $($_.FileSystemRights)"}
    $packagesAccessString = $packagessAccessString -join '<br>'
    if ($packagesSddl -eq $packagesDefaultSddl)
    {
        $packagesHasDefaultPermissions = $true
        Out-Log $packagesHasDefaultPermissions -color Green -endLine
        $details = "$packagesFolderPath folder has default NTFS permissions" # <br>SDDL: $packagesSddl<br>$packagesAccessString"
        New-Check -name "$packagesFolderPath permissions" -result 'OK' -details $details
    }
    else
    {
        $packagesHasDefaultPermissions = $false
        Out-Log $packagesHasDefaultPermissions -color Cyan -endLine
        $details = "$packagesFolderPath does not have default NTFS permissions<br>SDDL: $packagesSddl<br>$packagesAccessString"
        New-Check -name "$packagesFolderPath permissions" -result 'Info' -details $details
        $mitigation = '<a href="https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/troubleshoot-extension-certificates-issues-windows-vm#solution-2-fix-the-access-control-list-acl-in-the-machinekeys-or-systemkeys-folders">Troubleshoot extension certificates</a>'
        New-Finding -type Information -name "Non-default $packagesFolderPath permissions" -description $details -mitigation $mitigation
    }
}
else
{
    $details = "Skipped (VM agent installed: $isVMAgentInstalled)"
    New-Check -name "$packagesFolderPath permissions" -result 'Skipped' -details $details
    Out-Log $details -endLine
}

Out-Log "System drive has sufficient disk space:" -startLine
$systemDriveLetter = "$env:SystemDrive" -split ':' | Select-Object -First 1
$systemDrive = Invoke-ExpressionWithLogging "Get-PSDrive -Name $systemDriveLetter" -verboseOnly
# "Get-PSDrive" doesn't call WMI but Free and Used properties are of type ScriptProperty,
# and make WMI calls when you view them.
$systemDriveFreeSpaceBytes = $systemDrive | Select-Object -ExpandProperty Free -ErrorAction SilentlyContinue
if ($systemDriveFreeSpaceBytes)
{
    $systemDriveFreeSpaceGB = [Math]::Round($systemDriveFreeSpaceBytes/1GB,1)
    $systemDriveFreeSpaceMB = [Math]::Round($systemDriveFreeSpaceBytes/1MB,1)

    if ($systemDriveFreeSpaceMB -lt 100)
    {
        $details = "<100MB free ($($systemDriveFreeSpaceMB)MB free) on drive $systemDriveLetter"
        Out-Log $false -color Red -endLine
        New-Check -name "Disk space check (<1GB Warn, <100MB Critical)" -result 'FAILED' -details $details
        New-Finding -type Critical -name "System drive low disk space" -description $details -mitigation ''
    }
    elseif ($systemDriveFreeSpaceGB -lt 1)
    {
        $details = "<1GB free ($($systemDriveFreeSpaceGB)GB free) on drive $systemDriveLetter"
        Out-Log $details -color Yellow -endLine
        New-Check -name "Disk space check (<1GB Warn, <100MB Critical)" -result 'Warning' -details $details
        New-Finding -type Warning -name "System drive low free space" -description $details -mitigation ''
    }
    else
    {
        $details = "$($systemDriveFreeSpaceGB)GB free on system drive $systemDriveLetter"
        Out-Log $details -color Green -endLine
        New-Check -name "Disk space check (<1GB Warn, <100MB Critical)" -result 'OK' -details $details
    }
}
else
{
    $details = "Unable to determine free space on system drive $systemDriveLetter"
    Out-Log $details -color Cyan -endLine
    New-Check -name "Disk space check (<1GB Warn, <100MB Critical)" -result 'Info' -details $details
    New-Finding -type Warning -name "System drive low free space" -description $details -mitigation ''
}

$joinInfo = Get-JoinInfo
$joinType = $joinInfo.JoinType
$productType = $joinInfo.ProductType

if ($winmgmt.Status -eq 'Running')
{
    $drivers = Get-Drivers
}

$scriptStartTimeLocalString = Get-Date -Date $scriptStartTime -Format o
$scriptStartTimeUTCString = Get-Date -Date $scriptStartTime -Format o

$scriptEndTime = Get-Date
$scriptEndTimeLocalString = Get-Date -Date $scriptEndTime -Format o
$scriptEndTimeUTCString = Get-Date -Date $scriptEndTime -Format 'yyyy-MM-ddTHH:mm:ssZ'

$scriptTimespan = New-TimeSpan -Start $scriptStartTime -End $scriptEndTime
$scriptDurationSeconds = $scriptTimespan.Seconds
$scriptDuration = '{0:hh}:{0:mm}:{0:ss}.{0:ff}' -f $scriptTimespan

# General
$vm.Add([PSCustomObject]@{Property = 'scriptDurationSeconds'; Value = $scriptDurationSeconds; Type = 'General'})
$vm.Add([PSCustomObject]@{Property = 'azEnvironment'; Value = $azEnvironment; Type = 'General'})
$vm.Add([PSCustomObject]@{Property = 'location'; Value = $location; Type = 'General'})
$vm.Add([PSCustomObject]@{Property = 'vmName'; Value = $vmName; Type = 'General'})
$vm.Add([PSCustomObject]@{Property = 'vmId'; Value = $vmId; Type = 'General'})
$vm.Add([PSCustomObject]@{Property = 'resourceId'; Value = $resourceId; Type = 'General'})
if ($virtualMachineScaleSetId -and $vmScaleSetName)
{
    $vm.Add([PSCustomObject]@{Property = 'virtualMachineScaleSetId'; Value = $virtualMachineScaleSetId; Type = 'General'})
    $vm.Add([PSCustomObject]@{Property = 'vmScaleSetName'; Value = $vmScaleSetName; Type = 'General'})
}
$vm.Add([PSCustomObject]@{Property = 'subscriptionId'; Value = $subscriptionId; Type = 'General'})
$vm.Add([PSCustomObject]@{Property = 'resourceGroupName'; Value = $resourceGroupName; Type = 'General'})
$vm.Add([PSCustomObject]@{Property = 'vmSize'; Value = $vmSize; Type = 'General'})
$vm.Add([PSCustomObject]@{Property = 'vmAgentVersion'; Value = $guestKeyGuestAgentVersion; Type = 'General'})
$vm.Add([PSCustomObject]@{Property = 'imageReference'; Value = $imageReference; Type = 'General'})
$vm.Add([PSCustomObject]@{Property = 'planPublisher'; Value = $planPublisher; Type = 'General'})
$vm.Add([PSCustomObject]@{Property = 'planProduct'; Value = $planProduct; Type = 'General'})
$vm.Add([PSCustomObject]@{Property = 'planName'; Value = $planName; Type = 'General'})
$vm.Add([PSCustomObject]@{Property = 'zone'; Value = $zone; Type = 'General'})
$vm.Add([PSCustomObject]@{Property = 'priority'; Value = $priority; Type = 'General'})
$vm.Add([PSCustomObject]@{Property = 'platformFaultDomain'; Value = $platformFaultDomain; Type = 'General'})
$vm.Add([PSCustomObject]@{Property = 'platformSubFaultDomain'; Value = $platformSubFaultDomain; Type = 'General'})
$vm.Add([PSCustomObject]@{Property = 'platformUpdateDomain'; Value = $platformUpdateDomain; Type = 'General'})
$vm.Add([PSCustomObject]@{Property = 'placementGroupId'; Value = $placementGroupId; Type = 'General'})
$vm.Add([PSCustomObject]@{Property = 'extendedLocationName'; Value = $extendedLocationName; Type = 'General'})
$vm.Add([PSCustomObject]@{Property = 'extendedLocationType'; Value = $extendedLocationType; Type = 'General'})
$vm.Add([PSCustomObject]@{Property = 'evictionPolicy'; Value = $evictionPolicy; Type = 'General'})
$vm.Add([PSCustomObject]@{Property = 'hostId'; Value = $hostId; Type = 'General'})
$vm.Add([PSCustomObject]@{Property = 'hostGroupId'; Value = $hostGroupId; Type = 'General'})
$vm.Add([PSCustomObject]@{Property = 'isHostCompatibilityLayerVm'; Value = $isHostCompatibilityLayerVm; Type = 'General'})
$vm.Add([PSCustomObject]@{Property = 'hibernationEnabled'; Value = $hibernationEnabled; Type = 'General'})

# OS
$vm.Add([PSCustomObject]@{Property = 'osVersion'; Value = $osVersion; Type = 'OS'})
$vm.Add([PSCustomObject]@{Property = 'ubr'; Value = $ubr; Type = 'OS'})
$vm.Add([PSCustomObject]@{Property = 'osInstallDate'; Value = $installDateString; Type = 'OS'})
$vm.Add([PSCustomObject]@{Property = 'computerName'; Value = $computerName; Type = 'OS'})
$vm.Add([PSCustomObject]@{Property = 'licenseType'; Value = $licenseType; Type = 'OS'})
$vm.Add([PSCustomObject]@{Property = 'joinType'; Value = $joinType; Type = 'OS'})
$vm.Add([PSCustomObject]@{Property = 'productType'; Value = $productType; Type = 'OS'})
$vm.Add([PSCustomObject]@{Property = 'timeZone'; Value = $timeZone; Type = 'OS'})

Out-Log "DHCP-assigned IP addresses:" -startLine

$nics = New-Object System.Collections.Generic.List[Object]

if ($useDotnetForNicDetails)
{
    # [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpConnections()
    # get-winevent -ProviderName Microsoft-Windows-NCSI
    # reg query 'HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet'
    $networkListManager = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]"{DCB00C01-570F-4A9B-8D69-199FDBA5723B}"))
    $connections = $networkListManager.GetNetworkConnections()

    $isConnected = $networkListManager.IsConnectedToInternet
    $isConnectedToInternet = $networkListManager.IsConnectedToInternet

    foreach ($connection in $connections)
    {
        $category = $connection.GetNetwork().GetCategory()
        switch ($category) {
            0 {$networkProfile = 'Public'}
            1 {$networkProfile = 'Private'}
            2 {$networkProfile = 'DomainAuthenticated'}
        }
    }

    $isNetworkAvailable = [Net.NetworkInformation.NetworkInterface]::GetIsNetworkAvailable()
    $networkInterfaces = [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()
    $networkInterfaces = $networkInterfaces | Where-Object {$_.NetworkInterfaceType -ne 'Loopback'}
    foreach ($networkInterface in $networkInterfaces)
    {
        $ipProperties = $networkInterface.GetIPProperties()
        $ipV4Properties = $ipProperties.GetIPv4Properties()
        $ipV6Properties = $ipProperties.GetIPv6Properties()

        $nic = [PSCustomObject]@{
            Description = $networkInterface.Description
            Alias = $networkInterface.Name
            Status = $networkInterface.OperationalStatus
            MACAddress = $networkInterface.GetPhysicalAddress()
            DHCPServerAddresses = $dhcpServerAddresses
            DNSAddresses = $ipProperties.DnsAddresses.IPAddressToString
            GatewayAddresses = $ipProperties.GatewayAddresses.Address.IPAddressToString
            IPV4Addresses = $ipV4Addresses
            IsDhcpEnabled = $ipV4Properties.IsDhcpEnabled
            Index = $ipV4Properties.Index
            IsAutomaticPrivateAddressingActive = $ipV4Properties.IsAutomaticPrivateAddressingActive
            $mtu = $ipV4Properties.Mtu
            $ipV4Addresses = $ipProperties | Select-Object -ExpandProperty UnicastAddresses | Select-Object -ExpandProperty Address | Where-Object {$_.AddressFamily -eq 'InterNetwork'}
            $ipV6Addresses = $ipProperties | Select-Object -ExpandProperty UnicastAddresses | Select-Object -ExpandProperty Address | Where-Object {$_.AddressFamily -eq 'InterNetworkV6'}
        }
        $nics.Add($nic)
    }
}
elseif ($winmgmt.Status -eq 'Running')
{
    # Get-NetIPConfiguration depends on WMI
    $ipconfigs = Invoke-ExpressionWithLogging "Get-NetIPConfiguration -Detailed" -verboseOnly
    foreach ($ipconfig in $ipconfigs)
    {
        $interfaceAlias = $ipconfig | Select-Object -ExpandProperty InterfaceAlias
        $interfaceIndex = $ipconfig | Select-Object -ExpandProperty InterfaceIndex
        $interfaceDescription = $ipconfig | Select-Object -ExpandProperty InterfaceDescription

        $netAdapter = $ipconfig | Select-Object -ExpandProperty NetAdapter
        $macAddress = $netAdapter | Select-Object -ExpandProperty MacAddress
        $macAddress = $macAddress -replace '-', ''
        $status = $netAdapter | Select-Object -ExpandProperty Status

        $netProfile = $ipconfig | Select-Object -ExpandProperty NetProfile
        $networkCategory = $netProfile | Select-Object -ExpandProperty NetworkCategory
        $ipV4Connectivity = $netProfile | Select-Object -ExpandProperty IPv4Connectivity
        $ipV6Connectivity = $netProfile | Select-Object -ExpandProperty IPv6Connectivity

        $ipV6LinkLocalAddress = $ipconfig | Select-Object -ExpandProperty IPv6LinkLocalAddress
        $ipV6Address = $ipV6LinkLocalAddress | Select-Object -ExpandProperty IPAddress

        $ipV4Address = $ipconfig | Select-Object -ExpandProperty IPv4Address
        $ipV4IpAddress = $ipV4Address | Select-Object -ExpandProperty IPAddress

        $ipV6DefaultGateway = $ipconfig | Select-Object -ExpandProperty IPv6DefaultGateway
        $ipV6DefaultGateway = $ipV6DefaultGateway | Select-Object -ExpandProperty NextHop

        $ipV4DefaultGateway = $ipconfig | Select-Object -ExpandProperty IPv4DefaultGateway
        $ipV4DefaultGateway = $ipV4DefaultGateway | Select-Object -ExpandProperty NextHop

        $netIPv6Interface = $ipconfig | Select-Object -ExpandProperty NetIPv6Interface
        $ipV6Dhcp = $netIPv6Interface | Select-Object -ExpandProperty DHCP

        $netIPv4Interface = $ipconfig | Select-Object -ExpandProperty NetIPv4Interface
        $ipV4Dhcp = $netIPv4Interface | Select-Object -ExpandProperty DHCP

        $dnsServer = $ipconfig | Select-Object -ExpandProperty DNSServer
        $ipV4DnsServers = $dnsServer | Where-Object {$_.AddressFamily -eq 2} | Select-Object -Expand ServerAddresses
        $ipV4DnsServers = $ipV4DnsServers -join ','
        $ipV6DnsServers = $dnsServer | Where-Object {$_.AddressFamily -eq 23} | Select-Object -Expand ServerAddresses
        $ipV6DnsServers = $ipV6DnsServers -join ','

        $nic = [PSCustomObject]@{
            Description        = $interfaceDescription
            Alias              = $interfaceAlias
            Index              = $interfaceIndex
            MacAddress         = $macAddress
            Status             = $status
            DHCP               = $ipV4Dhcp
            IpAddress          = $ipV4IpAddress
            DnsServers         = $ipV4DnsServers
            DefaultGateway     = $ipV4DefaultGateway
            Connectivity       = $ipV4Connectivity
            Category           = $networkCategory
            IPv6DHCP           = $ipV6Dhcp
            IPv6IpAddress      = $ipV6LinkLocalAddress
            IPv6DnsServers     = $ipV6DnsServers
            IPv6DefaultGateway = $ipV6DefaultGateway
            IPv6Connectivity   = $ipV6Connectivity
        }
        $nics.Add($nic)
    }

    $dhcpDisabledNics = $nics | Where-Object DHCP -eq 'Disabled'
    if ($dhcpDisabledNics)
    {
        $dhcpAssignedIpAddresses = $false
        Out-Log $dhcpAssignedIpAddresses -endLine -color Yellow
        $dhcpDisabledNicsString = "DHCP-disabled NICs: "
        foreach ($dhcpDisabledNic in $dhcpDisabledNics)
        {
            $dhcpDisabledNicsString += "Description: $($dhcpDisabledNic.Description) Alias: $($dhcpDisabledNic.Alias) Index: $($dhcpDisabledNic.Index) IpAddress: $($dhcpDisabledNic.IpAddress)"
        }
        New-Check -name "DHCP-assigned IP addresses" -result 'Info' -details $dhcpDisabledNicsString
        New-Finding -type Information -name "DHCP-disabled NICs" -description $dhcpDisabledNicsString -mitigation ''
    }
    else
    {
        $dhcpAssignedIpAddresses = $true
        Out-Log $dhcpAssignedIpAddresses -endLine -color Green
        $details = "All NICs have DHCP-assigned IP addresses"
        New-Check -name "DHCP-assigned IP addresses" -result 'OK' -details $details
    }

    $nicsImds = New-Object System.Collections.Generic.List[Object]
    foreach ($interface in $interfaces)
    {
        $ipV4privateIpAddresses = $interface.ipV4.ipAddress.privateIpAddress -join ','
        $ipV4publicIpAddresses = $interface.ipV4.ipAddress.publicIpAddress -join ','
        $ipV6privateIpAddresses = $interface.ipV6.ipAddress.privateIpAddress -join ','
        $ipV6publicIpAddresses = $interface.ipV6.ipAddress.publicIpAddress -join ','

        if ($ipV4privateIpAddresses) {$ipV4privateIpAddresses = $ipV4privateIpAddresses.TrimEnd(',')}
        if ($ipV4publicIpAddresses) {$ipV4publicIpAddresses = $ipV4publicIpAddresses.TrimEnd(',')}
        if ($ipV6privateIpAddresses) {$ipV6privateIpAddresses = $ipV6privateIpAddresses.TrimEnd(',')}
        if ($ipV6publicIpAddresses) {$ipV6publicIpAddresses = $ipV6publicIpAddresses.TrimEnd(',')}

        $nicImds = [PSCustomObject]@{
            'MAC Address'      = $interface.macAddress
            'IPv4 Private IPs' = $ipV4privateIpAddresses
            'IPv4 Public IPs'  = $ipV4publicIpAddresses
            'IPv6 Private IPs' = $ipV6privateIpAddresses
            'IPv6 Public IPs'  = $ipV6publicIpAddresses
        }
        $nicsImds.Add($nicImds)
    }

    $routes = Get-NetRoute | Select-Object AddressFamily,State,ifIndex,InterfaceAlias,InstanceID,TypeOfRoute,RouteMetric,InterfaceMetric,DestinationPrefix,NextHop | Sort-Object InterfaceAlias
}
else
{
    Out-Log "Unable to query network adapter details because winmgmt service is not running"
}

# Security
if ($imdsReachable.Succeeded -eq $false)
{
    $ErrorActionPreference = 'SilentlyContinue'
    if (Confirm-SecureBootUEFI)
    {
        $secureBootEnabled = $true
    }
    else
    {
        $secureBootEnabled = $false
    }
    $ErrorActionPreference = 'Continue'
}
$vm.Add([PSCustomObject]@{Property = 'encryptionAtHost'; Value = $encryptionAtHost; Type = 'Security'})
$vm.Add([PSCustomObject]@{Property = 'secureBootEnabled'; Value = $secureBootEnabled; Type = 'Security'})
$vm.Add([PSCustomObject]@{Property = 'securityType'; Value = $securityType; Type = 'Security'})
$vm.Add([PSCustomObject]@{Property = 'virtualTpmEnabled'; Value = $virtualTpmEnabled; Type = 'Security'})

# Storage
$vm.Add([PSCustomObject]@{Property = 'osDiskDiskSizeGB'; Value = $osDiskDiskSizeGB; Type = 'Storage'})
$vm.Add([PSCustomObject]@{Property = 'osDiskManagedDiskId'; Value = $osDiskManagedDiskId; Type = 'Storage'})
$vm.Add([PSCustomObject]@{Property = 'osDiskManagedDiskStorageAccountType'; Value = $osDiskManagedDiskStorageAccountType; Type = 'Storage'})
$vm.Add([PSCustomObject]@{Property = 'osDiskCreateOption'; Value = $osDiskCreateOption; Type = 'Storage'})
$vm.Add([PSCustomObject]@{Property = 'osDiskCaching'; Value = $osDiskCaching; Type = 'Storage'})
$vm.Add([PSCustomObject]@{Property = 'osDiskDiffDiskSettings'; Value = $osDiskDiffDiskSettings; Type = 'Storage'})
$vm.Add([PSCustomObject]@{Property = 'osDiskEncryptionSettingsEnabled'; Value = $osDiskEncryptionSettingsEnabled; Type = 'Storage'})
$vm.Add([PSCustomObject]@{Property = 'osDiskImageUri'; Value = $osDiskImageUri; Type = 'Storage'})
$vm.Add([PSCustomObject]@{Property = 'osDiskName'; Value = $osDiskName; Type = 'Storage'})
$vm.Add([PSCustomObject]@{Property = 'osDiskOsType'; Value = $osDiskOsType; Type = 'Storage'})
$vm.Add([PSCustomObject]@{Property = 'osDiskVhdUri'; Value = $osDiskVhdUri; Type = 'Storage'})
$vm.Add([PSCustomObject]@{Property = 'osDiskWriteAcceleratorEnabled'; Value = $osDiskWriteAcceleratorEnabled; Type = 'Storage'})

foreach ($dataDisk in $dataDisks)
{
    $bytesPerSecondThrottle = $dataDisk.bytesPerSecondThrottle
    $diskCapacityBytes = $dataDisk.diskCapacityBytes
    $diskSizeGB = $dataDisk.diskSizeGB
    $imageUri = $dataDisk.image.uri
    $isSharedDisk = $dataDisk.isSharedDisk
    $isUltraDisk = $dataDisk.isUltraDisk
    $lun = $dataDisk.lun
    $managedDiskId = $dataDisk.managedDisk.id
    $name = $dataDisk.name
    $opsPerSecondThrottle = $dataDisk.opsPerSecondThrottle
    $vhdUri = $dataDisk.vhd.uri
    $writeAcceleratorEnabled = $dataDisk.writeAcceleratorEnabled

    $vm.Add([PSCustomObject]@{Property = "Data disk LUN $lun Name"; Value = $name; Type = 'Storage'})
    $vm.Add([PSCustomObject]@{Property = "Data disk LUN $lun BytesPerSecondThrottle"; Value = $bytesPerSecondThrottle; Type = 'Storage'})
    $vm.Add([PSCustomObject]@{Property = "Data disk LUN $lun diskCapacityBytes"; Value = $diskCapacityBytes; Type = 'Storage'})
    $vm.Add([PSCustomObject]@{Property = "Data disk LUN $lun diskSizeGB"; Value = $diskSizeGB; Type = 'Storage'})
    $vm.Add([PSCustomObject]@{Property = "Data disk LUN $lun imageUri"; Value = $imageUri; Type = 'Storage'})
    $vm.Add([PSCustomObject]@{Property = "Data disk LUN $lun isSharedDisk"; Value = $isSharedDisk; Type = 'Storage'})
    $vm.Add([PSCustomObject]@{Property = "Data disk LUN $lun isUltraDisk"; Value = $isUltraDisk; Type = 'Storage'})
    $vm.Add([PSCustomObject]@{Property = "Data disk LUN $lun managedDiskId"; Value = $managedDiskId; Type = 'Storage'})
    $vm.Add([PSCustomObject]@{Property = "Data disk LUN $lun opsPerSecondThrottle"; Value = $opsPerSecondThrottle; Type = 'Storage'})
    $vm.Add([PSCustomObject]@{Property = "Data disk LUN $lun vhd"; Value = $vhd; Type = 'Storage'})
    $vm.Add([PSCustomObject]@{Property = "Data disk LUN $lun writeAcceleratorEnabled"; Value = $writeAcceleratorEnabled; Type = 'Storage'})
}

$uninstallPaths = ('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                   'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
                   'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                   'HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
$software = Get-ItemProperty -Path $uninstallPaths -ErrorAction SilentlyContinue
$software = $software | Where-Object {$_.DisplayName} | Select-Object DisplayName,DisplayVersion,Publisher | Sort-Object -Property DisplayName

if ($winmgmt.Status -eq 'Running')
{
    $updates = Get-HotFix | Select-Object -Property HotFixID,Description,InstalledOn | Sort-Object -Property InstalledOn -Descending
}
else
{
    Out-Log "Unable to query Windows update details because the winmgmt service is not running"
}

$output = [PSCustomObject]@{

    wireserverPort80Reachable                             = $wireserverPort80Reachable
    wireserverPort32526Reachable                          = $wireserverPort32526Reachable
    windowsAzureFolderExists                              = $windowsAzureFolderExists
    windowsAzureGuestAgentExeFileVersion                  = $windowsAzureGuestAgentExeFileVersion
    waAppAgentExeFileVersion                              = $waAppAgentExeFileVersion

    computerName                                          = $computerName
    vmId                                                  = $vmId
    installDate                                           = $installDateString
    osVersion                                             = $osVersion
    ubr                                                   = $ubr

    subscriptionId                                        = $subscriptionId
    resourceGroupName                                     = $resourceGroupName
    location                                              = $location
    vmSize                                                = $vmSize
    vmIdFromImds                                          = $vmIdFromImds
    publisher                                             = $publisher
    offer                                                 = $offer
    sku                                                   = $sku
    version                                               = $version
    imageReference                                        = $imageReference
    privateIpAddress                                      = $privateIpAddress
    publicIpAddress                                       = $publicIpAddress
    publicIpAddressReportedFromAwsCheckIpService          = $publicIpAddressReportedFromAwsCheckIpService

    aggregateStatusGuestAgentStatusVersion                = $aggregateStatusGuestAgentStatusVersion
    aggregateStatusGuestAgentStatusStatus                 = $aggregateStatusGuestAgentStatusStatus
    aggregateStatusGuestAgentStatusFormattedMessage       = $aggregateStatusGuestAgentStatusMessage
    aggregateStatusGuestAgentStatusLastStatusUploadMethod = $aggregateStatusGuestAgentStatusLastStatusUploadMethod
    aggregateStatusGuestAgentStatusLastStatusUploadTime   = $aggregateStatusGuestAgentStatusLastStatusUploadTime

    guestKey                                              = $guestKey
    guestKeyPath                                          = $guestKeyPath
    guestKeyDHCPStatus                                    = $guestKeyDHCPStatus
    guestKeyDhcpWithFabricAddressTime                     = $guestKeyDhcpWithFabricAddressTime
    guestKeyGuestAgentStartTime                           = $guestKeyGuestAgentStartTime
    guestKeyGuestAgentStatus                              = $guestKeyGuestAgentStatus
    guestKeyGuestAgentVersion                             = $guestKeyGuestAgentVersion
    minSupportedGuestAgentVersion                         = $minSupportedGuestAgentVersion
    isAtLeastMinSupportedVersion                          = $isAtLeastMinSupportedVersion
    guestKeyOsVersion                                     = $guestKeyOsVersion
    guestKeyRequiredDotNetVersionPresent                  = $guestKeyRequiredDotNetVersionPresent
    guestKeyTransparentInstallerStartTime                 = $guestKeyTransparentInstallerStartTime
    guestKeyTransparentInstallerStatus                    = $guestKeyTransparentInstallerStatus
    guestKeyWireServerStatus                              = $guestKeyWireServerStatus

    windowsAzureKeyPath                                   = $windowsAzureKeyPath
    windowsAzureKey                                       = $windowsAzureKey

    guestAgentKey                                         = $guestAgentKey
    guestAgentKeyPath                                     = $guestAgentKeyPath
    guestAgentKeyContainerId                              = $guestAgentKeyContainerId
    guestAgentKeyDirectoryToDelete                        = $guestAgentKeyDirectoryToDelete
    guestAgentKeyHeartbeatLastStatusUpdateTime            = $guestAgentKeyHeartbeatLastStatusUpdateTime
    guestAgentKeyIncarnation                              = $guestAgentKeyIncarnation
    guestAgentKeyInstallerRestart                         = $guestAgentKeyInstallerRestart
    guestAgentKeyManifestTimeStamp                        = $guestAgentKeyManifestTimeStamp
    guestAgentKeyMetricsSelfSelectionSelected             = $guestAgentKeyMetricsSelfSelectionSelected
    guestAgentKeyUpdateNewGAVersion                       = $guestAgentKeyUpdateNewGAVersion
    guestAgentKeyUpdatePreviousGAVersion                  = $guestAgentKeyUpdatePreviousGAVersion
    guestAgentKeyUpdateStartTime                          = $guestAgentKeyUpdateStartTime
    guestAgentKeyVmProvisionedAt                          = $guestAgentKeyVmProvisionedAt

    guestAgentUpdateStateKeyPath                          = $guestAgentUpdateStateKeyPath
    guestAgentUpdateStateCode                             = $guestAgentUpdateStateCode
    guestAgentUpdateStateMessage                          = $guestAgentUpdateStateMessage
    guestAgentUpdateStateState                            = $guestAgentUpdateStateState

    handlerStateKeyPath                                   = $handlerStateKeyPath
    handlerStates                                         = $handlerStates

    rdAgentStatus                                         = $rdAgentStatus
    rdAgentStartType                                      = $rdAgentStartType

    rdAgentKeyPath                                        = $rdAgentKeyPath
    rdAgentKeyStartValue                                  = $rdAgentKeyStartValue
    rdAgentKeyErrorControlValue                           = $rdAgentKeyErrorControlValue
    rdAgentKeyImagePathValue                              = $rdAgentKeyImagePathValue
    rdAgentKeyObjectNameValue                             = $rdAgentKeyObjectNameValue

    rdAgentExitCode                                       = $rdAgentExitCode
    rdAgentErrorControl                                   = $rdAgentErrorControl

    scQueryExRdAgentOutput                                = $scQueryExRdAgentOutput
    scQueryExRdAgentExitCode                              = $scQueryExRdAgentExitCode
    scQcRdAgentOutput                                     = $scQcRdAgentOutput
    scQcRdAgentExitCode                                   = $scQcRdAgentExitCode

    windowsAzureGuestAgentStatus                          = $windowsAzureGuestAgentStatus
    windowsAzureGuestAgentStartType                       = $windowsAzureGuestAgentStartType

    windowsAzureGuestAgentKeyPath                         = $windowsAzureGuestAgentKeyPath
    windowsAzureGuestAgentKeyStartValue                   = $windowsAzureGuestAgentKeyStartValue
    windowsAzureGuestAgentKeyErrorControlValue            = $windowsAzureGuestAgentKeyErrorControlValue
    windowsAzureGuestAgentKeyImagePathValue               = $windowsAzureGuestAgentKeyImagePathValue
    windowsAzureGuestAgentKeyObjectNameValue              = $windowsAzureGuestAgentKeyObjectNameValue

    windowsAzureGuestAgentExitCode                        = $windowsAzureGuestAgentExitCode
    windowsAzureGuestAgentErrorControl                    = $windowsAzureGuestAgentErrorControl

    scQueryExWindowsAzureGuestAgentOutput                 = $scQueryExWindowsAzureGuestAgentOutput
    scQueryExWindowsAzureGuestAgentExitCode               = $scQueryExWindowsAzureGuestAgentExitCode
    scQcWindowsAzureGuestAgentOutput                      = $scQcWindowsAzureGuestAgentOutput
    scQcWindowsAzureGuestAgentExitCode                    = $scQcWindowsAzureGuestAgentExitCode

    userProxyEnable                                       = $userProxyEnable
    userProxyServer                                       = $userProxyServer
    machineProxyEnable                                    = $machineProxyEnable
    machineProxyServer                                    = $machineProxyServer

    scriptStartTimeLocal                                  = $scriptStartTimeLocalString
    scriptStartTimeUTC                                    = $scriptStartTimeUTCString
    scriptEndTimeLocal                                    = $scriptEndTimeLocalString
    scriptEndTimeUTC                                      = $scriptEndTimeUTCString
    scriptDuration                                        = $scriptDuration
}

$css = @'
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <style>
        body {
            font-family: sans-serif;
            text-align: left
        }
        table.table2 {
            border: 0px solid;
            border-collapse: collapse;
            text-align: left
        }
        table {
            background-color: #DDEBF7;
            border: 1px solid;
            border-collapse: collapse;
            text-align: left
        }
        th {
            background: #5B9BD5;
            border: 1px solid;
            color: White;
            font-size: 100%;
            padding: 5px;
            text-align: left;
            vertical-align: middle
        }
        tr:hover {
            background-color: Cyan;
        }
        tr:nth-child(odd) {
            background-color: #BDD7EE;
        }
        td {
            border: 1px solid;
            padding: 5px;
            text-align: left;
            white-space: nowrap
        }
        td.CRITICAL {
            background: Salmon;
            color: Black;
            text-align: center
        }
        td.WARNING {
            background: Yellow;
            color: Black;
            text-align: center
        }
        td.INFO {
            background: Cyan;
            color: Black;
            text-align: center
        }
        td.OK {
            background: PaleGreen;
            color: Black;
            text-align: center
        }
        td.PASSED {
            background: PaleGreen;
            color: Black;
            text-align: center
        }
        td.FAILED {
            background: Salmon;
            color: Black;
            text-align: center
        }
        td.SKIPPED {
            background: LightGrey;
            color: Black;
            text-align: center
        }
        /* Style the tab */
        .gray {
            color: dimgray;
            font-weight: bold;
        }
        .tab {
          overflow: hidden;
          border: 1px solid #ccc;
          background-color: #f1f1f1;
        }

        /* Style the buttons inside the tab */
        .tab button {
          background-color: inherit;
          float: left;
          border: none;
          outline: none;
          cursor: pointer;
          padding: 14px 16px;
          transition: 0.3s;
          font-size: 17px;
        }

        /* Change background color of buttons on hover */
        .tab button:hover {
          background-color: #ddd;
        }

        /* Create an active/current tablink class */
        .tab button.active {
          background-color: #ccc;
        }

        /* Style the tab content */
        .tabcontent {
          display: none;
          padding: 6px 12px;
          border: 1px solid #ccc;
          border-top: none;
        }

        /* Style the button that is used to open and close the collapsible content */
        .collapsible {
          background-color: #eee;
          color: #444;
          cursor: pointer;
          padding: 18px;
          width: 100%;
          border: none;
          text-align: left;
          outline: none;
          font-size: 15px;
        }

        /* Add a background color to the button if it is clicked on (add the .active class with JS), and when you move the mouse over it (hover) */
        .active, .collapsible:hover {
          background-color: #ccc;
        }

        /* Style the collapsible content. Note: hidden by default */
        .content {
          padding: 0 18px;
          display: none;
          overflow: hidden;
          background-color: #f1f1f1;
        }

        /* Style the buttons that are used to open and close the accordion panel */
        .accordion {
          background-color: #eee;
          color: #444;
          cursor: pointer;
          padding: 10px;
          width: 100%;
          text-align: left;
          border: none;
          outline: none;
          transition: 0.4s;
          font-family: sans-serif;
          font-size: 17px;
          font-weight: bold;
        }

        /* Add a background color to the button if it is clicked on (add the .active class with JS), and when you move the mouse over it (hover) */
        .active2, .accordion:hover {
          background-color: #ccc;
        }

        .accordion:after {
            content: '\02795'; /* Unicode character for "plus" sign (+) */
            color: #777;
            float: right;
            margin-left: 5px;
        }

          .active2:after {
            content: "\2796"; /* Unicode character for "minus" sign (-) */
        }

        /* Style the accordion panel. Note: hidden by default */
        .panel {
          padding: 0 18px;
          font-family: sans-serif;
          font-size: 17px;
          background-color: white;
          display: none;
          overflow: hidden;
        }
    </style>
</head>
<body>
'@

$tabs = @'
<div class="tab">
  <button class="tablinks active" onclick="openTab(event, 'Findings')">Findings</button>
  <button class="tablinks" onclick="openTab(event, 'OS')">OS</button>
  <button class="tablinks" onclick="openTab(event, 'Agent')">Agent</button>
  <button class="tablinks" onclick="openTab(event, 'Extensions')">Extensions</button>
  <button class="tablinks" onclick="openTab(event, 'Network')">Network</button>
  <button class="tablinks" onclick="openTab(event, 'Firewall')">Firewall</button>
  <button class="tablinks" onclick="openTab(event, 'Services')">Services</button>
  <button class="tablinks" onclick="openTab(event, 'Drivers')">Drivers</button>
  <button class="tablinks" onclick="openTab(event, 'Software')">Software</button>
  <button class="tablinks" onclick="openTab(event, 'Updates')">Updates</button>
</div>
'@

$script = @'
<script>
function openTab(evt, cityName) {
  var i, tabcontent, tablinks;
  tabcontent = document.getElementsByClassName("tabcontent");
  for (i = 0; i < tabcontent.length; i++) {
    tabcontent[i].style.display = "none";
  }
  tablinks = document.getElementsByClassName("tablinks");
  for (i = 0; i < tablinks.length; i++) {
    tablinks[i].className = tablinks[i].className.replace(" active", "");
  }
  document.getElementById(cityName).style.display = "block";
  evt.currentTarget.className += " active";
}

var coll = document.getElementsByClassName("collapsible");
var i;

for (i = 0; i < coll.length; i++) {
  coll[i].addEventListener("click", function() {
    this.classList.toggle("active");
    var content = this.nextElementSibling;
    if (content.style.display === "block") {
      content.style.display = "none";
    } else {
      content.style.display = "block";
    }
  });
}

var acc = document.getElementsByClassName("accordion");
var i;

for (i = 0; i < acc.length; i++) {
  acc[i].addEventListener("click", function() {
    /* Toggle between adding and removing the "active" class,
    to highlight the button that controls the panel */
    this.classList.toggle("active");

    /* Toggle between hiding and showing the active panel */
    var panel = this.nextElementSibling;
    if (panel.style.display === "block") {
      panel.style.display = "none";
    } else {
      panel.style.display = "block";
    }
  });
}
</script>
'@

$stringBuilder = New-Object Text.StringBuilder

<# https://www.w3schools.com/howto/tryit.asp?filename=tryhow_js_collapsible
https://www.w3schools.com/howto/howto_js_accordion.asp
<button type="button" class="collapsible">Open Collapsible</button>
<div class="content">
  <p>Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.</p>
</div>
#>
$css | ForEach-Object {[void]$stringBuilder.Append("$_`r`n")}

[void]$stringBuilder.Append("VM Name: <span style='font-weight:bold'>$vmName</span> VMID: <span style='font-weight:bold'>$vmId</span>")
if ($guestAgentKeyContainerId)
{
    [void]$stringBuilder.Append(" ContainerId: <span style='font-weight:bold'>$guestAgentKeyContainerId</span>")
}
if ($resourceId)
{
    [void]$stringBuilder.Append("<br>ResourceId: <span style='font-weight:bold'>$resourceId</span>")
}
[void]$stringBuilder.Append("<br>Report Created: <span style='font-weight:bold'>$scriptEndTimeUTCString</span> Duration: <span style='font-weight:bold'>$scriptDuration</span><p>")

$tabs | ForEach-Object {[void]$stringBuilder.Append("$_`r`n")}
[void]$stringBuilder.Append('<div id="Findings" class="tabcontent" style="display:block;">')
[void]$stringBuilder.Append("<h2 id=`"findings`">Findings</h2>`r`n")
$findingsCount = $findings | Measure-Object | Select-Object -ExpandProperty Count
if ($findingsCount -ge 1)
{
    #<#
    foreach($finding in $findings)
    {
        [void]$stringBuilder.Append("<button class='accordion'>$($finding.Name)</button>")
        [void]$stringBuilder.Append('<div class="panel" style="display:none;">')
        [void]$stringBuilder.Append('<p>')
        [void]$stringBuilder.Append("<br>TimeCreated: <span style='font-weight:bold'>$($finding.TimeCreated)</span>")
        [void]$stringBuilder.Append("<br>Type: <span style='font-weight:bold'>$($finding.Type)</span>")
        #[void]$stringBuilder.Append("<br>Name: <span style='font-weight:bold'>$($finding.Name)</span>")
        [void]$stringBuilder.Append("<br>Description: <span style='font-weight:bold'>$($finding.Description)</span>")
        [void]$stringBuilder.Append("<br>Mitigation: <span style='font-weight:bold'>$($finding.Mitigation)</span>")
        [void]$stringBuilder.Append('</p>')
        [void]$stringBuilder.Append('</div>')
    }
    #>
    <#
    $findingsTable = $findings | Select-Object Type, Name, Description, Mitigation | ConvertTo-Html -Fragment -As Table
    $findingsTable = $findingsTable -replace '<td>Critical</td>', '<td class="CRITICAL">Critical</td>'
    $findingsTable = $findingsTable -replace '<td>Warning</td>', '<td class="WARNING">Warning</td>'
    $findingsTable = $findingsTable -replace '<td>Information</td>', '<td class="INFORMATION">Information</td>'
    $findingsTable = $findingsTable -replace '<td>Info</td>', '<td class="INFO">Info</td>'
    $global:dbgFindingsTable = $findingsTable
    $findingsTable | ForEach-Object {[void]$stringBuilder.Append("$_`r`n")}
    #>
}
else
{
    [void]$stringBuilder.Append("<h3>No issues found. VM agent is healthy.</h3>`r`n")
}

$checksTable = $checks | Select-Object Name, Result, Details | ConvertTo-Html -Fragment -As Table
$checksTable = $checksTable -replace '<td>Info</td>', '<td class="INFO">Info</td>'
$checksTable = $checksTable -replace '<td>Passed</td>', '<td class="PASSED">Passed</td>'
$checksTable = $checksTable -replace '<td>OK</td>', '<td class="OK">OK</td>'
$checksTable = $checksTable -replace '<td>Failed</td>', '<td class="FAILED">Failed</td>'
$checksTable = $checksTable -replace '<td>Skipped</td>', '<td class="SKIPPED">Skipped</td>'
$global:dbgChecksTable = $checksTable
[void]$stringBuilder.Append("<h2 id=`"checks`">Checks</h2>`r`n")
$checksTable | ForEach-Object {[void]$stringBuilder.Append("$_`r`n")}
[void]$stringBuilder.Append('</div>')

[void]$stringBuilder.Append('<div id="OS" class="tabcontent">')
[void]$stringBuilder.Append("<h2 id=`"vm`">VM Details</h2>`r`n")

[void]$stringBuilder.Append("<h3 id=`"vmGeneral`">General</h3>`r`n")
$vmGeneralTable = $vm | Where-Object {$_.Type -eq 'General'} | Select-Object Property, Value | ConvertTo-Html -Fragment -As Table
$vmGeneralTable | ForEach-Object {[void]$stringBuilder.Append("$_`r`n")}

[void]$stringBuilder.Append("<h3 id=`"vmOS`">OS</h3>`r`n")
$vmOsTable = $vm | Where-Object {$_.Type -eq 'OS'} | Select-Object Property, Value | ConvertTo-Html -Fragment -As Table
$vmOsTable | ForEach-Object {[void]$stringBuilder.Append("$_`r`n")}

[void]$stringBuilder.Append("<h3 id=`"vmSecurity`">Security</h3>`r`n")
$vmSecurityTable = $vm | Where-Object {$_.Type -eq 'Security'} | Select-Object Property, Value | ConvertTo-Html -Fragment -As Table
$vmSecurityTable | ForEach-Object {[void]$stringBuilder.Append("$_`r`n")}
[void]$stringBuilder.Append('</div>')

[void]$stringBuilder.Append('<div id="Agent" class="tabcontent">')
[void]$stringBuilder.Append("<h3 id=`"vmAgent`">Agent</h3>`r`n")
$vmAgentTable = $vm | Where-Object {$_.Type -eq 'Agent'} | Select-Object Property, Value | ConvertTo-Html -Fragment -As Table
$vmAgentTable | ForEach-Object {[void]$stringBuilder.Append("$_`r`n")}
[void]$stringBuilder.Append('</div>')

[void]$stringBuilder.Append('<div id="Extensions" class="tabcontent">')
foreach ($handlerKeyName in $handlerKeyNames)
{
    $handlerName = Split-Path -Path $handlerKeyName -Leaf
    [void]$stringBuilder.Append("<h3>$handlerName</h3>`r`n")
    $handlerValues = $handlerStateKey | Where-Object {$_.SubkeyName -eq $handlerKeyName} | Select-Object ValueName,ValueData | Sort-Object ValueName
    $vmHandlerValuesTable = $handlerValues | ConvertTo-Html -Fragment -As Table
    $vmHandlerValuesTable | ForEach-Object {[void]$stringBuilder.Append("$_`r`n")}
}
[void]$stringBuilder.Append('</div>')

[void]$stringBuilder.Append('<div id="Network" class="tabcontent">')
[void]$stringBuilder.Append("<h4>NIC Details</h4>`r`n")
$vmNetworkTable = $nics | ConvertTo-Html -Fragment -As Table
$vmNetworkTable = $vmNetworkTable -replace '<td>Up</td>', '<td class="PASSED">Up</td>'
$vmNetworkTable = $vmNetworkTable -replace '<td>Down</td>', '<td class="FAILED">Down</td>'
$vmNetworkTable | ForEach-Object {[void]$stringBuilder.Append("$_`r`n")}

[void]$stringBuilder.Append("<h4>NIC Details from IMDS</h4>`r`n")
$vmNetworkImdsTable = $nicsImds | ConvertTo-Html -Fragment -As Table
$vmNetworkImdsTable | ForEach-Object {[void]$stringBuilder.Append("$_`r`n")}

[void]$stringBuilder.Append("<h4>Route Table</h4>`r`n")
$vmNetworkRoutesTable = $routes | ConvertTo-Html -Fragment -As Table
$vmNetworkRoutesTable | ForEach-Object {[void]$stringBuilder.Append("$_`r`n")}
[void]$stringBuilder.Append('</div>')

[void]$stringBuilder.Append('<div id="Firewall" class="tabcontent">')
[void]$stringBuilder.Append("<h3>Enabled Inbound Windows Firewall Rules</h3>`r`n")
if ($enabledFirewallRules.Inbound)
{
    $vmEnabledInboundFirewallRulesTable = $enabledFirewallRules.Inbound | ConvertTo-Html -Fragment -As Table
    $vmEnabledInboundFirewallRulesTable | ForEach-Object {[void]$stringBuilder.Append("$_`r`n")}
}
else
{
    [void]$stringBuilder.Append("<h5>There are no enabled inbound Windows Firewall rules</h5>`r`n")
}

[void]$stringBuilder.Append("<h3>Enabled Outbound Windows Firewall Rules</h3>`r`n")
if ($enabledFirewallRules.Outbound)
{
    $vmEnabledOutboundFirewallRulesTable = $enabledFirewallRules.Outbound | ConvertTo-Html -Fragment -As Table
    $vmEnabledOutboundFirewallRulesTable | ForEach-Object {[void]$stringBuilder.Append("$_`r`n")}
}
else
{
    [void]$stringBuilder.Append("<h4>There are no enabled outbound Windows Firewall rules</h4>`r`n")
}

[void]$stringBuilder.Append("<h3>Windows Filtering Platform Filters - Wireserver</h3>`r`n")
$wireserverWfpFiltersTable = $wfpFilters.wireserverFilters | ConvertTo-Html -Fragment -As Table
$wireserverWfpFiltersTable | ForEach-Object {[void]$stringBuilder.Append("$_`r`n")}
[void]$stringBuilder.Append("<h3>Windows Filtering Platform Filters</h3>`r`n")
$wfpFiltersTable = $wfpFilters.Filters | ConvertTo-Html -Fragment -As Table
$wfpFiltersTable | ForEach-Object {[void]$stringBuilder.Append("$_`r`n")}
[void]$stringBuilder.Append("<h3>Windows Filtering Platform Providers</h3>`r`n")
$wfpProvidersTable = $wfpFilters.Providers | ConvertTo-Html -Fragment -As Table
$wfpProvidersTable | ForEach-Object {[void]$stringBuilder.Append("$_`r`n")}
[void]$stringBuilder.Append('</div>')

[void]$stringBuilder.Append('<div id="Services" class="tabcontent">')
$services = Get-Services
$vmServicesTable = $services | ConvertTo-Html -Fragment -As Table
$vmServicesTable | ForEach-Object {[void]$stringBuilder.Append("$_`r`n")}
[void]$stringBuilder.Append('</div>')

[void]$stringBuilder.Append('<div id="Drivers" class="tabcontent">')
[void]$stringBuilder.Append("<h3 id=`"vmThirdpartyRunningDrivers`">Third-party Running Drivers</h3>`r`n")
$vmthirdPartyRunningDriversTable = $drivers.thirdPartyRunningDrivers | ConvertTo-Html -Fragment -As Table
$vmthirdPartyRunningDriversTable | ForEach-Object {[void]$stringBuilder.Append("$_`r`n")}
[void]$stringBuilder.Append("<h3 id=`"vmMicrosoftRunningDrivers`">Microsoft Running Drivers</h3>`r`n")
$vmMicrosoftRunningDriversTable = $drivers.microsoftRunningDrivers | ConvertTo-Html -Fragment -As Table
$vmMicrosoftRunningDriversTable | ForEach-Object {[void]$stringBuilder.Append("$_`r`n")}
[void]$stringBuilder.Append('</div>')

[void]$stringBuilder.Append('<div id="Disk" class="tabcontent">')
[void]$stringBuilder.Append("<h3 id=`"vmStorage`">Storage</h3>`r`n")
$vmStorageTable = $vm | Where-Object {$_.Type -eq 'Storage'} | Select-Object Property, Value | ConvertTo-Html -Fragment -As Table
$vmStorageTable | ForEach-Object {[void]$stringBuilder.Append("$_`r`n")}
[void]$stringBuilder.Append('</div>')

[void]$stringBuilder.Append('<div id="Software" class="tabcontent">')
$vmSoftwareTable = $software | ConvertTo-Html -Fragment -As Table
$vmSoftwareTable | ForEach-Object {[void]$stringBuilder.Append("$_`r`n")}
[void]$stringBuilder.Append('</div>')

[void]$stringBuilder.Append('<div id="Updates" class="tabcontent">')
$vmUpdatesTable = $updates | ConvertTo-Html -Fragment -As Table
$vmUpdatesTable | ForEach-Object {[void]$stringBuilder.Append("$_`r`n")}
[void]$stringBuilder.Append('</div>')

$script | ForEach-Object {[void]$stringBuilder.Append("$_`r`n")}

[void]$stringBuilder.Append("</body>`r`n")
[void]$stringBuilder.Append("</html>`r`n")

$htm = $stringBuilder.ToString()

$checksJson = $checks | ConvertTo-Json -Depth 10

$properties = [PSCustomObject]@{}
$properties | Add-Member -MemberType NoteProperty -Name findingsCount -Value $findingsCount
$vm | Sort-Object Property | ForEach-Object {$properties | Add-Member -MemberType NoteProperty -Name $_.Property -Value $_.Value}
$properties | Add-Member -MemberType NoteProperty -Name checks -Value $checksJson
if ($findingsCount -ge 1)
{
    $findingsJson = $findings | ConvertTo-Json -Depth 10
    $properties | Add-Member -MemberType NoteProperty -Name findings -Value $findingsJson
}
else
{
    $properties | Add-Member -MemberType NoteProperty -Name findings -Value 'No issues found'
}
Send-Telemetry -properties $properties

$global:dbgProperties = $properties
$global:dbgvm = $vm
$global:dbgchecks = $checks
$global:dbgchecksJson = $checksJson
$global:dbgfindings = $findings
$global:dbgfindingsJson = $findingsJson
$global:dbgnics = $nics

$htmFileName = "$($scriptBaseName)_$($computerName)_$($scriptStartTimeString).htm"
$htmFilePath = "$logFolderPath\$htmFileName"

$htm = $htm.Replace('&lt;', '<').Replace('&gt;', '>').Replace('&quot;', '"')

$htm | Out-File -FilePath $htmFilePath
Out-Log "HTML report: $htmFilePath"
if ($showReport -and $installationType -ne 'Server Core')
{
    Invoke-Item -Path $htmFilePath
}

Out-Log "Log file: $logFilePath"
$scriptDuration = '{0:hh}:{0:mm}:{0:ss}.{0:ff}' -f (New-TimeSpan -Start $scriptStartTime -End (Get-Date))
Out-Log "$scriptName duration:" -startLine
Out-Log $scriptDuration -endLine -color Cyan

# [int]$findingsCount = $findings | Measure-Object | Select-Object -ExpandProperty Count
if ($findingsCount -ge 1)
{
    $color = 'Cyan'
}
else
{
    $color = 'Green'
}
Out-Log "$findingsCount issue(s) found." -color $color

<# Possible findings:
WCF debugging enabled
Application error
Service terminated unexpectedly
Third-party modules in process
Rdagent service not installed
WindowsAzureGuestAgent service not installed
Rdagent service incorrect startType
WindowsAzureGuestAgent service incorrect startType
Rdagent service status not running
WindowsAzureGuestAgent service status not running
Rdagent service incorrect imagepath
WindowsAzureGuestAgent service incorrect imagepath
Rdagent service not installed
WindowsAzureGuestAgent service not installed
StdRegProv WMI class query failed
VM agent not installed
Proxy configured
TenantEncryptionCert expired
Wireserver not reachable
IMDS endpoint not reachable
Non-default machinekeys permissions
Non-default C:\WindowsAzure permissions
Non-default packages permissions
System drive low disk space
DHCP-disabled NICs
#>

<# https://github.com/search?q=get-counter+language%3APowerShell&type=code&l=PowerShell
$key = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows Azure\GuestAgentUpdateState' | where {[bool]($_.PSChildName -as [version]) -eq $true}
# Build timeline of GA service starts/stops,Windows starts/stop to aid in RCA for transient "agent not ready"
# .NET to check for ghost NICs - https://raw.githubusercontent.com/istvans/scripts/master/removeGhosts.ps1
# Perhaps to diagnose credit exhaustion, query for Microsoft-Windows-Resource-Exhaustion-Detector warning/error events
check for missing Message value in "HKLM\SOFTWARE\Microsoft\Windows Azure\GuestAgentUpdateState\<ga version>" and if missing, suggest deleting LatestExpectedVersion value in HKLM\SOFTWARE\Microsoft\Windows Azure\GuestAgentUpdateState)

# get-winevent -ProviderName Microsoft-Windows-Resource-Exhaustion-Detector | Where-Object {$_.LevelDisplayName -ne 'Information'}
P0 ### Re-enable and finish Findings accordion
P0 ### Review and complete all description/mitigation text
P0 ### Finish WCF profiling finding
P0 ### $uuid = Get-CimInstance -Query 'SELECT UUID FROM Win32_ComputerSystemProduct' | Select-Object -ExpandProperty UUID
P0 ### Check for system crashes (bugchecks), surface most recent one as well as crash count last 24 hour
P0 ### Disk space check should also check drive with page file if different than system drive
P0 ### Last known heartbeat
P0 ### Use checkaws to verify external IP, which then confirms internet access as well
P0 ### Available memory
P0 ### Page file settings
    get-ciminstance -class Win32_PageFile | select *
    get-item c:\pagefile.sys -force
P0 ### filter drivers
P0 ### Mellanox driver version check (alread shows up on 3rd-party running drivers tab)
P0 ### installed extensions and their statuses (if possible to get this cleanly from inside the guest without calling CRP)
P0 ### Need to also check for ProxySettingsPerUser https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.InternetExplorer::UserProxy
        Computer Configuration\Administrative Templates\Windows Components\Internet Explorer\Make proxy settings per-machine (rather than per user)
P0 ### (implemented, just needs content written) permissions on C:\WindowsAzure and c:\Packages folder during startup. It first removes all user/groups and then sets the following permission (Read & Execute: Everyone, Full Control: SYSTEM & Local Administrators only) to these folders. If GA fails to remove/set the permission, it can't proceed further.
        WaAppAgent.log shows this: [00000006] {ALPHANUMERICPII} [FATAL] Failed to set access rules for agent directories. Exception: System.Security.Principal.IdentityNotMappedException: {Namepii} or all identity references could not be translated. Symptom reported: Guest agent not ready (Unresponsive status).
P0 ### Update github repo readme with additional ways to run VMAssist.ps1 (mostly done)

P1 ### Add test cases for each check
P1 ### if possible, replace Get-NetIPConfiguration with cmdlets that don't rely on WMI
P1 ### -verboseonly should always log to log file
P1 ### Include script log contents at bottom of HTML report in code block so the single report .htm file will always include the log file
P1 ### Clean up 'VM agent installed' check (mostly done?)
P1 ### Commit
P1 ### Check for out-dated netvsc.sys
        Get-CimInstance -Query "'SELECT Name,Status,ExitCode,Started,StartMode,ErrorControl,PathName FROM Win32_SystemDriver WHERE Name='netvsc'"
        get-itemproperty hklm:\system\currentcontrolset\services\netvsc | Select-Object -ExpandProperty ImagePath
        \SystemRoot\System32\drivers\netvsc63.sys - ws12r2
        \SystemRoot\System32\drivers\netvsc.sys - win11,ws22
        get-itemproperty hklm:\system\currentcontrolset\services\netvsc | Select-Object -ExpandProperty ImagePath
P1 ### Windows activation status, relevant reg settings, most recent software licensing service events
P1 ### Add relevant checks from Set-Wallpaper.ps1
P1 ### Add mitigations for existing checks (XL)
#>

$global:dbgOutput = $output
$global:dbgFindings = $findings
