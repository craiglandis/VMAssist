<#
# WS12R2
Get-Acl -Path $env:ProgramData\Microsoft\Crypto\RSA\MachineKeys | Select-Object -ExpandProperty Sddl
O:SYG:SYD:PAI(A;;0x12019f;;;WD)(A;;FA;;;BA)

md c:\my -ea sil;cd c:\my;copy \\tsclient\c\src\Get-VMHealth\Get-VMHealth.ps1;.\Get-VMHealth.ps1

if ( -not $showErrors ) { $ErrorActionPreference = 'SilentlyContinue'}
https://github.com/mkellerman/Invoke-CommandAs
Install-Module -Name Invoke-CommandAs -Scope AllUsers -Repository PSGallery -Force
PS C:\> Invoke-CommandAs {Test-NetConnection -ComputerName 169.254.169.254 -Port 80 -InformationLevel Quiet -WarningAction SilentlyContinue} -AsSystem
True
PS C:\> Invoke-CommandAs {whoami} -AsSystem
nt authority\system
get-winevent -LogName Microsoft-Windows-TaskScheduler/Operational | where Id -in 100,102,106,141,200,201,325| where message -match 'e51f1a23-96e2-4bc6-9bbc-1b15e865f4eb'
Event 106 User "NORTHAMERICA\clandis"  registered Task Scheduler task "\e51f1a23-96e2-4bc6-9bbc-1b15e865f4eb"

cluster('https://ade.applicationinsights.io/subscriptions/927f2a7f-5662-40f2-8d19-521fe803ed2e/resourcegroups/rg/providers/microsoft.insights/components/ai1').database('ai1').customEvents
| project timestamp, name, itemType, customDimensions, customMeasurements
| sort by timestamp desc

[ENVIRONMENT]::Is64BitProcess

TODO:
1. permissions on C:\WindowsAzure and c:\Packages folder during startup. It first removes all user/groups and then sets the following permission (Read & Execute: Everyone, Full Control: SYSTEM & Local Administrators only) to these folders. If GA fails to remove/set the permission, it can't proceed further.
WaAppAgent.log shows this: [00000006] {ALPHANUMERICPII} [FATAL] Failed to set access rules for agent directories. Exception: System.Security.Principal.IdentityNotMappedException: {Namepii} or all identity references could not be translated. Symptom reported: Guest agent not ready (Unresponsive status).
2. Check for presence and validity of CRP cert
3. Check for WCF Profiling being enabled
4. Check for out-dated netvsc.sys Get-CimInstance -Query "'SELECT Name,Status,ExitCode,Started,StartMode,ErrorControl,PathName FROM Win32_SystemDriver WHERE Name='netvsc'"
get-itemproperty hklm:\system\currentcontrolset\services\netvsc | Select-Object -ExpandProperty ImagePath
\SystemRoot\System32\drivers\netvsc63.sys - ws12r2
\SystemRoot\System32\drivers\netvsc.sys - win11,ws22
get-itemproperty hklm:\system\currentcontrolset\services\netvsc | Select-Object -ExpandProperty ImagePath

5.


#>
[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [string]$outputPath = 'C:\logs'
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
    Exit
}

function Out-Log
{
    param(
        [string]$text,
        [switch]$verboseOnly,
        [string]$prefix,
        [switch]$raw,
        [switch]$logonly,
        [ValidateSet('Black', 'DarkBlue', 'DarkGreen', 'DarkCyan', 'DarkRed', 'DarkMagenta', 'DarkYellow', 'Gray', 'DarkGray', 'Blue', 'Green', 'Cyan', 'Red', 'Magenta', 'Yellow', 'White')]
        [string]$color = 'White'
    )

    if ($verboseOnly)
    {
        if ($verbose)
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
            if ($prefix -eq 'timespan' -and $global:scriptStartTime)
            {
                $timespan = New-TimeSpan -Start $global:scriptStartTime -End (Get-Date)
                $prefixString = '{0:hh}:{0:mm}:{0:ss}.{0:ff}' -f $timespan
            }
            elseif ($prefix -eq 'both' -and $global:scriptStartTime)
            {
                $timestamp = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'
                $timespan = New-TimeSpan -Start $global:scriptStartTime -End (Get-Date)
                $prefixString = "$($timestamp) $('{0:hh}:{0:mm}:{0:ss}.{0:ff}' -f $timespan)"
            }
            else
            {
                $prefixString = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'
            }

            if ($logonly)
            {
                if ($logFilePath)
                {
                    "$prefixString $text" | Out-File $logFilePath -Append
                }
            }
            else
            {
                Write-Host $prefixString -NoNewline -ForegroundColor Cyan
                Write-Host " $text" -ForegroundColor $color
                if ($logFilePath)
                {
                    "$prefixString $text" | Out-File $logFilePath -Append
                }
            }
        }
    }
}

function Invoke-ExpressionWithLogging
{
    param(
        [string]$command
    )
    Out-Log $command -verboseOnly
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
    Equivalent Test-NetConnection command (except no timeout since it doesn't support timeouts):
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
            Out-Log "Sending telemetry: $ingestionDnsName ($ip4Address)"
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
                $headers = @{'Content-Type' = 'application/x-json-stream'; }
                $result = Invoke-RestMethod -Uri $ingestionEndpoint -Method Post -Headers $headers -Body $body -ErrorAction SilentlyContinue
                if ($result)
                {
                    $itemsReceived = $result | Select-Object -ExpandProperty itemsReceived
                    $itemsAccepted = $result | Select-Object -ExpandProperty itemsAccepted
                    $errors = $result | Select-Object -ExpandProperty errors
                    $message = "Sending Telemetry: Received: $itemsReceived Accepted: $itemsAccepted"
                    if ($errors)
                    {
                        $message = "$message Errors: $errors"
                        Out-Log $message -color Red
                    }
                    else
                    {
                        Out-Log $message -color Green
                    }
                }
            }
            else
            {
                Out-Log "Sending telemetry: ingestion endpoint $($ip4Address):443 not reachable"
            }
        }
        else
        {
            Out-Log "Sending telemetry: could not resolve $ingestionDnsName to an IP address"
        }
    }
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
    Write-Error "You are using PowerShell $psVersionString. This script requires Powershell version 5.1, 5.0, or 4.0."
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
    Invoke-ExpressionWithLogging "New-Item -Path $logFolderPath -ItemType Directory -Force | Out-Null"
}
$invokeWmiMethodResult = Invoke-WmiMethod -Path "Win32_Directory.Name='$logFolderPath'" -Name Compress
$logFilePath = "$logFolderPath\$($scriptBaseName)_$(Get-Date -Format yyyyMMddhhmmss).log"
if ((Test-Path -Path $logFilePath -PathType Leaf) -eq $false)
{
    New-Item -Path $logFilePath -ItemType File -Force | Out-Null
}
Out-Log "Log file: $logFilePath"

$result = New-Object System.Collections.Generic.List[Object]
$checks = New-Object System.Collections.Generic.List[Object]
$findings = New-Object System.Collections.Generic.List[Object]
$vm = New-Object System.Collections.Generic.List[Object]

$computerName = $env:COMPUTERNAME

$ErrorActionPreference = 'SilentlyContinue'
$version = [environment]::osversion.version.ToString()
$buildNumber = [environment]::osversion.version.build
$currentVersionKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$currentVersionKey = Invoke-ExpressionWithLogging "Get-ItemProperty -Path '$currentVersionKeyPath' -ErrorAction SilentlyContinue"
if ($currentVersionKey)
{
    $productName = $currentVersionKey.ProductName
    if ($productName -match 'Windows 10' -and $buildNumber -ge 22000)
    {
        $productName = $productName.Replace('Windows 10', 'Windows 11')
    }
    $ubr = $currentVersionKey.UBR
    $installDate = $currentVersionKey.InstallDate
    $installDateString = Get-Date -Date ([datetime]'1/1/1970').AddSeconds($installDate) -Format yyyy-MM-ddTHH:mm:ss
    if ($buildNumber -ge 14393)
    {
        $releaseId = $currentVersionKey.ReleaseId
        $displayVersion = $currentVersionKey.DisplayVersion
    }
}
$ErrorActionPreference = 'Continue'

if ($releaseId -and $displayVersion)
{
    $osVersion = "$productName $displayVersion $releaseId $version"
}
else
{
    $osVersion = "$productName $version"
}
Out-Log "$osVersion installed $installDateString"

$windowsAzureFolderPath = "$env:SystemDrive\WindowsAzure"
Out-Log "$windowsAzureFolderPath folder exists?"
if (Test-Path -Path $windowsAzureFolderPath -PathType Container)
{
    New-Check -name "$windowsAzureFolderPath folder exists" -result 'Passed' -details ''
    $windowsAzureFolderExists = $true
    Out-Log "$windowsAzureFolderPath folder exists: $windowsAzureFolderExists" -color Green
    $windowsAzureFolder = Invoke-ExpressionWithLogging "Get-ChildItem -Path $windowsAzureFolderPath -Recurse -ErrorAction SilentlyContinue"

    Out-Log 'WindowsAzureGuestAgent.exe exists?'
    $windowsAzureGuestAgentExe = $windowsAzureFolder | Where-Object {$_.Name -eq 'WindowsAzureGuestAgent.exe'}
    if ($windowsAzureGuestAgentExe)
    {
        New-Check -name "WindowsAzureGuestAgent.exe exists in $windowsAzureFolderPath" -result 'Passed' -details ''
        $windowsAzureGuestAgentExeExists = $true
        $windowsAzureGuestAgentExeFileVersion = $windowsAzureGuestAgentExe | Select-Object -ExpandProperty VersionInfo | Select-Object -ExpandProperty FileVersion
        Out-Log "WindowsAzureGuestAgent.exe exists: $windowsAzureGuestAgentExeExists (version $windowsAzureGuestAgentExeFileVersion)" -color Green
    }
    else
    {
        New-Check -name "WindowsAzureGuestAgent.exe exists in $windowsAzureFolderPath" -result 'Failed' -details ''
        $windowsAzureGuestAgentExe = $false
        Out-Log "WindowsAzureGuestAgent.exe exists: $windowsAzureGuestAgentExeExists" -color Red
    }

    Out-Log 'WaAppAgent.exe exists?'
    $waAppAgentExe = $windowsAzureFolder | Where-Object {$_.Name -eq 'WaAppAgent.exe'}
    if ($waAppAgentExe)
    {
        New-Check -name "WaAppAgent.exe exists in $windowsAzureFolderPath" -result 'Passed' -details ''
        $waAppAgentExeExists = $true
        $waAppAgentExeFileVersion = $waAppAgentExe | Select-Object -ExpandProperty VersionInfo | Select-Object -ExpandProperty FileVersion
        Out-Log "WaAppAgent.exe exists: $waAppAgentExeExists (version $waAppAgentExeFileVersion)" -color Green
    }
    else
    {
        New-Check -name "WaAppAgent.exe exists in $windowsAzureFolderPath" -result 'Failed' -details ''
        $waAppAgentExeExists = $false
        Out-Log "WaAppAgent.exe exists: $waAppAgentExeExists" -color Red
    }

    # $waAppAgentLogPath = $windowsAzureFolder | Where-Object {$_.Name -eq 'WaAppAgent.log'} | Select-Object -ExpandProperty FullName
    # $waAppAgentLog = Get-Content -Path $waAppAgentLogPath

    # WaAppAgent.log errors when there is no wireserver connectivity:
    # [ERROR] ControlSystem not initialized. Skip getting goal state
    # [ERROR] GetVersions() failed with exception: System.AggregateException: One or more errors occurred. ---> System.Net.Http.HttpRequestException: An error occurred while sending the request. ---> System.Net.WebException: Unable to connect to the remote server ---> System.Net.Sockets.SocketException: An attempt was made to access a socket in a way forbidden by its access permissions 168.63.129.16:80
    # [ERROR] There was no match for protocol version. ControlSystem not initialized.
    # once wireserver connectivity is resolved, you'll see:
    # ControlSystem initialized with version 2012-11-30.

    <#
    # $services = ('rdagent','WindowsAzureGuestAgent'); $services | % {Set-Service $_ -StartupType Disabled -PassThru | Set-Service -Status Stopped}; get-service $services | ft -a Name,ServiceName,Status,StartType
    # stop-azvm rg win11 -force
    # $services = ('rdagent','WindowsAzureGuestAgent'); $services | % {Set-Service $_ -StartupType Automatic -PassThru | Set-Service -Status Running}; get-service $services | ft -a Name,ServiceName,Status,StartType

    aggregateStatus still says Ready if services are disabled, because the services must be runing for aggregateStatus to be changed

    aggregateStatusGuestAgentStatusVersion                : 2.7.41491.1083
    aggregateStatusGuestAgentStatusStatus                 : Ready
    aggregateStatusGuestAgentStatusFormattedMessage       : GuestAgent is running and processing the extensions.
    aggregateStatusGuestAgentStatusLastStatusUploadMethod : HostGA Plugin - Default
    aggregateStatusGuestAgentStatusLastStatusUploadTime   : 4/19/2023 9:36:23 PM

    New-NetFirewallRule -DisplayName 'Block outbound traffic to 168.63.129.16' -Direction Outbound –LocalPort Any -Protocol TCP -Action Block -RemoteAddress 168.63.129.16
    New-NetFirewallRule -DisplayName 'Block outbound traffic to 169.254.169.254' -Direction Outbound –LocalPort Any -Protocol TCP -Action Block -RemoteAddress 169.254.169.254

    get-azvm rg win11 -Status

    MAgent                    :
    VmAgentVersion           : Unknown
    Statuses[0]              :
        Code                   : ProvisioningState/Unavailable
        Level                  : Warning
        DisplayStatus          : Not Ready
        Message                : VM status blob is found but not yet populated.
        Time                   : 4/23/2023 12:45:05 AM

    #>
}
else
{
    New-Check -name "$windowsAzureFolderPath folder exists" -result 'Failed' -details ''
    Out-Log "$windowsAzureFolderPath folder exists: $windowsAzureFolderExists" -color Red
    $windowsAzureFolderExists = $false
}

<#
# An empty C:\Packages folder does exist if no extensions have ever been installed in the VM
# But if you delete C:\Packages and then install an extension, C:\Packages is automatically recreated
# Just checking for its existence is irrelevant as the agent will recreate it if needed
# And if it is not present, that doesn't mean the agent isn't fully installed, because again, it will create it as needed on extension install
# However a too-restrictive ACL on C:\Packages can be a problem, that would be a separate check to implement
$packagesFolderPath = "$env:SystemDrive\Packages"
Out-Log "Checking if $packagesFolderPath folder exists"
if (Test-Path -Path $packagesFolderPath -PathType Container)
{
    Out-Log "$packagesFolderPath folder exists" -color Green
    $packagesFolderExists = $true
}
else
{
    Out-Log "$packagesFolderPath folder does not exist" -color Red
    $packagesFolderExists = $false
}
#>

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

Out-Log 'RdAgent service installed?'
$rdAgent = Invoke-ExpressionWithLogging "Get-Service -Name 'RdAgent' -ErrorAction SilentlyContinue"
if ($rdAgent)
{
    New-Check -name 'RdAgent service installed' -result 'Passed' -details ''
    $rdAgentServiceExists = $true
    Out-Log "RdAgent service installed: $rdAgentServiceExists" -color Green

    $rdAgentBinaryPathName = $rdAgent.BinaryPathName
    $rdAgentUserName = $rdAgent.UserName
    $rdAgentStatus = $rdAgent.Status
    $rdAgentStartType = $rdAgent.StartType
    $rdAgentRequiredServices = $rdAgent.RequiredServices
    $rdAgentDependentServices = $rdAgent.DependentServices
    $rdAgentServicesDependedOn = $rdAgent.ServicesDependedOn

    $rdAgentServiceStatus = [Win32.Service.Ext]::QueryServiceStatus($rdAgent.ServiceHandle)
    $rdAgentWin32ExitCode = $rdAgentServiceStatus | Select-Object -ExpandProperty Win32ExitCode
    $rdAgentServiceSpecificExitCode = $rdAgentServiceStatus | Select-Object -ExpandProperty ServiceSpecificExitCode
    Out-Log "RdAgent Win32ExitCode: $rdAgentWin32ExitCode ServiceSpecificExitCode: $rdAgentServiceSpecificExitCode"

    if ($rdAgentStatus -eq 'Running')
    {
        New-Check -name 'RdAgent service running' -result 'Passed' -details ''
        $rdAgentStatusRunning = $true
    }
    else
    {
        New-Check -name 'RdAgent service running' -result 'Failed' -details ''
        $rdAgentStatusRunning = $false
    }
}
else
{
    New-Check -name 'RdAgent service installed' -result 'Failed' -details ''
    $rdAgentServiceExists = $false
    Out-Log "RdAgent service installed: $rdAgentServiceExists" -color Red
}

$rdAgentKeyPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\RdAgent'
$rdAgentKey = Invoke-ExpressionWithLogging "Get-ItemProperty -Path '$rdAgentKeyPath' -ErrorAction SilentlyContinue"
if ($rdAgentKey)
{
    $rdAgentKeyExists = $true

    $rdAgentKeyStartValue = $rdAgentKey.Start
    $rdAgentKeyErrorControlValue = $rdAgentKey.ErrorControl
    $rdAgentKeyImagePathValue = $rdAgentKey.ImagePath
    $rdAgentKeyObjectNameValue = $rdAgentKey.ObjectName
}
else
{
    $rdAgentKeyExists = $false
}

$scExe = "$env:SystemRoot\System32\sc.exe"

$scQueryExRdAgentOutput = Invoke-ExpressionWithLogging "& $scExe queryex RdAgent"
$scQueryExRdAgentExitCode = $LASTEXITCODE

$scQcRdAgentOutput = Invoke-ExpressionWithLogging "& $scExe qc RdAgent"
$scQcRdAgentExitCode = $LASTEXITCODE

Out-Log 'WindowsAzureGuestAgent service installed?'
$windowsAzureGuestAgent = Invoke-ExpressionWithLogging "Get-Service -Name 'WindowsAzureGuestAgent' -ErrorAction SilentlyContinue"
if ($windowsAzureGuestAgent)
{
    New-Check -name 'WindowsAzureGuestAgent service installed' -result 'Passed' -details ''
    $windowsAzureGuestAgentServiceExists = $true
    Out-Log "WindowsAzureGuestAgent service installed: $windowsAzureGuestAgentServiceExists" -color Green

    $windowsAzureGuestAgentBinaryPathName = $windowsAzureGuestAgent.BinaryPathName
    $windowsAzureGuestAgentStatus = $windowsAzureGuestAgent.Status
    $windowsAzureGuestAgentStartType = $windowsAzureGuestAgent.StartType
    $windowsAzureGuestAgentUserName = $windowsAzureGuestAgent.UserName
    $windowsAzureGuestAgentRequiredServices = $windowsAzureGuestAgent.RequiredServices
    $windowsAzureGuestAgentDependentServices = $windowsAzureGuestAgent.DependentServices
    $windowsAzureGuestAgentServicesDependedOn = $windowsAzureGuestAgent.ServicesDependedOn

    $windowsAzureGuestAgentServiceStatus = [Win32.Service.Ext]::QueryServiceStatus($windowsAzureGuestAgent.ServiceHandle)
    $windowsAzureGuestAgentWin32ExitCode = $windowsAzureGuestAgentServiceStatus | Select-Object -ExpandProperty Win32ExitCode
    $windowsAzureGuestAgentServiceSpecificExitCode = $windowsAzureGuestAgentServiceStatus | Select-Object -ExpandProperty ServiceSpecificExitCode
    Out-Log "WindowsAzureGuestAgent Win32ExitCode: $windowsAzureGuestAgentWin32ExitCode ServiceSpecificExitCode: $windowsAzureGuestAgentServiceSpecificExitCode"

    if ($windowsAzureGuestAgentStatus -eq 'Running')
    {
        New-Check -name 'WindowsAzureGuestAgent service running' -result 'Passed' -details ''
        $windowsAzureGuestAgentStatusRunning = $true
    }
    else
    {
        New-Check -name 'WindowsAzureGuestAgent service running' -result 'Failed' -details ''
        $windowsAzureGuestAgentStatusRunning = $false
    }
}
else
{
    New-Check -name 'WindowsAzureGuestAgent service installed' -result 'Failed' -details ''
    $windowsAzureGuestAgentServiceExists = $false
    Out-Log "WindowsAzureGuestAgent service installed: $windowsAzureGuestAgentServiceExists" -color Red
}

$windowsAzureGuestAgentKeyPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\WindowsAzureGuestAgent'
$windowsAzureGuestAgentKey = Invoke-ExpressionWithLogging "Get-ItemProperty -Path '$windowsAzureGuestAgentKeyPath' -ErrorAction SilentlyContinue"
if ($windowsAzureGuestAgentKey)
{
    $windowsAzureGuestAgentKeyExists = $true

    $windowsAzureGuestAgentKeyStartValue = $windowsAzureGuestAgentKey.Start
    $windowsAzureGuestAgentKeyErrorControlValue = $windowsAzureGuestAgentKey.ErrorControl
    $windowsAzureGuestAgentKeyImagePathValue = $windowsAzureGuestAgentKey.ImagePath
    $windowsAzureGuestAgentKeyObjectNameValue = $windowsAzureGuestAgentKey.ObjectName
}
else
{
    $windowsAzureGuestAgentKeyExists = $false
}

if ($useWMI)
{
    $windowsAzureGuestAgentFilter = "Name='WindowsAzureGuestAgent'"
    $windowsAzureGuestAgentFromWMI = Invoke-ExpressionWithLogging "Get-CimInstance -ClassName Win32_Service -Filter $windowsAzureGuestAgentFilter -ErrorAction SilentlyContinue"
    if ($windowsAzureGuestAgentFromWMI)
    {
        $windowsAzureGuestAgentExitCode = $windowsAzureGuestAgentFromWMI.ExitCode
        $windowsAzureGuestAgentErrorControl = $windowsAzureGuestAgentErrorControl.ErrorControl
    }
}

$scQueryExWindowsAzureGuestAgentOutput = Invoke-ExpressionWithLogging "& $scExe queryex WindowsAzureGuestAgent"
$scQueryExWindowsAzureGuestAgentExitCode = $LASTEXITCODE

$scQcWindowsAzureGuestAgentOutput = Invoke-ExpressionWithLogging "& $scExe qc WindowsAzureGuestAgent"
$scQcWindowsAzureGuestAgentExitCode = $LASTEXITCODE

Out-Log 'VM Agent installed?'
$messageSuffix = "(windowsAzureFolderExists:$windowsAzureFolderExists rdAgentServiceExists:$rdAgentServiceExists windowsAzureGuestAgentServiceExists:$windowsAzureGuestAgentServiceExists rdAgentKeyExists:$rdAgentKeyExists windowsAzureGuestAgentKeyExists:$windowsAzureGuestAgentKeyExists waAppAgentExeExists:$waAppAgentExeExists windowsAzureGuestAgentExeExists:$windowsAzureGuestAgentExeExists windowsAzureGuestAgentKeyExists:$windowsAzureGuestAgentKeyExists windowsAzureGuestAgentKeyExists:$windowsAzureGuestAgentKeyExists)"
if ($windowsAzureFolderExists -and $rdAgentServiceExists -and $windowsAzureGuestAgentServiceExists -and $rdAgentKeyExists -and $windowsAzureGuestAgentKeyExists -and $waAppAgentExeExists -and $windowsAzureGuestAgentExeExists -and $windowsAzureGuestAgentKeyExists -and $windowsAzureGuestAgentKeyExists)
{
    New-Check -name 'VM agent installed' -result 'Passed' -details ''
    $vmAgentInstalled = $true
    Out-Log "VM Agent installed: $vmAgentInstalled $messageSuffix" -color Green
    $message = "VM agent is installed $messageSuffix"
}
else
{
    New-Check -name 'VM agent installed' -result 'Failed' -details ''
    $vmAgentInstalled = $false
    Out-Log "VM Agent installed: $vmAgentInstalled" -color Red
    $description = "VM agent is not installed $messageSuffix"
    Out-Log $message -color Red
    New-Finding -type Critical -Name 'VM agent not installed' -description $description
}

<#
Out-Log "VM agent services running?"
$messageSuffix = "(rdAgentStatusRunning:$rdAgentStatusRunning windowsAzureGuestAgentStatusRunning:$windowsAzureGuestAgentStatusRunning)"
if ($rdAgentStatusRunning -and $windowsAzureGuestAgentStatusRunning)
{
    $vmAgentServicesRunning = $true
    Out-Log "VM agent services running: $vmAgentServicesRunning $messageSuffix" -color Green
    $message = "VM agent services are running $messageSuffix"
    New-Finding -level 4 -type VMAgentServicesRunning -message $message
}
else
{
    $vmAgentServicesRunning = $false
    Out-Log "VM agent services running: $vmAgentServicesRunning $messageSuffix" -color Red
    $message = "VM agent services are not running $messageSuffix"
    New-Finding -level 1 -type VMAgentServicesNotRunning -message $message
}
#>

<#
$waSetupXmlFilePath = "$env:SystemRoot\Panther\WaSetup.xml"
if (Test-Path -Path $waSetupXmlFilePath -PathType Leaf)
{
    $waSetupXml = Get-Content -Path $waSetupXmlFilePath
    $waSetupXmlErrors = $waSetupXml | Select-String -SimpleMatch `"ERROR`"
    if ($waSetupXmlErrors)
    {
        Out-Log $waSetupXmlErrors -raw
    }
}

$vmAgentInstallerXmlFilePath = "$env:SystemRoot\Panther\VmAgentInstaller.xml"
if (Test-Path -Path $vmAgentInstallerXmlFilePath -PathType Leaf)
{
    $vmAgentInstallerXml = Get-Content -Path $vmAgentInstallerXmlFilePath
    $vmAgentInstallerXmlErrors = $vmAgentInstallerXml | Select-String -SimpleMatch `"ERROR`" | Where-Object {$_ -notmatch 'logman.exe'}
    if ($vmAgentInstallerXmlErrors)
    {
        Out-Log $vmAgentInstallerXmlErrors -raw
    }
}
#>

Out-Log 'VM agent installed by provisioning agent or MSI?'
$uninstallKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
$uninstallKey = Invoke-ExpressionWithLogging "Get-Item -Path '$uninstallKeyPath' -ErrorAction SilentlyContinue"
$agentUninstallKey = $uninstallkey.GetSubKeyNames() | ForEach-Object {Get-ItemProperty -Path $uninstallKeyPath\$_ | Where-Object {$_.Publisher -eq 'Microsoft Corporation' -and $_.DisplayName -match 'Windows Azure VM Agent'}}
$agentUninstallKeyDisplayName = $agentUninstallKey.DisplayName
$agentUninstallKeyDisplayVersion = $agentUninstallKey.DisplayVersion
$agentUninstallKeyInstallDate = $agentUninstallKey.InstallDate

if ($agentUninstallKey)
{
    New-Check -name 'VM agent installed by provisioning agent' -result 'Passed' -details ''
    Out-Log 'VM agent installed by provisioning agent or MSI: MSI' -color Green
}
else
{
    New-Check -name 'VM agent installed by provisioning agent' -result 'Passed' -details ''
    Out-Log 'VM agent installed by provisioning agent or MSI: Provisioning agent' -color Green
}

Out-Log 'VM agent is a supported version?'
$guestKeyPath = 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest'
$guestKey = Invoke-ExpressionWithLogging "Get-ItemProperty -Path '$guestKeyPath' -ErrorAction SilentlyContinue"
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
        New-Check -name 'VM agent is supported version' -result 'Passed' -details "Installed version: $guestKeyGuestAgentVersion, minimum supported version: $minSupportedGuestAgentVersion"
        $isAtLeastMinSupportedVersion = $true
        Out-Log "VM agent is a supported version: $isAtLeastMinSupportedVersion (installed version: $guestKeyGuestAgentVersion, minimum supported version: $minSupportedGuestAgentVersion)" -color Green
    }
    else
    {
        New-Check -name 'VM agent is supported version' -result 'Failed' -details "Installed version: $guestKeyGuestAgentVersion, minimum supported version: $minSupportedGuestAgentVersion"
        Out-Log "VM agent is a supported version: $isAtLeastMinSupportedVersion (installed version: $guestKeyGuestAgentVersion, minimum supported version: $minSupportedGuestAgentVersion)" -color Red
    }
}

$autoKeyPath = 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Auto'
$autoKey = Invoke-ExpressionWithLogging "Get-ItemProperty -Path '$autoKeyPath' -ErrorAction SilentlyContinue"
if ($autoKey)
{

}

$guestAgentKeyPath = 'HKLM:\SOFTWARE\Microsoft\GuestAgent'
$guestAgentKey = Invoke-ExpressionWithLogging "Get-ItemProperty -Path '$guestAgentKeyPath' -ErrorAction SilentlyContinue"
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
}

$windowsAzureKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows Azure'
$windowsAzureKey = Invoke-ExpressionWithLogging "Get-ItemProperty -Path '$windowsAzureKeyPath' -ErrorAction SilentlyContinue"
if ($windowsAzureKey)
{
    $vmId = $windowsAzureKey.vmId
    if ($vmId)
    {
        $vmId = $vmId.ToLower()
    }
}

$guestAgentUpdateStateKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows Azure\GuestAgentUpdateState'
$guestAgentUpdateStateKey = Invoke-ExpressionWithLogging "Get-Item -Path '$guestAgentUpdateStateKeyPath' -ErrorAction SilentlyContinue"
if ($guestAgentUpdateStateKey)
{
    $guestAgentUpdateStateSubKeyName = $guestAgentUpdateStateKey.GetSubKeyNames() | Sort-Object {[Version]$_} | Select-Object -Last 1
    $guestAgentUpdateStateSubKey = Invoke-ExpressionWithLogging "Get-ItemProperty -Path '$guestAgentUpdateStateKeyPath\$guestAgentUpdateStateSubKeyName' -ErrorAction SilentlyContinue"
    if ($guestAgentUpdateStateSubKey)
    {
        $guestAgentUpdateStateCode = $guestAgentUpdateStateSubKey.Code
        $guestAgentUpdateStateMessage = $guestAgentUpdateStateSubKey.Message
        $guestAgentUpdateStateState = $guestAgentUpdateStateSubKey.State
    }
}

$handlerStateKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows Azure\HandlerState'
$handlerStateKey = Invoke-ExpressionWithLogging "Get-Item -Path '$handlerStateKeyPath' -ErrorAction SilentlyContinue"
if ($handlerStateKey)
{
    $handlerNames = $handlerStateKey.GetSubKeyNames()
    if ($handlerNames)
    {
        $handlerStates = New-Object System.Collections.Generic.List[Object]
        foreach ($handlerName in $handlerNames)
        {
            $handlerState = Invoke-ExpressionWithLogging "Get-ItemProperty -Path '$handlerStateKeyPath\$handlerName' -ErrorAction SilentlyContinue"
            if ($handlerState)
            {
                $handlerStates.Add($handlerState)
                $handlerState = $null
            }
        }
    }
}

# The ProxyEnable key controls the proxy settings. 0 disables them, and 1 enables them. If you are using a proxy, you will get its value under the ProxyServer key.
# This gets the same settings as running "netsh winhttp show proxy"
# Need to also check for ProxySettingsPerUser https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.InternetExplorer::UserProxy
# Computer Configuration\Administrative Templates\Windows Components\Internet Explorer\Make proxy settings per-machine (rather than per user)
$proxyConfigured = $false
Out-Log 'Proxy configured?'
$netshWinhttpShowProxyOutput = netsh winhttp show proxy
$connectionsKeyPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections'
$connectionsKey = Get-ItemProperty -Path $connectionsKeyPath -ErrorAction SilentlyContinue
$winHttpSettings = $connectionsKey | Select-Object -ExpandProperty WinHttpSettings -ErrorAction SilentlyContinue
$winHttpSettings = ($winHttpSettings | ForEach-Object {'{0:X2}' -f $_}) -join ''
$defaultWinHttpSettings = '1800000000000000010000000000000000000000'
if ($winHttpSettings -ne $defaultWinHttpSettings)
{
    $proxyConfigured = $true
}

# [System.Net.WebProxy]::GetDefaultProxy() works on Windows PowerShell but not PowerShell Core
$defaultProxy = Invoke-ExpressionWithLogging '[System.Net.WebProxy]::GetDefaultProxy()'
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
$userInternetSettingsKey = Invoke-ExpressionWithLogging "Get-ItemProperty -Path $userInternetSettingsKeyPath -ErrorAction SilentlyContinue"
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
$machineInternetSettingsKey = Invoke-ExpressionWithLogging "Get-ItemProperty -Path $machineInternetSettingsKeyPath -ErrorAction SilentlyContinue"
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
$machinePoliciesInternetSettingsKey = Invoke-ExpressionWithLogging "Get-ItemProperty -Path $machinePoliciesInternetSettingsKeyPath -ErrorAction SilentlyContinue"
$proxySettingsPerUser = $machinePoliciesInternetSettingsKey | Select-Object -ExpandProperty ProxySettingsPerUser -ErrorAction SilentlyContinue
Out-Log "$machinePoliciesInternetSettingsKeyPath\ProxySettingsPerUser: $proxySettingsPerUser" -verboseOnly

if ($proxyConfigured)
{
    New-Check -name 'Proxy configured' -result 'Failed' -details ''
    Out-Log "Proxy configured: $proxyConfigured" -color Yellow
    New-Finding -type Information -name 'Proxy configured' -description 'A proxy is configured.'
}
else
{
    New-Check -name 'Proxy configured' -result 'Passed' -details ''
    Out-Log "Proxy configured: $proxyConfigured" -color Green
}

$machineConfigx64FilePath = "$env:SystemRoot\Microsoft.NET\Framework64\v4.0.30319\config\machine.config"
#$machineConfigFilePath = "$env:SystemRoot\Microsoft.NET\Framework\v4.0.30319\Config\machine.config"
[xml]$machineConfigx64 = Get-Content -Path $machineConfigx64FilePath

$machineKeysPath = "$env:ALLUSERSPROFILE\Microsoft\Crypto\RSA\MachineKeys"
$machineKeysAcl = Get-Acl -Path $machineKeysPath
$machineKeysAcl.Access
$machineKeysAclString = $machineKeysAcl.Access | Format-Table -AutoSize -HideTableHeaders IdentityReference, AccessControlType, FileSystemRights | Out-String

<#
To check the currently set proxy use:
netsh winhttp show proxy
To clear the proxy settings use:
netsh winhttp reset proxy
You can also import the settings for IE by typing:
netsh winhttp import proxy source=ie
#>

<#
https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/no-internet-access-multi-ip
$netAdapter = Get-NetAdapter | where-object {$_.ComponentID -eq 'VMBUS\{f8615163-df3e-46c5-913f-f2d2f965ed0e}'}
$ipAddress = $netAdapter | Get-NetIPAddress -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress
$ipAddressCount = $ipAddress | Measure-Object | Select-Object -ExpandProperty Count

$primaryIP = "<Primary IP address that you set in Azure portal>"
$netInterface = "<NIC name in Windows>"
[array]$IPs = Get-NetIPAddress -InterfaceAlias $netInterface | Where-Object {$_.AddressFamily -eq "IPv4" -and $_.IPAddress -ne $primaryIP}
Set-NetIPAddress -IPAddress $primaryIP -InterfaceAlias $netInterface -SkipAsSource $false
Set-NetIPAddress -IPAddress $IPs.IPAddress -InterfaceAlias $netInterface -SkipAsSource $true

$netAdapter = Get-NetAdapter | where-object {$_.ComponentID -eq 'VMBUS\{f8615163-df3e-46c5-913f-f2d2f965ed0e}'}
Set-NetIPAddress -IPAddress 10.0.0.10 -InterfaceIndex $netAdapter.ifIndex -SkipAsSource $false
Set-NetIPAddress -IPAddress 10.0.0.7 -InterfaceIndex $netAdapter.ifIndex -SkipAsSource $true

#>

Out-Log "DHCP request returns option 245?"
$dhcpReturnedOption245 = Confirm-AzureVM
if ($dhcpReturnedOption245)
{
    Out-Log "DHCP request returned option 245" -color Green
}
else
{
    Out-Log "DHCP request did not return option 245" -color Yellow
}

# wireserver doesn't listen on 8080 even though it creates a BFE filter for it
# Test-NetConnection -ComputerName 168.63.129.16 -Port 80 -InformationLevel Quiet -WarningAction SilentlyContinue
# Test-NetConnection -ComputerName 168.63.129.16 -Port 32526 -InformationLevel Quiet -WarningAction SilentlyContinue
# Test-NetConnection -ComputerName 169.254.169.254 -Port 80 -InformationLevel Quiet -WarningAction SilentlyContinue
Out-Log '168.63.129.16:80 reachable?'
$wireserverPort80Reachable = Test-Port -ipAddress '168.63.129.16' -port 80 -timeout 1000
$description = "168.63.129.16:80 reachable: $($wireserverPort80Reachable.Succeeded) $($wireserverPort80Reachable.Error)"
#$mitigation = 'https://learn.microsoft.com/en-us/azure/virtual-network/what-is-ip-address-168-63-129-16'
$mitigation = '<a href="https://learn.microsoft.com/en-us/azure/virtual-network/what-is-ip-address-168-63-129-16">What is IP address 168.63.129.16?</a>'
if ($wireserverPort80Reachable.Succeeded)
{
    New-Check -name '168.63.129.16:80 reachable' -result 'Passed' -details ''
    Out-Log $description -color Green
}
else
{
    New-Check -name '168.63.129.16:80 reachable' -result 'Failed' -details ''
    Out-Log $description -color Red
    New-Finding -type Critical -name '168.63.129.16:80 not reachable' -description $description -mitigation $mitigation
}

Out-Log '168.63.129.16:32526 reachable?'
$wireserverPort32526Reachable = Test-Port -ipAddress '168.63.129.16' -port 32526 -timeout 1000
$description = "168.63.129.16:32526 reachable: $($wireserverPort32526Reachable.Succeeded) $($wireserverPort80Reachable.Error)"
if ($wireserverPort32526Reachable.Succeeded)
{
    New-Check -name '168.63.129.16:32526 reachable' -result 'Passed' -details ''
    Out-Log $description -color Green
}
else
{
    New-Check -name '168.63.129.16:32526 reachable' -result 'Failed' -details ''
    Out-Log $description -color Red
    New-Finding -type Critical -name '168.63.129.16:32526 not reachable' -description $description -mitigation $mitigation
}

Out-Log 'Instance Metadata Service 169.254.169.254:80 reachable?'
$imdsReachable = Test-Port -ipAddress '169.254.169.254' -port 80 -timeout 1000
$description = "Instance Metadata Service 169.254.169.254:80 reachable: $($imdsReachable.Succeeded) $($imdsReachable.Error)"
if ($imdsReachable.Succeeded)
{
    New-Check -name 'Instance Metadata Service 169.254.169.254:80 reachable' -result 'Passed' -details ''
    Out-Log $description -color Green
}
else
{
    New-Check -name 'Instance Metadata Service 169.254.169.254:80 reachable' -result 'Failed' -details ''
    Out-Log $description -color Red
    New-Finding -type Information -name 'Instance Metadata Service 169.254.169.254:80 not reachable' -description $description
}

if ($imdsReachable.Succeeded)
{
    Out-Log 'Querying Instance Metadata service 169.254.169.254:80'
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072
    # Below three lines have it use a null proxy, bypassing any configured proxy, see also https://github.com/microsoft/azureimds/blob/master/IMDSSample.ps1
    $proxy = New-Object System.Net.WebProxy
    $webSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $webSession.Proxy = $proxy
    $apiVersions = Invoke-RestMethod -Headers @{'Metadata' = 'true'} -Method GET -Uri 'http://169.254.169.254/metadata/versions' -WebSession $webSession | Select-Object -ExpandProperty apiVersions
    $apiVersion = $apiVersions | Select-Object -Last 1
    $metadata = Invoke-RestMethod -Headers @{'Metadata' = 'true'} -Method GET -Uri "http://169.254.169.254/metadata/instance?api-version=$apiVersion" -WebSession $webSession
    if ($metadata)
    {
        $global:dbgMetadata = $metadata
        Out-Log 'Querying Instance Metadata service 169.254.169.254:80 succeeded' -color Green

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
        Out-Log 'Querying Instance Metadata service 169.254.169.254:80 failed' -color Red
    }
}
<#
Invoke-RestMethod -Method GET -Uri 'http://168.63.129.16/machine/ac9257a2-f6d0-4096-9480-c6f40ab833a5/b7d92ed1%2Dbc85%2D4d75%2Daf23%2D4f5ffd9e29e6.%5Fwin11?comp=config&type=hostingEnvironmentConfig&incarnation=2' -Headers @{'x-ms-version' = '2012-11-30'}
Invoke-RestMethod -Method GET -Uri 'http://168.63.129.16:80/machine/ac9257a2-f6d0-4096-9480-c6f40ab833a5/b7d92ed1%2Dbc85%2D4d75%2Daf23%2D4f5ffd9e29e6.%5Fwin11?comp=config&type=sharedConfig&incarnation=2' -Headers @{'x-ms-version' = '2012-11-30'}

Invoke-RestMethod -Method GET -Uri 'http://168.63.129.16:80/machine/ac9257a2-f6d0-4096-9480-c6f40ab833a5/b7d92ed1%2Dbc85%2D4d75%2Daf23%2D4f5ffd9e29e6.%5Fwin11?comp=config&type=extensionsConfig&incarnation=2' -Headers @{'x-ms-version' = '2012-11-30'}

HostingEnvironmentConfig : http://168.63.129.16:80/machine/ac9257a2-f6d0-4096-9480-c6f40ab833a5/b7d92ed1%2Dbc85%2D4d75%2Daf23%2D4f5ffd9e29e6.%5Fwin11?comp=config&type=hostingEnvironmentConfig&incarnation=2
SharedConfig             : http://168.63.129.16:80/machine/ac9257a2-f6d0-4096-9480-c6f40ab833a5/b7d92ed1%2Dbc85%2D4d75%2Daf23%2D4f5ffd9e29e6.%5Fwin11?comp=config&type=sharedConfig&incarnation=2
ExtensionsConfig         : http://168.63.129.16:80/machine/ac9257a2-f6d0-4096-9480-c6f40ab833a5/b7d92ed1%2Dbc85%2D4d75%2Daf23%2D4f5ffd9e29e6.%5Fwin11?comp=config&type=extensionsConfig&incarnation=2
FullConfig               : http://168.63.129.16:80/machine/ac9257a2-f6d0-4096-9480-c6f40ab833a5/b7d92ed1%2Dbc85%2D4d75%2Daf23%2D4f5ffd9e29e6.%5Fwin11?comp=config&type=fullConfig&incarnation=2
Certificates             : http://168.63.129.16:80/machine/ac9257a2-f6d0-4096-9480-c6f40ab833a5/b7d92ed1%2Dbc85%2D4d75%2Daf23%2D4f5ffd9e29e6.%5Fwin11?comp=certificates&incarnation=2
ConfigName               : b7d92ed1-bc85-4d75-af23-4f5ffd9e29e6.1.b7d92ed1-bc85-4d75-af23-4f5ffd9e29e6.4._win11.1.xml
#>

if ($wireserverPort80Reachable.Succeeded -and $wireserverPort32526Reachable.Succeeded)
{
    Out-Log 'Getting status from aggregatestatus.json'
    $aggregateStatusJsonFilePath = $windowsAzureFolder | Where-Object {$_.Name -eq 'aggregatestatus.json'} | Select-Object -ExpandProperty FullName
    $aggregateStatus = Get-Content -Path $aggregateStatusJsonFilePath
    $aggregateStatus = $aggregateStatus -replace '\0' | ConvertFrom-Json

    $aggregateStatusGuestAgentStatusVersion = $aggregateStatus.aggregateStatus.guestAgentStatus.version
    $aggregateStatusGuestAgentStatusStatus = $aggregateStatus.aggregateStatus.guestAgentStatus.status
    $aggregateStatusGuestAgentStatusMessage = $aggregateStatus.aggregateStatus.guestAgentStatus.formattedMessage.message
    $aggregateStatusGuestAgentStatusLastStatusUploadMethod = $aggregateStatus.aggregateStatus.guestAgentStatus.lastStatusUploadMethod
    $aggregateStatusGuestAgentStatusLastStatusUploadTime = $aggregateStatus.aggregateStatus.guestAgentStatus.lastStatusUploadTime

    Out-Log "Version: $aggregateStatusGuestAgentStatusVersion"
    Out-Log "Status: $aggregateStatusGuestAgentStatusStatus"
    Out-Log "Message: $aggregateStatusGuestAgentStatusMessage"
    Out-Log "LastStatusUploadMethod: $aggregateStatusGuestAgentStatusLastStatusUploadMethod"
    Out-Log "LastStatusUploadTime: $aggregateStatusGuestAgentStatusLastStatusUploadTime"

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
    # 'x-ms-guest-agent-public-x509-cert' header is missing.
    # $certificates = Invoke-RestMethod -Method GET -Uri $certificatesUri -Headers $headers -WebSession $webSession | Select-Object -ExpandProperty Certificates

    $statusUploadBlobUri = $extensions.StatusUploadBlob.'#text'
    # $statusUploadBlob = Invoke-RestMethod -Uri $statusUploadBlobUri
    $inVMGoalStateMetaData = $extensions.InVMGoalStateMetaData

    #$inVMArtifactsProfileBlob = Invoke-WebRequest -Uri $extensions.InVMArtifactsProfileBlob | Select-Object -ExpandProperty Content
    # Remove null characters ('\0') from end of string, else ConvertFrom-Json on PS5.1 and earlier fails with "invalid json primitive"
    # $inVMArtifactsProfileBlob = $inVMArtifactsProfileBlob -replace '\0' | ConvertFrom-Json
    # $inVMArtifactsProfileBlob = Invoke-RestMethod -Uri $extensions.InVMArtifactsProfileBlob -WebSession $webSession
}

$scriptStartTimeLocalString = Get-Date -Date $scriptStartTime -Format o
$scriptStartTimeUTCString = Get-Date -Date $scriptStartTime -Format o

$scriptEndTime = Get-Date
$scriptEndTimeLocalString = Get-Date -Date $scriptEndTime -Format o
$scriptEndTimeUTCString = Get-Date -Date $scriptEndTime -Format 'yyyy-MM-ddTHH:mm:ssZ'

$scriptDuration = '{0:hh}:{0:mm}:{0:ss}.{0:ff}' -f (New-TimeSpan -Start $scriptStartTime -End $scriptEndTime)

# General
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

$nics = New-Object System.Collections.Generic.List[Object]

$ipconfigs = Get-NetIPConfiguration -Detailed
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
    $ipV6DnsServers = $dnsServer | Where-Object {$_.AddressFamily -eq 23} | Select-Object -Expand ServerAddresses

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

#$adapters = Get-NetAdapter
#$interfaceAliases = $adapters | Select-Object -ExpandProperty InterfaceAlias
<#
foreach ($nic in $nics)
{
    $adapter = Get-NetAdapter -InterfaceIndex $nic.InterfaceIndex
    $nic | Add-Member -MemberType NoteProperty -Name ComponentID -Value $adapter.ComponentID -Force
    $nic | Add-Member -MemberType NoteProperty -Name Status -Value $adapter.Status -Force
    $nic | Add-Member -MemberType NoteProperty -Name MediaConnectionState -Value $adapter.MediaConnectionState -Force
    $nic | Add-Member -MemberType NoteProperty -Name DriverInformation -Value $adapter.DriverInformation -Force
    $nic | Add-Member -MemberType NoteProperty -Name MacAddress -Value $adapter.MacAddress -Force

    $ipV4Addresses = Get-NetIPAddress -InterfaceIndex $nic.InterfaceIndex -AddressFamily IPv4
    foreach ($ipV4Address in $ipV4Addresses)
    {
        $ipV4AddressString = $ipV4Address.IPAddress
        if ($ipV4Address.PrefixOrigin -eq 'Dhcp' -and $ipV4Address.SuffixOrigin -eq 'Dhcp')
        {
            $ipV4AddressString = "$ipV4AddressString (DHCP)"
        }
        else
        {
            $ipV4AddressString = "$ipV4AddressString (Static)"
        }

        if ($ipV4Address.SkipAsSource -eq $true)
        {
            $ipV4AddressString = "$ipV4AddressString (Primary)"
        }
        $ipV4AddressesString += "$ipV4AddressString, "
    }
    $ipV4AddressesString.Trim(', ')
    $nic | Add-Member -MemberType NoteProperty -Name 'IPv4 Addresses' -Value $ipV4AddressesString -Force
}

$waAppAgentPid = Get-Process -Name WaAppAgent | Select-Object -ExpandProperty Id
$waAppAgentConnections = Get-NetTCPConnection -OwningProcess $waAppAgentPid
$windowsAzureGuestAgentPid = Get-Process -Name WindowsAzureGuestAgent | Select-Object -ExpandProperty Id
$windowsAzureGuestAgentConnections = Get-NetTCPConnection -OwningProcess $windowsAzureGuestAgentPid


# Network

Get-NetAdapter
    InterfaceAlias
    InterfaceAlias


$waAppAgentPid = Get-Process -Name WaAppAgent | Select-Object -ExpandProperty Id
$waAppAgentConnections = Get-NetTCPConnection -OwningProcess $waAppAgentPid
$windowsAzureGuestAgentPid = Get-Process -Name WindowsAzureGuestAgent | Select-Object -ExpandProperty Id
$windowsAzureGuestAgentConnections = Get-NetTCPConnection -OwningProcess $windowsAzureGuestAgentPid
#>

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

#$vm.Add([PSCustomObject]@{Property = 'publicIpAddressReportedFromAwsCheckIpService'; Value = $publicIpAddressReportedFromAwsCheckIpService; Type = 'Network'})

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

$output = [PSCustomObject]@{

    wireserverPort80Reachable                             = $wireserverPort80Reachable
    wireserverPort32526Reachable                          = $wireserverPort32526Reachable
    windowsAzureFolderExists                              = $windowsAzureFolderExists
    # packagesFolderExists                                  = $packagesFolderExists
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

$global:dbgOutput = $output
$global:dbgFindings = $findings

$css = @'
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <style>
        body {
            font-family: sans-serif;
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
            text-align: left
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
            text-align: left
        }
        td.CRITICAL {
            background: Salmon;
            color: Black;
            text-align: left
        }
        td.WARNING {
            background: Yellow;
            color: Black;
            text-align: left
        }
        td.INFORMATION {
            background: Cyan;
            color: Black;
            text-align: left
        }
        td.PASSED {
            background: PaleGreen;
            color: Black;
            text-align: left
        }
        td.FAILED {
            background: Salmon;
            color: Black;
            text-align: left
        }
    </style>
</head>
<body>
'@

$stringBuilder = New-Object Text.StringBuilder

$css | ForEach-Object {[void]$stringBuilder.Append("$_`r`n")}
[void]$stringBuilder.Append('<h1>VM Health Report</h1>')
[void]$stringBuilder.Append("<h3>VM: $vmName VMID: $vmId Time Generated: $scriptEndTimeUTCString</h3>")
<#
[void]$stringBuilder.Append("<a href=`"#findings`"><strong>Findings</strong></a><br />`r`n")
[void]$stringBuilder.Append("<a href=`"#checks`"><strong>Checks</strong></a><br />`r`n")
[void]$stringBuilder.Append("<a href=`"#vm`"><strong>VM Details</strong></a><br />`r`n")
[void]$stringBuilder.Append("&emsp;<a href=`"#vmGeneral`"><strong>General</strong></a><br />`r`n")
[void]$stringBuilder.Append("&emsp;<a href=`"#vmOS`"><strong>OS</strong></a><br />`r`n")
[void]$stringBuilder.Append("&emsp;<a href=`"#vmNetwork`"><strong>Network</strong></a><br />`r`n")
[void]$stringBuilder.Append("&emsp;<a href=`"#vmSecurity`"><strong>Security</strong></a><br />`r`n")
[void]$stringBuilder.Append("&emsp;<a href=`"#vmStorage`"><strong>Storage</strong></a><br />`r`n")
#>

[void]$stringBuilder.Append("<h2 id=`"findings`">Findings</h2>`r`n")
$findingsCount = $findings | Measure-Object | Select-Object -ExpandProperty Count
if ($findingsCount -ge 1)
{
    $findingsTable = $findings | Select-Object Type, Name, Description, Mitigation | ConvertTo-Html -Fragment -As Table
    $findingsTable = $findingsTable -replace '<td>Critical</td>', '<td class="CRITICAL">Critical</td>'
    $findingsTable = $findingsTable -replace '<td>Warning</td>', '<td class="WARNING">Warning</td>'
    $findingsTable = $findingsTable -replace '<td>Information</td>', '<td class="INFORMATION">Information</td>'
    $global:dbgFindingsTable = $findingsTable
    #[void]$stringBuilder.Append("<h2 id=`"findings`">Findings</h2>`r`n")
    $findingsTable | ForEach-Object {[void]$stringBuilder.Append("$_`r`n")}
}
else
{
    [void]$stringBuilder.Append("<h3>No issues found. VM agent is healthy.</h3>`r`n")
}

$checksTable = $checks | Select-Object Name, Result, Details | ConvertTo-Html -Fragment -As Table
$checksTable = $checksTable -replace '<td>Passed</td>', '<td class="PASSED">Passed</td>'
$checksTable = $checksTable -replace '<td>Failed</td>', '<td class="FAILED">Failed</td>'
$global:dbgChecksTable = $checksTable
[void]$stringBuilder.Append("<h2 id=`"checks`">Checks</h2>`r`n")
$checksTable | ForEach-Object {[void]$stringBuilder.Append("$_`r`n")}

[void]$stringBuilder.Append("<h2 id=`"vm`">VM Details</h2>`r`n")

[void]$stringBuilder.Append("<h3 id=`"vmGeneral`">General</h3>`r`n")
$vmGeneralTable = $vm | Where-Object {$_.Type -eq 'General'} | Select-Object Property, Value | ConvertTo-Html -Fragment -As Table
$vmGeneralTable | ForEach-Object {[void]$stringBuilder.Append("$_`r`n")}

[void]$stringBuilder.Append("<h3 id=`"vmOS`">OS</h3>`r`n")
$vmOsTable = $vm | Where-Object {$_.Type -eq 'OS'} | Select-Object Property, Value | ConvertTo-Html -Fragment -As Table
$vmOsTable | ForEach-Object {[void]$stringBuilder.Append("$_`r`n")}

[void]$stringBuilder.Append("<h3 id=`"vmNetwork`">Network</h3>`r`n")
[void]$stringBuilder.Append("<h4>NIC Details</h4>`r`n")
$vmNetworkTable = $nics | ConvertTo-Html -Fragment -As Table
$vmNetworkTable = $vmNetworkTable -replace '<td>Up</td>', '<td class="PASSED">Up</td>'
$vmNetworkTable = $vmNetworkTable -replace '<td>Down</td>', '<td class="FAILED">Down</td>'
$vmNetworkTable | ForEach-Object {[void]$stringBuilder.Append("$_`r`n")}

[void]$stringBuilder.Append("<h4>NIC Details from IMDS</h4>`r`n")
$vmNetworkImdsTable = $nicsImds | ConvertTo-Html -Fragment -As Table
$vmNetworkImdsTable | ForEach-Object {[void]$stringBuilder.Append("$_`r`n")}

[void]$stringBuilder.Append("<h3 id=`"vmSecurity`">Security</h3>`r`n")
$vmSecurityTable = $vm | Where-Object {$_.Type -eq 'Security'} | Select-Object Property, Value | ConvertTo-Html -Fragment -As Table
$vmSecurityTable | ForEach-Object {[void]$stringBuilder.Append("$_`r`n")}

[void]$stringBuilder.Append("<h3 id=`"vmStorage`">Storage</h3>`r`n")
$vmStorageTable = $vm | Where-Object {$_.Type -eq 'Storage'} | Select-Object Property, Value | ConvertTo-Html -Fragment -As Table
$vmStorageTable | ForEach-Object {[void]$stringBuilder.Append("$_`r`n")}

[void]$stringBuilder.Append("</body>`r`n")
[void]$stringBuilder.Append("</html>`r`n")

$html = $stringBuilder.ToString()

$findingsJson = $findings | ConvertTo-Json -Depth 10
$checksJson = $checks | ConvertTo-Json -Depth 10
$vmJson = $vm | ConvertTo-Json -Depth 10
$properties = @{
    vmId     = $vmId
    vm       = $vmJson
    findings = $findingsJson
    checks   = $checksJson
}
Send-Telemetry -properties $properties
$global:dbgProperties = $properties
$global:dbgvm = $vm
$global:dbgnics = $nics

$htmlFileName = "$($scriptBaseName)_$($computerName.ToUpper())_$($osVersion.Replace(' ', '_'))_$(Get-Date -Format yyyyMMddhhmmss).html"
$htmlFilePath = "$logFolderPath\$htmlFileName"

#$html.Replace('&lt;','<').Replace('&gt;','>').Replace('&lessthan;', '&lt;').Replace('&greaterthan;', '&gt;').ToString() | Out-File $script:reportContentFile -Encoding utf8
$html = $html.Replace('&lt;', '<').Replace('&gt;', '>')
$html | Out-File -FilePath $htmlFilePath
Out-Log "HTML report: $htmlFilePath"
Invoke-Item -Path $htmlFilePath

Out-Log "Log file: $logFilePath"
$scriptDuration = '{0:hh}:{0:mm}:{0:ss}.{0:ff}' -f (New-TimeSpan -Start $scriptStartTime -End (Get-Date))
Out-Log "$scriptName duration: $scriptDuration"

$findingsCount = $findings | Measure-Object | Select-Object -ExpandProperty Count
if ($findingsCount -ge 1)
{
    Out-Log "$issuesCount issue(s) found." -color Cyan
}
else
{
    Out-Log 'No issues found.' -color Green
}

<#
# $summaryString = $output | Select-Object -Property isWireServerReachable, aggregateStatusGuestAgentStatusVersion, aggregateStatusGuestAgentStatusStatus, aggregateStatusGuestAgentStatusFormattedMessage, aggregateStatusGuestAgentStatusLastStatusUploadMethod, aggregateStatusGuestAgentStatusLastStatusUploadTime, windowsAzureFolderExists, packagesFolderExists, windowsAzureGuestAgentExeFileVersion, waAppAgentExeFileVersion | Format-List | Out-String
# $summaryString = $summaryString.Trim()
#Out-Log "`n$summaryString`n" -raw
$issues = $findings | Where-Object {$_.Level -in 1, 2, 3}
$issuesCount = $issues | Measure-Object | Select-Object -ExpandProperty Count
$findingsString = $findings | Sort-Object timeCreated | Format-Table -AutoSize | Out-String
$findingsString = $findingsString.Trim()
Out-Log "`n$findingsString`n" -raw
if ($issues)
{
    Out-Log "$issuesCount issue(s) found." -color Yellow
}
else
{
    Out-Log 'No issues found.' -color Green
}
#>
