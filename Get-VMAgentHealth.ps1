<#
.SYNOPSIS
    Checks Azure VM agent health
.DESCRIPTION
    Checks Azure VM agent health
.NOTES
    Supported on Windows Server 2012 R2 and later versions of Windows.
    Supported in Windows PowerShell 4.0+ and PowerShell 6.0+.
    Not supported on Linux.
.LINK
    https://github.com/craiglandis/Get-VMAgentHealth/blob/main/README.md
.EXAMPLE
    RDP to Azure VM
    Launch an elevated PowerShell prompt
    Download Get-VMAgentHealth.ps1 with the following command

    Get-VMAgentHealth.ps1
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
                    Write-Host $prefixString -NoNewline -ForegroundColor DarkGray
                    Write-Host "$text " -NoNewline -ForegroundColor $color
                }
                elseif ($endLine)
                {
                    Write-Host $text -ForegroundColor $color
                }
                else
                {
                    Write-Host $prefixString -NoNewline -ForegroundColor DarkGray
                    Write-Host $text -ForegroundColor $color
                }

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
                $headers = @{'Content-Type' = 'application/x-json-stream'; }
                $result = Invoke-RestMethod -Uri $ingestionEndpoint -Method Post -Headers $headers -Body $body -ErrorAction SilentlyContinue
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
    Invoke-ExpressionWithLogging "New-Item -Path $logFolderPath -ItemType Directory -Force | Out-Null" -verboseOnly
}
$computerName = $env:COMPUTERNAME.ToUpper()
$invokeWmiMethodResult = Invoke-WmiMethod -Path "Win32_Directory.Name='$logFolderPath'" -Name Compress
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
    $installDate = $currentVersionKey.InstallDate
    $installDateString = Get-Date -Date ([datetime]'1/1/1970').AddSeconds($installDate) -Format yyyy-MM-ddTHH:mm:ss
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

Out-Log "$osVersion installed $installDateString" -color Cyan

$windowsAzureFolderPath = "$env:SystemDrive\WindowsAzure"
Out-Log "$windowsAzureFolderPath folder exists:" -startLine
if (Test-Path -Path $windowsAzureFolderPath -PathType Container)
{
    $windowsAzureFolderExists = $true
    Out-Log $windowsAzureFolderExists -color Green -endLine
    New-Check -name "$windowsAzureFolderPath folder exists" -result 'Passed' -details ''
    $windowsAzureFolder = Invoke-ExpressionWithLogging "Get-ChildItem -Path $windowsAzureFolderPath -Recurse -ErrorAction SilentlyContinue" -verboseOnly
    Out-Log 'WindowsAzureGuestAgent.exe exists:' -startLine
    $windowsAzureGuestAgentExe = $windowsAzureFolder | Where-Object {$_.Name -eq 'WindowsAzureGuestAgent.exe'}
    if ($windowsAzureGuestAgentExe)
    {
        New-Check -name "WindowsAzureGuestAgent.exe exists in $windowsAzureFolderPath" -result 'Passed' -details ''
        $windowsAzureGuestAgentExeExists = $true
        $windowsAzureGuestAgentExeFileVersion = $windowsAzureGuestAgentExe | Select-Object -ExpandProperty VersionInfo | Select-Object -ExpandProperty FileVersion
        Out-Log "$windowsAzureGuestAgentExeExists (version $windowsAzureGuestAgentExeFileVersion)" -color Green -endLine
    }
    else
    {
        New-Check -name "WindowsAzureGuestAgent.exe exists in $windowsAzureFolderPath" -result 'Failed' -details ''
        $windowsAzureGuestAgentExe = $false
        Out-Log $windowsAzureGuestAgentExeExists -color Red -endLine
    }

    Out-Log 'WaAppAgent.exe exists:' -startLine
    $waAppAgentExe = $windowsAzureFolder | Where-Object {$_.Name -eq 'WaAppAgent.exe'}
    if ($waAppAgentExe)
    {
        New-Check -name "WaAppAgent.exe exists in $windowsAzureFolderPath" -result 'Passed' -details ''
        $waAppAgentExeExists = $true
        $waAppAgentExeFileVersion = $waAppAgentExe | Select-Object -ExpandProperty VersionInfo | Select-Object -ExpandProperty FileVersion
        Out-Log "$waAppAgentExeExists (version $waAppAgentExeFileVersion)" -color Green -endLine
    }
    else
    {
        New-Check -name "WaAppAgent.exe exists in $windowsAzureFolderPath" -result 'Failed' -details ''
        $waAppAgentExeExists = $false
        Out-Log $waAppAgentExeExists -color Red -endLine
    }
}
else
{
    New-Check -name "$windowsAzureFolderPath folder exists" -result 'Failed' -details ''
    Out-Log $windowsAzureFolderExists -color Red -endLine
    $windowsAzureFolderExists = $false
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

Out-Log 'RdAgent service installed:' -startLine
$rdAgent = Invoke-ExpressionWithLogging "Get-Service -Name 'RdAgent' -ErrorAction SilentlyContinue" -verboseOnly
if ($rdAgent)
{
    New-Check -name 'RdAgent service installed' -result 'Passed' -details ''
    $rdAgentServiceExists = $true
    Out-Log $rdAgentServiceExists -color Green -endLine

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
    # Out-Log "RdAgent Win32ExitCode: $rdAgentWin32ExitCode ServiceSpecificExitCode: $rdAgentServiceSpecificExitCode"

    Out-Log 'RdAgent service running:' -startLine
    if ($rdAgentStatus -eq 'Running')
    {
        $rdAgentStatusRunning = $true
        Out-Log $rdAgentStatusRunning -color Green -endLine
        New-Check -name 'RdAgent service running' -result 'Passed' -details ''
    }
    else
    {
        $rdAgentStatusRunning = $false
        Out-Log $rdAgentStatusRunning -color Red -endLine
        New-Check -name 'RdAgent service running' -result 'Failed' -details "Status: $rdAgentStatus Win32ExitCode: $rdAgentWin32ExitCode ServiceSpecificExitCode: $rdAgentServiceSpecificExitCode"
        $description = "RdAgent service is not running (Status: $rdAgentStatus Win32ExitCode: $rdAgentWin32ExitCode ServiceSpecificExitCode: $rdAgentServiceSpecificExitCode)"
        $mitigation = '<a href="https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/windows-azure-guest-agent#step-3-check-whether-the-guest-agent-services-are-running">Check guest agent services</a>'
        New-Finding -type Critical -name RdAgentServiceNotRunning -description $description -mitigation $mitigation
    }
}
else
{
    New-Check -name 'RdAgent service installed' -result 'Failed' -details ''
    $rdAgentServiceExists = $false
    Out-Log $rdAgentServiceExists -color Red -endLine
}

$rdAgentKeyPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\RdAgent'
$rdAgentKey = Invoke-ExpressionWithLogging "Get-ItemProperty -Path '$rdAgentKeyPath' -ErrorAction SilentlyContinue" -verboseOnly
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

$scQueryExRdAgentOutput = Invoke-ExpressionWithLogging "& $scExe queryex RdAgent" -verboseOnly
$scQueryExRdAgentExitCode = $LASTEXITCODE

$scQcRdAgentOutput = Invoke-ExpressionWithLogging "& $scExe qc RdAgent" -verboseOnly
$scQcRdAgentExitCode = $LASTEXITCODE

Out-Log 'WindowsAzureGuestAgent service installed:' -startLine
$windowsAzureGuestAgent = Invoke-ExpressionWithLogging "Get-Service -Name 'WindowsAzureGuestAgent' -ErrorAction SilentlyContinue" -verboseOnly
if ($windowsAzureGuestAgent)
{
    New-Check -name 'WindowsAzureGuestAgent service installed' -result 'Passed' -details ''
    $windowsAzureGuestAgentServiceExists = $true
    Out-Log $windowsAzureGuestAgentServiceExists -color Green -endLine

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
    # Out-Log "WindowsAzureGuestAgent Win32ExitCode: $windowsAzureGuestAgentWin32ExitCode ServiceSpecificExitCode: $windowsAzureGuestAgentServiceSpecificExitCode"

    Out-Log 'WindowsAzureGuestAgent service running:' -startLine
    if ($windowsAzureGuestAgentStatus -eq 'Running')
    {
        $windowsAzureGuestAgentStatusRunning = $true
        Out-Log $windowsAzureGuestAgentStatusRunning -color Green -endLine
        New-Check -name 'WindowsAzureGuestAgent service running' -result 'Passed' -details ''
    }
    else
    {
        New-Check -name 'WindowsAzureGuestAgent service running' -result 'Failed' -details "Status: $windowsAzureGuestAgentStatus Win32ExitCode: $windowsAzureGuestAgentWin32ExitCode ServiceSpecificExitCode: $windowsAzureGuestAgentServiceSpecificExitCode"
        $windowsAzureGuestAgentStatusRunning = $false
        Out-Log $windowsAzureGuestAgentStatusRunning -color Red -endLine
        $description = "WindowsAzureGuestAgent service is not running (Status: $windowsAzureGuestAgentStatus Win32ExitCode: $windowsAzureGuestAgentWin32ExitCode ServiceSpecificExitCode: $windowsAzureGuestAgentServiceSpecificExitCode)"
        $mitigation = '<a href="https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/windows-azure-guest-agent#step-3-check-whether-the-guest-agent-services-are-running">Check guest agent services</a>'
        New-Finding -type Critical -name WindowsAzureGuestAgentServiceNotRunning -description $description -mitigation $mitigation
    }
}
else
{
    New-Check -name 'WindowsAzureGuestAgent service installed' -result 'Failed' -details ''
    $windowsAzureGuestAgentServiceExists = $false
    Out-Log $windowsAzureGuestAgentServiceExists -color Red -endLine
}

$windowsAzureGuestAgentKeyPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\WindowsAzureGuestAgent'
$windowsAzureGuestAgentKey = Invoke-ExpressionWithLogging "Get-ItemProperty -Path '$windowsAzureGuestAgentKeyPath' -ErrorAction SilentlyContinue" -verboseOnly
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
    $windowsAzureGuestAgentFromWMI = Invoke-ExpressionWithLogging "Get-CimInstance -ClassName Win32_Service -Filter $windowsAzureGuestAgentFilter -ErrorAction SilentlyContinue" -verboseOnly
    if ($windowsAzureGuestAgentFromWMI)
    {
        $windowsAzureGuestAgentExitCode = $windowsAzureGuestAgentFromWMI.ExitCode
        $windowsAzureGuestAgentErrorControl = $windowsAzureGuestAgentErrorControl.ErrorControl
    }
}

$scQueryExWindowsAzureGuestAgentOutput = Invoke-ExpressionWithLogging "& $scExe queryex WindowsAzureGuestAgent" -verboseOnly
$scQueryExWindowsAzureGuestAgentExitCode = $LASTEXITCODE

$scQcWindowsAzureGuestAgentOutput = Invoke-ExpressionWithLogging "& $scExe qc WindowsAzureGuestAgent" -verboseOnly
$scQcWindowsAzureGuestAgentExitCode = $LASTEXITCODE

<#
Out-Log 'VM Agent installed:' -startLine
$messageSuffix = "(windowsAzureFolderExists:$windowsAzureFolderExists rdAgentServiceExists:$rdAgentServiceExists windowsAzureGuestAgentServiceExists:$windowsAzureGuestAgentServiceExists rdAgentKeyExists:$rdAgentKeyExists windowsAzureGuestAgentKeyExists:$windowsAzureGuestAgentKeyExists waAppAgentExeExists:$waAppAgentExeExists windowsAzureGuestAgentExeExists:$windowsAzureGuestAgentExeExists windowsAzureGuestAgentKeyExists:$windowsAzureGuestAgentKeyExists windowsAzureGuestAgentKeyExists:$windowsAzureGuestAgentKeyExists)"
if ($windowsAzureFolderExists -and $rdAgentServiceExists -and $windowsAzureGuestAgentServiceExists -and $rdAgentKeyExists -and $windowsAzureGuestAgentKeyExists -and $waAppAgentExeExists -and $windowsAzureGuestAgentExeExists -and $windowsAzureGuestAgentKeyExists -and $windowsAzureGuestAgentKeyExists)
{
    New-Check -name 'VM agent installed' -result 'Passed' -details ''
    $vmAgentInstalled = $true
    Out-Log "$vmAgentInstalled $messageSuffix" -color Green -endLine
    $message = "VM agent is installed $messageSuffix"
}
else
{
    New-Check -name 'VM agent installed' -result 'Failed' -details ''
    $vmAgentInstalled = $false
    Out-Log $vmAgentInstalled -color Red -endLine
    $description = "VM agent is not installed $messageSuffix"
    Out-Log $message -color Red
    New-Finding -type Critical -Name 'VM agent not installed' -description $description
}
#>

Out-Log 'VM agent installed by provisioning agent or Windows Installer package (MSI):' -startLine
$uninstallKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
$uninstallKey = Invoke-ExpressionWithLogging "Get-Item -Path '$uninstallKeyPath' -ErrorAction SilentlyContinue" -verboseOnly
$agentUninstallKey = $uninstallkey.GetSubKeyNames() | ForEach-Object {Get-ItemProperty -Path $uninstallKeyPath\$_ | Where-Object {$_.Publisher -eq 'Microsoft Corporation' -and $_.DisplayName -match 'Windows Azure VM Agent'}}
$agentUninstallKeyDisplayName = $agentUninstallKey.DisplayName
$agentUninstallKeyDisplayVersion = $agentUninstallKey.DisplayVersion
$agentUninstallKeyInstallDate = $agentUninstallKey.InstallDate

if ($agentUninstallKey)
{
    New-Check -name 'VM agent installed by provisioning agent' -result 'Passed' -details ''
    Out-Log 'MSI: MSI' -color Green -endLine
}
else
{
    New-Check -name 'VM agent installed by provisioning agent' -result 'Passed' -details ''
    Out-Log 'Provisioning agent' -color Green -endLine
}

Out-Log 'VM agent is supported version:' -startLine
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
        New-Check -name 'VM agent is supported version' -result 'Passed' -details "Installed version: $guestKeyGuestAgentVersion, minimum supported version: $minSupportedGuestAgentVersion"
        $isAtLeastMinSupportedVersion = $true
        Out-Log "$isAtLeastMinSupportedVersion (installed: $guestKeyGuestAgentVersion, minimum supported: $minSupportedGuestAgentVersion)" -color Green -endLine
    }
    else
    {
        New-Check -name 'VM agent is supported version' -result 'Failed' -details "Installed version: $guestKeyGuestAgentVersion, minimum supported version: $minSupportedGuestAgentVersion"
        Out-Log "$isAtLeastMinSupportedVersion (installed: $guestKeyGuestAgentVersion, minimum supported: $minSupportedGuestAgentVersion)" -color Red -endLine
    }
}

$autoKeyPath = 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Auto'
$autoKey = Invoke-ExpressionWithLogging "Get-ItemProperty -Path '$autoKeyPath' -ErrorAction SilentlyContinue" -verboseOnly
if ($autoKey)
{

}

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
}

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
    New-Check -name 'Proxy configured' -result 'Information' -details $proxyServers
    Out-Log $proxyConfigured -color Cyan -endLine
    $mitigation = '<a href="https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/windows-azure-guest-agent#solution-3-enable-dhcp-and-make-sure-that-the-server-isnt-blocked-by-firewalls-proxies-or-other-sources">Check proxy settings</a>'
    New-Finding -type Information -name 'Proxy configured' -description $proxyServers -mitigation $mitigation
}
else
{
    New-Check -name 'Proxy configured' -result 'Passed' -details 'No proxy configured'
    Out-Log $proxyConfigured -color Green -endLine
}

Out-Log 'TenantEncryptionCert installed:' -startLine
$tenantEncryptionCert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.FriendlyName -eq 'TenantEncryptionCert' -and $_.Issuer -eq 'DC=Windows Azure CRP Certificate Generator' -and $_.Subject -eq 'DC=Windows Azure CRP Certificate Generator'}
if ($tenantEncryptionCert)
{
    $tenantEncryptionCertInstalled = $true
    Out-Log $tenantEncryptionCertInstalled -color Green -endLine
    $subject = $tenantEncryptionCert.Subject
    $issuer =  $tenantEncryptionCert.Issuer
    $effective = Get-Date -Date $tenantEncryptionCert.NotBefore.ToUniversalTime() -Format yyyy-MM-ddTHH:mm:ssZ
    $expires = Get-Date -Date $tenantEncryptionCert.NotAfter.ToUniversalTime() -Format yyyy-MM-ddTHH:mm:ssZ
    $now = Get-Date -Date (Get-Date).ToUniversalTime() -Format yyyy-MM-ddTHH:mm:ssZ
    New-Check -name 'TenantEncryptionCert installed' -result 'Passed' -details "Subject: $subject Issuer: $issuer"

    Out-Log 'TenantEncryptionCert within validity period:' -startLine
    if ($tenantEncryptionCert.NotBefore -le [System.DateTime]::Now -and $tenantEncryptionCert.NotAfter -gt [System.DateTime]::Now)
    {
        $tenantEncryptionCertWithinValidityPeriod = $true
        Out-Log $tenantEncryptionCertWithinValidityPeriod -color Green -endLine
        New-Check -name 'TenantEncryptionCert within validity period' -result 'Passed' -details "Now: $now Effective: $effective Expires: $expires"
    }
    else
    {
        $tenantEncryptionCertWithinValidityPeriod = $false
        Out-Log $tenantEncryptionCertWithinValidityPeriod -color Red -endLine
        New-Check -name 'TenantEncryptionCert within validity period' -result 'Failed' -details "Now: $now Effective: $effective Expires: $expires"
        New-Finding -type Critical -name 'TenantEncryptionCert not within validity period' -description "Now: $now Effective: $effective Expires: $expires" -mitigation $mitigation
    }
}
else
{
    New-Check -name 'TenantEncryptionCert installed' -result 'Failed' -details ''
    New-Finding -type Critical -name 'TenantEncryptionCert not installed' -description '' -mitigation ''
}

$machineConfigx64FilePath = "$env:SystemRoot\Microsoft.NET\Framework64\v4.0.30319\config\machine.config"
#$machineConfigFilePath = "$env:SystemRoot\Microsoft.NET\Framework\v4.0.30319\Config\machine.config"
[xml]$machineConfigx64 = Get-Content -Path $machineConfigx64FilePath

Out-Log 'DHCP request returns option 245:' -startLine
$dhcpReturnedOption245 = Confirm-AzureVM
if ($dhcpReturnedOption245)
{
    Out-Log $dhcpReturnedOption245 -color Green -endLine
}
else
{
    Out-Log $dhcpReturnedOption245 -color Yellow
}

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
    New-Check -name 'Wireserver endpoint 168.63.129.16:80 reachable' -result 'Passed' -details ''
    Out-Log "$($wireserverPort80Reachable.Succeeded) $($wireserverPort80Reachable.Error)" -color Green -endline
}
else
{
    New-Check -name 'Wireserver endpoint 168.63.129.16:80 reachable' -result 'Failed' -details ''
    Out-Log $wireserverPort80Reachable.Succeeded -color Red -endLine
    New-Finding -type Critical -name 'Wireserver endpoint 168.63.129.16:80 not reachable' -description $description -mitigation $mitigation
}

Out-Log 'Wireserver endpoint 168.63.129.16:32526 reachable:' -startLine
$wireserverPort32526Reachable = Test-Port -ipAddress '168.63.129.16' -port 32526 -timeout 1000
$description = "Wireserver endpoint 168.63.129.16:32526 reachable: $($wireserverPort32526Reachable.Succeeded) $($wireserverPort80Reachable.Error)"
if ($wireserverPort32526Reachable.Succeeded)
{
    New-Check -name 'Wireserver endpoint 168.63.129.16:32526 reachable' -result 'Passed' -details ''
    Out-Log $wireserverPort32526Reachable.Succeeded -color Green -endLine
}
else
{
    New-Check -name 'Wireserver endpoint 168.63.129.16:32526 reachable' -result 'Failed' -details ''
    Out-Log "$($wireserverPort32526Reachable.Succeeded) $($wireserverPort80Reachable.Error)" -color Red -endLine
    New-Finding -type Critical -name 'Wireserver endpoint 168.63.129.16:32526 not reachable' -description $description -mitigation $mitigation
}

Out-Log 'IMDS endpoint 169.254.169.254:80 reachable:' -startLine
$imdsReachable = Test-Port -ipAddress '169.254.169.254' -port 80 -timeout 1000
$description = "IMDS endpoint 169.254.169.254:80 reachable: $($imdsReachable.Succeeded) $($imdsReachable.Error)"
if ($imdsReachable.Succeeded)
{
    New-Check -name 'IMDS endpoint 169.254.169.254:80 reachable' -result 'Passed' -details ''
    Out-Log $imdsReachable.Succeeded -color Green -endLine
}
else
{
    New-Check -name 'IMDS endpoint 169.254.169.254:80 reachable' -result 'Failed' -details ''
    Out-Log "$($imdsReachable.Succeeded) $($imdsReachable.Error)" -color Red -endLine
    New-Finding -type Information -name 'IMDS endpoint 169.254.169.254:80 not reachable' -description $description
}

if ($imdsReachable.Succeeded)
{
    Out-Log 'IMDS 169.254.169.254:80 returned expected result:' -startLine
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
        Out-Log $true -color Green -endLine

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
        Out-Log $false -color Red -endLine
    }
}

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

Out-Log '3rd-party modules in WaAppAgent.exe:' -startLine
if ($rdAgentStatusRunning)
{
    $waAppAgent = Get-Process -Name WaAppAgent -ErrorAction SilentlyContinue
    if ($waAppAgent)
    {
        $waAppAgentThirdPartyModules = $waAppAgent | Select-Object -ExpandProperty modules | Where-Object Company -NE 'Microsoft Corporation' | Select-Object ModuleName, company, description, product, filename, @{Name = 'Version'; Expression = {$_.FileVersionInfo.FileVersion}} | Sort-Object company
        if ($waAppAgentThirdPartyModules)
        {
            $details = "$($($waAppAgentThirdPartyModules.ModuleName -join ',').TrimEnd(','))"
            New-Check -name '3rd-party modules in WaAppAgent.exe' -result 'Information' -details $details
            Out-Log $true -color Cyan -endLine
            New-Finding -type Information -name '3rd-party modules in WaAppAgent.exe' -description $details -mitigation ''
        }
        else
        {
            New-Check -name '3rd-party modules in WaAppAgent.exe' -result 'Passed' -details 'No 3rd-party modules in WaAppAgent.exe'
            Out-Log $false -color Green -endLine
        }
    }
    else
    {
        $details = 'WaAppAgent.exe process not running'
        New-Check -name '3rd-party modules in WaAppAgent.exe' -result 'Information' -details $details
        Out-Log $details -color Cyan -endLine
    }
}
else
{
    $details = 'Skipped (RdAgent service not running)'
    New-Check -name '3rd-party modules in WaAppAgent.exe' -result 'Skipped' -details $details
    Out-Log $details -color DarkGray -endLine
}


Out-Log '3rd-party modules in WindowsAzureGuestAgent.exe:' -startLine
if ($windowsAzureGuestAgentStatusRunning)
{
    $windowsAzureGuestAgent = Get-Process -Name WindowsAzureGuestAgent -ErrorAction SilentlyContinue
    if ($windowsAzureGuestAgent)
    {
        $windowsAzureGuestAgentThirdPartyModules = $windowsAzureGuestAgent | Select-Object -ExpandProperty modules | Where-Object Company -NE 'Microsoft Corporation' | Select-Object ModuleName, company, description, product, filename, @{Name = 'Version'; Expression = {$_.FileVersionInfo.FileVersion}} | Sort-Object company
        if ($windowsAzureGuestAgentThirdPartyModules)
        {
            $details = "$($($windowsAzureGuestAgentThirdPartyModules.ModuleName -join ',').TrimEnd(','))"
            New-Check -name '3rd-party modules in WindowsAzureGuestAgent.exe' -result 'Information' -details $details
            Out-Log $true -color Cyan -endLine
            New-Finding -type Information -name '3rd-party modules in WindowsAzureGuestAgent.exe' -description $details -mitigation ''
        }
        else
        {
            New-Check -name '3rd-party modules in WindowsAzureGuestAgent.exe' -result 'Passed' -details 'No 3rd-party modules in WindowsAzureGuestAgent.exe'
            Out-Log $false -color Green -endLine
        }
    }
    else
    {
        $details = 'WindowsAzureGuestAgent.exe process not running'
        New-Check -name '3rd-party modules in WindowsAzureGuestAgent.exe' -result 'Information' -details $details
        Out-Log $details -color Cyan -endLine
    }
}
else
{
    $details = 'Skipped (WindowsAzureGuestAgent service not running)'
    New-Check -name '3rd-party modules in WindowsAzureGuestAgent.exe' -result 'Skipped' -details $details
    Out-Log $details -color DarkGray -endLine
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
    $details = "$machineKeysPath folder has default NTFS permissions<br>SDDL: $machineKeysSddl<br>$machineKeysAccessString"
    New-Check -name 'MachineKeys folder permissions' -result 'Passed' -details $details
}
else
{
    $machineKeysHasDefaultPermissions = $false
    Out-Log $machineKeysHasDefaultPermissions -color Cyan -endLine
    $details = "$machineKeysPath folder does not have default NTFS permissions<br>SDDL: $machineKeysSddl<br>$machineKeysAccessString"
    New-Check -name 'MachineKeys folder permissions' -result 'Information' -details $details
    $mitigation = '<a href="https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/troubleshoot-extension-certificates-issues-windows-vm#solution-2-fix-the-access-control-list-acl-in-the-machinekeys-or-systemkeys-folders">Troubleshoot extension certificates</a>'
    New-Finding -type Information -name 'Non-default MachineKeys permissions' -description $details -mitigation $mitigation
}

# Permissions on C:\WindowsAzure and c:\Packages folder during startup.
# It first removes all user/groups and then sets the following permission
# (Read & Execute: Everyone, Full Control: SYSTEM & Local Administrators only) to these folders.
# If GA fails to remove/set the permission, it can't proceed further.
$windowsAzureDefaultSddl = 'O:SYG:SYD:PAI(A;OICI;0x1200a9;;;WD)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
$windowsAzurePath = 'C:\WindowsAzure'
Out-Log "$windowsAzurePath folder has default permissions:" -startLine
$windowsAzureAcl = Get-Acl -Path $windowsAzurePath
$windowsAzureSddl = $windowsAzureAcl | Select-Object -ExpandProperty Sddl
$windowsAzureAccess = $windowsAzureAcl | Select-Object -ExpandProperty Access
$windowsAzureAccessString = $windowsAzureAccess | ForEach-Object {"$($_.IdentityReference) $($_.AccessControlType) $($_.FileSystemRights)"}
$windowsAzureAccessString = $windowsAzureAccessString -join '<br>'
if ($windowsAzureSddl -eq $windowsAzureDefaultSddl)
{
    $windowsAzureHasDefaultPermissions = $true
    Out-Log $windowsAzureHasDefaultPermissions -color Green -endLine
    $details = "$windowsAzurePath folder has default NTFS permissions<br>SDDL: $windowsAzureSddl<br>$windowsAzureAccessString"
    New-Check -name "$windowsAzurePath permissions" -result 'Passed' -details $details
}
else
{
    $windowsAzureHasDefaultPermissions = $false
    Out-Log $windowsAzureHasDefaultPermissions -color Cyan -endLine
    $details = "$windowsAzurePath does not have default NTFS permissions<br>SDDL: $windowsAzureSddl<br>$windowsAzureAccessString"
    New-Check -name "$windowsAzurePath permissions" -result 'Information' -details $details
    $mitigation = '<a href="https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/troubleshoot-extension-certificates-issues-windows-vm#solution-2-fix-the-access-control-list-acl-in-the-machinekeys-or-systemkeys-folders">Troubleshoot extension certificates</a>'
    New-Finding -type Information -name "Non-default $windowsAzurePath permissions" -description $details -mitigation $mitigation
}

$packagesDefaultSddl = 'O:BAG:SYD:PAI(A;OICI;0x1200a9;;;WD)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
$packagesPath = 'C:\Packages'
Out-Log "$packagesPath folder has default permissions:" -startLine
$packagesAcl = Get-Acl -Path $packagesPath
$packagesSddl = $packagesAcl | Select-Object -ExpandProperty Sddl
$packagesAccess = $packagesAcl | Select-Object -ExpandProperty Access
$packagessAccessString = $packagesAccess | ForEach-Object {"$($_.IdentityReference) $($_.AccessControlType) $($_.FileSystemRights)"}
$packagesAccessString = $packagessAccessString -join '<br>'
if ($packagesSddl -eq $packagesDefaultSddl)
{
    $packagesHasDefaultPermissions = $true
    Out-Log $packagesHasDefaultPermissions -color Green -endLine
    $details = "$packagesPath folder has default NTFS permissions<br>SDDL: $packagesSddl<br>$packagesAccessString"
    New-Check -name "$packagesPath permissions" -result 'Passed' -details $details
}
else
{
    $packagesHasDefaultPermissions = $false
    Out-Log $packagesHasDefaultPermissions -color Cyan -endLine
    $details = "$packagesPath does not have default NTFS permissions<br>SDDL: $packagesSddl<br>$packagesAccessString"
    New-Check -name "$packagesPath permissions" -result 'Information' -details $details
    $mitigation = '<a href="https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/troubleshoot-extension-certificates-issues-windows-vm#solution-2-fix-the-access-control-list-acl-in-the-machinekeys-or-systemkeys-folders">Troubleshoot extension certificates</a>'
    New-Finding -type Information -name "Non-default $packagesPath permissions" -description $details -mitigation $mitigation
}

$systemDriveLetter = "$env:SystemDrive" -split ':' | Select-Object -First 1
$systemDrive = Invoke-ExpressionWithLogging "Get-PSDrive -Name $systemDriveLetter" -verboseOnly
$systemDriveFreeSpaceBytes = $systemDrive | Select-Object -ExpandProperty Free
$systemDriveFreeSpaceGB = [Math]::Round($systemDriveFreeSpaceBytes/1GB,1)
$systemDriveFreeSpaceMB = [Math]::Round($systemDriveFreeSpaceBytes/1MB,1)
Out-Log "System drive does not have low disk space:" -startLine
if ($systemDriveFreeSpaceMB -lt 100)
{
    $details = "<100MB free ($($systemDriveFreeSpaceMB)MB free) on drive $systemDriveLetter"
    Out-Log $false -color Red -endLine
    New-Check -name "Low disk space check" -result 'Failed' -details $details
    New-Finding -type Critical -name "System drive low disk space" -description $details -mitigation ''
}
elseif ($systemDriveFreeSpaceGB -lt 1)
{
    $details = "<1GB free ($($systemDriveFreeSpaceGB)GB free) on drive $systemDriveLetter"
    Out-Log $false -color Yellow -endLine
    New-Check -name "Low disk space check" -result 'Warning' -details $details
    New-Finding -type Warning -name "System drive free space" -description $details -mitigation ''
}
else
{
    $details = "$($systemDriveFreeSpaceGB)GB free on system drive $systemDriveLetter"
    Out-Log $true -color Green -endLine
    New-Check -name "Low disk space check" -result 'Passed' -details $details
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

Out-Log "DHCP-assigned IP addresses" -startLine

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
    New-Check -name "DHCP-assigned IP addresses" -result 'Information' -details $dhcpDisabledNicsString
    New-Finding -type Information -name "DHCP-disabled NICs" -description $dhcpDisabledNicsString -mitigation ''
}
else
{
    $dhcpAssignedIpAddresses = $true
    Out-Log $dhcpAssignedIpAddresses -endLine -color Green
    $details = "All NICs have DHCP-assigned IP addresses"
    New-Check -name "DHCP-assigned IP addresses" -result 'Passed' -details $details
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
        td.SKIPPED {
            background: LightGrey;
            color: Black;
            text-align: left
        }
    </style>
</head>
<body>
'@

$stringBuilder = New-Object Text.StringBuilder

$css | ForEach-Object {[void]$stringBuilder.Append("$_`r`n")}
[void]$stringBuilder.Append('<h1>VM Agent Health Report</h1>')
[void]$stringBuilder.Append("<h3>NAME: $vmName VMID: $vmId Report Created: $scriptEndTimeUTCString</h3>")

[void]$stringBuilder.Append("<h2 id=`"findings`">Findings</h2>`r`n")
$findingsCount = $findings | Measure-Object | Select-Object -ExpandProperty Count
if ($findingsCount -ge 1)
{
    $findingsTable = $findings | Select-Object Type, Name, Description, Mitigation | ConvertTo-Html -Fragment -As Table
    $findingsTable = $findingsTable -replace '<td>Critical</td>', '<td class="CRITICAL">Critical</td>'
    $findingsTable = $findingsTable -replace '<td>Warning</td>', '<td class="WARNING">Warning</td>'
    $findingsTable = $findingsTable -replace '<td>Information</td>', '<td class="INFORMATION">Information</td>'
    $global:dbgFindingsTable = $findingsTable
    $findingsTable | ForEach-Object {[void]$stringBuilder.Append("$_`r`n")}
}
else
{
    [void]$stringBuilder.Append("<h3>No issues found. VM agent is healthy.</h3>`r`n")
}

$checksTable = $checks | Select-Object Name, Result, Details | ConvertTo-Html -Fragment -As Table
$checksTable = $checksTable -replace '<td>Information</td>', '<td class="INFORMATION">Information</td>'
$checksTable = $checksTable -replace '<td>Passed</td>', '<td class="PASSED">Passed</td>'
$checksTable = $checksTable -replace '<td>Failed</td>', '<td class="FAILED">Failed</td>'
$checksTable = $checksTable -replace '<td>Skipped</td>', '<td class="SKIPPED">Skipped</td>'
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

$htm = $stringBuilder.ToString()

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

$htmFileName = "$($scriptBaseName)_$($computerName)_$($scriptStartTimeString).htm"
$htmFilePath = "$logFolderPath\$htmFileName"

$htm = $htm.Replace('&lt;', '<').Replace('&gt;', '>').Replace('&quot;', '"')

$htm | Out-File -FilePath $htmFilePath
Out-Log "HTML report: $htmFilePath"
if ($installationType -ne 'Server Core')
{
    Invoke-Item -Path $htmFilePath
}

Out-Log "Log file: $logFilePath"
$scriptDuration = '{0:hh}:{0:mm}:{0:ss}.{0:ff}' -f (New-TimeSpan -Start $scriptStartTime -End (Get-Date))
Out-Log "$scriptName duration: $scriptDuration"

[int]$findingsCount = $findings | Measure-Object | Select-Object -ExpandProperty Count
if ($findingsCount -ge 1)
{
    $color = 'Cyan'
}
else
{
    $color = 'Green'
}
Out-Log "$findingsCount issue(s) found." -color $color

$todo = @'
### Last known heartbeat?
### Create warning finding for "service running but set to disabled instead of automatic" for Rdagent and WindowsAzureGuestAgent services
### Clean up 'VM agent installed' check
### Use checkaws to verify external IP, which then confirms internet access as well
### Create table with service details
### Create table with installed app details
### Available memory
### Page file settings
### Commit
### workgroup vs. domain join vs AAD joined
### filter drivers
### 3rd-party processes - get-process | where {$_.Company -and $_.Company -ne 'Microsoft Corporation'} | Select-Object Id,Name,ProcessName,Description,Product,Company,FileVersion,CommandLine
### 3rd-party kernel drivers
### Mellanox driver version
### installed extensions and their statuses (if possible to get this cleanly from inside the guest without calling CRP)
### Windows activation status, relevant reg settings, most recent software licensing service events
### Add relevant checks from Set-Wallpaper.ps1
### Need to also check for ProxySettingsPerUser https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.InternetExplorer::UserProxy
Computer Configuration\Administrative Templates\Windows Components\Internet Explorer\Make proxy settings per-machine (rather than per user)
### permissions on C:\WindowsAzure and c:\Packages folder during startup. It first removes all user/groups and then sets the following permission (Read & Execute: Everyone, Full Control: SYSTEM & Local Administrators only) to these folders. If GA fails to remove/set the permission, it can't proceed further.
WaAppAgent.log shows this: [00000006] {ALPHANUMERICPII} [FATAL] Failed to set access rules for agent directories. Exception: System.Security.Principal.IdentityNotMappedException: {Namepii} or all identity references could not be translated. Symptom reported: Guest agent not ready (Unresponsive status).
### Check for presence and validity of CRP cert
### Check for WCF Profiling being enabled
### Check that the service EXE files exist in the path specified in the registry, since we've seen those get confused
### Check for app crashes referencing guest agent processes (Application log event ID 1000), surface most recent one as well as crash count last 24 hours
### Check for system crashes (bugchecks), surface most recent one as well as crash count last 24 hours
### Update github repo readme with additional ways to run Get-VMAgentHealth.ps1
### Update Loop for bug bash to include ways to test using both Test-GetVMhealth.ps1 but also the manual commands
### Check if WinPA and/or VM agent MSI still use StdRegProv WMI, if so, add basic WMI functionality check
### Check for out-dated netvsc.sys
Get-CimInstance -Query "'SELECT Name,Status,ExitCode,Started,StartMode,ErrorControl,PathName FROM Win32_SystemDriver WHERE Name='netvsc'"
get-itemproperty hklm:\system\currentcontrolset\services\netvsc | Select-Object -ExpandProperty ImagePath
\SystemRoot\System32\drivers\netvsc63.sys - ws12r2
\SystemRoot\System32\drivers\netvsc.sys - win11,ws22
get-itemproperty hklm:\system\currentcontrolset\services\netvsc | Select-Object -ExpandProperty ImagePath
### Add mitigations for existing checks (XL)
'@
$todo = $todo.Split("`n").Trim()
