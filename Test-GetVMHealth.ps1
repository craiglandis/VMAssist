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
\\tsclient\c\src\Get-VMHealth\Test-GetVMHealth.ps1 -enableProxy
\\tsclient\c\src\Get-VMHealth\Test-GetVMHealth.ps1 -disableProxy

#>
param(
    [switch]$setprofile,
    [switch]$blockwireserver,
    [switch]$blockimds,
    [switch]$unblockwireserver,
    [switch]$unblockimds,
    [switch]$enableProxy,
    [switch]$disableProxy,
    [switch]$loadModule, # https://chat.openai.com/share/cc75e85d-da52-455e-a945-a826af4d3866
    [switch]$unloadModule
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

if ($enableProxy)
{
    Invoke-ExpressionWithLogging "netsh winhttp set proxy proxy-server='http=192.168.0.1:8080;https=192.168.0.1:8080'"
    Invoke-ExpressionWithLogging "netsh winhttp show proxy"
}

if ($disableProxy)
{
    Invoke-ExpressionWithLogging "netsh winhttp reset proxy"
    Invoke-ExpressionWithLogging "netsh winhttp show proxy"
}