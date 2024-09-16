<#
.SYNOPSIS
    Scans hosts within a given CIDR range for availability and open ports.
.DESCRIPTION
    This script takes a CIDR notation as input and checks if hosts within that range are alive.
    It supports multiple CIDR inputs, custom ping count, timeout, and output options.
    Additionally, it can perform port scanning on alive hosts and resolve DNS names.
.PARAMETER CIDR
    The CIDR notation(s) to scan. Can be a single CIDR or an array of CIDRs.
.PARAMETER PingCount
    The number of ping attempts per host. Default is 1.
.PARAMETER Timeout
    The timeout in milliseconds for each ping attempt. Default is 1000ms.
.PARAMETER ShowAll
    If set, shows results for all hosts, not just the alive ones.
.PARAMETER ExportCSV
    If provided, exports the results to a CSV file at the specified path.
.PARAMETER HostThrottleLimit
    The maximum number of concurrent host scanning operations. Default is 100.
.PARAMETER PortThrottleLimit
    The maximum number of concurrent port scanning operations. Default is 50.
.PARAMETER ResolveDNS
    If set, resolves the DNS name for each host.
.PARAMETER Ports
    The list of ports to scan on alive hosts.
.PARAMETER TopPorts
    The number of top ports to scan. Valid values are 10, 20, 30, 40, or 50.
.PARAMETER LogFile
    The path to the log file. Default is ".\scan_log.txt".
.PARAMETER OutputFormat
    The output format for the results. Valid values are "CSV", "JSON", or "XML". Default is "CSV".
.PARAMETER Exclude
    The IP addresses or subnets to exclude from the scan.
.PARAMETER UseTcpSyn
    If set, uses TCP SYN packets for host discovery instead of ICMP echo requests.
.PARAMETER NetworkInterface
    The network interface to use for scanning.
.PARAMETER Help
    Displays the help information for this script.
.PARAMETER Detailed
    Displays detailed help information for this script.
.EXAMPLE
    .\scanner.ps1 -CIDR "192.168.1.0/24" -PingCount 2 -Timeout 500 -ShowAll
.EXAMPLE
    .\scanner.ps1 -CIDR "10.0.0.0/24","172.16.0.0/16" -ExportCSV "C:\results.csv"
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false, Position = 0)]
    [string[]]$CIDR,
    
    [Parameter(Mandatory = $false)]
    [switch]$Help,
    
    [Parameter(Mandatory = $false)]
    [switch]$Detailed,
    
    [Parameter(Mandatory = $false)]
    [int]$PingCount = 1,
    
    [Parameter(Mandatory = $false)]
    [int]$Timeout = 1000,
    
    [Parameter(Mandatory = $false)]
    [switch]$ShowAll,
    
    [Parameter(Mandatory = $false)]
    [string]$ExportCSV,

    [Parameter(Mandatory = $false)]
    [int]$HostThrottleLimit = 100,

    [Parameter(Mandatory = $false)]
    [int]$PortThrottleLimit = 50,

    [Parameter(Mandatory = $false)]
    [switch]$ResolveDNS,

    [Parameter(Mandatory = $false)]
    [int[]]$Ports,

    [Parameter(Mandatory = $false)]
    [ValidateSet(10, 20, 30, 40, 50)]
    [int]$TopPorts,

    [Parameter(Mandatory = $false)]
    [string]$LogFile = ".\scan_log.txt",

    [Parameter(Mandatory = $false)]
    [ValidateSet("CSV", "JSON", "XML")]
    [string]$OutputFormat = "CSV",

    [Parameter(Mandatory = $false)]
    [string[]]$Exclude,

    [Parameter(Mandatory = $false)]
    [switch]$UseTcpSyn,

    [Parameter(Mandatory = $false)]
    [string]$NetworkInterface
)

if ($Help -or $Detailed) {
    Get-Help $MyInvocation.MyCommand.Path -Detailed:$Detailed
    exit
}

if (-not $CIDR) {
    Write-Host "Error: CIDR parameter is required when not using -Help or -Detailed." -ForegroundColor Red
    exit
}

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

function Get-IPRange {
    param ([string]$CIDR)

    $network, $subnetBits = $CIDR.Split('/')
    $ipAddress = [System.Net.IPAddress]::Parse($network)
    $ipBytes = $ipAddress.GetAddressBytes()
    [Array]::Reverse($ipBytes)
    $ipInt = [System.BitConverter]::ToUInt32($ipBytes, 0)

    $maskInt = ([Math]::Pow(2, 32) - 1) -shl (32 - [int]$subnetBits)
    $startIP = $ipInt -band $maskInt
    $endIP = $startIP + ($maskInt -bxor 0xFFFFFFFF)

    for ($i = $startIP; $i -le $endIP; $i++) {
        $bytes = [System.BitConverter]::GetBytes($i)
        [Array]::Reverse($bytes)
        [System.Net.IPAddress]::new($bytes).ToString()
    }
}

$topPortsList = @{
    10 = @(20, 21, 22, 23, 25, 53, 80, 110, 443, 3389)
    20 = @(20, 21, 22, 23, 25, 53, 80, 110, 443, 3389, 143, 445, 993, 995, 1723, 3306, 5900, 8080, 8443, 9100)
    30 = @(20, 21, 22, 23, 25, 53, 80, 110, 443, 3389, 143, 445, 993, 995, 1723, 3306, 5900, 8080, 8443, 9100, 135, 139, 1433, 1521, 2049, 3690, 5060, 5432, 5901, 6001)
    40 = @(20, 21, 22, 23, 25, 53, 80, 110, 443, 3389, 143, 445, 993, 995, 1723, 3306, 5900, 8080, 8443, 9100, 135, 139, 1433, 1521, 2049, 3690, 5060, 5432, 5901, 6001, 389, 636, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720)
    50 = @(20, 21, 22, 23, 25, 53, 80, 110, 443, 3389, 143, 445, 993, 995, 1723, 3306, 5900, 8080, 8443, 9100, 135, 139, 1433, 1521, 2049, 3690, 5060, 5432, 5901, 6001, 389, 636, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128)
}

if ($TopPorts) {
    $Ports = $topPortsList[$TopPorts]
}

function Test-Port {
    param(
        [string]$ComputerName,
        [int]$Port,
        [int]$Timeout
    )
    
    $tcpClient = New-Object System.Net.Sockets.TcpClient
    $connect = $tcpClient.BeginConnect($ComputerName, $Port, $null, $null)
    $wait = $connect.AsyncWaitHandle.WaitOne($Timeout, $false)
    
    if (!$wait) {
        $tcpClient.Close()
        return $false
    }
    else {
        $tcpClient.EndConnect($connect)
        $tcpClient.Close()
        return $true
    }
}

function Write-Log {
    param ([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Add-Content -Path $LogFile -Value $logMessage
    Write-Verbose $logMessage
}

function Get-ServiceName {
    param ([int]$Port)
    $commonPorts = @{
        20 = "FTP-Data"; 21 = "FTP"; 22 = "SSH"; 23 = "Telnet"; 25 = "SMTP";
        53 = "DNS"; 80 = "HTTP"; 110 = "POP3"; 143 = "IMAP"; 443 = "HTTPS";
        3389 = "RDP"; 3306 = "MySQL"; 5432 = "PostgreSQL"
    }
    if ($commonPorts.ContainsKey($Port)) { return $commonPorts[$Port] }
    return "Unknown"
}

function Resolve-DnsAsync {
    param ([string[]]$IpAddresses)
    $runspacePool = [runspacefactory]::CreateRunspacePool(1, [Environment]::ProcessorCount)
    $runspacePool.Open()
    $runspaces = @()

    foreach ($ip in $IpAddresses) {
        $powershell = [powershell]::Create().AddScript({
                param($IP)
                try {
                    [System.Net.Dns]::GetHostEntry($IP).HostName
                }
                catch {
                    "Unable to resolve"
                }
            }).AddArgument($ip)
        $powershell.RunspacePool = $runspacePool
        $runspaces += [PSCustomObject]@{
            IP         = $ip
            Runspace   = $powershell.BeginInvoke()
            PowerShell = $powershell
        }
    }

    $results = @{}
    foreach ($runspace in $runspaces) {
        $results[$runspace.IP] = $runspace.PowerShell.EndInvoke($runspace.Runspace)
        $runspace.PowerShell.Dispose()
    }
    $runspacePool.Close()
    $runspacePool.Dispose()
    return $results
}

function ConvertFrom-PortRanges {
    param ([string[]]$PortInput)
    $parsedPorts = @()
    foreach ($item in $PortInput) {
        if ($item -match '^\d+$') {
            $parsedPorts += [int]$item
        }
        elseif ($item -match '^(\d+)-(\d+)$') {
            $start = [int]$Matches[1]
            $end = [int]$Matches[2]
            $parsedPorts += $start..$end
        }
    }
    return $parsedPorts | Sort-Object -Unique
}

function Test-TcpConnection {
    param(
        [string]$ComputerName,
        [int]$Port = 80,
        [int]$Timeout = 1000
    )

    $tcpClient = New-Object System.Net.Sockets.TcpClient
    try {
        $result = $tcpClient.BeginConnect($ComputerName, $Port, $null, $null)
        $success = $result.AsyncWaitHandle.WaitOne($Timeout, $false)
        if ($success) {
            $tcpClient.EndConnect($result)
            return $true
        }
    }
    catch {}
    finally {
        $tcpClient.Close()
    }
    return $false
}

function Export-Results {
    param (
        [Array]$Results,
        [string]$OutputFormat,
        [string]$ExportPath
    )

    try {
        switch ($OutputFormat) {
            "CSV" {
                $Results | Select-Object IPAddress, Hostname, Status, @{Name = 'OpenPorts'; Expression = { $_.OpenPorts -join ', ' } }, CIDR | Export-Csv -Path $ExportPath -NoTypeInformation -ErrorAction Stop
            }
            "JSON" {
                $Results | ConvertTo-Json | Out-File -FilePath $ExportPath -ErrorAction Stop
            }
            "XML" {
                $Results | Export-Clixml -Path $ExportPath -ErrorAction Stop
            }
        }
        Write-Host "Results exported to: $ExportPath" -ForegroundColor Yellow
    }
    catch {
        Write-Host "Error exporting results: $_" -ForegroundColor Red
        Write-Log "Error exporting results: $_" -Level "ERROR"
        throw
    }
}

Write-Host "`n==== Network Scanner ====" -ForegroundColor Cyan
Write-Host "Scanning CIDR(s): $($CIDR -join ', ')" -ForegroundColor Green
Write-Host "Ping Count: $PingCount" -ForegroundColor Green
Write-Host "Timeout: $Timeout ms" -ForegroundColor Green
Write-Host "Show All Hosts: $ShowAll" -ForegroundColor Green
Write-Host "Host Throttle Limit: $HostThrottleLimit" -ForegroundColor Green
Write-Host "Resolve DNS: $ResolveDNS" -ForegroundColor Green
if ($Ports) {
    Write-Host "Ports to scan: $($Ports -join ', ')" -ForegroundColor Green
    Write-Host "Port Throttle Limit: $PortThrottleLimit" -ForegroundColor Green
}
else {
    Write-Host "Port scanning: Disabled" -ForegroundColor Green
}
Write-Host "Output Format: $OutputFormat" -ForegroundColor Green
if ($Exclude) {
    Write-Host "Excluded IPs/Subnets: $($Exclude -join ', ')" -ForegroundColor Green
}
Write-Host "Use TCP SYN: $UseTcpSyn" -ForegroundColor Green
if ($NetworkInterface) {
    Write-Host "Network Interface: $NetworkInterface" -ForegroundColor Green
}
Write-Host "==============================`n" -ForegroundColor Cyan

$totalHosts = 0
$aliveHosts = 0

try {
    # Wrap the main scanning logic in a try-catch block
    $results = foreach ($cidrRange in $CIDR) {
        Write-Host "Scanning range: $cidrRange" -ForegroundColor Yellow
        $ipAddresses = Get-IPRange -CIDR $cidrRange
        $totalHosts += $ipAddresses.Count

        # Add this line to filter out excluded IPs
        $ipAddresses = $ipAddresses | Where-Object { $_ -notin $Exclude }

        $remainingHosts = $ipAddresses

        Write-Host "Phase 1: Host Discovery" -ForegroundColor Magenta
        $hostResults = $remainingHosts | ForEach-Object -ThrottleLimit $HostThrottleLimit -Parallel {
            $ip = $_
            $timeoutSeconds = [Math]::Max(1, $using:Timeout / 1000)
            $result = Test-Connection -ComputerName $ip -Count $using:PingCount -Quiet -TimeoutSeconds $timeoutSeconds
            $status = if ($result) { "Alive" } else { "Not responding" }
            
            $hostname = if ($using:ResolveDNS -and $result) {
                try {
                    [System.Net.Dns]::GetHostEntry($ip).HostName
                }
                catch {
                    "Unable to resolve"
                }
            }
            else {
                "N/A"
            }

            # Report progress
            $progressParams = @{
                Activity        = "Host Discovery"
                Status          = "Scanning $ip"
                PercentComplete = (([array]::IndexOf($using:ipAddresses, $ip) + 1) / $using:ipAddresses.Count * 100)
                Id              = 1  # Assign a specific ID for the host scanning progress bar
            }
            Write-Progress @progressParams

            [PSCustomObject]@{
                IPAddress = $ip
                Hostname  = $hostname
                Status    = $status
                CIDR      = $using:cidrRange
                IsAlive   = $result
            }
        }

        # Clear the host scanning progress bar
        Write-Progress -Activity "Host Discovery" -Completed -Id 1

        # Display alive hosts after Phase 1
        $hostResults | Where-Object { $_.IsAlive -or $ShowAll } | ForEach-Object {
            $color = if ($_.IsAlive) { "Green" } else { "Red" }
            Write-Host ("{0,-15} {1,-20} {2,-15}" -f $_.IPAddress, $_.Hostname, $_.Status) -ForegroundColor $color
        }

        $aliveHosts += ($hostResults | Where-Object { $_.IsAlive }).Count

        if ($Ports) {
            Write-Host "`nPhase 2: Port Scanning" -ForegroundColor Magenta
            $portResults = $hostResults | Where-Object { $_.IsAlive } | ForEach-Object -ThrottleLimit $PortThrottleLimit -Parallel {
                $ip = $_.IPAddress
                $openPorts = @()
                
                # Define the Test-Port function within the parallel scriptblock
                function Test-Port {
                    param(
                        [string]$ComputerName,
                        [int]$Port,
                        [int]$Timeout
                    )
                    
                    $tcpClient = New-Object System.Net.Sockets.TcpClient
                    $connect = $tcpClient.BeginConnect($ComputerName, $Port, $null, $null)
                    $wait = $connect.AsyncWaitHandle.WaitOne($Timeout, $false)
                    
                    if (!$wait) {
                        $tcpClient.Close()
                        return $false
                    }
                    else {
                        $tcpClient.EndConnect($connect)
                        $tcpClient.Close()
                        return $true
                    }
                }

                foreach ($port in $using:Ports) {
                    if (Test-Port -ComputerName $ip -Port $port -Timeout $using:Timeout) {
                        $openPorts += $port
                    }

                    # Report progress
                    # Update progress bar with a specific ID for port scanning
                    $progressParams = @{
                        Activity        = "Port Scanning"
                        Status          = "Scanning $ip : Port $port"
                        PercentComplete = (([array]::IndexOf($using:Ports, $port) + 1) / $using:Ports.Count * 100)
                        Id              = 2  # Assign a specific ID for the port scanning progress bar
                    }
                    Write-Progress @progressParams

                }
                
                [PSCustomObject]@{
                    IPAddress = $ip
                    OpenPorts = $openPorts
                }
            }

            # Clear the port scanning progress bar
            Write-Progress -Activity "Port Scanning" -Completed -Id 2

            # Display alive hosts with open ports after Phase 2
            $hostResults | ForEach-Object {
                $portInfo = $portResults | Where-Object { $_.IPAddress -eq $_.IPAddress }
                $_ | Add-Member -MemberType NoteProperty -Name OpenPorts -Value ($portInfo.OpenPorts | Select-Object -Unique) -Force

                if ($_.IsAlive) {
                    $portDisplay = if ($_.OpenPorts) { "$($_.OpenPorts -join ', ')" } else { "None" }
                    Write-Host ("{0,-15} {1,-20} {2,-7} {3,-20}" -f $_.IPAddress, $_.Hostname, "Alive", "Open ports: $portDisplay") -ForegroundColor Green
                }
                elseif ($ShowAll) {
                    Write-Host ("{0,-15} {1,-20} {2,-7}" -f $_.IPAddress, "N/A", "Down") -ForegroundColor Red
                }
            }
        }

        $hostResults
    }

    $stopwatch.Stop()

    Write-Host "`n==== Scan Summary ====" -ForegroundColor Cyan
    Write-Host "Total hosts scanned: $totalHosts" -ForegroundColor Green
    Write-Host "Alive hosts found: $aliveHosts" -ForegroundColor Green
    Write-Host "Scan duration: $($stopwatch.Elapsed.ToString())" -ForegroundColor Green
    if ($Ports) {
        $totalOpenPorts = ($results | Where-Object { $_.IsAlive } | ForEach-Object { $_.OpenPorts.Count } | Measure-Object -Sum).Sum
        Write-Host "Total open ports found: $totalOpenPorts" -ForegroundColor Green
    }
    Write-Host "Output Format: $OutputFormat" -ForegroundColor Green

    if ($results.Count -gt 0) {
        if ($ExportCSV) {
            $exportPath = $ExportCSV
        }
        else {
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $extension = $OutputFormat.ToLower()
            $exportPath = ".\scan_results_${timestamp}.${extension}"
        }

        Export-Results -Results $results -OutputFormat $OutputFormat -ExportPath $exportPath
    }
    else {
        Write-Host "No results to export." -ForegroundColor Yellow
        Write-Log "No results to export." -Level "WARNING"
    }

    Write-Host "`nScan completed." -ForegroundColor Green
}
catch {
    Write-Host "An error occurred during the scan: $_" -ForegroundColor Red
    Write-Log "An error occurred during the scan: $_" -Level "ERROR"
}
finally {
    # Ensure that the progress bar is cleared even if an error occurs
    Write-Progress -Activity "Scanning hosts" -Completed
    Write-Progress -Activity "Scanning ports" -Completed
}