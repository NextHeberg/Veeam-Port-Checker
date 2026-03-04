#Requires -Version 5.1

<#
.SYNOPSIS
    Veeam Port Checker — Verifies network port reachability for Veeam Backup & Replication.

.DESCRIPTION
    Tests TCP/UDP connectivity and RPC/WMI availability for all ports required by
    Veeam Backup & Replication. Choose to check all ports at once or filter by
    functional category. RPC services (WMI, Hyper-V) receive enhanced two-phase
    validation that tests both port 135 and actual WMI namespace connectivity.

.PARAMETER Target
    One or more target hostnames or IP addresses, comma-separated.

.PARAMETER TimeoutMs
    Per-port connection timeout in milliseconds. Default: 3000.

.PARAMETER ExportCsv
    Export results to a CSV file.

.PARAMETER CsvPath
    Output path for the CSV file. Defaults to a timestamped name in the current directory.

.EXAMPLE
    .\Veeam-Port-Checker.ps1
    Interactive mode — prompts for target and category.

.EXAMPLE
    .\Veeam-Port-Checker.ps1 -Target "192.168.1.10" -ExportCsv
    Check all ports against a single host and export results to CSV.

.EXAMPLE
    .\Veeam-Port-Checker.ps1 -Target "vbr01,repo01,proxy01" -TimeoutMs 5000
    Check multiple hosts with a 5-second timeout.

.NOTES
    Port reference : https://helpcenter.veeam.com/docs/backup/vsphere/used_ports.html
    RPC/WMI checks : Run as Administrator on the local machine for best results.
                     The target machine must permit WMI connections from your account.
    Requires       : PowerShell 5.1 or later.
#>

[CmdletBinding()]
param(
    [Parameter(HelpMessage = 'Target hostname(s) or IP address(es), comma-separated')]
    [string]$Target,

    [Parameter(HelpMessage = 'Connection timeout per port in milliseconds (500–30000)')]
    [ValidateRange(500, 30000)]
    [int]$TimeoutMs = 3000,

    [Parameter(HelpMessage = 'Export results to a CSV file')]
    [switch]$ExportCsv,

    [Parameter(HelpMessage = 'Output path for the CSV export file')]
    [string]$CsvPath = "VeeamPortCheck_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

Set-StrictMode -Version Latest

# ==============================================================================
# PORT DATABASE
# Each entry: Category, Service, Port, Protocol, CheckType (TCP|UDP|RPC),
#             Description
# ==============================================================================

$PortDatabase = [PSCustomObject[]]@(

    # ── Core VBR Services ────────────────────────────────────────────────────
    [PSCustomObject]@{ Category = 'Core VBR Services'; Service = 'Veeam Backup Service';            Port = 9392;  Protocol = 'TCP'; CheckType = 'TCP'; Description = 'Internal VBR communication, console connection, Enterprise Manager data collection' }
    [PSCustomObject]@{ Category = 'Core VBR Services'; Service = 'Veeam Guest Catalog Service';     Port = 9393;  Protocol = 'TCP'; CheckType = 'TCP'; Description = 'Catalog replication from backup servers to Enterprise Manager' }
    [PSCustomObject]@{ Category = 'Core VBR Services'; Service = 'Secure Connections (Mount Srv)';  Port = 9401;  Protocol = 'TCP'; CheckType = 'TCP'; Description = 'Mount server to backup server secure connections' }
    [PSCustomObject]@{ Category = 'Core VBR Services'; Service = 'REST API Service';                Port = 9419;  Protocol = 'TCP'; CheckType = 'TCP'; Description = 'Veeam Backup & Replication REST API endpoint' }

    # ── Backup Proxies — VMware ───────────────────────────────────────────────
    [PSCustomObject]@{ Category = 'Backup Proxies - VMware'; Service = 'Proxy -> Backup Server';    Port = 9392;  Protocol = 'TCP'; CheckType = 'TCP'; Description = 'Backup proxy to backup server communication' }
    [PSCustomObject]@{ Category = 'Backup Proxies - VMware'; Service = 'Veeam Installer Service';   Port = 6160;  Protocol = 'TCP'; CheckType = 'TCP'; Description = 'Proxy to vSphere hosts / vCenter (installer and agent service)' }
    [PSCustomObject]@{ Category = 'Backup Proxies - VMware'; Service = 'vSphere HTTP';              Port = 80;    Protocol = 'TCP'; CheckType = 'TCP'; Description = 'Proxy to vSphere hosts (HTTP, if configured)' }
    [PSCustomObject]@{ Category = 'Backup Proxies - VMware'; Service = 'vSphere HTTPS';             Port = 443;   Protocol = 'TCP'; CheckType = 'TCP'; Description = 'Proxy to vSphere hosts (HTTPS)' }

    # ── Backup Proxies — Hyper-V ──────────────────────────────────────────────
    [PSCustomObject]@{ Category = 'Backup Proxies - Hyper-V'; Service = 'Proxy -> Backup Server';   Port = 9392;  Protocol = 'TCP'; CheckType = 'TCP'; Description = 'Backup proxy to backup server communication' }
    [PSCustomObject]@{ Category = 'Backup Proxies - Hyper-V'; Service = 'Hyper-V HTTP';             Port = 80;    Protocol = 'TCP'; CheckType = 'TCP'; Description = 'Proxy to Hyper-V hosts (HTTP)' }
    [PSCustomObject]@{ Category = 'Backup Proxies - Hyper-V'; Service = 'Hyper-V HTTPS';            Port = 443;   Protocol = 'TCP'; CheckType = 'TCP'; Description = 'Proxy to Hyper-V hosts (HTTPS)' }

    # ── Backup Repositories ───────────────────────────────────────────────────
    [PSCustomObject]@{ Category = 'Backup Repositories'; Service = 'SMB / CIFS';                    Port = 445;   Protocol = 'TCP'; CheckType = 'TCP'; Description = 'Windows SMB/CIFS file shares' }
    [PSCustomObject]@{ Category = 'Backup Repositories'; Service = 'NFS Portmapper (TCP)';          Port = 111;   Protocol = 'TCP'; CheckType = 'TCP'; Description = 'NFS portmapper / rpcbind (TCP)' }
    [PSCustomObject]@{ Category = 'Backup Repositories'; Service = 'NFS Portmapper (UDP)';          Port = 111;   Protocol = 'UDP'; CheckType = 'UDP'; Description = 'NFS portmapper / rpcbind (UDP)' }
    [PSCustomObject]@{ Category = 'Backup Repositories'; Service = 'NFS (TCP)';                     Port = 2049;  Protocol = 'TCP'; CheckType = 'TCP'; Description = 'NFS file shares (TCP)' }
    [PSCustomObject]@{ Category = 'Backup Repositories'; Service = 'NFS (UDP)';                     Port = 2049;  Protocol = 'UDP'; CheckType = 'UDP'; Description = 'NFS file shares (UDP)' }
    [PSCustomObject]@{ Category = 'Backup Repositories'; Service = 'SSH (Linux Repository)';        Port = 22;    Protocol = 'TCP'; CheckType = 'TCP'; Description = 'SSH access to Linux repositories' }
    [PSCustomObject]@{ Category = 'Backup Repositories'; Service = 'Veeam Internal (Repo)';         Port = 9392;  Protocol = 'TCP'; CheckType = 'TCP'; Description = 'Proxy <-> Repository and Mount Server <-> Repository communication' }

    # ── Cloud Storage ─────────────────────────────────────────────────────────
    [PSCustomObject]@{ Category = 'Cloud Storage'; Service = 'S3 / Azure / GCP / VDC Vault';        Port = 443;   Protocol = 'TCP'; CheckType = 'TCP'; Description = 'HTTPS to Amazon S3, Azure Blob Storage, Google Cloud, Veeam Data Cloud Vault' }

    # ── WAN Accelerators ──────────────────────────────────────────────────────
    [PSCustomObject]@{ Category = 'WAN Accelerators'; Service = 'WAN Accel -> Backup Server';       Port = 9392;  Protocol = 'TCP'; CheckType = 'TCP'; Description = 'WAN Accelerator to backup server communication' }
    [PSCustomObject]@{ Category = 'WAN Accelerators'; Service = 'WAN Traffic (primary)';            Port = 8060;  Protocol = 'TCP'; CheckType = 'TCP'; Description = 'Optimized WAN backup traffic (primary channel)' }
    [PSCustomObject]@{ Category = 'WAN Accelerators'; Service = 'WAN Traffic (secondary)';          Port = 8061;  Protocol = 'TCP'; CheckType = 'TCP'; Description = 'Optimized WAN backup traffic (secondary channel)' }
    [PSCustomObject]@{ Category = 'WAN Accelerators'; Service = 'WAN Accelerator Default';          Port = 8000;  Protocol = 'TCP'; CheckType = 'TCP'; Description = 'Default WAN Accelerator service port' }

    # ── Enterprise Manager ────────────────────────────────────────────────────
    [PSCustomObject]@{ Category = 'Enterprise Manager'; Service = 'EM Web UI (HTTPS)';              Port = 9443;  Protocol = 'TCP'; CheckType = 'TCP'; Description = 'Enterprise Manager web interface (HTTPS)' }
    [PSCustomObject]@{ Category = 'Enterprise Manager'; Service = 'EM Console Connection';          Port = 9392;  Protocol = 'TCP'; CheckType = 'TCP'; Description = 'Console connection to Enterprise Manager' }
    [PSCustomObject]@{ Category = 'Enterprise Manager'; Service = 'Veeam License Service';          Port = 10006; Protocol = 'TCP'; CheckType = 'TCP'; Description = 'Veeam licensing service' }
    [PSCustomObject]@{ Category = 'Enterprise Manager'; Service = 'SQL Server';                     Port = 1433;  Protocol = 'TCP'; CheckType = 'TCP'; Description = 'SQL Server configuration database' }
    [PSCustomObject]@{ Category = 'Enterprise Manager'; Service = 'PostgreSQL';                     Port = 5432;  Protocol = 'TCP'; CheckType = 'TCP'; Description = 'PostgreSQL configuration database (Linux appliance)' }

    # ── Guest Processing (Application-Aware) ──────────────────────────────────
    [PSCustomObject]@{ Category = 'Guest Processing (App-Aware)'; Service = 'Guest Agent / Indexing'; Port = 6160; Protocol = 'TCP'; CheckType = 'TCP'; Description = 'Application-aware processing, persistent agent, VBR guest indexing service' }

    # ── Log Shipping ──────────────────────────────────────────────────────────
    [PSCustomObject]@{ Category = 'Log Shipping'; Service = 'Log Shipping Service';                 Port = 5017;  Protocol = 'TCP'; CheckType = 'TCP'; Description = 'Transaction log shipping — default port' }
    [PSCustomObject]@{ Category = 'Log Shipping'; Service = 'SQL Server (Log Shipping)';            Port = 1433;  Protocol = 'TCP'; CheckType = 'TCP'; Description = 'SQL Server for transaction log shipping' }

    # ── Cloud Connect ─────────────────────────────────────────────────────────
    [PSCustomObject]@{ Category = 'Cloud Connect'; Service = 'Cloud Connect Repository';            Port = 9392;  Protocol = 'TCP'; CheckType = 'TCP'; Description = 'Secure Cloud Connect repository communication' }
    [PSCustomObject]@{ Category = 'Cloud Connect'; Service = 'Cloud Connect HTTPS';                 Port = 443;   Protocol = 'TCP'; CheckType = 'TCP'; Description = 'Encrypted Cloud Connect connections' }

    # ── Veeam Agents ──────────────────────────────────────────────────────────
    [PSCustomObject]@{ Category = 'Veeam Agents'; Service = 'Agent <-> Server / Repository';        Port = 6160;  Protocol = 'TCP'; CheckType = 'TCP'; Description = 'Veeam Agent for Windows/Linux: server and repository data transfer' }
    [PSCustomObject]@{ Category = 'Veeam Agents'; Service = 'Email Notifications (SMTP)';           Port = 25;    Protocol = 'TCP'; CheckType = 'TCP'; Description = 'Standard SMTP for email notifications' }
    [PSCustomObject]@{ Category = 'Veeam Agents'; Service = 'Email Notifications (SMTP/TLS)';       Port = 587;   Protocol = 'TCP'; CheckType = 'TCP'; Description = 'SMTP with TLS/STARTTLS for email notifications' }

    # ── Veeam Explorers ───────────────────────────────────────────────────────
    [PSCustomObject]@{ Category = 'Veeam Explorers'; Service = 'Exchange / SharePoint Online';      Port = 443;   Protocol = 'TCP'; CheckType = 'TCP'; Description = 'Explorer for Exchange and SharePoint Online (HTTPS)' }
    [PSCustomObject]@{ Category = 'Veeam Explorers'; Service = 'Explorer for SQL Server';           Port = 1433;  Protocol = 'TCP'; CheckType = 'TCP'; Description = 'SQL Server connection for Veeam Explorer for SQL' }

    # ── Notifications & Monitoring ────────────────────────────────────────────
    [PSCustomObject]@{ Category = 'Notifications & Monitoring'; Service = 'SNMP';                   Port = 161;   Protocol = 'UDP'; CheckType = 'UDP'; Description = 'SNMP trap / notification receiver' }
    [PSCustomObject]@{ Category = 'Notifications & Monitoring'; Service = 'Syslog';                 Port = 514;   Protocol = 'UDP'; CheckType = 'UDP'; Description = 'Syslog log forwarding' }
    [PSCustomObject]@{ Category = 'Notifications & Monitoring'; Service = 'SMTP Standard';          Port = 25;    Protocol = 'TCP'; CheckType = 'TCP'; Description = 'Standard SMTP server for alert emails' }
    [PSCustomObject]@{ Category = 'Notifications & Monitoring'; Service = 'SMTP Authenticated';     Port = 587;   Protocol = 'TCP'; CheckType = 'TCP'; Description = 'SMTP with TLS/STARTTLS authentication' }
    [PSCustomObject]@{ Category = 'Notifications & Monitoring'; Service = 'SMTPS (SSL)';            Port = 465;   Protocol = 'TCP'; CheckType = 'TCP'; Description = 'SMTP over SSL (SMTPS)' }

    # ── VMware Infrastructure ─────────────────────────────────────────────────
    [PSCustomObject]@{ Category = 'VMware Infrastructure'; Service = 'vCenter / ESXi HTTPS';        Port = 443;   Protocol = 'TCP'; CheckType = 'TCP'; Description = 'vCenter Server and ESXi HTTPS — Web Services API, management' }
    [PSCustomObject]@{ Category = 'VMware Infrastructure'; Service = 'vCenter HTTP';                Port = 80;    Protocol = 'TCP'; CheckType = 'TCP'; Description = 'vCenter Server HTTP (if configured)' }

    # ── Hyper-V Infrastructure ────────────────────────────────────────────────
    # CheckType 'RPC' triggers two-phase validation: port 135 + WMI namespace check
    [PSCustomObject]@{ Category = 'Hyper-V Infrastructure'; Service = 'RPC Endpoint Mapper + WMI';  Port = 135;   Protocol = 'TCP'; CheckType = 'RPC'; Description = 'WMI/RPC for Hyper-V management (port 135 + WMI connectivity test). Dynamic RPC ports 49152-65535 must also be permitted on the firewall.' }
    [PSCustomObject]@{ Category = 'Hyper-V Infrastructure'; Service = 'NetBIOS Name Service';       Port = 137;   Protocol = 'UDP'; CheckType = 'UDP'; Description = 'NetBIOS name resolution' }
    [PSCustomObject]@{ Category = 'Hyper-V Infrastructure'; Service = 'NetBIOS Datagram';           Port = 138;   Protocol = 'UDP'; CheckType = 'UDP'; Description = 'NetBIOS datagram service' }
    [PSCustomObject]@{ Category = 'Hyper-V Infrastructure'; Service = 'NetBIOS Session';            Port = 139;   Protocol = 'TCP'; CheckType = 'TCP'; Description = 'NetBIOS session service' }
    [PSCustomObject]@{ Category = 'Hyper-V Infrastructure'; Service = 'SMB Data Transfer';          Port = 445;   Protocol = 'TCP'; CheckType = 'TCP'; Description = 'SMB for Hyper-V VM data transfer' }
    [PSCustomObject]@{ Category = 'Hyper-V Infrastructure'; Service = 'Hyper-V HTTP';               Port = 80;    Protocol = 'TCP'; CheckType = 'TCP'; Description = 'Hyper-V Management API (HTTP)' }
    [PSCustomObject]@{ Category = 'Hyper-V Infrastructure'; Service = 'Hyper-V HTTPS';              Port = 443;   Protocol = 'TCP'; CheckType = 'TCP'; Description = 'Hyper-V Management API (HTTPS)' }

    # ── Storage Systems ───────────────────────────────────────────────────────
    [PSCustomObject]@{ Category = 'Storage Systems'; Service = 'SSH Management';                    Port = 22;    Protocol = 'TCP'; CheckType = 'TCP'; Description = 'SSH management (Dell EMC Data Domain, ExaGrid)' }
    [PSCustomObject]@{ Category = 'Storage Systems'; Service = 'Storage HTTPS API';                 Port = 443;   Protocol = 'TCP'; CheckType = 'TCP'; Description = 'HTTPS management API (HPE StoreOnce, Quantum DXi, ExaGrid, Dell EMC)' }

    # ── CDP (Continuous Data Protection) ─────────────────────────────────────
    [PSCustomObject]@{ Category = 'CDP (Continuous Data Protection)'; Service = 'CDP Driver / I/O Filter / Proxy'; Port = 6160; Protocol = 'TCP'; CheckType = 'TCP'; Description = 'CDP I/O filter driver and proxy cache communication' }
    [PSCustomObject]@{ Category = 'CDP (Continuous Data Protection)'; Service = 'CDP Appliance HTTPS';             Port = 443;  Protocol = 'TCP'; CheckType = 'TCP'; Description = 'CDP appliance management (HTTPS)' }
)

# ==============================================================================
# NETWORK TEST FUNCTIONS
# ==============================================================================

function Test-TCPPort {
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][int]   $Port,
        [Parameter(Mandatory)][int]   $TimeoutMs
    )
    $client = $null
    try {
        $client      = [System.Net.Sockets.TcpClient]::new()
        $asyncResult = $client.BeginConnect($ComputerName, $Port, $null, $null)
        $connected   = $asyncResult.AsyncWaitHandle.WaitOne($TimeoutMs, $false)

        if ($connected) {
            try {
                $client.EndConnect($asyncResult)
                return 'Open'
            } catch {
                return 'Refused'
            }
        } else {
            return 'Timeout'
        }
    } catch [System.Net.Sockets.SocketException] {
        switch ($_.Exception.SocketErrorCode) {
            'ConnectionRefused' { return 'Refused' }
            'HostNotFound'      { return 'DNS Error' }
            'NoData'            { return 'DNS Error' }
            default             { return "Error: $($_.Exception.SocketErrorCode)" }
        }
    } catch {
        return "Error: $($_.Exception.Message)"
    } finally {
        if ($null -ne $client) { $client.Close() }
    }
}

function Test-UDPPort {
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][int]   $Port,
        [Parameter(Mandatory)][int]   $TimeoutMs
    )
    # UDP is connectionless — we send a probe and watch for an ICMP Port Unreachable
    # response. If nothing comes back, the port is Open or Filtered (indistinguishable
    # without application-layer knowledge).
    $client = $null
    try {
        $client = [System.Net.Sockets.UdpClient]::new()
        $client.Client.ReceiveTimeout = $TimeoutMs
        $client.Connect($ComputerName, $Port)

        $probe = [byte[]]@(0x00)
        $client.Send($probe, $probe.Length) | Out-Null

        try {
            $ep = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
            $client.Receive([ref]$ep) | Out-Null
            return 'Open'
        } catch [System.Net.Sockets.SocketException] {
            $code = $_.Exception.SocketErrorCode
            if ($code -in @([System.Net.Sockets.SocketError]::ConnectionReset,
                            [System.Net.Sockets.SocketError]::ConnectionRefused)) {
                return 'Closed'   # ICMP Port Unreachable received
            }
            if ($code -eq [System.Net.Sockets.SocketError]::TimedOut) {
                return 'Open|Filtered'   # No ICMP response within timeout
            }
            return "Error: $code"
        }
    } catch {
        return "Error: $($_.Exception.Message)"
    } finally {
        if ($null -ne $client) { $client.Close() }
    }
}

function Test-RPCService {
    # Two-phase RPC/WMI validation:
    #   Phase 1 — TCP port 135 (RPC Endpoint Mapper)
    #   Phase 2 — WMI namespace connectivity (root\cimv2)
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][int]   $TimeoutMs
    )

    $p135 = Test-TCPPort -ComputerName $ComputerName -Port 135 -TimeoutMs $TimeoutMs
    if ($p135 -ne 'Open') {
        return [PSCustomObject]@{
            Status = $p135
            Detail = "RPC Endpoint Mapper (port 135): $p135"
        }
    }

    try {
        $opts         = [System.Management.ConnectionOptions]::new()
        $opts.Timeout = [System.TimeSpan]::FromMilliseconds($TimeoutMs)
        $scope        = [System.Management.ManagementScope]::new("\\$ComputerName\root\cimv2", $opts)
        $scope.Connect()
        return [PSCustomObject]@{
            Status = 'Open'
            Detail = 'Port 135 reachable; WMI connection successful'
        }
    } catch {
        return [PSCustomObject]@{
            Status = 'Open/WMI-Failed'
            Detail = "Port 135 reachable; WMI failed: $($_.Exception.Message)"
        }
    }
}

# ==============================================================================
# OUTPUT HELPERS
# ==============================================================================

function Get-StatusColor {
    param([string]$Status)
    switch -Wildcard ($Status) {
        'Open'           { return 'Green' }
        'Open*'          { return 'Yellow' }     # Open|Filtered, Open/WMI-Failed
        'Closed'         { return 'Red' }
        'Refused'        { return 'Red' }
        'Timeout'        { return 'DarkYellow' }
        'DNS Error'      { return 'Magenta' }
        default          { return 'Gray' }
    }
}

function Write-ResultRow {
    param([Parameter(Mandatory)][PSCustomObject]$Result)
    $color     = Get-StatusColor -Status $Result.Status
    $portProto = '{0}/{1}' -f $Result.Port, $Result.Protocol

    Write-Host ('  {0,-36} {1,-10} ' -f $Result.Service, $portProto) -NoNewline
    Write-Host $Result.Status -ForegroundColor $color -NoNewline
    if ($Result.Detail) {
        Write-Host " -- $($Result.Detail)" -ForegroundColor DarkGray
    } else {
        Write-Host ''
    }
}

function Show-CategoryHeader {
    param([string]$Name)
    Write-Host ''
    Write-Host "  >> $Name" -ForegroundColor DarkCyan
}

function Show-Legend {
    Write-Host ''
    Write-Host '  Status legend:' -ForegroundColor DarkGray
    Write-Host '    Open          -- Port reachable and accepting connections' -ForegroundColor Green
    Write-Host '    Refused       -- Reachable but connection refused (service may be stopped)' -ForegroundColor Red
    Write-Host '    Closed        -- UDP: ICMP Port Unreachable received' -ForegroundColor Red
    Write-Host '    Timeout       -- No response within timeout (firewall drop or host unreachable)' -ForegroundColor DarkYellow
    Write-Host '    Open|Filtered -- UDP: no ICMP response; port may be open or silently dropped' -ForegroundColor Yellow
    Write-Host '    Open/WMI-Fail -- RPC port 135 open but WMI namespace unreachable' -ForegroundColor Yellow
    Write-Host '    DNS Error     -- Target hostname could not be resolved' -ForegroundColor Magenta
    Write-Host ''
}

function Show-Summary {
    param(
        [Parameter(Mandatory)][PSCustomObject[]]$Results,
        [Parameter(Mandatory)][string]           $HostName
    )
    $total    = $Results.Count
    $open     = ($Results | Where-Object { $_.Status -eq 'Open' }).Count
    $closed   = ($Results | Where-Object { $_.Status -in @('Closed', 'Refused') }).Count
    $timeout  = ($Results | Where-Object { $_.Status -eq 'Timeout' }).Count
    $filtered = ($Results | Where-Object { $_.Status -like 'Open*' -and $_.Status -ne 'Open' }).Count
    $errors   = ($Results | Where-Object { $_.Status -like 'Error*' -or $_.Status -eq 'DNS Error' }).Count

    $line = '  ' + ('=' * 50)
    Write-Host ''
    Write-Host $line -ForegroundColor Cyan
    Write-Host "  SUMMARY -- $HostName" -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Cyan
    Write-Host ("  Total checks   : {0}" -f $total)
    Write-Host ("  Open           : {0}" -f $open)     -ForegroundColor Green
    Write-Host ("  Closed/Refused : {0}" -f $closed)   -ForegroundColor Red
    Write-Host ("  Timeout        : {0}" -f $timeout)  -ForegroundColor DarkYellow
    Write-Host ("  Open|Filtered  : {0}  (UDP -- open or silently dropped)" -f $filtered) -ForegroundColor Yellow
    Write-Host ("  Errors         : {0}" -f $errors)   -ForegroundColor Gray
    Write-Host $line -ForegroundColor Cyan
    Write-Host ''
}

# ==============================================================================
# BANNER & MENU
# ==============================================================================

function Show-Banner {
    Write-Host ''
    Write-Host '  +--------------------------------------------------------------+' -ForegroundColor Cyan
    Write-Host '  |       VEEAM PORT CHECKER  --  Backup & Replication           |' -ForegroundColor Cyan
    Write-Host '  |   Validates port reachability for Veeam infrastructure       |' -ForegroundColor Cyan
    Write-Host '  |   Ref: helpcenter.veeam.com/docs/backup/vsphere/used_ports   |' -ForegroundColor Cyan
    Write-Host '  +--------------------------------------------------------------+' -ForegroundColor Cyan
    Write-Host ''
}

function Get-ValidatedTargets {
    param([string]$InputString)
    $raw = $InputString -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
    $valid = foreach ($t in $raw) {
        if ($t -match '^[a-zA-Z0-9.\-_\[\]:]+$') {
            $t
        } else {
            Write-Warning "Skipping invalid target: '$t'"
        }
    }
    return @($valid)
}

function Show-CheckModeMenu {
    param([string[]]$Categories)
    Write-Host '  Select check mode:' -ForegroundColor White
    Write-Host ''
    Write-Host '  [0]  All Ports  (one test per unique port/protocol combination)' -ForegroundColor Cyan
    Write-Host ''
    for ($i = 0; $i -lt $Categories.Count; $i++) {
        Write-Host ('  [{0,-2}] {1}' -f ($i + 1), $Categories[$i]) -ForegroundColor White
    }
    Write-Host ''
    Write-Host '  [Q]  Quit' -ForegroundColor DarkGray
    Write-Host ''
    return (Read-Host '  Your choice').Trim()
}

# ==============================================================================
# CHECK ENGINE
# ==============================================================================

function Invoke-SingleCheck {
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)][string]        $ComputerName,
        [Parameter(Mandatory)][PSCustomObject] $Entry,
        [Parameter(Mandatory)][int]            $TimeoutMs
    )
    $status = $null
    $detail = $null

    switch ($Entry.CheckType) {
        'TCP' {
            $status = Test-TCPPort -ComputerName $ComputerName -Port $Entry.Port -TimeoutMs $TimeoutMs
        }
        'UDP' {
            $status = Test-UDPPort -ComputerName $ComputerName -Port $Entry.Port -TimeoutMs $TimeoutMs
        }
        'RPC' {
            $rpc    = Test-RPCService -ComputerName $ComputerName -TimeoutMs $TimeoutMs
            $status = $rpc.Status
            $detail = $rpc.Detail
        }
    }

    return [PSCustomObject]@{
        Target      = $ComputerName
        Category    = $Entry.Category
        Service     = $Entry.Service
        Port        = $Entry.Port
        Protocol    = $Entry.Protocol
        CheckType   = $Entry.CheckType
        Status      = $status
        Detail      = $detail
        Description = $Entry.Description
    }
}

function Invoke-PortChecks {
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)][string]          $ComputerName,
        [Parameter(Mandatory)][PSCustomObject[]] $Entries,
        [Parameter(Mandatory)][int]              $TimeoutMs
    )

    $results      = [System.Collections.Generic.List[PSCustomObject]]::new()
    $prevCategory = $null
    $hasRPC       = @($Entries | Where-Object { $_.CheckType -eq 'RPC' }).Count -gt 0

    Write-Host ''
    Write-Host "  ====  Target: $ComputerName  ====" -ForegroundColor White

    if ($hasRPC) {
        Write-Host ''
        Write-Host '  NOTE: RPC/WMI checks also require dynamic ports 49152-65535.' -ForegroundColor DarkYellow
        Write-Host '        Ensure your firewall permits those ports in addition to 135.' -ForegroundColor DarkYellow
    }

    Write-Host ''
    Write-Host ('  {0,-36} {1,-10} {2}' -f 'Service', 'Port/Proto', 'Status') -ForegroundColor DarkGray
    Write-Host ('  ' + ('-' * 65)) -ForegroundColor DarkGray

    foreach ($entry in $Entries) {
        if ($entry.Category -ne $prevCategory) {
            Show-CategoryHeader -Name $entry.Category
            $prevCategory = $entry.Category
        }
        $result = Invoke-SingleCheck -ComputerName $ComputerName -Entry $entry -TimeoutMs $TimeoutMs
        Write-ResultRow -Result $result
        $results.Add($result)
    }

    return $results.ToArray()
}

# ==============================================================================
# MAIN
# ==============================================================================

Show-Banner

# -- 1. Collect and validate targets ------------------------------------------
if (-not $Target) {
    Write-Host '  Enter one or more target hostnames or IP addresses.' -ForegroundColor Gray
    Write-Host '  Separate multiple targets with commas (e.g. vbr01,repo01,192.168.1.5).' -ForegroundColor Gray
    Write-Host ''
    $Target = Read-Host '  Target(s)'
}

$targets = @(Get-ValidatedTargets -InputString $Target)
if ($targets.Count -eq 0) {
    Write-Host '  No valid targets provided. Exiting.' -ForegroundColor Red
    exit 1
}

# -- 2. Build category list and show menu -------------------------------------
$categories = $PortDatabase |
    Select-Object -ExpandProperty Category -Unique |
    Sort-Object

Write-Host ''
$choice = Show-CheckModeMenu -Categories $categories

# -- 3. Resolve which entries to test -----------------------------------------
$entriesToCheck = @()

switch -Regex ($choice) {
    '^0$' {
        # All ports — deduplicate by (Port, Protocol, CheckType) to avoid
        # testing the same socket endpoint multiple times
        $seen = [System.Collections.Generic.HashSet[string]]::new()
        $entriesToCheck = @(
            foreach ($e in $PortDatabase) {
                $key = '{0}_{1}_{2}' -f $e.Port, $e.Protocol, $e.CheckType
                if ($seen.Add($key)) { $e }
            }
        ) | Sort-Object Category, Port

        Write-Host "  Mode: All Ports -- $($entriesToCheck.Count) unique checks" -ForegroundColor Cyan
        break
    }

    '^[1-9]\d*$' {
        $idx = [int]$choice - 1
        if ($idx -ge $categories.Count) {
            Write-Host '  Selection out of range.' -ForegroundColor Red
            exit 1
        }
        $selectedCategory = $categories[$idx]
        $entriesToCheck   = @($PortDatabase | Where-Object { $_.Category -eq $selectedCategory })

        Write-Host "  Mode: $selectedCategory -- $($entriesToCheck.Count) checks" -ForegroundColor Cyan
        break
    }

    '^[qQ]$' {
        Write-Host '  Exiting.' -ForegroundColor Gray
        exit 0
    }

    default {
        Write-Host "  Invalid selection: '$choice'" -ForegroundColor Red
        exit 1
    }
}

if ($entriesToCheck.Count -eq 0) {
    Write-Host '  No entries to check.' -ForegroundColor Yellow
    exit 0
}

Show-Legend

# -- 4. Run checks for each target --------------------------------------------
$allResults = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($t in $targets) {
    $results = Invoke-PortChecks -ComputerName $t -Entries $entriesToCheck -TimeoutMs $TimeoutMs
    $allResults.AddRange([PSCustomObject[]]$results)
    Show-Summary -Results $results -HostName $t
}

# -- 5. Export to CSV (optional) ----------------------------------------------
if ($ExportCsv) {
    try {
        $allResults |
            Select-Object Target, Category, Service, Port, Protocol, CheckType, Status, Detail, Description |
            Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
        Write-Host "  Results exported to: $CsvPath" -ForegroundColor Cyan
    } catch {
        Write-Warning "CSV export failed: $($_.Exception.Message)"
    }
}

Write-Host '  Done.' -ForegroundColor Cyan
Write-Host ''
