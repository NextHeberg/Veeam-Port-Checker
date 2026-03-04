#Requires -Version 5.1
<#
.SYNOPSIS
    Veeam Port Checker - Tests network port accessibility for Veeam Backup & Replication.

.DESCRIPTION
    Verifies TCP and UDP port connectivity from this machine to a target host for all ports
    required by Veeam Backup & Replication. Supports checking all ports at once or by
    component category. Also includes a dedicated Windows RPC service check.

.PARAMETER Target
    Target hostname or IP address to test against.

.PARAMETER TimeoutMs
    TCP connection timeout per port in milliseconds. Default: 3000.

.EXAMPLE
    .\Veeam-Port-Checker.ps1
    .\Veeam-Port-Checker.ps1 -Target 192.168.1.100
    .\Veeam-Port-Checker.ps1 -Target veeam-server.contoso.com -TimeoutMs 5000
#>

[CmdletBinding()]
param(
    [string]$Target    = "",
    [int]   $TimeoutMs = 3000
)

# ==============================================================================
# PORT DEFINITIONS
# Each entry: Port, Protocol (TCP|UDP), Service name, Description
# ==============================================================================
$PortDefinitions = [ordered]@{

    "Core VBR Services" = @(
        [PSCustomObject]@{ Port = 9392; Protocol = "TCP"; Service = "Veeam Backup Service";  Description = "Internal VBR communication and console connection" }
        [PSCustomObject]@{ Port = 9393; Protocol = "TCP"; Service = "Catalog Service";       Description = "Guest Catalog Service / EM data replication" }
        [PSCustomObject]@{ Port = 9401; Protocol = "TCP"; Service = "Secure Connections";    Description = "Mount server to backup server (secure)" }
        [PSCustomObject]@{ Port = 9419; Protocol = "TCP"; Service = "REST API";              Description = "Veeam Backup & Replication REST API" }
    )

    "Backup Proxies" = @(
        [PSCustomObject]@{ Port = 9392; Protocol = "TCP"; Service = "Proxy -> Backup Server"; Description = "Proxy communication with backup server" }
        [PSCustomObject]@{ Port = 6160; Protocol = "TCP"; Service = "Veeam Services";         Description = "Proxy to vSphere/vCenter / installer service" }
        [PSCustomObject]@{ Port = 80;   Protocol = "TCP"; Service = "HTTP";                   Description = "HTTP communication with hypervisors" }
        [PSCustomObject]@{ Port = 443;  Protocol = "TCP"; Service = "HTTPS";                  Description = "HTTPS communication with hypervisors" }
    )

    "Backup Repositories" = @(
        [PSCustomObject]@{ Port = 22;   Protocol = "TCP"; Service = "SSH";          Description = "Linux repository / storage management" }
        [PSCustomObject]@{ Port = 111;  Protocol = "TCP"; Service = "NFS RPC";      Description = "NFS portmapper" }
        [PSCustomObject]@{ Port = 445;  Protocol = "TCP"; Service = "SMB/CIFS";     Description = "Windows file sharing / SMB repositories" }
        [PSCustomObject]@{ Port = 2049; Protocol = "TCP"; Service = "NFS";          Description = "NFS shares / vPower NFS instant recovery" }
        [PSCustomObject]@{ Port = 9392; Protocol = "TCP"; Service = "VBR Internal"; Description = "Proxy / Mount Server to repository communication" }
    )

    "Gateway Servers" = @(
        [PSCustomObject]@{ Port = 9392; Protocol = "TCP"; Service = "VBR Internal";       Description = "Communication with backup server" }
        [PSCustomObject]@{ Port = 9401; Protocol = "TCP"; Service = "Secure Connections"; Description = "Secure connections to mount server" }
    )

    "WAN Accelerators" = @(
        [PSCustomObject]@{ Port = 8000; Protocol = "TCP"; Service = "WAN Accelerator"; Description = "WAN Accelerator default port" }
        [PSCustomObject]@{ Port = 8060; Protocol = "TCP"; Service = "WAN Traffic";     Description = "WAN-optimised backup traffic" }
        [PSCustomObject]@{ Port = 8061; Protocol = "TCP"; Service = "WAN Traffic";     Description = "WAN-optimised backup traffic" }
        [PSCustomObject]@{ Port = 9392; Protocol = "TCP"; Service = "VBR Internal";    Description = "Backup server communication" }
    )

    "Enterprise Manager" = @(
        [PSCustomObject]@{ Port = 1433;  Protocol = "TCP"; Service = "SQL Server";      Description = "Configuration database (SQL Server)" }
        [PSCustomObject]@{ Port = 5432;  Protocol = "TCP"; Service = "PostgreSQL";      Description = "Configuration database (PostgreSQL)" }
        [PSCustomObject]@{ Port = 9392;  Protocol = "TCP"; Service = "EM Console";      Description = "Console / backup server communication" }
        [PSCustomObject]@{ Port = 9443;  Protocol = "TCP"; Service = "EM Web UI";       Description = "Enterprise Manager web interface (HTTPS)" }
        [PSCustomObject]@{ Port = 10006; Protocol = "TCP"; Service = "License Service"; Description = "Veeam License Service" }
    )

    "Application-Aware Processing" = @(
        [PSCustomObject]@{ Port = 6160; Protocol = "TCP"; Service = "Guest Agent"; Description = "Guest interaction / indexing / persistent agent" }
    )

    "Log Shipping" = @(
        [PSCustomObject]@{ Port = 1433; Protocol = "TCP"; Service = "SQL Server";   Description = "SQL Server log shipping" }
        [PSCustomObject]@{ Port = 5017; Protocol = "TCP"; Service = "Log Shipping"; Description = "Transaction log shipping (default port)" }
    )

    "Cloud Connect" = @(
        [PSCustomObject]@{ Port = 443;  Protocol = "TCP"; Service = "HTTPS";        Description = "Encrypted Cloud Connect connections" }
        [PSCustomObject]@{ Port = 9392; Protocol = "TCP"; Service = "Cloud Connect"; Description = "Secure cloud repository communication" }
    )

    "Veeam Agents" = @(
        [PSCustomObject]@{ Port = 25;   Protocol = "TCP"; Service = "SMTP";          Description = "Email notifications" }
        [PSCustomObject]@{ Port = 587;  Protocol = "TCP"; Service = "SMTP (Auth)";   Description = "Authenticated SMTP (TLS/STARTTLS)" }
        [PSCustomObject]@{ Port = 6160; Protocol = "TCP"; Service = "Agent Service"; Description = "Agent <-> Backup Server / Repository" }
    )

    "Veeam Explorers" = @(
        [PSCustomObject]@{ Port = 443;  Protocol = "TCP"; Service = "HTTPS";      Description = "Explorer for Exchange / SharePoint Online" }
        [PSCustomObject]@{ Port = 1433; Protocol = "TCP"; Service = "SQL Server"; Description = "Explorer for SQL Server" }
    )

    "Notifications and Monitoring" = @(
        [PSCustomObject]@{ Port = 25;  Protocol = "TCP"; Service = "SMTP";       Description = "Standard SMTP email" }
        [PSCustomObject]@{ Port = 161; Protocol = "UDP"; Service = "SNMP";       Description = "SNMP notifications" }
        [PSCustomObject]@{ Port = 465; Protocol = "TCP"; Service = "SMTPS";      Description = "SMTP over SSL" }
        [PSCustomObject]@{ Port = 514; Protocol = "UDP"; Service = "Syslog";     Description = "Syslog forwarding" }
        [PSCustomObject]@{ Port = 587; Protocol = "TCP"; Service = "SMTP (Auth)"; Description = "Authenticated SMTP (TLS/STARTTLS)" }
    )

    "Virtualization - vSphere" = @(
        [PSCustomObject]@{ Port = 80;  Protocol = "TCP"; Service = "vCenter HTTP";  Description = "vCenter HTTP (if enabled)" }
        [PSCustomObject]@{ Port = 443; Protocol = "TCP"; Service = "vCenter HTTPS"; Description = "vCenter / ESXi / vSphere Web Services API" }
    )

    "Virtualization - Hyper-V" = @(
        [PSCustomObject]@{ Port = 80;  Protocol = "TCP"; Service = "HTTP";               Description = "Hyper-V management API" }
        [PSCustomObject]@{ Port = 135; Protocol = "TCP"; Service = "RPC Endpoint Mapper"; Description = "WMI/RPC entry point (also uses dynamic ports 49152-65535)" }
        [PSCustomObject]@{ Port = 139; Protocol = "TCP"; Service = "NetBIOS Session";     Description = "NetBIOS session / SMB over TCP" }
        [PSCustomObject]@{ Port = 443; Protocol = "TCP"; Service = "HTTPS";               Description = "Hyper-V management API" }
        [PSCustomObject]@{ Port = 445; Protocol = "TCP"; Service = "SMB";                 Description = "SMB data transfer" }
    )

    "Storage Systems" = @(
        [PSCustomObject]@{ Port = 22;  Protocol = "TCP"; Service = "SSH";   Description = "Appliance management (Dell EMC Data Domain, ExaGrid)" }
        [PSCustomObject]@{ Port = 443; Protocol = "TCP"; Service = "HTTPS"; Description = "Storage API (HPE StoreOnce, ExaGrid, Quantum DXi)" }
    )

    "CDP (Continuous Data Protection)" = @(
        [PSCustomObject]@{ Port = 443;  Protocol = "TCP"; Service = "CDP Appliance"; Description = "CDP appliance management (HTTPS)" }
        [PSCustomObject]@{ Port = 6160; Protocol = "TCP"; Service = "CDP Driver";    Description = "I/O filter communication / proxy cache" }
    )

    "Windows RPC" = @(
        [PSCustomObject]@{ Port = 135; Protocol = "TCP"; Service = "RPC Endpoint Mapper"; Description = "REQUIRED: RPC entry point for WMI, DCOM, Hyper-V management" }
        [PSCustomObject]@{ Port = 139; Protocol = "TCP"; Service = "NetBIOS Session";     Description = "NetBIOS session / RPC over SMB (legacy)" }
        [PSCustomObject]@{ Port = 137; Protocol = "UDP"; Service = "NetBIOS Name";        Description = "NetBIOS name resolution" }
        [PSCustomObject]@{ Port = 138; Protocol = "UDP"; Service = "NetBIOS Datagram";    Description = "NetBIOS datagram service" }
        [PSCustomObject]@{ Port = 445; Protocol = "TCP"; Service = "SMB / RPC over SMB";  Description = "Named pipes for RPC; required alongside port 135" }
    )
}

# ==============================================================================
# PORT TEST FUNCTIONS
# ==============================================================================

function Test-TcpPort {
    param(
        [string]$Hostname,
        [int]   $Port,
        [int]   $Timeout
    )

    $result = [PSCustomObject]@{ Success = $false; Status = "Unknown"; Detail = "" }

    try {
        $tcp  = New-Object System.Net.Sockets.TcpClient
        $ar   = $tcp.BeginConnect($Hostname, $Port, $null, $null)
        $wait = $ar.AsyncWaitHandle.WaitOne($Timeout, $false)

        if ($wait) {
            try {
                $tcp.EndConnect($ar)
                $result.Success = $true
                $result.Status  = "Open"
            }
            catch {
                $result.Status = "Closed"
                $result.Detail = $_.Exception.InnerException.Message ?? $_.Exception.Message
            }
        }
        else {
            $result.Status = "Timeout"
            $result.Detail = "No response within ${Timeout}ms"
        }
    }
    catch {
        $result.Status = "Error"
        $result.Detail = $_.Exception.Message
    }
    finally {
        if ($tcp) { $tcp.Close() }
    }

    return $result
}

function Test-UdpPort {
    # UDP is connectionless: no response means open OR filtered, not definitely closed.
    # An ICMP Port Unreachable reply confirms the port is closed.
    param(
        [string]$Hostname,
        [int]   $Port,
        [int]   $Timeout
    )

    $result = [PSCustomObject]@{ Success = $false; Status = "Open|Filtered"; Detail = "No response (UDP - open or filtered)" }

    try {
        $udp = New-Object System.Net.Sockets.UdpClient
        $udp.Client.ReceiveTimeout = $Timeout
        $probe = [System.Text.Encoding]::ASCII.GetBytes("VBR-PortCheck")
        $udp.Send($probe, $probe.Length, $Hostname, $Port) | Out-Null

        $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        try {
            $udp.Receive([ref]$ep) | Out-Null
            $result.Success = $true
            $result.Status  = "Responded"
            $result.Detail  = ""
        }
        catch [System.Net.Sockets.SocketException] {
            if ($_.Exception.SocketErrorCode -eq [System.Net.Sockets.SocketError]::ConnectionReset) {
                $result.Status = "Closed"
                $result.Detail = "ICMP Port Unreachable received"
            }
            # Timeout -> leave as Open|Filtered
        }
    }
    catch {
        $result.Status = "Error"
        $result.Detail = $_.Exception.Message
    }
    finally {
        if ($udp) { $udp.Close() }
    }

    return $result
}

# ==============================================================================
# OUTPUT HELPERS
# ==============================================================================

function Get-StatusColor ([string]$Status) {
    switch ($Status) {
        "Open"          { return "Green"  }
        "Responded"     { return "Green"  }
        "Closed"        { return "Red"    }
        "Timeout"       { return "Yellow" }
        "Open|Filtered" { return "Yellow" }
        default         { return "Red"    }
    }
}

function Get-StatusIcon ([string]$Status) {
    switch ($Status) {
        "Open"          { return "[+]" }
        "Responded"     { return "[+]" }
        "Timeout"       { return "[?]" }
        "Open|Filtered" { return "[?]" }
        default         { return "[-]" }
    }
}

# ==============================================================================
# CATEGORY CHECK
# ==============================================================================

function Invoke-CategoryCheck {
    param(
        [string]$CategoryName,
        [array] $Ports,
        [string]$Hostname,
        [int]   $Timeout
    )

    Write-Host ""
    Write-Host "  [$CategoryName]" -ForegroundColor Cyan
    Write-Host ("  " + "-" * 66) -ForegroundColor DarkGray
    Write-Host ("  {0,-10} {1,-28} {2,-14} {3}" -f "Port","Service","Status","Detail") -ForegroundColor DarkGray
    Write-Host ("  " + "-" * 66) -ForegroundColor DarkGray

    # De-duplicate within this category (same port + protocol)
    $unique = $Ports | Sort-Object Port, Protocol -Unique

    $results = foreach ($entry in $unique) {
        $check = if ($entry.Protocol -eq "TCP") {
            Test-TcpPort -Hostname $Hostname -Port $entry.Port -Timeout $Timeout
        } else {
            Test-UdpPort -Hostname $Hostname -Port $entry.Port -Timeout $Timeout
        }

        $portProto = "$($entry.Port)/$($entry.Protocol)"
        $icon      = Get-StatusIcon  $check.Status
        $color     = Get-StatusColor $check.Status

        Write-Host ("  {0} {1,-10} {2,-28} " -f $icon, $portProto, $entry.Service) -NoNewline
        Write-Host ("{0,-14}" -f $check.Status) -ForegroundColor $color -NoNewline

        if ($check.Detail) {
            Write-Host $check.Detail -ForegroundColor DarkGray
        } else {
            Write-Host ""
        }

        [PSCustomObject]@{
            Category  = $CategoryName
            Port      = $entry.Port
            Protocol  = $entry.Protocol
            Service   = $entry.Service
            Status    = $check.Status
            Reachable = $check.Success
            Detail    = $check.Detail
        }
    }

    return $results
}

# ==============================================================================
# RPC SERVICE CHECK
# Checks port 135 (endpoint mapper) + 445 (RPC over SMB) and explains
# the dynamic port requirement (49152-65535).
# ==============================================================================

function Invoke-RpcCheck {
    param([string]$Hostname, [int]$Timeout)

    Write-Host ""
    Write-Host "  [Windows RPC Service Check]" -ForegroundColor Cyan
    Write-Host ("  " + "-" * 66) -ForegroundColor DarkGray

    $rpc135 = Test-TcpPort -Hostname $Hostname -Port 135 -Timeout $Timeout
    $smb445 = Test-TcpPort -Hostname $Hostname -Port 445 -Timeout $Timeout

    $icon135  = Get-StatusIcon  $rpc135.Status
    $color135 = Get-StatusColor $rpc135.Status
    $icon445  = Get-StatusIcon  $smb445.Status
    $color445 = Get-StatusColor $smb445.Status

    Write-Host "  $icon135 135/TCP  RPC Endpoint Mapper         " -NoNewline
    Write-Host $rpc135.Status -ForegroundColor $color135

    Write-Host "  $icon445 445/TCP  SMB / RPC over Named Pipes   " -NoNewline
    Write-Host $smb445.Status -ForegroundColor $color445

    Write-Host ""
    Write-Host "  RPC notes:" -ForegroundColor DarkGray
    Write-Host "  - Port 135 is the entry point; Windows then negotiates a dynamic port." -ForegroundColor DarkGray
    Write-Host "  - Dynamic port range: 49152-65535 (Vista/2008+) or 1024-65535 (older)." -ForegroundColor DarkGray
    Write-Host "  - For Hyper-V/WMI, allow port 135 + dynamic range, or use 'stateful' " -ForegroundColor DarkGray
    Write-Host "    firewall rules that track the RPC negotiation automatically." -ForegroundColor DarkGray
    Write-Host "  - Port 445 (SMB) is needed for RPC over named pipes (e.g., DCOM)." -ForegroundColor DarkGray

    return @(
        [PSCustomObject]@{ Category="Windows RPC"; Port=135; Protocol="TCP"; Service="RPC Endpoint Mapper"; Status=$rpc135.Status; Reachable=$rpc135.Success; Detail=$rpc135.Detail }
        [PSCustomObject]@{ Category="Windows RPC"; Port=445; Protocol="TCP"; Service="SMB / RPC over SMB";  Status=$smb445.Status; Reachable=$smb445.Success; Detail=$smb445.Detail }
    )
}

# ==============================================================================
# SUMMARY
# ==============================================================================

function Show-Summary {
    param([array]$Results)

    # De-duplicate by port+protocol for counts (a port may appear in several categories)
    $unique    = $Results | Group-Object Port, Protocol | ForEach-Object {
        # If the port was reachable in any category run, count it as reachable
        $_.Group | Sort-Object Reachable -Descending | Select-Object -First 1
    }

    $total     = $unique.Count
    $open      = ($unique | Where-Object { $_.Reachable }).Count
    $closed    = ($unique | Where-Object { $_.Status -in "Closed","Error" }).Count
    $uncertain = ($unique | Where-Object { $_.Status -in "Timeout","Open|Filtered" }).Count

    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor DarkGray
    Write-Host "  RESULTS SUMMARY  -  Target: $script:Target" -ForegroundColor White
    Write-Host ("=" * 70) -ForegroundColor DarkGray
    Write-Host ("  {0,-30} {1}" -f "Total unique ports tested:",  $total)
    Write-Host ("  {0,-30} {1}" -f "Reachable (open):",           $open)      -ForegroundColor Green
    Write-Host ("  {0,-30} {1}" -f "Unreachable (closed/error):", $closed)    -ForegroundColor Red
    Write-Host ("  {0,-30} {1}" -f "Uncertain (timeout/UDP):",    $uncertain) -ForegroundColor Yellow

    if ($closed -gt 0) {
        Write-Host ""
        Write-Host "  UNREACHABLE PORTS:" -ForegroundColor Red
        $Results | Where-Object { $_.Status -in "Closed","Error" } |
            Sort-Object Port, Protocol -Unique |
            ForEach-Object {
                Write-Host ("  [-] {0,-10} {1,-28} ({2})" -f "$($_.Port)/$($_.Protocol)", $_.Service, $_.Category) -ForegroundColor Red
            }
    }

    if ($uncertain -gt 0) {
        Write-Host ""
        Write-Host "  UNCERTAIN PORTS (timeout or UDP open|filtered):" -ForegroundColor Yellow
        $Results | Where-Object { $_.Status -in "Timeout","Open|Filtered" } |
            Sort-Object Port, Protocol -Unique |
            ForEach-Object {
                Write-Host ("  [?] {0,-10} {1,-28} ({2})" -f "$($_.Port)/$($_.Protocol)", $_.Service, $_.Category) -ForegroundColor Yellow
            }
    }

    Write-Host ""
}

# ==============================================================================
# MAIN
# ==============================================================================

Clear-Host
Write-Host ""
Write-Host "  ============================================================" -ForegroundColor Cyan
Write-Host "   VEEAM PORT CHECKER" -ForegroundColor Cyan
Write-Host "   Veeam Backup & Replication - Network Port Validator" -ForegroundColor Cyan
Write-Host "  ============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Legend: " -NoNewline
Write-Host "[+] Open  " -NoNewline -ForegroundColor Green
Write-Host "[?] Uncertain/Timeout  " -NoNewline -ForegroundColor Yellow
Write-Host "[-] Closed/Error" -ForegroundColor Red
Write-Host "         (UDP ports: no response means open OR filtered - not definitively open)" -ForegroundColor DarkGray

# --- Target ---
if (-not $Target) {
    Write-Host ""
    Write-Host "  Target hostname or IP: " -NoNewline -ForegroundColor White
    $Target = (Read-Host).Trim()
}

if ([string]::IsNullOrWhiteSpace($Target)) {
    Write-Host "  ERROR: No target specified." -ForegroundColor Red
    exit 1
}

try {
    $null = [System.Net.Dns]::GetHostAddresses($Target)
}
catch {
    Write-Host "  ERROR: Cannot resolve '$Target'. Verify the hostname or IP." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "  Target  : $Target"           -ForegroundColor White
Write-Host "  Timeout : ${TimeoutMs} ms per port" -ForegroundColor DarkGray

# --- Menu ---
$categories  = @($PortDefinitions.Keys)    # preserves insertion order (ordered hashtable)
$categoryMap = @{}

Write-Host ""
Write-Host ("  " + "=" * 50) -ForegroundColor DarkGray
Write-Host "  SELECT SCOPE" -ForegroundColor White
Write-Host ("  " + "=" * 50) -ForegroundColor DarkGray
Write-Host "  [A]  Check ALL ports"
Write-Host "  [R]  Windows RPC service check only"
Write-Host ""

for ($i = 0; $i -lt $categories.Count; $i++) {
    $cat       = $categories[$i]
    $portCount = ($PortDefinitions[$cat] | Sort-Object Port, Protocol -Unique).Count
    $num       = ($i + 1).ToString()
    Write-Host ("  [{0,-3}] {1}  ({2} ports)" -f $num, $cat, $portCount)
    $categoryMap[$num] = $cat
}

Write-Host "  [Q]  Quit"
Write-Host ""
Write-Host "  Your choice: " -NoNewline -ForegroundColor White
$choice = (Read-Host).Trim().ToUpper()

if ($choice -eq "Q") {
    Write-Host "  Exiting." -ForegroundColor DarkGray
    exit 0
}

$allResults = @()

switch ($choice) {

    "A" {
        Write-Host ""
        Write-Host "  Checking ALL Veeam ports against: $Target" -ForegroundColor Cyan
        foreach ($cat in $categories) {
            $allResults += Invoke-CategoryCheck -CategoryName $cat -Ports $PortDefinitions[$cat] -Hostname $Target -Timeout $TimeoutMs
        }
    }

    "R" {
        $allResults += Invoke-RpcCheck -Hostname $Target -Timeout $TimeoutMs
    }

    default {
        if ($categoryMap.ContainsKey($choice)) {
            $selectedCat = $categoryMap[$choice]

            # Extra RPC note for categories that rely heavily on RPC
            if ($selectedCat -in "Virtualization - Hyper-V", "Windows RPC") {
                Write-Host ""
                Write-Host "  Note: '$selectedCat' uses RPC. Port 135 is the endpoint mapper;" -ForegroundColor Yellow
                Write-Host "        WMI/DCOM also requires dynamic ports 49152-65535 to be allowed." -ForegroundColor Yellow
            }

            $allResults += Invoke-CategoryCheck `
                -CategoryName $selectedCat `
                -Ports        $PortDefinitions[$selectedCat] `
                -Hostname     $Target `
                -Timeout      $TimeoutMs
        }
        else {
            Write-Host "  Invalid choice '$choice'. Exiting." -ForegroundColor Red
            exit 1
        }
    }
}

Show-Summary -Results $allResults

Write-Host "  Press any key to exit..." -ForegroundColor DarkGray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
