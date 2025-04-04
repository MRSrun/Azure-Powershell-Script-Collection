<#
.SYNOPSIS
    Tests network connectivity requirements for Microsoft Intune.
.DESCRIPTION
    Fetches Intune network endpoints from Microsoft’s JSON and tests connectivity using TCP and UDP.
.EXAMPLE
    .\Get-IntuneNetworkRequirements.ps1 -UseMSJSON -ShowResults
.NOTES
    Version: 1.0
    Author: Adapted for PowerShell 5.1
    Date: April 04, 2025
#>

param(
    [switch]$UseMSJSON = $false,
    [switch]$ShowResults = $false,
    [switch]$CheckCertRevocation = $false,
    [string]$TPMAttestation = ""
)

# Logging function (simplified for PowerShell 5.1)
function Write-Log {
    param(
        [string]$Message,
        [string]$Component = "General"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] [$Component] $Message"
}

# Function to test TCP connectivity
function Test-TCPConnection {
    param(
        [string]$Target,
        [int]$Port
    )
    Write-Log "Testing TCP connection to $Target on port $Port" -Component "TestTCP"
    $tcpClient = New-Object System.Net.Sockets.TcpClient
    try {
        $tcpClient.Connect($Target, $Port)
        Write-Log "TCP connection to $Target:$Port succeeded" -Component "TestTCP"
        return $true
    }
    catch {
        Write-Log "TCP connection to $Target:$Port failed: $_" -Component "TestTCP"
        return $false
    }
    finally {
        $tcpClient.Close()
    }
}

# Function to test UDP (NTP) connectivity
function Test-NTPviaUDP {
    param(
        [string]$Target,
        [int]$Port = 123
    )
    Write-Log "Testing UDP connection to $Target on port $Port" -Component "TestNTP"
    $udpClient = New-Object System.Net.Sockets.UdpClient
    $udpClient.Client.Blocking = $false
    $ntpData = New-Object byte[] 48
    $ntpData[0] = 27  # NTP request header

    try {
        $udpClient.Connect($Target, $Port)
        $udpClient.Send($ntpData, $ntpData.Length) | Out-Null
        Start-Sleep -Milliseconds 500  # Wait for response
        if ($udpClient.Available -gt 0) {
            Write-Log "UDP connection to $Target:$Port succeeded" -Component "TestNTP"
            return $true
        }
        else {
            Write-Log "UDP connection to $Target:$Port failed (no response)" -Component "TestNTP"
            return $false
        }
    }
    catch {
        Write-Log "UDP connection to $Target:$Port failed: $_" -Component "TestNTP"
        return $false
    }
    finally {
        $udpClient.Close()
    }
}

# Fetch Microsoft Intune endpoints
if ($UseMSJSON) {
    Write-Log "Fetching Intune network requirements from Microsoft JSON" -Component "DataFetch"
    $url = "https://endpoints.office.com/endpoints/worldwide?clientrequestid=$(New-Guid)"
    try {
        $response = Invoke-WebRequest -Uri $url -UseBasicParsing
        $endpoints = $response.Content | ConvertFrom-Json
        $intuneEndpoints = $endpoints | Where-Object { $_.serviceArea -eq "Intune" }
    }
    catch {
        Write-Log "Failed to fetch Intune endpoints: $_" -Component "DataFetch"
        exit 1
    }
}
else {
    Write-Log "Using hardcoded endpoints (MSJSON not specified)" -Component "DataFetch"
    $intuneEndpoints = @(
        [PSCustomObject]@{ urls = @("*.manage.microsoft.com"); tcpPorts = "443"; serviceArea = "Intune" }
        [PSCustomObject]@{ urls = @("time.windows.com"); tcpPorts = "123"; udpPorts = "123"; serviceArea = "Intune" }
    )
}

# Test connectivity and store results
$results = @()
foreach ($endpoint in $intuneEndpoints) {
    foreach ($url in $endpoint.urls) {
        $target = $url -replace "\*", "test"  # Replace wildcard for testing
        $tcpPorts = $endpoint.tcpPorts -split ","
        $udpPorts = $endpoint.udpPorts -split ","

        # Test TCP ports
        foreach ($port in $tcpPorts) {
            if ($port) {
                $tcpResult = Test-TCPConnection -Target $target -Port $port
                $results += [PSCustomObject]@{
                    Target       = $target
                    Port         = $port
                    Protocol     = "TCP"
                    Success      = $tcpResult
                    ServiceArea  = $endpoint.serviceArea
                }
            }
        }

        # Test UDP ports (e.g., NTP)
        foreach ($port in $udpPorts) {
            if ($port) {
                $udpResult = Test-NTPviaUDP -Target $target -Port $port
                $results += [PSCustomObject]@{
                    Target       = $target
                    Port         = $port
                    Protocol     = "UDP"
                    Success      = $udpResult
                    ServiceArea  = $endpoint.serviceArea
                }
            }
        }
    }
}

# Display results if requested
if ($ShowResults) {
    $results | Format-Table -Property Target, Port, Protocol, Success, ServiceArea -AutoSize
}

# Output results to console
Write-Log "Testing completed. Total endpoints tested: $($results.Count)" -Component "Summary"
