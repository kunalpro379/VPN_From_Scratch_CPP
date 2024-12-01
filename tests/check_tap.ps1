Write-Host "Checking TAP adapter installation..."

# Check if TAP adapter exists in network adapters
$tapAdapter = Get-NetAdapter | Where-Object { $_.InterfaceDescription -like "*TAP-Windows*" }

if ($tapAdapter) {
    Write-Host "`nTAP adapter found:"
    Write-Host "Name: $($tapAdapter.Name)"
    Write-Host "Description: $($tapAdapter.InterfaceDescription)"
    Write-Host "Status: $($tapAdapter.Status)"
    Write-Host "MAC Address: $($tapAdapter.MacAddress)"
} else {
    Write-Host "`nNo TAP adapter found!"
    Write-Host "Please install TAP-Windows adapter:"
    Write-Host "1. Download OpenVPN installer from: https://openvpn.net/community-downloads/"
    Write-Host "2. During installation, make sure 'TAP Virtual Ethernet Adapter' is selected"
    Write-Host "3. After installation, verify TAP adapter appears in Network Connections"
}
