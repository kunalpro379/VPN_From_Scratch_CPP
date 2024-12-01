Write-Host "=== TAP Adapter Details ===" -ForegroundColor Green
Get-NetAdapter | Where-Object { $_.InterfaceDescription -like "*TAP*" } | Format-List *

Write-Host "`n=== Network Interface Configuration ===" -ForegroundColor Green
Get-NetIPConfiguration | Where-Object { $_.InterfaceDescription -like "*TAP*" } | Format-List *

Write-Host "`n=== Driver Information ===" -ForegroundColor Green
Get-NetAdapterBinding | Where-Object { $_.InterfaceDescription -like "*TAP*" } | Format-List *
