@echo off
echo Configuring TAP adapter...

:: Get the interface index for TAP adapter
for /f "tokens=2 delims=:" %%i in ('netsh interface show interface "TAP-Windows Adapter V9" ^| findstr "Interface Index"') do set TAP_INDEX=%%i

:: First disable the adapter
netsh interface set interface "TAP-Windows Adapter V9" admin=disabled
timeout /t 2

:: Enable the adapter
netsh interface set interface "TAP-Windows Adapter V9" admin=enabled
timeout /t 2

:: Configure IP address
netsh interface ip set address name="TAP-Windows Adapter V9" static 10.0.0.1 255.255.255.0
timeout /t 2

:: Delete any existing routes for our network
route delete 10.0.0.0 mask 255.255.255.0
timeout /t 1

:: Add our route using the interface index
route add 10.0.0.0 mask 255.255.255.0 10.0.0.1 if %TAP_INDEX%

echo Running VPN client...
build\vpn_client.exe
