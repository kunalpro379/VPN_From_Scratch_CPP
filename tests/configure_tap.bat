@echo off
netsh interface ipv4 set address name="OpenVPN TAP-Windows6" source=static addr=10.8.0.1 mask=255.255.255.0
netsh interface ipv4 add route 0.0.0.0/0 "OpenVPN TAP-Windows6" 10.8.0.1
echo TAP interface configured!
