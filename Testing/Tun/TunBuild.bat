@echo off
echo Building TUN setup...
g++ -o tun_setup.exe tun_setup.cpp -lws2_32 -liphlpapi -static
if %ERRORLEVEL% EQU 0 (
    echo TUN setup build successful!
) else (
    echo TUN setup build failed! Make sure MinGW-w64 is installed
    pause
    exit /b 1
)

echo Building Routing...