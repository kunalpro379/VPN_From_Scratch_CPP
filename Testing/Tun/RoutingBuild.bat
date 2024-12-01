@echo off
echo Building Routing...
g++ -o routing.exe routing.cpp -lws2_32 -liphlpapi -static -D_WIN32_WINNT=0x0600
if %ERRORLEVEL% EQU 0 (
    echo Routing build successful!
) else (
    echo Routing build failed! Make sure MinGW-w64 is installed
    pause
    exit /b 1
)
pause