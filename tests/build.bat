@echo off
setlocal enabledelayedexpansion

:: Set paths for vcpkg and OpenSSL
set VCPKG_ROOT=C:\vcpkg
set OPENSSL_INCLUDE=%VCPKG_ROOT%\installed\x64-windows\include
set OPENSSL_LIB=%VCPKG_ROOT%\installed\x64-windows\lib
set OPENSSL_BIN=%VCPKG_ROOT%\installed\x64-windows\bin

:: Create build directory if it doesn't exist
if not exist "build" mkdir build

:: Compile the VPN client
echo Compiling VPN client...
g++ -o build/vpn_client.exe ^
    NetworkInterfacing/vni.test.cpp ^
    NetworkInterfacing/tun.cpp ^
    NetworkInterfacing/routing.cpp ^
    Tun_Tap/tun_interface.cpp ^
    -I"%OPENSSL_INCLUDE%" ^
    -L"%OPENSSL_LIB%" ^
    -I"." ^
    -lws2_32 ^
    -liphlpapi ^
    -lssl ^
    -lcrypto ^
    -pthread ^
    -std=c++17

:: Check if compilation was successful
if %errorlevel% equ 0 (
    echo Compilation successful!
    echo Copying required DLLs...
    
    :: Copy required OpenSSL DLLs to build directory
    copy "%OPENSSL_BIN%\libssl-3-x64.dll" "build\"
    copy "%OPENSSL_BIN%\libcrypto-3-x64.dll" "build\"
    
    echo Build complete! You can find the executable in the build directory.
    echo To run the VPN client, navigate to the build directory and run vpn_client.exe
) else (
    echo Compilation failed!
)

pause
