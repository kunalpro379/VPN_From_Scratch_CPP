@echo off
setlocal enabledelayedexpansion

REM Find Visual Studio installation
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "!VSWHERE!" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"

if not exist "!VSWHERE!" (
    echo Error: Visual Studio installation not found
    echo Please install Visual Studio with C++ development tools
    exit /b 1
)

for /f "usebackq tokens=*" %%i in (`"!VSWHERE!" -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
    set "VS_PATH=%%i"
)

if not defined VS_PATH (
    echo Error: Visual Studio with C++ tools not found
    echo Please install Visual Studio with C++ development tools
    exit /b 1
)

REM Initialize Visual Studio environment
if exist "!VS_PATH!\Common7\Tools\VsDevCmd.bat" (
    call "!VS_PATH!\Common7\Tools\VsDevCmd.bat" -arch=amd64
) else (
    echo Error: Visual Studio environment initialization script not found
    exit /b 1
)

REM Check for vcpkg installation
set "VCPKG_PATH=C:\vcpkg"
set "VCPKG_INSTALLED=!VCPKG_PATH!\installed\x64-windows"

if not exist "!VCPKG_INSTALLED!\include\openssl\ssl.h" (
    echo Error: OpenSSL not found in vcpkg installation
    echo Please install OpenSSL using: vcpkg install openssl:x64-windows
    exit /b 1
)

REM Set compiler and linker flags for vcpkg
set CFLAGS=/I"!VCPKG_INSTALLED!\include" /DWIN32 /D_WINDOWS /D_CRT_SECURE_NO_WARNINGS
set LDFLAGS=/LIBPATH:"!VCPKG_INSTALLED!\lib" libssl.lib libcrypto.lib ws2_32.lib crypt32.lib advapi32.lib secur32.lib

echo Building VPN client...
cl /I "C:\vcpkg\installed\x64-windows\include" /D_CRT_SECURE_NO_WARNINGS client.c /Fe:client.exe /link /LIBPATH:"C:\vcpkg\installed\x64-windows\lib" libssl.lib libcrypto.lib ws2_32.lib crypt32.lib advapi32.lib secur32.lib

if %ERRORLEVEL% neq 0 (
    echo Compilation failed
    exit /b 1
)

REM Copy required DLLs to current directory
echo Copying OpenSSL DLLs...
if exist "client.exe" (
    taskkill /F /IM client.exe 2>nul
    timeout /t 1 /nobreak >nul
)
copy /Y "!VCPKG_INSTALLED!\bin\libssl*.dll" . >nul 2>nul
copy /Y "!VCPKG_INSTALLED!\bin\libcrypto*.dll" . >nul 2>nul

echo Build completed successfully
echo Run client.exe <server_ip> <port> to start the VPN client
