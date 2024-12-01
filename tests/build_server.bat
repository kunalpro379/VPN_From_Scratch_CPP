@echo off
setlocal enabledelayedexpansion

:: Find Visual Studio installation
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
    set "VS_PATH=%%i"
)

if not defined VS_PATH (
    echo Error: Visual Studio with C++ tools not found
    exit /b 1
)

:: Initialize Visual Studio environment
echo Setting up Visual Studio environment...
call "!VS_PATH!\VC\Auxiliary\Build\vcvars64.bat"

:: Build the server
echo Building VPN server...
cl /I "C:\vcpkg\installed\x64-windows\include" server.c /Fe:server.exe /link /LIBPATH:"C:\vcpkg\installed\x64-windows\lib" libssl.lib libcrypto.lib Ws2_32.lib Crypt32.lib User32.lib Advapi32.lib Secur32.lib

:: Copy OpenSSL DLLs if build successful
if %ERRORLEVEL% EQU 0 (
    echo Copying OpenSSL DLLs...
    copy /Y "C:\vcpkg\installed\x64-windows\bin\libssl-3-x64.dll" .
    copy /Y "C:\vcpkg\installed\x64-windows\bin\libcrypto-3-x64.dll" .
    echo Build completed successfully
) else (
    echo Build failed
    exit /b 1
)
