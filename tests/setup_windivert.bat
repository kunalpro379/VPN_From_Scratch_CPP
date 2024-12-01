@echo off
powershell -Command "& {Invoke-WebRequest -Uri 'https://www.reqrypt.org/download/WinDivert-2.2.2-A.zip' -OutFile 'WinDivert.zip'}"
powershell -Command "& {Expand-Archive -Path 'WinDivert.zip' -DestinationPath 'WinDivert' -Force}"
copy WinDivert\x64\WinDivert.dll .
copy WinDivert\x64\WinDivert.lib .
copy WinDivert\x64\WinDivert.sys .
copy WinDivert\include\windivert.h .
echo WinDivert files have been set up!
