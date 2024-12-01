$url = "https://build.openvpn.net/downloads/releases/tap-windows-9.24.7-I601-Win10.exe"
$output = "tap-installer.exe"
Invoke-WebRequest -Uri $url -OutFile $output
Start-Process -FilePath $output -ArgumentList "/S" -Wait
Remove-Item $output
