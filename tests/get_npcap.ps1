$url = "https://npcap.com/dist/npcap-1.75.exe"
$output = "npcap-installer.exe"
Invoke-WebRequest -Uri $url -OutFile $output
Start-Process -FilePath $output -ArgumentList "/S" -Wait
Remove-Item $output

# Download Npcap SDK
$sdkUrl = "https://npcap.com/dist/npcap-sdk-1.13.zip"
$sdkOutput = "npcap-sdk.zip"
Invoke-WebRequest -Uri $sdkUrl -OutFile $sdkOutput
Expand-Archive -Path $sdkOutput -DestinationPath "npcap-sdk" -Force
Remove-Item $sdkOutput
