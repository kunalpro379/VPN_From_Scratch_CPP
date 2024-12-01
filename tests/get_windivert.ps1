$url = "https://www.reqrypt.org/download/WinDivert-2.2.2-A.zip"
$output = "WinDivert.zip"
Invoke-WebRequest -Uri $url -OutFile $output
Expand-Archive -Path $output -DestinationPath "WinDivert" -Force
Remove-Item $output
