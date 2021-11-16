$BaseURL= "http://192.168.0.227"
##$Folder = "checkfileextensionsbenign"
#$File = "16f741d14a9af2cf05588d4ca748dd9a4bba9780c464f424076258b3911807ee_gif.gif"

$inputFile = "C:\tools\web-proxy-test-downloader\files.txt"


foreach($line in Get-Content $inputFile) {
    $Folder = $line.split("/")[0]
    $File = $line.split("/")[1]


    $URL= $BaseURL + "/" + $Folder +"/"+ $File
    $wc = [System.Net.WebClient]::new()
    $Response = iwr($URL)

    $FileHash_recv = (Get-FileHash -InputStream ($wc.OpenRead($URL))).Hash
    $FileHash_orig = $File.split("_")[0]
    #$FileHash_recv
    #$FileHash_orig
    $HashMath = $FileHash_recv -eq $FileHash_orig

    Write-Host -NoNewline  $Folder : $File : $HashMath
    Write-Host
    
}


