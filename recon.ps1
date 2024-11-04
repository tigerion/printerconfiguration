# Define the output file path
$outputFile = "C:\TEMP\ProcessAndUserInfo.txt"

# Ensure the tmp folder exists
if (!(Test-Path -Path "C:\TEMP")) {
    New-Item -ItemType Directory -Path "C:\TEMP"
}

# Get the list of all processes with detailed information
Get-Process | Select-Object -Property Name, Id, Handles, CPU, StartTime, @{Name="User";Expression={(Get-WmiObject -Class Win32_Process -Filter "ProcessId=$($_.Id)").GetOwner().User}}, Description | Format-Table -AutoSize | Out-String | Out-File -FilePath $outputFile -Encoding UTF8 -Append

# Add a separator for clarity
Add-Content -Path $outputFile -Value "`n=== WHOAMI /ALL OUTPUT ===`n"

# Run whoami /all and append output to the file
whoami /all | Out-File -FilePath $outputFile -Encoding UTF8 -Append

Write-Output "Process and user information written to $outputFile"
