#Requires -Version 5.1
<#
.SYNOPSIS
    Exports all detections from ESET Inspect On-Prem via REST API, including analyst notes/comments.

.DESCRIPTION
    Authenticates against the ESET Inspect On-Prem REST API, retrieves all detections with full
    detail (including analyst notes/comments) using paginated requests, and exports results to
    CSV and/or JSON.

    The list endpoint (GET /api/v1/detections) is called first with pagination. Then the detail
    endpoint (GET /api/v1/detections/{id}) is called per-detection to retrieve fields only
    available there: note (analyst comment), handled, processPath, moduleFirstSeenLocally,
    moduleLastExecutedLocally.

    Robustness features:
      - Parameter validation with meaningful error messages
      - -DaysBack convenience parameter (auto-builds creationTime filter)
      - -DaysBack and -Filter are mutually exclusive (validated at runtime)
      - Pre-flight DNS resolution + TCP-443 connectivity check
      - Output directory auto-creation + writability test before any API calls
      - Explicit auth success/failure messages (HTTP status + token presence + token length)
      - HTTP 401 / 403 / 404 / 0 authentication error disambiguation
      - Session token age warning at 20 min (sessions typically expire ~30 min)
      - Automatic retry with exponential back-off on 429 / 5xx / network errors
      - Respects Retry-After header on 429 responses
      - OData filter pre-validation (warns on unrecognised fields/operators)
      - Write-Progress bars for list pages and per-detection detail fetch
      - Graceful partial export on fatal error (saves whatever was collected)
      - Password zeroed from memory immediately after authentication
      - Structured JSON run-log with full audit trail saved alongside exports
      - Emergency run-log saved on any fatal error
      - Proper exit codes: 0 = success / no results, 1 = error

.PARAMETER Server
    FQDN or IP of the ESET Inspect On-Prem server. Do not include https:// or trailing slash.
    Examples: inspect.corp.local   /   192.168.1.10

.PARAMETER Username
    Username for API authentication.

.PARAMETER Password
    Optional. If omitted you are prompted with a masked secure input (recommended).
    Avoid passing on the command line — it appears in shell history.

.PARAMETER Domain
    Set to $true when authenticating with a domain account. Default: $false

.PARAMETER OutputPath
    Directory where export files are saved. Created automatically if it does not exist.
    Default: current working directory.

.PARAMETER ExportFormat
    CSV, JSON, or Both. Default: Both

.PARAMETER DaysBack
    Convenience parameter. Export detections created within the last N days.
    Mutually exclusive with -Filter.
    Example: -DaysBack 30  exports the last 30 days of detections.

.PARAMETER Filter
    Raw OData filter expression. Mutually exclusive with -DaysBack.
    Filterable fields : id, resolved, creationTime
    Supported operators: eq, ne, gt, ge, lt, le, and, or, ()
    Examples:
        "resolved eq false"
        "resolved eq true and creationTime ge 2024-01-01T00:00:00Z"
        "creationTime ge 2024-06-01T00:00:00Z and creationTime le 2024-06-30T23:59:59Z"

.PARAMETER PageSize
    Detections per list-page API call. Range 1-1000. Default: 100.

.PARAMETER FetchDetails
    When $true (default), calls GET /detections/{id} per detection to populate the note
    (analyst comment) and other detail-only fields.
    Use -FetchDetails $false for a faster export that omits those fields.

.PARAMETER DetailDelayMs
    Milliseconds to wait between consecutive detail-fetch calls to avoid throttling.
    Default: 50. Increase to 200-500 if you see 429 responses on large datasets.

.PARAMETER MaxRetries
    Maximum retry attempts per failed API call before giving up. Default: 3.

.PARAMETER SkipCertificateCheck
    Ignore TLS/SSL certificate errors. Required for self-signed certs. Default: $true.
    Set to $false in production environments with valid certificates.

.EXAMPLE
    # Interactive — prompts for password securely
    .\Export-EsetInspectDetections.ps1 -Server "inspect.corp.local" -Username "Administrator"

.EXAMPLE
    # Last 30 days only
    .\Export-EsetInspectDetections.ps1 -Server "inspect.corp.local" -Username "admin" -DaysBack 30

.EXAMPLE
    # Unresolved detections, last 7 days, CSV only, custom output folder
    $since = (Get-Date).AddDays(-7).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    .\Export-EsetInspectDetections.ps1 -Server "192.168.1.10" -Username "admin" `
        -Filter "resolved eq false and creationTime ge $since" `
        -ExportFormat CSV -OutputPath "C:\Reports"

.EXAMPLE
    # Fast export — skip per-detection detail fetch (no notes, much faster for huge sets)
    .\Export-EsetInspectDetections.ps1 -Server "inspect.corp.local" -Username "admin" `
        -FetchDetails $false -DaysBack 7

.EXAMPLE
    # Domain account, slower/safer throttle delay for large environments
    .\Export-EsetInspectDetections.ps1 -Server "inspect.corp.local" -Username "CORP\svc_eset" `
        -Domain $true -DetailDelayMs 200 -MaxRetries 5

.NOTES
    API reference : https://help.eset.com/ei_navigate/2.5/en-US/rest_api_detections.html
    Tested against: ESET Inspect On-Prem 2.5 / 2.6
    Exit codes    : 0 = success (or no detections found), 1 = error
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true, HelpMessage = "FQDN or IP of the ESET Inspect On-Prem server")]
    [ValidateNotNullOrEmpty()]
    [string]$Server,

    [Parameter(Mandatory = $true, HelpMessage = "API username")]
    [ValidateNotNullOrEmpty()]
    [string]$Username,

    [Parameter(Mandatory = $false)]
    [string]$Password = "",

    [Parameter(Mandatory = $false)]
    [bool]$Domain = $false,

    [Parameter(Mandatory = $false)]
    [ValidateScript({
        if ($_ -and -not (Test-Path $_ -IsValid)) {
            throw "OutputPath '$_' is not a valid filesystem path."
        }
        $true
    })]
    [string]$OutputPath = (Get-Location).Path,

    [Parameter(Mandatory = $false)]
    [ValidateSet("CSV", "JSON", "Both")]
    [string]$ExportFormat = "Both",

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 36500)]
    [int]$DaysBack = 0,

    [Parameter(Mandatory = $false)]
    [string]$Filter = "",

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 1000)]
    [int]$PageSize = 100,

    [Parameter(Mandatory = $false)]
    [bool]$FetchDetails = $true,

    [Parameter(Mandatory = $false)]
    [ValidateRange(0, 60000)]
    [int]$DetailDelayMs = 50,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 10)]
    [int]$MaxRetries = 3,

    [Parameter(Mandatory = $false)]
    [bool]$SkipCertificateCheck = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Script-scoped state ──────────────────────────────────────────────────────
$script:RunStart  = Get-Date
$script:AuthTime  = $null
$script:ExitCode  = 0
$script:RunLog    = [System.Collections.Generic.List[hashtable]]::new()

#region ── Logging ───────────────────────────────────────────────────────────────

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "OK", "WARN", "ERROR", "DEBUG")]
        [string]$Level = "INFO"
    )
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "OK"    { "Green"    }
        "WARN"  { "Yellow"   }
        "ERROR" { "Red"      }
        "DEBUG" { "DarkGray" }
        default { "Cyan"     }
    }
    Write-Host "[$ts][$Level] $Message" -ForegroundColor $color
    $script:RunLog.Add(@{ timestamp = $ts; level = $Level; message = $Message })
}

#endregion

#region ── TLS ───────────────────────────────────────────────────────────────────

function Enable-TlsBypass {
    # PS 5.1 requires a custom ICertificatePolicy; PS 6+ uses -SkipCertificateCheck per-call
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        if (-not ([System.Management.Automation.PSTypeName]"EsetTrustAll").Type) {
            Add-Type -TypeDefinition @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class EsetTrustAll : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint sp, X509Certificate cert, WebRequest req, int problem) { return true; }
}
"@
        }
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object EsetTrustAll
    }
    # Ensure TLS 1.2 is enabled — many servers have TLS 1.0/1.1 disabled
    $needed = [System.Net.SecurityProtocolType]::Tls12
    if (-not ([System.Net.ServicePointManager]::SecurityProtocol -band $needed)) {
        [System.Net.ServicePointManager]::SecurityProtocol =
            [System.Net.ServicePointManager]::SecurityProtocol -bor $needed
    }
}

#endregion

#region ── Pre-flight ────────────────────────────────────────────────────────────

function Test-ServerReachable {
    param([string]$Hostname)

    Write-Log "Pre-flight: DNS resolution for '$Hostname'..."
    try {
        $addrs = [System.Net.Dns]::GetHostAddresses($Hostname) |
                 Select-Object -ExpandProperty IPAddressToString
        Write-Log "  DNS OK -> $($addrs -join ', ')" "OK"
    } catch {
        Write-Log "DNS resolution failed for '$Hostname': $_" "ERROR"
        return $false
    }

    Write-Log "Pre-flight: TCP port 443 connectivity test..."
    try {
        $tcp   = New-Object System.Net.Sockets.TcpClient
        $async = $tcp.BeginConnect($Hostname, 443, $null, $null)
        $ok    = $async.AsyncWaitHandle.WaitOne(5000)   # 5-second timeout
        $tcp.Close()
        if (-not $ok) {
            Write-Log "TCP 443 connection to '$Hostname' timed out (5 s)." "ERROR"
            return $false
        }
        Write-Log "  TCP 443 OK." "OK"
        return $true
    } catch {
        Write-Log "TCP 443 connectivity test failed: $_" "ERROR"
        return $false
    }
}

function Test-FilterSyntax {
    param([string]$F)
    if (-not $F) { return }

    $allowedFields = @("id", "resolved", "creationTime")
    $allowedOps    = @("eq", "ne", "gt", "ge", "lt", "le", "and", "or", "not", "true", "false")
    $tokens        = [regex]::Matches($F, '[a-zA-Z]+') | ForEach-Object { $_.Value }
    $unknowns      = $tokens | Where-Object { $_ -notin $allowedOps -and $_ -notin $allowedFields }

    if ($unknowns) {
        Write-Log ("Filter pre-validation WARNING: unrecognised token(s): " +
                   "'$($unknowns -join "', '")'." +
                   " Allowed filter fields: $($allowedFields -join ', ')." +
                   " Proceeding — the server API will reject an invalid expression.") "WARN"
    } else {
        Write-Log "Filter expression pre-validation passed." "OK"
    }
}

function Assert-OutputWritable {
    param([string]$Dir)

    if (-not (Test-Path $Dir)) {
        Write-Log "Output directory does not exist — creating: $Dir"
        try {
            New-Item -ItemType Directory -Path $Dir -Force | Out-Null
            Write-Log "Directory created." "OK"
        } catch {
            throw "Failed to create output directory '$Dir': $_"
        }
    }

    $probe = Join-Path $Dir ".eset_write_probe_$PID"
    try {
        [System.IO.File]::WriteAllText($probe, "ok")
        Remove-Item $probe -Force -ErrorAction SilentlyContinue
        Write-Log "Output directory is writable: $Dir" "OK"
    } catch {
        throw "Output directory '$Dir' is not writable. Check permissions. Error: $_"
    }
}

#endregion

#region ── API core (with retry) ─────────────────────────────────────────────────

function New-ApiSplat {
    # Centralised splat builder so every call gets TLS bypass and content-type consistently
    param(
        [string]   $Uri,
        [string]   $Method  = "GET",
        [hashtable]$Headers = @{},
        [object]   $Body    = $null
    )
    $s = @{
        Uri             = $Uri
        Method          = $Method
        Headers         = $Headers
        ContentType     = "application/json"
        UseBasicParsing = $true
    }
    if ($null -ne $Body) {
        $s["Body"] = ($Body | ConvertTo-Json -Depth 10 -Compress)
    }
    if ($SkipCertificateCheck -and $PSVersionTable.PSVersion.Major -ge 6) {
        $s["SkipCertificateCheck"] = $true
    }
    return $s
}

function Invoke-ApiCall {
    <#
    Wraps Invoke-RestMethod with retry + back-off.
    Retries on : 429, 5xx, connection failures (status 0)
    Gives up on: 4xx (except 429) — these are client errors and won't self-heal
    Back-off   : exponential (1s, 2s, 4s...) honouring Retry-After on 429
    #>
    param(
        [string]   $Uri,
        [string]   $Method  = "GET",
        [hashtable]$Headers = @{},
        [object]   $Body    = $null
    )

    $attempt = 0
    while ($true) {
        $attempt++
        try {
            $splat = New-ApiSplat -Uri $Uri -Method $Method -Headers $Headers -Body $Body
            return Invoke-RestMethod @splat

        } catch [System.Net.WebException] {
            $webEx    = $_.Exception
            $response = $webEx.Response
            $status   = if ($response) { [int]$response.StatusCode } else { 0 }

            # Read response body for diagnostic detail
            $body = ""
            if ($response) {
                try {
                    $sr   = New-Object System.IO.StreamReader($response.GetResponseStream())
                    $body = $sr.ReadToEnd(); $sr.Close()
                } catch { }
            }

            $isRetryable = ($status -eq 429) -or ($status -ge 500) -or ($status -eq 0)

            if (-not $isRetryable -or $attempt -ge $MaxRetries) {
                $msg = "API call failed (HTTP $status) — URI: $Uri"
                if ($body) { $msg += "`n  Server response: $body" }
                throw $msg
            }

            # Honour Retry-After if present (429), otherwise exponential back-off
            $retryAfterMs = 0
            if ($response -and $response.Headers["Retry-After"]) {
                $ra = 0
                if ([int]::TryParse($response.Headers["Retry-After"], [ref]$ra)) {
                    $retryAfterMs = $ra * 1000
                }
            }
            $backoffMs = [int][Math]::Max($retryAfterMs, ([Math]::Pow(2, $attempt - 1) * 1000))
            Write-Log "  Attempt $attempt/$MaxRetries failed (HTTP $status). Retrying in ${backoffMs}ms..." "WARN"
            Start-Sleep -Milliseconds $backoffMs

        } catch {
            if ($attempt -ge $MaxRetries) { throw }
            $backoffMs = [int]([Math]::Pow(2, $attempt - 1) * 1000)
            Write-Log "  Attempt $attempt/$MaxRetries error: $_. Retrying in ${backoffMs}ms..." "WARN"
            Start-Sleep -Milliseconds $backoffMs
        }
    }
}

#endregion

#region ── Authentication ────────────────────────────────────────────────────────

function Invoke-Authenticate {
    param([string]$Pwd)

    $splat = New-ApiSplat -Uri "https://$Server/api/v1/authenticate" -Method "PUT"
    # Override Body manually — we need Invoke-WebRequest (not RestMethod) to access headers
    $splat["Body"] = (@{ username = $Username; password = $Pwd; domain = $Domain } | ConvertTo-Json)

    $resp = $null
    try {
        $resp = Invoke-WebRequest @splat
    } catch [System.Net.WebException] {
        $status  = 0
        $errBody = ""
        if ($_.Exception.Response) {
            $status = [int]$_.Exception.Response.StatusCode
            try {
                $sr      = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                $errBody = $sr.ReadToEnd(); $sr.Close()
            } catch { }
        }

        $hint = switch ($status) {
            401     { "Invalid username or password. Verify credentials and account status." }
            403     { "Account lacks API access. Check ESET Inspect user role/permissions." }
            404     { "Authentication endpoint not found (HTTP 404). Verify the server address and that ESET Inspect is running on port 443." }
            0       { "No response received from server. Check hostname, firewall rules, and that the ESET Inspect service is running." }
            default { "Unexpected HTTP $status during authentication." }
        }

        $msg = "Authentication FAILED: $hint"
        if ($errBody) { $msg += " | Server said: $errBody" }
        throw $msg
    } catch {
        throw "Authentication FAILED (unexpected error): $_"
    }

    # ── Validate HTTP status ───────────────────────────────────────────────────
    if ($resp.StatusCode -ne 200) {
        throw ("Authentication returned HTTP $($resp.StatusCode) — expected 200. " +
               "The server accepted the connection but did not confirm login success.")
    }

    # ── Extract and validate the session token ────────────────────────────────
    # PS 5.1 returns IDictionary; PS 7+ returns HttpResponseHeaders (may be string[])
    $token = $null
    try {
        $token = $resp.Headers["X-Security-Token"]
        if ($token -is [System.Object[]]) { $token = $token[0] }   # PS 7 array unwrap
    } catch { }

    if ([string]::IsNullOrWhiteSpace($token)) {
        throw ("Authentication returned HTTP 200, but the X-Security-Token header is absent. " +
               "Possible causes: a proxy is stripping response headers, the API path is wrong, " +
               "or the server is running an API version incompatible with this script.")
    }

    if ($token.Length -lt 16) {
        throw ("X-Security-Token appears too short (length=$($token.Length)). " +
               "The server may have returned an error in token form. Token value: '$token'")
    }

    Write-Log "Authentication SUCCESS — session token received (length=$($token.Length))." "OK"
    $script:AuthTime = Get-Date
    return $token
}

function Test-TokenAge {
    # Warn once when approaching typical session expiry (~30 min)
    if ($null -ne $script:AuthTime -and
        ((Get-Date) - $script:AuthTime).TotalMinutes -gt 20) {
        Write-Log ("Session token is over 20 minutes old. ESET Inspect sessions typically " +
                   "expire around 30 minutes. If you see HTTP 401 errors, re-run the script.") "WARN"
        $script:AuthTime = Get-Date   # reset so warning fires again after another 20 min
    }
}

#endregion

#region ── Detection field mappings ─────────────────────────────────────────────

$script:DetectionTypeMap = @{
    0 = "UnknownAlarm"
    1 = "RuleActivated"
    2 = "MalwareFoundOnDisk"
    3 = "MalwareFoundInMemory"
    4 = "ExploitDetected"
    5 = "FirewallDetection"
    7 = "BlockedAddress"
    8 = "CryptoBlockerDetection"
}

$script:SignatureTypeMap = @{
    90 = "Trusted"
    80 = "Valid"
    75 = "AdHoc"
    70 = "None"
    60 = "Invalid"
}

function Get-SeverityLabel([int]$Score) {
    if ($Score -ge 70) { return "Threat"  }
    if ($Score -ge 40) { return "Warning" }
    return "Info"
}

function ConvertTo-FlatDetection {
    param([PSCustomObject]$D)

    # Safe coercions — bad or missing fields become -1/0, never throw
    $typeId  = try { [int]$D.type }               catch { -1 }
    $sigType = try { [int]$D.moduleSignatureType } catch { -1 }
    $score   = try { [int]$D.severityScore }       catch {  0 }

    [PSCustomObject]@{
        # ── Identifiers ───────────────────────────────────────────────────────
        id                        = $D.id
        uuid                      = $D.uuid

        # ── Timestamps ────────────────────────────────────────────────────────
        creationTime              = $D.creationTime
        moduleFirstSeenLocally    = $D.moduleFirstSeenLocally       # detail endpoint only
        moduleLastExecutedLocally = $D.moduleLastExecutedLocally    # detail endpoint only

        # ── Computer ──────────────────────────────────────────────────────────
        computerId                = $D.computerId
        computerName              = $D.computerName
        computerUuid              = $D.computerUuid

        # ── Rule ──────────────────────────────────────────────────────────────
        ruleId                    = $D.ruleId
        ruleUuid                  = $D.ruleUuid
        ruleName                  = $D.ruleName

        # ── Classification ────────────────────────────────────────────────────
        type                      = $typeId
        typeLabel                 = if ($script:DetectionTypeMap.ContainsKey($typeId)) {
                                        $script:DetectionTypeMap[$typeId]
                                    } else { "Unknown($typeId)" }
        severity                  = $D.severity
        severityScore             = $score
        severityLabel             = Get-SeverityLabel $score
        priority                  = $D.priority

        # ── Status ────────────────────────────────────────────────────────────
        resolved                  = $D.resolved
        handled                   = $D.handled                      # detail endpoint only

        # ── Threat ────────────────────────────────────────────────────────────
        threatName                = $D.threatName
        threatUri                 = $D.threatUri

        # ── Process ───────────────────────────────────────────────────────────
        processId                 = $D.processId
        processUser               = $D.processUser
        processCommandLine        = $D.processCommandLine
        processPath               = $D.processPath                  # detail endpoint only

        # ── Module / Executable ───────────────────────────────────────────────
        moduleId                  = $D.moduleId
        moduleName                = $D.moduleName
        moduleSha1                = $D.moduleSha1
        moduleSigner              = $D.moduleSigner
        moduleSignatureType       = $sigType
        moduleSignatureLabel      = if ($script:SignatureTypeMap.ContainsKey($sigType)) {
                                        $script:SignatureTypeMap[$sigType]
                                    } else { "Unknown($sigType)" }
        moduleLgAge               = $D.moduleLgAge
        moduleLgPopularity        = $D.moduleLgPopularity
        moduleLgReputation        = $D.moduleLgReputation

        # ── Analyst note / comment ─────────────────────────────────────────────
        # Only populated when FetchDetails=$true (detail endpoint only)
        note                      = $D.note
    }
}

#endregion

#region ── Output helpers ────────────────────────────────────────────────────────

function Get-SafeOutputPath {
    # Returns a path that does not already exist, appending _1, _2 ... if needed
    param([string]$Dir, [string]$Base, [string]$Ext)
    $candidate = Join-Path $Dir "$Base.$Ext"
    $counter   = 1
    while (Test-Path $candidate) {
        $candidate = Join-Path $Dir "${Base}_${counter}.$Ext"
        $counter++
    }
    return $candidate
}

function Save-RunLog {
    param([string]$Dir, [string]$Base, [hashtable]$Meta)
    try {
        $path = Get-SafeOutputPath -Dir $Dir -Base "${Base}_runlog" -Ext "json"
        @{ meta = $Meta; log = $script:RunLog } |
            ConvertTo-Json -Depth 10 | Out-File -FilePath $path -Encoding UTF8
        Write-Log "Run log -> $path" "OK"
    } catch {
        Write-Log "WARNING: Could not save run log: $_" "WARN"
    }
}

function Export-Detections {
    param(
        [System.Collections.Generic.List[object]]$Data,
        [string]$Base,
        [string]$Dir,
        [string]$Format,
        [string]$Label = ""  # e.g. "PARTIAL" for emergency saves
    )
    if ($Data.Count -eq 0) { return }

    if ($Format -in @("CSV", "Both")) {
        $path = Get-SafeOutputPath -Dir $Dir -Base $Base -Ext "csv"
        $Data | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        Write-Log "CSV$(if ($Label){" [$Label]"}) -> $path" "OK"
    }
    if ($Format -in @("JSON", "Both")) {
        $path = Get-SafeOutputPath -Dir $Dir -Base $Base -Ext "json"
        $Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $path -Encoding UTF8
        Write-Log "JSON$(if ($Label){" [$Label]"}) -> $path" "OK"
    }
}

#endregion

#region ── Main ──────────────────────────────────────────────────────────────────

$detailErrors  = 0
$totalCount    = 0
$enriched      = [System.Collections.Generic.List[object]]::new()
$allDetections = [System.Collections.Generic.List[object]]::new()
$timestamp     = Get-Date -Format "yyyyMMdd_HHmmss"
$baseName      = "ESET_Inspect_Detections_$timestamp"

try {

    # ═══════════════════════════════════════════════════════════════
    # STEP 0 — Banner
    # ═══════════════════════════════════════════════════════════════
    Write-Log "======================================================"
    Write-Log " ESET Inspect On-Prem -- Detection Exporter v2.0"
    Write-Log " Started : $($script:RunStart.ToString('yyyy-MM-dd HH:mm:ss'))"
    Write-Log "======================================================"

    # ═══════════════════════════════════════════════════════════════
    # STEP 1 — Resolve / validate parameters
    # ═══════════════════════════════════════════════════════════════

    # Mutually exclusive: -DaysBack and -Filter
    if ($DaysBack -gt 0 -and $Filter -ne "") {
        throw "-DaysBack and -Filter are mutually exclusive. Use one or the other, not both."
    }

    # Build the OData filter automatically when -DaysBack is supplied
    if ($DaysBack -gt 0) {
        $since  = (Get-Date).ToUniversalTime().AddDays(-$DaysBack).ToString("yyyy-MM-ddTHH:mm:ssZ")
        $Filter = "creationTime ge $since"
        Write-Log "DaysBack $DaysBack -> filter: $Filter"
    }

    Write-Log "Server        : $Server"
    Write-Log "Username      : $Username"
    Write-Log "Domain auth   : $Domain"
    Write-Log "Filter        : $(if ($Filter) { $Filter } else { '(none — all detections)' })"
    Write-Log "FetchDetails  : $FetchDetails"
    Write-Log "ExportFormat  : $ExportFormat"
    Write-Log "OutputPath    : $OutputPath"
    Write-Log "PageSize      : $PageSize  |  MaxRetries: $MaxRetries  |  DetailDelayMs: $DetailDelayMs"
    Write-Log "------------------------------------------------------"

    # ═══════════════════════════════════════════════════════════════
    # STEP 2 — TLS
    # ═══════════════════════════════════════════════════════════════
    if ($SkipCertificateCheck) {
        Enable-TlsBypass
        Write-Log "TLS certificate verification DISABLED (SkipCertificateCheck=true)." "WARN"
        Write-Log "Set -SkipCertificateCheck `$false in production with valid certificates." "WARN"
    }

    # ═══════════════════════════════════════════════════════════════
    # STEP 3 — OData filter pre-validation
    # ═══════════════════════════════════════════════════════════════
    Test-FilterSyntax -F $Filter

    # ═══════════════════════════════════════════════════════════════
    # STEP 4 — Output directory writability (fail early, before network I/O)
    # ═══════════════════════════════════════════════════════════════
    Assert-OutputWritable -Dir $OutputPath

    # ═══════════════════════════════════════════════════════════════
    # STEP 5 — Pre-flight: network reachability
    # ═══════════════════════════════════════════════════════════════
    if (-not (Test-ServerReachable -Hostname $Server)) {
        throw ("Server '$Server' is not reachable on TCP 443. " +
               "Verify the hostname/IP, firewall rules, and that ESET Inspect is running.")
    }

    # ═══════════════════════════════════════════════════════════════
    # STEP 6 — Secure password prompt (if not supplied)
    # ═══════════════════════════════════════════════════════════════
    if ([string]::IsNullOrEmpty($Password)) {
        $secPwd   = Read-Host -Prompt "Password for '$Username'" -AsSecureString
        $bstr     = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secPwd)
        $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
    if ([string]::IsNullOrWhiteSpace($Password)) {
        throw "Password cannot be empty."
    }

    # ═══════════════════════════════════════════════════════════════
    # STEP 7 — Authenticate
    # ═══════════════════════════════════════════════════════════════
    Write-Log "Authenticating as '$Username' on '$Server'..."
    $token       = Invoke-Authenticate -Pwd $Password

    # Zero the password string from memory — it is no longer needed
    $Password    = "x" * $Password.Length
    $Password    = ""

    $authHeaders = @{ "Authorization" = "Bearer $token" }
    $baseUrl     = "https://$Server"

    # ═══════════════════════════════════════════════════════════════
    # STEP 8 — Query total detection count
    # ═══════════════════════════════════════════════════════════════
    Write-Log "Querying total detection count..."
    $countQuery = "`$count=1"
    if ($Filter) { $countQuery += "&`$filter=$([Uri]::EscapeDataString($Filter))" }

    $countResp = Invoke-ApiCall -Uri "$baseUrl/api/v1/detections?$countQuery" -Headers $authHeaders

    if ($null -eq $countResp) {
        throw "Detection count API returned null. The server may have returned an empty response body."
    }
    if (-not ($countResp.PSObject.Properties.Name -contains 'count')) {
        throw ("API response is missing the 'count' field. " +
               "Possible API version mismatch or proxy interference. " +
               "Raw response: $($countResp | ConvertTo-Json -Compress -Depth 3)")
    }

    $totalCount = [int]$countResp.count
    Write-Log "Total detections matching filter: $totalCount" "OK"

    if ($totalCount -eq 0) {
        Write-Log "No detections match the specified filter. Nothing to export." "WARN"
        if ($Filter) { Write-Log "Active filter: $Filter" "WARN" }
        exit 0
    }

    # ═══════════════════════════════════════════════════════════════
    # STEP 9 — Paginate through the detection list
    # ═══════════════════════════════════════════════════════════════
    $pageCount = [Math]::Ceiling($totalCount / $PageSize)
    Write-Log "Fetching $totalCount detection(s) across $pageCount page(s) (page size: $PageSize)..."

    for ($page = 0; $page -lt $pageCount; $page++) {
        Test-TokenAge

        $skip  = $page * $PageSize
        $query = "`$skip=$skip&`$top=$PageSize&`$orderBy=creationTime desc"
        if ($Filter) { $query += "&`$filter=$([Uri]::EscapeDataString($Filter))" }

        $pageResp = Invoke-ApiCall -Uri "$baseUrl/api/v1/detections?$query" -Headers $authHeaders

        if ($null -eq $pageResp) {
            Write-Log "Page $($page+1) returned null — skipping." "WARN"
            continue
        }
        if (-not ($pageResp.PSObject.Properties.Name -contains 'value') -or $null -eq $pageResp.value) {
            Write-Log "Page $($page+1) has no 'value' array — skipping." "WARN"
            continue
        }

        $batch = [object[]]$pageResp.value
        $allDetections.AddRange($batch)

        $pct = [int](($page + 1) / $pageCount * 100)
        Write-Progress -Id 1 -Activity "Fetching detection list" `
            -Status   "Page $($page+1) of $pageCount  |  $($allDetections.Count) collected so far" `
            -PercentComplete $pct
    }
    Write-Progress -Id 1 -Activity "Fetching detection list" -Completed
    Write-Log "List fetch complete: $($allDetections.Count) detection(s) collected." "OK"

    if ($allDetections.Count -eq 0) {
        Write-Log ("List pages returned 0 items despite count=$totalCount. " +
                   "This may indicate a server/API issue.") "WARN"
        exit 0
    }

    # ═══════════════════════════════════════════════════════════════
    # STEP 10 — Enrich with per-detection detail (for notes + extra fields)
    # ═══════════════════════════════════════════════════════════════
    if ($FetchDetails) {
        Write-Log ("Fetching full detail per detection to capture analyst notes/comments " +
                   "and detail-only fields: processPath, handled, moduleFirstSeen, moduleLastExecuted.")
        Write-Log ("This makes 1 additional API call per detection ($($allDetections.Count) calls total). " +
                   "Use -FetchDetails `$false to skip and export faster without notes.")

        $fetched = 0
        foreach ($det in $allDetections) {
            Test-TokenAge
            $fetched++

            $pct = [int]($fetched / $allDetections.Count * 100)
            Write-Progress -Id 2 -Activity "Fetching detection details" `
                -Status   "$fetched / $($allDetections.Count)  |  id=$($det.id)  |  errors=$detailErrors" `
                -PercentComplete $pct

            try {
                $detail = Invoke-ApiCall -Uri "$baseUrl/api/v1/detections/$($det.id)" -Headers $authHeaders
                $enriched.Add((ConvertTo-FlatDetection $detail))
            } catch {
                $detailErrors++
                Write-Log "  Detail fetch FAILED for id=$($det.id): $_ — using list data (note will be empty)." "WARN"
                $enriched.Add((ConvertTo-FlatDetection $det))
            }

            if ($DetailDelayMs -gt 0) { Start-Sleep -Milliseconds $DetailDelayMs }
        }
        Write-Progress -Id 2 -Activity "Fetching detection details" -Completed

        if ($detailErrors -gt 0) {
            Write-Log ("$detailErrors / $($allDetections.Count) detail fetch(es) failed and fell " +
                       "back to list data. Those detections will have empty note fields.") "WARN"
        } else {
            Write-Log "All $($allDetections.Count) detail fetch(es) completed successfully." "OK"
        }
    } else {
        Write-Log "FetchDetails=false — note/comment and detail-only fields will be empty." "WARN"
        foreach ($det in $allDetections) {
            $enriched.Add((ConvertTo-FlatDetection $det))
        }
    }

    Write-Log "$($enriched.Count) detection(s) ready for export." "OK"

    # ═══════════════════════════════════════════════════════════════
    # STEP 11 — Write export files
    # ═══════════════════════════════════════════════════════════════
    Export-Detections -Data $enriched -Base $baseName -Dir $OutputPath -Format $ExportFormat

    # ═══════════════════════════════════════════════════════════════
    # STEP 12 — Save structured run log (audit trail)
    # ═══════════════════════════════════════════════════════════════
    $runMeta = @{
        scriptVersion     = "2.0"
        runStart          = $script:RunStart.ToString("o")
        runEnd            = (Get-Date).ToString("o")
        durationSeconds   = [int]((Get-Date) - $script:RunStart).TotalSeconds
        server            = $Server
        username          = $Username
        domain            = $Domain
        daysBack          = $DaysBack
        filter            = $Filter
        pageSize          = $PageSize
        fetchDetails      = $FetchDetails
        detailDelayMs     = $DetailDelayMs
        maxRetries        = $MaxRetries
        exportFormat      = $ExportFormat
        outputPath        = $OutputPath
        totalMatched      = $totalCount
        totalFetched      = $allDetections.Count
        totalExported     = $enriched.Count
        detailFetchErrors = $detailErrors
        exitCode          = $script:ExitCode
    }
    Save-RunLog -Dir $OutputPath -Base $baseName -Meta $runMeta

    # ═══════════════════════════════════════════════════════════════
    # STEP 13 — Final summary
    # ═══════════════════════════════════════════════════════════════
    $duration = [int]((Get-Date) - $script:RunStart).TotalSeconds
    Write-Log "======================================================"
    Write-Log " Export complete in ${duration} second(s)"
    Write-Log " Matched by filter   : $totalCount"
    Write-Log " Detections exported : $($enriched.Count)"
    if ($FetchDetails) {
        Write-Log " Detail fetch errors : $detailErrors"
    }
    Write-Log "======================================================"

} catch {
    $script:ExitCode = 1
    Write-Log "FATAL ERROR: $_" "ERROR"
    Write-Log "Stack trace:`n$($_.ScriptStackTrace)" "DEBUG"

    # Save emergency run log + any partial data we already collected
    $emergBase = "ESET_Inspect_Detections_FAILED_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    $emergMeta = @{
        runStart   = $script:RunStart.ToString("o")
        runEnd     = (Get-Date).ToString("o")
        server     = $Server
        username   = $Username
        fatalError = $_.ToString()
        stackTrace = $_.ScriptStackTrace
        partialDetectionsCollected = $enriched.Count
    }
    Save-RunLog -Dir $OutputPath -Base $emergBase -Meta $emergMeta

    if ($enriched.Count -gt 0) {
        Write-Log "Saving $($enriched.Count) partially-collected detection(s) before exit..." "WARN"
        Export-Detections -Data $enriched -Base "${emergBase}_partial" `
                          -Dir $OutputPath -Format $ExportFormat -Label "PARTIAL"
    }

} finally {
    # Always clear progress bars to avoid leaving them stuck on the console
    Write-Progress -Id 1 -Activity "Fetching detection list"    -Completed -ErrorAction SilentlyContinue
    Write-Progress -Id 2 -Activity "Fetching detection details" -Completed -ErrorAction SilentlyContinue
}

exit $script:ExitCode

#endregion
