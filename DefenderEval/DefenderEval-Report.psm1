#Requires -Version 5.1

<#
.SYNOPSIS
    Verify configuration are aligning with recommended settings when performing an evaluation of Microsoft Defender Antivirus and Microsoft Defender for Endpoint

.DESCRIPTION


.NOTES
    Jonathan Devere-Ellery
    Cloud Solution Architect - Microsoft


##############################################################################################
#This sample script is not supported under any Microsoft standard support program or service.
#This sample script is provided AS IS without warranty of any kind.
#Microsoft further disclaims all implied warranties including, without limitation, any implied
#warranties of merchantability or of fitness for a particular purpose. The entire risk arising
#out of the use or performance of the sample script and documentation remains with you. In no
#event shall Microsoft, its authors, or anyone else involved in the creation, production, or
#delivery of the scripts be liable for any damages whatsoever (including, without limitation,
#damages for loss of business profits, business interruption, loss of business information,
#or other pecuniary loss) arising out of the use of or inability to use the sample script or
#documentation, even if Microsoft has been advised of the possibility of such damages.
##############################################################################################

#> 

Function Invoke-CheckDefenderRecommendations {
    param (

    )

    $Results = @()

    $MpPref = Get-MpPreference

    # Cloud Protection - https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-using-powershell#cloud-protection-features

    switch ($MpPref.MAPSReporting) {
        {1 -or 2} {$MAPSReporting = "Advanced"}
        default {$MAPSReporting = "Disabled"}
    }

    if ($MAPSReporting -eq "Advanced") {$Result="Yes"} else {$Result="No"}

    $Results += New-Object -TypeName psobject -Property @{
        Topic="Cloud Protection"
        Check="MAPSReporting"
        Result=$Result
        Config=$MAPSReporting
        Description= "Enable the Microsoft Defender Cloud for near-instant protection and increased protection"
    }


    switch ($MpPref.SubmitSamplesConsent) {
        1 {$SubmitType = "SafeSamples"}
        2 {$SubmitType = "NeverSend"}
        3 {$SubmitType = "AllSamples"}
        4 {$SubmitType = "AlwaysPrompt"}
    }

    if ($SubmitType -eq "AllSamples") {$Result="Yes"} else {$Result="No"}

    $Results += New-Object -TypeName psobject -Property @{
        Topic="Cloud Protection"
        Check="SubmitSamplesConsent"
        Result=$Result
        Config=$SubmitType
        Description= "Automatically submit samples to increase group protection"
    }


    switch ($MpPref.DisableBlockAtFirstSeen) {
        1 {$BAFS = "Disabled"}
        default {$BAFS = "Enabled"}
    }
    if ($BAFS -eq "Enabled") {$Result="Yes"} else {$Result="No"}

    $Results += New-Object -TypeName psobject -Property @{
        Topic="Cloud Protection"
        Check="BlockAtFirstSeen"
        Result=$Result
        Config=$BAFS
        Description= "Always Use the cloud to block new malware within seconds"
    }


    switch ($MpPref.DisableIOAVProtection) {
        1 {$IOAV = "Disabled"}
        default {$IOAV = "Enabled"}
    }
    if ($IOAV -eq "Enabled") {$Result="Yes"} else {$Result="No"}

    $Results += New-Object -TypeName psobject -Property @{
        Topic="Cloud Protection"
        Check="IOAVProtection"
        Result=$Result
        Config=$IOAV
        Description= "Scan all downloaded files and attachments"
    }


    switch ($MpPref.CloudBlockLevel) {
        0 {$CloudBlockLevel = "Default"}
        1 {$CloudBlockLevel = "Moderate"}
        2 {$CloudBlockLevel = "High"}
        4 {$CloudBlockLevel = "HighPlus"}
        6 {$CloudBlockLevel = "ZeroTolerance"}
        default {$CloudBlockLevel = "Default"}
    }
    if ($CloudBlockLevel -eq "High" -or $CloudBlockLevel -eq "HighPlus" -or $CloudBlockLevel -eq "ZeroTolerance") {
        $Result="Yes"
    } else {$Result="No"}

    $Results += New-Object -TypeName psobject -Property @{
        Topic="Cloud Protection"
        Check="CloudBlockLevel"
        Result=$Result
        Config=$CloudBlockLevel
        Description= "Set cloud block level to at least 'High'"
    }


    if ($MpPref.CloudExtendedTimeout -ge 50) {$Result="Yes"} else {$Result="No"}

    $Results += New-Object -TypeName psobject -Property @{
        Topic="Cloud Protection"
        Check="CloudExtendedTimeout"
        Result=$Result
        Config=$MpPref.CloudExtendedTimeout
        Description= "Set cloud block time-out to 1 minute"
    }


    # Real-time Scanning - https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-using-powershell#always-on-protection-real-time-scanning
    switch ($MpPref.DisableRealtimeMonitoring) {
        1 {$RTPMonitoring = "Disabled"}
        default {$RTPMonitoring = "Enabled"}
    }
    if ($RTPMonitoring -eq "Enabled") {$Result="Yes"} else {$Result="No"}

    $Results += New-Object -TypeName psobject -Property @{
        Topic="Real-time Scanning"
        Check="RealtimeMonitoring"
        Result=$Result
        Config=$RTPMonitoring
        Description= "Constantly monitor files and processes for known malware modifications"
    }


    switch ($MpPref.DisableBehaviorMonitoring) {
        1 {$BehaviorMonitoring = "Disabled"}
        default {$BehaviorMonitoring = "Enabled"}
    }
    if ($BehaviorMonitoring -eq "Enabled") {$Result="Yes"} else {$Result="No"}

    $Results += New-Object -TypeName psobject -Property @{
        Topic="Real-time Scanning"
        Check="BehaviorMonitoring"
        Result=$Result
        Config=$BehaviorMonitoring
        Description= "Constantly monitor for known malware behaviors - even in 'clean' files and running programs"
    }


    switch ($MpPref.DisableScriptScanning) {
        1 {$ScriptScanning = "Disabled"}
        default {$ScriptScanning = "Enabled"}
    }
    if ($ScriptScanning -eq "Enabled") {$Result="Yes"} else {$Result="No"}

    $Results += New-Object -TypeName psobject -Property @{
        Topic="Real-time Scanning"
        Check="ScriptScanning"
        Result=$Result
        Config=$ScriptScanning
        Description= "Scan scripts as soon as they're seen or run"
    }


    switch ($MpPref.DisableRemovableDriveScanning) {
        1 {$RemovableDriveScanning = "Disabled"}
        default {$RemovableDriveScanning = "Enabled"}
    }
    if ($RemovableDriveScanning -eq "Enabled") {$Result="Yes"} else {$Result="No"}

    $Results += New-Object -TypeName psobject -Property @{
        Topic="Real-time Scanning"
        Check="RemovableDriveScanning"
        Result=$Result
        Config=$RemovableDriveScanning
        Description= "Scan removable drives as soon as they're inserted or mounted"
    }


    # Potentially Unwanted Application protection - https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-using-powershell#potentially-unwanted-application-protection

    switch ($MpPref.PUAProtection) {
        0 {$PUA = "Disabled"}
        1 {$PUA = "Enabled"}
        2 {$PUA = "Audit"}
    }
    if ($PUA -eq "Enabled") {$Result="Yes"} else {$Result="No"}

    $Results += New-Object -TypeName psobject -Property @{
        Topic="Potentially Unwanted Application protection"
        Check="PUAProtection"
        Result=$Result
        Config=$PUA
        Description= "Prevent grayware, adware, and other potentially unwanted apps from installing"
    }


    # Email and archive scanning - https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-using-powershell#email-and-archive-scanning

    switch ($MpPref.DisableArchiveScanning) {
        1 {$ArchiveScan = "Disabled"}
        default {$ArchiveScan = "Enabled"}
    }
    if ($ArchiveScan -eq "Enabled") {$Result="Yes"} else {$Result="No"}

    $Results += New-Object -TypeName psobject -Property @{
        Topic="Email and archive scanning"
        Check="ArchiveScanning"
        Result=$Result
        Config=$ArchiveScan
        Description= "Scan files contained within archives"
    }


    switch ($MpPref.DisableEmailScanning) {
        0 {$EmailScan = "Disabled"}
        default {$EmailScan = "Disabled"}
    }
    if ($EmailScan -eq "Enabled") {$Result="Yes"} else {$Result="No"}

    $Results += New-Object -TypeName psobject -Property @{
        Topic="Email and archive scanning"
        Check="EmailScanning"
        Result=$Result
        Config=$EmailScan
        Description= "Scan email stored within files (e.g. .PST)"
    }


    # Exploit protection - https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-using-powershell#advanced-threat-and-exploit-mitigation-and-prevention-controlled-folder-access

    switch ($MpPref.EnableControlledFolderAccess) {
        0 {$CFA = "Disabled"}
        1 {$CFA = "Enabled"}
        2 {$CFA = "Audit"}
        3 {$CFA = "BlockDiskOnly"}
        4 {$CFA = "AuditDiskOnly"}
    }
    if ($CFA -eq "Enabled") {$Result="Yes"} else {$Result="No"}

    $Results += New-Object -TypeName psobject -Property @{
        Topic="Exploit protection"
        Check="EnableControlledFolderAccess"
        Result=$Result
        Config=$CFA
        Description= "Prevent malicious and suspicious apps (such as ransomware) from making changes to protected folders with Controlled folder access"
    }


    switch ($MpPref.EnableNetworkProtection) {
        0 {$NetworkProtection = "Disabled"}
        1 {$NetworkProtection = "Enabled"}
        2 {$NetworkProtection = "Audit"}
    }
    if ($NetworkProtection -eq "Enabled") {$Result="Yes"} else {$Result="No"}

    $Results += New-Object -TypeName psobject -Property @{
        Topic="Exploit protection"
        Check="EnableNetworkProtection"
        Result=$Result
        Config=$NetworkProtection
        Description= "Block connections to known bad IP addresses and other network connections with Network protection"
    }


    # https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference

    $ASRDefinitions = @{
        "56a863a9-875e-4185-98a7-b882c64b5ce5" = "Block abuse of exploited vulnerable signed drivers";
        "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = "Block Adobe Reader from creating child processes";
        "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = "Block all Office applications from creating child processes";
        "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = "Block credential stealing from the Windows local security authority subsystem (lsass.exe)";
        "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = "Block executable content from email client and webmail";
        "01443614-cd74-433a-b99e-2ecdc07bfc25" = "Block executable files from running unless they meet a prevalence, age, or trusted list criterion";
        "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = "Block execution of potentially obfuscated scripts";
        "d3e037e1-3eb8-44c8-a917-57927947596d" = "Block JavaScript or VBScript from launching downloaded executable content";
        "3b576869-a4ec-4529-8536-b80a7769e899" = "Block Office applications from creating executable content";
        "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" = "Block Office applications from injecting code into other processes";
        "26190899-1602-49e8-8b27-eb1d0a1ce869" = "Block Office communication application from creating child processes";
        "e6db77e5-3df2-4cf1-b95a-636979351e5b" = "Block persistence through WMI event subscription";
        "d1e49aac-8f56-4280-b9ba-993a6d77406c" = "Block process creations originating from PSExec and WMI commands";
        "33ddedf1-c6e0-47cb-833e-de6133960387" = "Block rebooting machine in Safe Mode";
        "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = "Block untrusted and unsigned processes that run from USB";
        "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb" = "Block use of copied or impersonated system tools";
        "a8f5898e-1dc8-49a9-9878-85004b8a61e6" = "Block Webshell creation for Servers";
        "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = "Block Win32 API calls from Office macros";
        "c1db55ab-c21a-4637-bb3f-a12568109d35" = "Use advanced protection against ransomware";
    }


    $ASRIds = $MpPref.AttackSurfaceReductionRules_Ids
    $ASRActions = $MpPref.AttackSurfaceReductionRules_Actions

    $MappedASR = @()
    $i = 0

    # Map both the ASR ID and Action within the same array
    foreach ($ASRId in $ASRIds) {
        $MappedASR += New-Object -TypeName psobject -Property @{
            ID=$ASRId
            Action=$ASRActions[$i]
        }
        $i++
    }


    ForEach ($ASR in $MappedASR) {
        # ASR Rule modes
        switch ($ASR.Action) {
            0 {$ASRState = "Disabled"}
            1 {$ASRState = "Block"}
            2 {$ASRState = "Audit"}
            6 {$ASRState = "Warn"}
        }

        if ($ASRState -eq "Block") {$Result="Yes"} else {$Result="No"}

        $ASRName = $ASRDefinitions[$ASR.ID]

        $Results += New-Object -TypeName psobject -Property @{
            Topic="Exploit protection"
            Check="ASR Rule ($($ASR.ID))"
            Result=$Result
            Config=$ASRState
            Description=$ASRName
        }
    }

    # Return the results
    Invoke-GenerateReport -Results $Results
}


function Invoke-GenerateReport {
    param (
        $Results
    )

    $ReportTitle = "Defender Evaluation report"
    $ReportHeading = "Defender Evaluation report"
    $IntroText = "Verify configuration are aligning with recommended settings when performing an evaluation of Microsoft Defender Antivirus and Microsoft Defender for Endpoint."

     # Output start
     $output += "<!doctype html>
     <html lang='en'>
     <head>
        <!-- Required meta tags -->
        <meta charset='utf-8'>
        <meta name='viewport' content='width=device-width, initial-scale=1, shrink-to-fit=no'>

        <link rel='stylesheet' href='https://cdn.jsdelivr.net/npm/bootstrap@4.3.1/dist/css/bootstrap.min.css' integrity='sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T' crossorigin='anonymous'>

        <title>$ReportTitle</title>
    </head>
      <body>
        <div class='jumbotron jumbotron-fluid'>
            <div class='container'>
                <h1 class='display-4'>$ReportHeading</h1>
                <p class='lead'>$IntroText</p>
                <a class='btn btn-primary btn-lg' href='https://learn.microsoft.com/en-us/defender-endpoint/evaluate-microsoft-defender-antivirus' role='button' target='_blank'>Learn more</a>
                <div class='text-right'>Report generated: $((get-date).ToString("dd MMMM yyyy - HH:mm:ss"))</div>
            </div>
        </div>

        <script src='https://code.jquery.com/jquery-3.3.1.slim.min.js' integrity='sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo' crossorigin='anonymous'></script>
        <script src='https://cdn.jsdelivr.net/npm/popper.js@1.14.7/dist/umd/popper.min.js' integrity='sha384-UO2eT0CpHqdSJQ6hJty5KVphtPhzWj9WO1clHTMGa3JDZwrnQq4sF86dIHNDz0W1' crossorigin='anonymous'></script>
        <script src='https://cdn.jsdelivr.net/npm/bootstrap@4.3.1/dist/js/bootstrap.min.js' integrity='sha384-JjSmVgyd0p3pXB1rRibZUAYoIIy6OrQ6VrjIEaFf/nJGzIxFDsf4x0xIM+B07jRM' crossorigin='anonymous'></script>
    "
    
    # Loop each Topic
    foreach ($Topic in ($Results | Group-Object Topic)){
        $output += "<div class='card m-3'>
            <h5 class='card-header'>$($Topic.Name)</h5>
        <div class='card-body'>
        <table class='table table-borderless table-hover'>
            <thead><tr>
                <th scope='col'></th>
                <th scope='col'>Feature</th>
                <th scope='col'>Current Value</th>
                <th scope='col'>Follows Recommendation?</th>
                <th scope='col'>Description</th>
            </tr></thead>
            <tbody>
        "

        # Loop each Result
        foreach ($Result in ($Results | Where-Object {$_.Topic -eq $Topic.Name})) {
            $output += "<tr><th scope='row'></th>
                <td>$($Result.Check)</td>
                <td>$($Result.Config)</td>
                <td";if($($Result.Result -eq "Yes")) {$output += " class='table-success'"} else {$output += " class='table-danger'"};$output+=">$($Result.Result)</td>
                <td>$($Result.Description)</td>
            </tr>"
        }

        $output += "</tbody></table></div></div>"
    }


    # End of the report
    $output += "
    </body>
    </html>
    "


    # Export the generated HTML file

    $Folder = (Get-Item .).FullName
    $OutFile = "DefenderEval_$(Get-Date -Format ("yyyymmdd-HHmmss")).html"
    #$OutFile = "DefenderEval.html" # Static report for testing
    $FilePath = Join-Path -Path $Folder -ChildPath $OutFile

    $output | Out-File -FilePath $FilePath

    Invoke-Expression "&'$FilePath'"
}
