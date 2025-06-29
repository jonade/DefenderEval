#Requires -Version 5.1

<#
.SYNOPSIS
    Verify configuration are aligning with recommended settings when performing an 
    evaluation of Microsoft Defender Antivirus and Microsoft Defender for Endpoint

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

Function Get-RunningElevated {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    Return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}


Function Invoke-ModuleVersionCheck {
    # Determines if the module is up to date
    
    $GalleryVersion = Find-Module DefenderEval
    $InstalledVersion = Get-Module DefenderEval | Select-Object -First 1

    If($GalleryVersion.Version -gt $InstalledVersion.Version) {
        Write-Host "$(Get-Date) The loaded version of the DefenderEval module ($($InstalledVersion.Version)) is older than the latest version in the PSGallery ($($GalleryVersion.Version)). Attempting to upgrade to the latest version."
        
        Try {
            Update-Module DefenderEval -Force
            Import-Module DefenderEval -RequiredVersion $GalleryVersion.Version -Force
        } Catch {
            Write-Error "Error while trying to upgrade the module. Try running Update-Module DefenderEval"
        }
        

        # Uninstall old versions
        $Modules = (Get-Module DefenderEval -ListAvailable | Sort-Object Version -Descending)
        $Latest = $Modules[0]

        If($Modules.Count -gt 1) {
            ForEach($Module in $Modules) {
                If($Module.Version -ne $Latest.Version) {
                    # Remove any out of date versions of the module
                    Write-Host "$(Get-Date) Uninstalling $($Module.Name) (Version $($Module.Version))"
                    Try {
                        Uninstall-Module $Module.Name -RequiredVersion $($Module.Version) -ErrorAction:Stop
                    } Catch {}
                }
            }
        }
    }
}

Function Get-DefenderEvaluationReport {
    param (

    )

    # Prechecks
    Invoke-ModuleVersionCheck
    
    if ((Get-RunningElevated) -eq $false) {
        throw "PowerShell must be run elevated as an administrator to be able to collect data from the machine."
    }

    $Results = @()
    $MpPref = Get-MpPreference
    $MpComputerStatus = Get-MpComputerStatus
    $ComputerInfo = Get-ComputerInfo


    # Evaluate Settings

    # Collect details of configured Exclusions
    $Exclusions = [ordered]@{
        'Excluded Paths' = @($MpPref.ExclusionPath)
        'Excluded Processes' = @($MpPref.ExclusionExtension)
        'Excluded Extensions' = @($MpPref.ExclusionExtension)
        'Excluded IPs' = @($MpPref.ExclusionIpAddress)
        'Controlled Folder Access Excluded Applications' = @($MpPref.ControlledFolderAccessAllowedApplications)
    }


    # Cloud Protection - https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-using-powershell#cloud-protection-features

    switch ($MpPref.MAPSReporting) {
        {1 -or 2} {$MAPSReporting = "Advanced"}
        default {$MAPSReporting = "Disabled"}
    }

    if ($MAPSReporting -eq "Advanced") {$Result="Yes"} else {$Result="No"}

    $Results += New-Object -TypeName psobject -Property @{
        Topic = "Cloud Protection"
        Check = "MAPSReporting"
        Result = $Result
        Config = $MAPSReporting
        Description = "Enable the Microsoft Defender Cloud for near-instant protection and increased protection"
        Fix = "Set-MpPreference -MAPSReporting Advanced"
    }


    switch ($MpPref.SubmitSamplesConsent) {
        0 {$SubmitType = "AlwaysPrompt"}
        1 {$SubmitType = "SafeSamples"}
        2 {$SubmitType = "NeverSend"}
        3 {$SubmitType = "AllSamples"}
    }

    if ($SubmitType -eq "AllSamples") {$Result="Yes"} else {$Result="No"}

    $Results += New-Object -TypeName psobject -Property @{
        Topic = "Cloud Protection"
        Check = "SubmitSamplesConsent"
        Result = $Result
        Config = $SubmitType
        Description = "Automatically submit samples to increase group protection"
        Fix = "Set-MpPreference -SubmitSamplesConsent SendAllSamples"
    }


    switch ($MpPref.DisableBlockAtFirstSeen) {
        $true {$BAFS = "Disabled"}
        default {$BAFS = "Enabled"}
    }
    if ($BAFS -eq "Enabled") {$Result="Yes"} else {$Result="No"}

    $Results += New-Object -TypeName psobject -Property @{
        Topic = "Cloud Protection"
        Check = "BlockAtFirstSeen"
        Result = $Result
        Config = $BAFS
        Description = "Always use the cloud to block new malware within seconds"
        Fix = "Set-MpPreference -DisableBlockAtFirstSeen `$false"
    }


    switch ($MpPref.DisableIOAVProtection) {
        $true {$IOAV = "Disabled"}
        default {$IOAV = "Enabled"}
    }
    if ($IOAV -eq "Enabled") {$Result="Yes"} else {$Result="No"}

    $Results += New-Object -TypeName psobject -Property @{
        Topic = "Cloud Protection"
        Check = "IOAVProtection"
        Result = $Result
        Config = $IOAV
        Description = "Scan all downloaded files and attachments"
        Fix = "Set-MpPreference -DisableIOAVProtection `$false"
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
        Topic = "Cloud Protection"
        Check = "CloudBlockLevel"
        Result = $Result
        Config = $CloudBlockLevel
        Description = "Set cloud block level to at least 'High'"
        Fix = "Set-MpPreference -CloudBlockLevel High"
    }


    if ($MpPref.CloudExtendedTimeout -ge 50) {$Result="Yes"} else {$Result="No"}

    $Results += New-Object -TypeName psobject -Property @{
        Topic = "Cloud Protection"
        Check = "CloudExtendedTimeout"
        Result = $Result
        Config = $MpPref.CloudExtendedTimeout
        Description = "Extend cloud block time-out to 1 minute"
        Fix = "Set-MpPreference -CloudExtendedTimeout 50"
    }


    # Real-time Scanning - https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-using-powershell#always-on-protection-real-time-scanning
    switch ($MpPref.DisableRealtimeMonitoring) {
        $true {$RTPMonitoring = "Disabled"}
        default {$RTPMonitoring = "Enabled"}
    }
    if ($RTPMonitoring -eq "Enabled") {$Result="Yes"} else {$Result="No"}

    $Results += New-Object -TypeName psobject -Property @{
        Topic = "Real-time Scanning"
        Check = "RealtimeMonitoring"
        Result = $Result
        Config = $RTPMonitoring
        Description = "Constantly monitor files and processes for known malware modifications"
        Fix = "Set-MpPreference -DisableRealtimeMonitoring `$false"
    }

    switch ($MpPref.RealTimeScanDirection) {
        1 {$RTPDirection = "Incoming Files"}
        2 {$RTPDirection = "Outgoing Files"}
        default {$RTPDirection = "Incoming and Outgoing Files"}
    }
    if ($RTPDirection -eq "Incoming and Outgoing Files") {$Result="Yes"} else {$Result="No"}

    $Results += New-Object -TypeName psobject -Property @{
        Topic = "Real-time Scanning"
        Check = "RealTimeScanDirection"
        Result = $Result
        Config = $RTPDirection
        Description = "Specifies scanning configuration for incoming and outgoing files on NTFS volumes"
        Fix = "Set-MpPreference -RealTimeScanDirection 0"
    }


    switch ($MpPref.DisableBehaviorMonitoring) {
        $true {$BehaviorMonitoring = "Disabled"}
        default {$BehaviorMonitoring = "Enabled"}
    }
    if ($BehaviorMonitoring -eq "Enabled") {$Result="Yes"} else {$Result="No"}

    $Results += New-Object -TypeName psobject -Property @{
        Topic = "Real-time Scanning"
        Check = "BehaviorMonitoring"
        Result = $Result
        Config = $BehaviorMonitoring
        Description = "Constantly monitor for known malware behaviors - even in 'clean' files and running programs"
        Fix = "Set-MpPreference -DisableBehaviorMonitoring `$false"
    }


    switch ($MpPref.DisableScriptScanning) {
        $true {$ScriptScanning = "Disabled"}
        default {$ScriptScanning = "Enabled"}
    }
    if ($ScriptScanning -eq "Enabled") {$Result="Yes"} else {$Result="No"}

    $Results += New-Object -TypeName psobject -Property @{
        Topic = "Real-time Scanning"
        Check = "ScriptScanning"
        Result = $Result
        Config = $ScriptScanning
        Description = "Scan scripts as soon as they're seen or run"
        Fix = "Set-MpPreference -DisableScriptScanning `$false"
    }


    switch ($MpPref.DisableRemovableDriveScanning) {
        $true {$RemovableDriveScanning = "Disabled"}
        default {$RemovableDriveScanning = "Enabled"}
    }
    if ($RemovableDriveScanning -eq "Enabled") {$Result="Yes"} else {$Result="No"}

    $Results += New-Object -TypeName psobject -Property @{
        Topic = "Real-time Scanning"
        Check = "RemovableDriveScanning"
        Result = $Result
        Config = $RemovableDriveScanning
        Description = "Scan removable drives as soon as they're inserted or mounted"
        Fix = "Set-MpPreference -DisableRemovableDriveScanning `$false"
    }


    switch ($MpPref.EnableFileHashComputation) {
        $true {$FileHash = "Enabled"}
        default {$FileHash = "Disabled"}
    }
    if ($FileHash -eq "Enabled") {$Result="Yes"} else {$Result="No"}

    $Results += New-Object -TypeName psobject -Property @{
        Topic = "Real-time Scanning"
        Check = "EnableFileHashComputation"
        Result = $Result
        Config = $FileHash
        Description = "Specifies whether to enable file hash computation for files that are scanned."
        DescriptionNote = "This improves blocking accuracy of file IoCs, however it may impact device performance"
        Fix = "Set-MpPreference -EnableFileHashComputation `$true"
    }


    # Potentially Unwanted Application protection - https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-using-powershell#potentially-unwanted-application-protection

    switch ($MpPref.PUAProtection) {
        0 {$PUA = "Disabled"}
        1 {$PUA = "Enabled"}
        2 {$PUA = "Audit"}
    }
    if ($PUA -eq "Enabled") {$Result="Yes"} else {$Result="No"}

    $Results += New-Object -TypeName psobject -Property @{
        Topic = "Potentially Unwanted Application protection"
        Check = "PUAProtection"
        Result = $Result
        Config = $PUA
        Description = "Prevent grayware, adware, and other potentially unwanted apps from installing"
        Fix = "Set-MpPreference -PUAProtection Enabled"
    }


    # Email and archive scanning - https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-using-powershell#email-and-archive-scanning

    switch ($MpPref.DisableArchiveScanning) {
        $true {$ArchiveScan = "Disabled"}
        default {$ArchiveScan = "Enabled"}
    }
    if ($ArchiveScan -eq "Enabled") {$Result="Yes"} else {$Result="No"}

    $Results += New-Object -TypeName psobject -Property @{
        Topic = "Email and archive scanning"
        Check = "ArchiveScanning"
        Result = $Result
        Config = $ArchiveScan
        Description = "Scan files contained within archives"
        Fix = "Set-MpPreference -DisableArchiveScanning `$false"
    }


    switch ($MpPref.DisableEmailScanning) {
        $false {$EmailScan = "Enabled"}
        default {$EmailScan = "Disabled"}
    }
    if ($EmailScan -eq "Enabled") {$Result="Yes"} else {$Result="No"}

    $Results += New-Object -TypeName psobject -Property @{
        Topic = "Email and archive scanning"
        Check = "EmailScanning"
        Result = $Result
        Config = $EmailScan
        Description = "Scan email stored within files (e.g. .PST)"
        Fix = "Set-MpPreference -DisableEmailScanning `$false"
    }

    # Protection updates - https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-using-powershell#manage-product-and-protection-updates

    switch ($MpPref.CheckForSignaturesBeforeRunningScan) {
        $true {$SignatureUpdate = "Enabled"}
        default {$SignatureUpdate = "Disabled"}
    }
    if ($SignatureUpdate -eq "Enabled") {$Result="Yes"} else {$Result="No"}

    $Results += New-Object -TypeName psobject -Property @{
        Topic = "Scan settings"
        Check = "CheckForSignaturesBeforeRunningScan"
        Result = $Result
        Config = $SignatureUpdate
        Description = "Check to update signatures before running a scheduled scan"
        Fix = "Set-MpPreference -CheckForSignaturesBeforeRunningScan `$true"
    }

    switch ($MpPref.UILockdown) {
        $true {$UILockdown = "Disabled"}
        default {$UILockdown = "Enabled"}
    }
    if ($UILockdown -eq "Enabled") {$Result="Yes"} else {$Result="No"}

    $Results += New-Object -TypeName psobject -Property @{
        Topic = "Scan settings"
        Check = " UILockdown"
        Result = $Result
        Config = $UILockdown
        Description = "Ensure notifications allow you to boot the PC into a specialized malware removal environment"
        Fix = "Set-MpPreference -UILockdown `$false"
    }


    # Windows Server specific settings

    If ($ComputerInfo.WindowsInstallationType -eq "Server") {
        switch ($MpPref.AllowNetworkProtectionOnWinServer) {
            $true {$NPServer = "Enabled"}
            default {$NPServer = "Disabled"}
        }
        if ($NPServer -eq "Enabled") {$Result="Yes"} else {$Result="No"}

        $Results += New-Object -TypeName psobject -Property @{
            Topic = "Windows Server settings"
            Check = "AllowNetworkProtectionOnWinServer"
            Result = $Result
            Config = $NPServer
            Description = "Enable Network Protection on Windows Server"
            Fix = "Set-MpPreference -AllowNetworkProtectionOnWinServer `$true"
        }

        switch ($MpPref.AllowNetworkProtectionDownLevel) {
            $true {$NPDownlevel = "Enabled"}
            default {$NPDownlevel = "Disabled"}
        }
        if ($NPDownlevel -eq "Enabled") {$Result="Yes"} else {$Result="No"}

        $Results += New-Object -TypeName psobject -Property @{
            Topic = "Windows Server settings"
            Check = "AllowNetworkProtectionDownLevel"
            Result = $Result
            Config = $NPDownlevel
            Description = "Enable Network Protection on downlevel Windows Server"
            Fix = "Set-MpPreference -AllowNetworkProtectionDownLevel `$true"
        }

        switch ($MpPref.AllowDatagramProcessingOnWinServer) {
            $true {$NPDatagram = "Enabled"}
            default {$NPDatagram = "Disabled"}
        }
        if ($NPDatagram -eq "Enabled") {$Result="Yes"} else {$Result="No"}

        $Results += New-Object -TypeName psobject -Property @{
            Topic = "Windows Server settings"
            Check = "AllowDatagramProcessingOnWinServer"
            Result = $Result
            Config = $NPDatagram
            Description = "Enable Datagram procesing on Windows Server"
            Fix = "Set-MpPreference -AllowDatagramProcessingOnWinServer `$true"
        }

        switch ($MpPref.DisableAutoExclusions) {
            $true {$AutoExclude = "Disabled"}
            default {$AutoExclude = "Enabled"}
        }
        if ($AutoExclude -eq "Enabled") {$Result="Yes"} else {$Result="No"}

        $Results += New-Object -TypeName psobject -Property @{
            Topic = "Windows Server settings"
            Check = "AutoExclusions"
            Result = $Result
            Config = $AutoExclude
            Description = "Disable automatic exclusions on Windows Server"
            Fix = "Set-MpPreference -DisableAutoExclusions `$false"
        }
    }

    # Network protection

    switch ($MpPref.EnableNetworkProtection) {
        0 {$NetworkProtection = "Disabled"}
        1 {$NetworkProtection = "Enabled"}
        2 {$NetworkProtection = "Audit"}
    }
    if ($NetworkProtection -eq "Enabled") {$Result="Yes"} else {$Result="No"}

    $Results += New-Object -TypeName psobject -Property @{
        Topic = "Network protection"
        Check = "EnableNetworkProtection"
        Result = $Result
        Config = $NetworkProtection
        Description = "Block connections to known bad IP addresses and other network connections with Network protection"
        Fix = "Set-MpPreference -EnableNetworkProtection Enabled"
    }


    switch ($MpPref.DisableInboundConnectionFiltering) {
        $true{$InboundFilter = "Disabled"}
        default {$InboundFilter = "Enabled"}
    }
    if ($InboundFilter -eq "Enabled") {$Result="Yes"} else {$Result="No"}

    $Results += New-Object -TypeName psobject -Property @{
        Topic = "Network protection"
        Check = "InboundConnectionFiltering"
        Result = $Result
        Config = $InboundFilter
        Description = "Specifies whether to inspect only outbound connections. By default, Network Protection inspects both inbound and outbound connections"
        Fix = "Set-MpPreference -DisableInboundConnectionFiltering `$false"
    }


    switch ($MpPref.DisableDatagramProcessing) {
        $true {$DatagramParse = "Disabled"}
        default {$DatagramParse = "Enabled"}
    }
    if ($DatagramParse -eq "Enabled") {$Result="Yes"} else {$Result="No"}

    $Results += New-Object -TypeName psobject -Property @{
        Topic = "Network protection"
        Check = "DatagramProcessing"
        Result = $Result
        Config = $DatagramParse
        Description = "Inspection of UDP connections"
        Fix = "Set-MpPreference -DisableDatagramProcessing `$false"
    }


    switch ($MpPref.DisableDnsParsing) {
        $true {$DNSParse = "Disabled"}
        default {$DNSParse = "Enabled"}
    }
    if ($DNSParse -eq "Enabled") {$Result="Yes"} else {$Result="No"}

    $Results += New-Object -TypeName psobject -Property @{
        Topic = "Network protection"
        Check = "DnsParsing"
        Result = $Result
        Config = $DNSParse
        Description = "Inspection of DNS traffic that occurs over a UDP channel"
        Fix = "Set-MpPreference -DisableDnsParsing `$false"
    }


    switch ($MpPref.DisableDnsOverTcpParsing) {
        $true {$TCPDNS = "Disabled"}
        default {$TCPDNS = "Enabled"}
    }
    if ($TCPDNS -eq "Enabled") {$Result="Yes"} else {$Result="No"}

    $Results += New-Object -TypeName psobject -Property @{
        Topic = "Network protection"
        Check = "DnsOverTcpParsing"
        Result = $Result
        Config = $TCPDNS
        Description = "Inspection of DNS traffic that occurs over a TCP channel"
        Fix = "Set-MpPreference -DisableDnsOverTcpParsing `$false"
    }


    switch ($MpPref.EnableDnsSinkhole) {
        $true {$DnsSinkhole = "Enabled"}
        default {$DnsSinkhole = "Disabled"}
    }
    if ($DnsSinkhole -eq "Enabled") {$Result="Yes"} else {$Result="No"}

    $Results += New-Object -TypeName psobject -Property @{
        Topic = "Network protection"
        Check = "DnsSinkhole"
        Result = $Result
        Config = $DnsSinkhole
        Description = "Inspect DNS traffic to detect and sinkhole DNS exfiltration attempts and other DNS based malicious attacks"
        Fix = "Set-MpPreference -EnableDnsSinkhole `$true"
    }


    switch ($MpPref.DisableFtpParsing) {
        $true {$FTPParse = "Disabled"}
        default {$FTPParse = "Enabled"}
    }
    if ($FTPParse -eq "Enabled") {$Result="Yes"} else {$Result="No"}

    $Results += New-Object -TypeName psobject -Property @{
        Topic = "Network protection"
        Check = "FtpParsing"
        Result = $Result
        Config = $FTPParse
        Description = "Inspection of FTP traffic"
        Fix = "Set-MpPreference -DisableFtpParsing `$false"
    }


    switch ($MpPref.DisableHttpParsing) {
        $true {$HTTPParse = "Disabled"}
        default {$HTTPParse = "Enabled"}
    }
    if ($HTTPParse -eq "Enabled") {$Result="Yes"} else {$Result="No"}

    $Results += New-Object -TypeName psobject -Property @{
        Topic = "Network protection"
        Check = "HttpParsing"
        Result = $Result
        Config = $HTTPParse
        Description = "Inspection of HTTP traffic"
        Fix = "Set-MpPreference -DisableHttpParsing `$false"
    }


    switch ($MpPref.DisableRdpParsing) {
        $true {$RDPParse = "Disabled"}
        default {$RDPParse = "Enabled"}
    }
    if ($RDPParse -eq "Enabled") {$Result="Yes"} else {$Result="No"}

    $Results += New-Object -TypeName psobject -Property @{
        Topic = "Network protection"
        Check = "RdpParsing"
        Result = $Result
        Config = $RDPParse
        Description = "Inspect RDP traffic to look for malicious attacks using the RDP protocol"
        Fix = "Set-MpPreference -DisableRdpParsing `$false"
    }


    switch ($MpPref.DisableSmtpParsing) {
        $true {$SMTPParse = "Disabled"}
        default {$SMTPParse = "Enabled"}
    }
    if ($SMTPParse -eq "Enabled") {$Result="Yes"} else {$Result="No"}

    $Results += New-Object -TypeName psobject -Property @{
        Topic = "Network protection"
        Check = "SmtpParsing"
        Result = $Result
        Config = $SMTPParse
        Description = "Inspection of SMTP traffic"
        Fix = "Set-MpPreference -DisableSmtpParsing `$false"
    }


    switch ($MpPref.DisableSshParsing) {
        $true {$SSHParse = "Disabled"}
        default {$SSHParse = "Enabled"}
    }
    if ($SSHParse -eq "Enabled") {$Result="Yes"} else {$Result="No"}

    $Results += New-Object -TypeName psobject -Property @{
        Topic = "Network protection"
        Check = "SshParsing"
        Result = $Result
        Config = $SSHParse
        Description = "Inspection of SSH traffic"
        Fix = "Set-MpPreference -DisableSshParsing `$false"
    }


    switch ($MpPref.DisableTlsParsing) {
        $true {$TLSParse = "Disabled"}
        default {$TLSParse = "Enabled"}
    }
    if ($TLSParse -eq "Enabled") {$Result="Yes"} else {$Result="No"}

    $Results += New-Object -TypeName psobject -Property @{
        Topic = "Network protection"
        Check = "TlsParsing"
        Result = $Result
        Config = $TLSParse
        Description = "Inspect of TLS traffic to see if a connection is being made to a malicious website, and provide metadata to behavior monitoring"
        Fix = "Set-MpPreference -DisableTlsParsing `$false"
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
        Topic = "Exploit protection"
        Check = "EnableControlledFolderAccess"
        Result = $Result
        Config = $CFA
        Description = "Prevent malicious and suspicious apps (such as ransomware) from making changes to protected folders with Controlled folder access"
        Fix = "Set-MpPreference -EnableControlledFolderAccess Enabled"
    }


    # Define the GUIDs and the names for the attack surface reduction rules for use in the report
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

    # Map both the ASR ID and Action together within the same object to make looping through them easier
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
            Topic = "Exploit protection"
            Check = "ASR Rule ($($ASR.ID))"
            ASR = $ASR.ID
            Result = $Result
            Config = $ASRState
            Description = $ASRName
            Fix = "Add-MpPreference -AttackSurfaceReductionRules_Ids $($ASR.ID) -AttackSurfaceReductionRules_Actions Enabled"
        }
    }

    # Ensure that rows are added to the results even if any defined ASR rules are missing
    foreach ($ASRDefinition in $($ASRDefinitions.GetEnumerator())) {
        if ($Results.ASR -notcontains $($ASRDefinition.Name)) {
            $Results += New-Object -TypeName psobject -Property @{
                Topic = "Exploit protection"
                Check = "ASR Rule ($($ASRDefinition.Name))"
                Result = "No"
                Config = "Missing"
                Description = $($ASRDefinition.Value)
                Fix = "Add-MpPreference -AttackSurfaceReductionRules_Ids $($ASRDefinition.Name) -AttackSurfaceReductionRules_Actions Enabled"
            }
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
    [version]$ModuleInfo = (Get-Module -Name DefenderEval | Select-Object -First 1).Version

     # Output start
     $output += "<!doctype html>
     <html lang='en'>
     <head>
        <!-- Required meta tags -->
        <meta charset='utf-8'>
        <meta name='viewport' content='width=device-width, initial-scale=1, shrink-to-fit=no'>

        <link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.5/dist/css/bootstrap.min.css' rel='stylesheet' integrity='sha384-SgOJa3DmI69IUzQ2PVdRZhwQ+dy64/BUtbMJw1MZ8t5HZApcHrRKUc4W0kG879m7' crossorigin='anonymous'>
        <link rel='stylesheet' href='https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css'>

        <title>$ReportTitle</title>
    </head>
      <body>
        <div class='container my-5'>
            <div class='toast-container position-fixed top-0 end-0 p-3'>
                <div class='toast show align-items-center' role='alert' aria-live='polite' aria-atomic='true' data-bs-autohide='false'>
                    <div class='toast-header'>
                        <strong class='me-auto'>Rate this report!</strong>
                        <button type='button' class='btn-close me-2 m-auto' data-bs-dismiss='toast' aria-label='Close'></button>
                    </div>
                    <div class='toast-body'>
                        <div class='rating-card p-0 m-0'>
                            <div class='star-rating animated-stars'>
                                <input type='radio' id='star5' name='rating' value='5' onclick=`"window.open('https://aka.ms/DefenderEval-Feedback-5','_blank');`" />
                                <label for='star5' class='bi bi-star-fill'></label>
                                <input type='radio' id='star4' name='rating' value='4' onclick=`"window.open('https://aka.ms/DefenderEval-Feedback-4','_blank');`" />
                                <label for='star4' class='bi bi-star-fill'></label>
                                <input type='radio' id='star3' name='rating' value='3' onclick=`"window.open('https://aka.ms/DefenderEval-Feedback-3','_blank');`" />
                                <label for='star3' class='bi bi-star-fill'></label>
                                <input type='radio' id='star2' name='rating' value='2' onclick=`"window.open('https://aka.ms/DefenderEval-Feedback-2','_blank');`" />
                                <label for='star2' class='bi bi-star-fill'></label>
                                <input type='radio' id='star1' name='rating' value='1' onclick=`"window.open('https://aka.ms/DefenderEval-Feedback-1','_blank');`" />
                                <label for='star1' class='bi bi-star-fill'></label>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class='position-relative p-5 text-center text-muted bg-dark-subtle border border-dashed rounded-5'>
                <svg xmlns='http://www.w3.org/2000/svg'  viewBox='0 0 48 48' width='60px' height='60px'><path fill='#0370c8' d='M24,44c-0.552,0-1-0.448-1-1s0.448-1,1-1V44z'/><path fill='#0f5094' d='M25,43c0,0.552-0.448,1-1,1v-2C24.552,42,25,42.448,25,43z'/><circle cx='42' cy='11' r='1' fill='#0883d9'/><circle cx='6' cy='11' r='1' fill='#33bff0'/><path fill='#0f5094' d='M24,43l0.427,0.907c0,0,15.144-7.9,18.08-19.907H24V43z'/><path fill='#0883d9' d='M43,11l-1-1c-11.122,0-11.278-6-18-6v20h18.507C42.822,22.712,43,21.378,43,20C43,16.856,43,11,43,11 z'/><path fill='#0370c8' d='M24,43l-0.427,0.907c0,0-15.144-7.9-18.08-19.907H24V43z'/><path fill='#33bff0' d='M5,11l1-1c11.122,0,11.278-6,18-6v20H5.493C5.178,22.712,5,21.378,5,20C5,16.856,5,11,5,11z'/></svg><h1 class='text-body-emphasis'>$ReportHeading</h1>
                <p class='col-lg-10 mx-auto mb-4'>$IntroText</p>
                <a class='btn btn-primary px-4 mb-4' href='https://aka.ms/mdavevaluate' role='button' target='_blank'>Learn more</a>
                <div class='text-right'>Report generated: $((get-date).ToString("dd MMMM yyyy - HH:mm:ss"))</div>
                </div>
            </div>
        </div>
        <script src='https://cdn.jsdelivr.net/npm/bootstrap@5.3.5/dist/js/bootstrap.bundle.min.js' integrity='sha384-k6d4wzSIapyDyv1kpU366/PK5hCdSbCRGRCMv+eplOQJWyd1fbcAu9OCUj5zNLiq' crossorigin='anonymous'></script>

        <style>
        .custom-popover {
            --bs-border-width: 2px;
        }

        .toast {
            max-width: 240px;
        }
    
        .star-rating {
            direction: rtl;
            display: inline-block;
            cursor: pointer;
        }

        .star-rating input {
            display: none;
        }

        .star-rating label {
            color: #91a6ff;
            font-size: 24px;
            padding: 0 2px;
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .star-rating label:hover,
        .star-rating label:hover ~ label,
        .star-rating input:checked ~ label {
            color: #f7b731;
        }

        </style>
    "

    # Add header cards to the beginning of the report before the main results

    $output += "<div class='row justify-content-around'>" # Start of header cards


    $output += "<div class='card text-bg-light text-center p-0 border-info' style='width: 18rem;'>
        <div class='card-header h5 mb-0 text-bg-info'>Computer ID</div>
        <div class='card-body mb-0 small'>
            <p class='card-text user-select-all'>$($MpPref.ComputerID)</p>
            <p class='card-text'><strong>Platform:</strong> $($MpComputerStatus.AMProductVersion)</p>
            <p class='card-text'><strong>Engine:</strong> $($MpComputerStatus.AMEngineVersion)</p>
        </div>
    </div>"


    $output += "<div class='card text-bg-light text-center p-0 border-info' style='width: 18rem;'>
        <div class='card-header h5 text-bg-info'>Operating System</div>
            <div class='card-body small'>
            <p class='card-text'><strong>Name:</strong> $(($ComputerInfo.OsName).TrimStart('Microsoft '))</p>"
            if ($($ComputerInfo.WindowsInstallationType) -eq "Client") {
                $output += "<p class='card-text'><strong>Version:</strong> $($ComputerInfo.OSDisplayVersion)</p>"
            }
            $output += "
            <p class='card-text'><strong>Type:</strong> $($ComputerInfo.WindowsInstallationType)</p>
        </div>
    </div>"


    $output += "<div class='card text-center p-0"
    if($($MpComputerStatus.IsTamperProtected -eq $true)) {
        $output += " text-bg-success"
    } else {
        $output += " text-bg-danger"
    }
    $output += "' style='width: 18rem;'>
        <div class='card-header'><h5>Tamper Protection</h5></div>
            <div class='card-body'>
            <p class='card-text mb-2 align-middle'><strong>Enabled:</strong> $($MpComputerStatus.IsTamperProtected)</p>
            <p class='card-text align-middle'><strong>Source:</strong> $($MpComputerStatus.TamperProtectionSource)</p>
        </div>
    </div>"


    $output += "</div>" # End of header cards

    
    # Create a new table for each category within the results
    foreach ($Topic in ($Results | Group-Object Topic)){
        $output += "<div class='card m-3'>
            <h5 class='card-header bg-dark-subtle'>$($Topic.Name)</h5>
        <div class='card-body'>
        <table class='table table-hover table-striped mb-1'>
            <thead class='table-light'><tr>
                <th scope='col'></th>
                <th scope='col'>Feature</th>
                <th scope='col'>Current Value</th>
                <th scope='col'>Follows Recommendation?</th>
                <th scope='col'>Description</th>
                <th scope='col'></th>
            </tr></thead>
            <tbody>
        "

        # Add a new row for each result
        foreach ($Result in ($Results | Where-Object {$_.Topic -eq $Topic.Name})) {
            $output += "<tr><th scope='row'></th>
                <td>$($Result.Check)</td>
                <td>$($Result.Config)</td>
                <td class='text-center "
                if ($($Result.Result -eq "Yes")) {
                    $output += "table-success'"
                } else {
                    $output += "table-danger'"
                }
                $output += ">$($Result.Result)"
                if ($Result.DescriptionNote) {
                    $output += "<br><i class='bi-exclamation-triangle-fill opacity-75' data-bs-title='$($Result.DescriptionNote)' data-bs-toggle='tooltip' data-bs-placement='top' style='font-size: 1.3rem'></i>"
                }
                $output += "</td>
                <td>$($Result.Description)</td>
                <td>"
                if ($($Result.Result -eq "No") -and $Result.Fix) {
                    $output += "<button type='button' class='btn btn-secondary float-end' data-bs-html='true' data-bs-container='body' data-bs-toggle='popover' data-bs-placement='left' data-bs-custom-class='custom-popover' data-bs-content='<p class=`"user-select-all m-0 font-monospace`"><strong>$($Result.Fix)</strong></p>'>How to fix</button>"
                }
                $output += "</td>
            </tr>"
        }

        $output += "</tbody></table></div></div>"
    }

    # Add details of Exclusions which have been configured
    foreach ($Ex in $Exclusions.Keys){
        $CollapsingName = ($Ex -replace ' ','') # Friendly name to allow collapsing of table rows

        # Add one table for each exclusion type        
        $output += "<div class='card m-3'>
            <div class='h5 card-header bg-dark-subtle'>$($Ex)"
            if ($($Exclusions.$Ex).Count -ge 10) {
                $output += "<button type='button' class='btn btn-secondary btn-sm float-end' data-bs-toggle='collapse' data-bs-target='#collapse$CollapsingName'>Collapse</button>"
            }
            $output += "</div>
                <table class='table table-hover table-striped mb-0'>"
        # Allow the exclusion table rows to be collapsed
        if ($($Exclusions.$Ex).Count -ge 10) {
            $output += "<tbody class='collapse' id='collapse$CollapsingName'>"
        } else {
            $output += "<tbody>"
        }

        # Define how to add a new row to the Exclusions tables
        $Row = "<tr>
        <td scope='row'><ReplaceMe></td></tr>
        "

        if ($($Exclusions.$Ex).Count -eq 0) {
            # Add a single row indicating there are no exclusions configured
            $newRow = ($Row -replace ("<ReplaceMe>","None"))
            $newRow = ($newRow -replace ("<td ","<td class='table-success'")) # Update the background formatting if there are no exclusions
            $output += $newRow
        } else {
            # Add a row for each configured exclusion
            foreach ($obj in ($Exclusions.$Ex)) {
                $newRow = ($Row -replace ("<ReplaceMe>","<small>$Obj</small>"))
                $output += $newRow
            }
        }

        $output += "
            </tbody></table>
            </div></div>"
    }


    # Add a Footer to the end of the report
    $output += "
        <div class='card m-3 card-body text-center border-light text-body-secondary'>
            <p>Version: $ModuleInfo | <a href='https://aka.ms/DefenderEval' class='link-secondary'>GitHub</a></p>
            <script>
            const popoverTriggerList = document.querySelectorAll('[data-bs-toggle=`"popover`"]')
            const popoverList = [...popoverTriggerList].map(popoverTriggerEl => new bootstrap.Popover(popoverTriggerEl))
            const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle=`"tooltip`"]')
            const tooltipList = [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl))
            const collapseElementList = document.querySelectorAll('.collapse')
            const collapseList = [...collapseElementList].map(collapseEl => new bootstrap.Collapse(collapseEl))
            </script>
        </div>
    </body>
    </html>
    "


    # Export the generated HTML file

    $Folder = (Get-Item .).FullName
    $OutFile = "DefenderEval_$(Get-Date -Format ("yyyymmdd-HHmmss")).html"
    $FilePath = Join-Path -Path $Folder -ChildPath $OutFile

    $output | Out-File -FilePath $FilePath

    Invoke-Expression "&'$FilePath'"
}
