# Daily Hunts

Sentinel workbook that runs the daily threat hunts from this repo, each in its own table.

> **Disclaimer:** This workbook does not replace alert triage. Alerts and incidents should still be investigated for a deeper investigation.

**Parameters:** `DeviceName` (shown as Hostname) for Device Hunts, `UserPrincipalName` for User Hunts, `TimeRange` for both. Leave the device and user boxes empty to sweep everything.

### 💻 Device Hunts

| Hunt | Finds |
|---|---|
| 🧅 HTTP + Tor Downloads | Cleartext HTTP executable/script downloads, weighted heavily when Tor is involved |
| 🧰 LOLBin Abuse | Signed Windows binaries used to download, decode or proxy-execute payloads |
| 📂 Remote File Drops | PsExec-style mass executable drops to admin shares |
| 🔑 Sensitive Config File Downloads | Credential/config file downloads within 10 minutes of a connection to a malicious IP |
| 🕸️ Webshell Detection | IIS requests containing command-execution patterns |
| 🥷 EDR Evasions | BYOVD drivers, EDR-killer tools, EDR process/service kills, Defender tampering, Safe Mode abuse, log tampering |
| ⚡ Highly Executed PowerShell from External Sources | PowerShell downloading from untrusted external sources, scored for obfuscation, bypass and chained execution |
| ⚙️ Rare Process As Service | Uncommon `services.exe` children, enriched with network, file and DLL activity |
| 🖥️ Unapproved Remote Access Tools | RMM, remote-support and VNC tools that aren't sanctioned |

### 👤 User Hunts

| Hunt | Finds |
|---|---|
| 📎 Malicious Attachments | Email attachments matching MalwareBazaar hashes, with delivery and click status |
| 📲 MFA Spamming | MFA push bombing, whether the user approved, and source IP threat intel |
| ☠️ Sign-In From IOC | Successful sign-ins from IPs on Sentinel TI, Feodo C2 or blocklist.de |


**Notes**
- Every hunt is a Grid. Set a Thresholds renderer on `Severity` if you want colored icons.
- Device Hunts filter by Hostname (the Webshell hunt matches the IIS server name). User Hunts filter by user (Malicious Attachments matches the recipient).
- Hunts that use `externaldata` pull threat intel feeds live, so they need outbound access to those sites.

---

# 💻 Device Hunts

## 🧅 HTTP + Tor Downloads
Grid. Only sees cleartext HTTP. Pulls the Tor exit node list live from the Tor Project.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let ExecutableFileExtensions = dynamic([
    "bat", "cmd", "com", "cpl", "dll", "ex", "exe",
    "hta", "jar", "js", "jse", "lnk", "msc", "msi",
    "ps1", "py", "reg", "scr", "vb", "vbe", "vbs",
    "ws", "wsf", "iso", "img"
]);
// === Tor exit node list (official Tor Project) ===
let TorExitNodes = materialize(
    externaldata(Indicator:string)
    [@"https://check.torproject.org/torbulkexitlist"]
    with (format="txt")
    | where Indicator matches regex @"^\d+\.\d+\.\d+\.\d+$"
    | distinct Indicator
);
let TorPorts = dynamic([9001, 9030, 9040, 9050, 9051, 9150, 9151]);
let TorProcesses = dynamic([
    "tor.exe", "torbrowser.exe", "firefox.exe",   // Tor Browser uses Firefox ESR
    "obfs4proxy.exe", "meek-client.exe", "snowflake-client.exe"
]);
DeviceNetworkEvents
| where TimeGenerated {TimeRange}
| where isempty(TargetDevice) or DeviceName has TargetDevice
| where ActionType == "NetworkSignatureInspected"
| extend
    SignatureName           = tostring(parse_json(AdditionalFields).SignatureName),
    SignatureMatchedContent = tostring(parse_json(AdditionalFields).SignatureMatchedContent),
    SamplePacketContent     = tostring(parse_json(AdditionalFields).SamplePacketContent)
| where SignatureName == "HTTP_Client"
// --- Parse request method & downloaded file ---
| extend HTTP_Request_Method = tostring(split(SignatureMatchedContent, " /", 0)[0])
| where HTTP_Request_Method == "GET"
| extend DownloadedContent = extract(@'.*/(.*)HTTP', 1, SignatureMatchedContent)
| extend DownloadFileExtension = tolower(extract(@'.*\.(.*)$', 1, DownloadedContent))
// --- Executable/script downloads only ---
| where isnotempty(DownloadFileExtension)
    and string_size(DownloadFileExtension) < 8
    and DownloadFileExtension has_any (ExecutableFileExtensions)
// --- Exclude known-good update/CDN destinations ---
| where not(SignatureMatchedContent has_any (
    "microsoft.com", "windowsupdate.com", "msftncsi.com",
    "azureedge.net", "akamai", "windows.com",
    "digicert.com", "symantec.com"
))
// --- Tor correlation ---
| extend
    IsTorExitNode  = RemoteIP in (TorExitNodes),
    IsTorPort      = RemotePort in (TorPorts),
    IsTorProcess   = InitiatingProcessFileName in~ (TorProcesses)
| extend IsTorRelated = IsTorExitNode or IsTorPort or IsTorProcess
// --- Enrich / flag indicators ---
| extend
    IsRawIPDownload   = isnotempty(RemoteIP) and RemoteUrl == "",
    IsHighRiskExt     = DownloadFileExtension in~ ("exe", "dll", "scr", "ps1", "hta", "js", "vbs", "lnk", "iso"),
    IsRemoteExternal  = RemoteIPType == "Public"
// --- Risk Score (Tor weighted heavily) ---
| extend RiskScore = 2
                   + (toint(IsHighRiskExt) * 2)
                   + (toint(IsRawIPDownload) * 2)
                   + (toint(IsRemoteExternal) * 1)
                   + (toint(IsTorExitNode) * 4)     // download FROM a Tor exit node
                   + (toint(IsTorPort) * 3)
                   + (toint(IsTorProcess) * 2)
| extend Severity = case(
    RiskScore >= 7, "🔴 Critical",
    RiskScore >= 4, "🟠 High",
    "🟡 Medium"
)
// --- Deduplicate ---
| summarize
    FirstSeen      = min(TimeGenerated),
    LastSeen       = max(TimeGenerated),
    DownloadCount  = count(),
    RemoteIPs      = make_set(RemoteIP, 20),
    Files          = make_set(DownloadedContent, 20)
    by DeviceName, InitiatingProcessFileName,
       DownloadFileExtension, Severity, RiskScore,
       IsHighRiskExt, IsRawIPDownload,
       IsTorRelated, IsTorExitNode, IsTorPort, IsTorProcess
| project
    FirstSeen,
    LastSeen,
    Severity,
    RiskScore,
    DownloadCount,
    DeviceName,
    InitiatingProcessFileName,
    DownloadFileExtension,
    IsTorRelated,
    IsTorExitNode,
    IsTorPort,
    IsTorProcess,
    Files,
    RemoteIPs,
    IsHighRiskExt,
    IsRawIPDownload
| sort by RiskScore desc, DownloadCount desc
```

## 🧰 LOLBin Abuse
Grid. Rows marked 🔴 are the high-confidence techniques.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let MgmtPaths = dynamic([
    "\\Windows\\CCM\\",
    "\\Program Files (x86)\\Microsoft Intune Management Extension\\",
    "\\Program Files\\Microsoft Monitoring Agent\\",
    "\\Windows\\System32\\GroupPolicy\\"
]);
DeviceProcessEvents
| where TimeGenerated {TimeRange}
| where isempty(TargetDevice) or DeviceName has TargetDevice
| where FileName in~ (
    "certutil.exe", "bitsadmin.exe", "regsvr32.exe", "rundll32.exe",
    "mshta.exe", "installutil.exe", "regasm.exe", "regsvcs.exe",
    "cmstp.exe", "odbcconf.exe", "msxsl.exe", "wmic.exe",
    "forfiles.exe", "pcalua.exe", "msbuild.exe", "presentationhost.exe",
    "msdt.exe", "hh.exe", "ieexec.exe", "xwizard.exe", "diskshadow.exe"
)
// Strip the binary's own name so its ".exe" doesn't self-match
| extend CmdArgs = replace_regex(ProcessCommandLine, @'(?i)^\s*"?[^"]*?\.exe"?', "")
| extend LowerArgs = tolower(CmdArgs)
| extend Technique = case(
    // --- certutil: download / decode (highest confidence) ---
    FileName =~ "certutil.exe" and LowerArgs has_any ("-urlcache", "urlcache", "-verifyctl", "verifyctl")
        and LowerArgs has_any ("http://", "https://", "ftp://"),
        "🔴 certutil Download",
    FileName =~ "certutil.exe" and LowerArgs has_any ("-decode", "decode", "-encode", "encode"),
        "🔴 certutil Encode/Decode",
    // --- regsvr32 Squiblydoo: remote scriptlet execution ---
    FileName =~ "regsvr32.exe" and LowerArgs has_any ("scrobj.dll", "/i:http", "/i:ftp", "i:http"),
        "🔴 regsvr32 Squiblydoo (remote scriptlet)",
    FileName =~ "regsvr32.exe" and LowerArgs has_any ("http://", "https://"),
        "🔴 regsvr32 Remote Load",
    // --- mshta: remote or inline script execution ---
    FileName =~ "mshta.exe" and LowerArgs has_any ("http://", "https://", "javascript:", "vbscript:"),
        "🔴 mshta Remote/Inline Script",
    // --- rundll32 abuse patterns ---
    FileName =~ "rundll32.exe" and LowerArgs has_any ("javascript:", "vbscript:", "mshtml"),
        "🔴 rundll32 Script Protocol",
    FileName =~ "rundll32.exe" and LowerArgs has "comsvcs" and LowerArgs has "minidump",
        "🔴 rundll32 comsvcs LSASS Dump",
    FileName =~ "rundll32.exe" and LowerArgs has_any ("url.dll", "openurl", "shell32.dll,shellexec"),
        "🟠 rundll32 URL/Shell Execution",
    FileName =~ "rundll32.exe" and LowerArgs matches regex
        @"(?i)[a-z]:\\(?:users|programdata|windows\\temp)\\[^,]*\.(?:dll|tmp|dat|log|txt|png|jpg),",
        "🔴 rundll32 DLL from User-Writable Path",
    // --- bitsadmin: background transfer ---
    FileName =~ "bitsadmin.exe" and LowerArgs has_any ("/transfer", "/addfile", "/create", "transfer"),
        "🔴 bitsadmin Transfer",
    // --- .NET LOLBins: proxy execution of managed assemblies ---
    FileName in~ ("installutil.exe", "regasm.exe", "regsvcs.exe")
        and LowerArgs has_any ("/logfile=", "/u ", "/logtoconsole=false", ".dll", ".exe"),
        "🔴 .NET LOLBin Proxy Execution",
    // --- msbuild inline task ---
    FileName =~ "msbuild.exe" and LowerArgs has_any (".xml", ".csproj", ".proj", ".targets")
        and not(InitiatingProcessFolderPath has_any (MgmtPaths)),
        "🟠 msbuild Project Execution",
    // --- wmic XSL execution ---
    FileName =~ "wmic.exe" and LowerArgs has_any ("/format:http", "/format:\\\\", "format:http"),
        "🔴 wmic Remote XSL Execution",
    // --- cmstp / odbcconf / msxsl ---
    FileName =~ "cmstp.exe" and LowerArgs has_any (".inf", "/s", "/ns"),
        "🔴 cmstp INF Execution",
    FileName =~ "odbcconf.exe" and LowerArgs has_any ("/a", "regsvr", ".rsp"),
        "🔴 odbcconf DLL Registration",
    FileName =~ "msxsl.exe",
        "🟠 msxsl XSL Execution",
    // --- process launchers used to break parent-child chains ---
    FileName in~ ("forfiles.exe", "pcalua.exe", "xwizard.exe")
        and LowerArgs has_any ("/c ", "-a ", "runwizard", ".exe", "cmd", "powershell"),
        "🟠 Process Launcher Proxy",
    // --- msdt (Follina-class) ---
    FileName =~ "msdt.exe" and LowerArgs has_any ("ms-msdt", "it_rebrowseforfile", "it_browseforfile"),
        "🔴 msdt Diagnostic Abuse",
    // --- diskshadow scripted mode ---
    FileName =~ "diskshadow.exe" and LowerArgs has_any ("/s ", "-s "),
        "🟠 diskshadow Script Mode",
    "⚪ Other"
)
| where Technique != "⚪ Other"
// Exclude signed management tooling running these legitimately
| where not(InitiatingProcessFolderPath has_any (MgmtPaths))
// --- Supporting context ---
| extend
    HasUrl = CmdArgs has_any ("http://", "https://", "ftp://"),
    HasUncPath = CmdArgs contains "\\\\",
    FromUserWritable = FolderPath has_any (
        "\\Temp\\", "\\AppData\\", "\\Downloads\\", "\\Public\\", "\\ProgramData\\"),
    SuspiciousParent = InitiatingProcessFileName in~ (
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe",
        "wscript.exe", "cscript.exe", "mshta.exe", "chrome.exe", "msedge.exe"),
    IsElevated = ProcessIntegrityLevel in ("High", "System"),
    IsHighConfidence = Technique startswith "🔴"
| extend RiskScore = 4
                   + (toint(IsHighConfidence) * 3)
                   + (toint(SuspiciousParent) * 4)
                   + (toint(HasUrl) * 2)
                   + (toint(FromUserWritable) * 2)
                   + (toint(HasUncPath) * 1)
                   + (toint(IsElevated) * 1)
| extend Severity = case(
    RiskScore >= 11, "🔴 Critical",
    RiskScore >= 8,  "🟠 High",
    RiskScore >= 6,  "🟡 Medium",
    "🟢 Low"
)
| summarize
    FirstSeen       = min(TimeGenerated),
    LastSeen        = max(TimeGenerated),
    OccurrenceCount = count(),
    Commands        = make_set(substring(CmdArgs, 0, 250), 3),
    Devices         = dcount(DeviceName)
    by Severity, RiskScore, Technique, IsHighConfidence,
       DeviceName, Account = AccountName, LolBin = FileName,
       ParentProcess = InitiatingProcessFileName,
       SuspiciousParent, HasUrl, FromUserWritable
| project
    FirstSeen,
    Severity,
    OccurrenceCount,
    Technique,
    DeviceName,
    Account,
    LolBin,
    ParentProcess,
    SuspiciousParent,
    HasUrl,
    FromUserWritable,
    Commands,
    RiskScore,
    IsHighConfidence,
    LastSeen
| sort by RiskScore desc, OccurrenceCount desc
```

## 📂 Remote File Drops
Grid. More than 4 executables dropped to remote paths by a PsExec-style tool in a 10-minute window.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let FileThreshold = 4;          // min distinct remote paths in the window
let TimeWindowBin = 10m;
DeviceFileEvents
| where TimeGenerated {TimeRange}
| where isempty(TargetDevice) or DeviceName has TargetDevice
// --- PsExec-style execution (accepteula is the classic tell) ---
| where InitiatingProcessCommandLine has_any (
    "accepteula",
    "psexec",
    "paexec",
    "-s -d",            // PsExec system + detached
    "\\\\*\\admin$",    // pushing to admin share
    "\\\\*\\c$"
)
// --- Dropped to a remote machine (UNC path) and is an executable ---
| where FolderPath has "\\\\"
| where FileName endswith ".exe" or FileName endswith ".bat" or FileName endswith ".cmd" or FileName endswith ".dll"
// --- Count executables referenced in the command line ---
| extend ExeCount = countof(InitiatingProcessCommandLine, ".exe")
| extend BatCount = countof(InitiatingProcessCommandLine, ".bat")
// --- Multiple binaries OR a batch script involved ---
| where (InitiatingProcessCommandLine !has ".ps1" and ExeCount > 1)
    or InitiatingProcessCommandLine has ".bat"
    or InitiatingProcessCommandLine has ".cmd"
// --- Exclusions (remove lines to widen scope) ---
| where not(InitiatingProcessCommandLine has_any (
    "batch", "auditpol", "script", "scripts",
    "illusive", "rebootrequired",
    "SccmClient", "ccmsetup", "MonitoringHost"   // common legit admin tools
))
// --- Flag suspicious indicators ---
| extend
    IsSuspiciousPath = FolderPath has_any (
        "\\temp\\", "\\tmp\\", "\\public\\",
        "\\windows\\temp\\", "\\programdata\\"
    ),
    IsAdminShare = FolderPath has_any ("admin$", "c$", "ipc$")
// --- Summarize per device per 10-min window ---
| summarize
    StartTime       = min(TimeGenerated),
    EndTime         = max(TimeGenerated),
    FileCount       = dcount(FolderPath),
    TotalEvents     = count(),
    DistinctHashes  = dcount(SHA1),
    Hashes          = make_set(SHA1, 50),
    Paths           = make_set(FolderPath, 50),
    Files           = make_set(FileName, 50),
    CommandLines    = make_set(InitiatingProcessCommandLine, 20),
    AnySuspiciousPath = max(IsSuspiciousPath),
    AnyAdminShare     = max(IsAdminShare)
    by DeviceId, DeviceName,
       TimeWindow = bin(TimeGenerated, TimeWindowBin),
       InitiatingProcessFileName,
       InitiatingProcessAccountName
// --- Only mass-drop events ---
| where FileCount > FileThreshold
// --- Risk Score ---
| extend RiskScore = 3                                  // base: PsExec mass drop
                   + toint(AnySuspiciousPath)
                   + toint(AnyAdminShare)
                   + iff(FileCount > 10, 3, 0)          // very high file count
                   + iff(DistinctHashes > 5, 2, 0)      // many unique binaries
| extend Severity = case(
    RiskScore >= 7, "🔴 Critical",
    RiskScore >= 5, "🟠 High",
    "🟡 Medium"
)
| project
    StartTime,
    EndTime,
    Severity,
    RiskScore,
    DeviceName,
    InitiatingProcessAccountName,
    InitiatingProcessFileName,
    FileCount,
    TotalEvents,
    DistinctHashes,
    AnySuspiciousPath,
    AnyAdminShare,
    Files,
    Paths,
    CommandLines,
    Hashes
| sort by RiskScore desc, FileCount desc
```

## 🔑 Sensitive Config File Downloads
Grid. Malicious IPs come from Sentinel TI plus live abuse.ch Feodo, SSLBL and blocklist.de feeds.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let TI_IPs = ThreatIntelligenceIndicator
    | where TimeGenerated > ago(30d)
    | where Active == true
    | where isnotempty(NetworkIP)
    | distinct NetworkIP;
let Feodo_IPs = materialize(
    externaldata(Indicator:string)
    [@"https://feodotracker.abuse.ch/downloads/ipblocklist.txt"]
    with (format="txt")
    | where Indicator matches regex @"^\d+\.\d+\.\d+\.\d+$"
    | distinct Indicator
);
let SSLBL_IPs = materialize(
    externaldata(Indicator:string)
    [@"https://sslbl.abuse.ch/blacklist/sslipblacklist.txt"]
    with (format="txt")
    | where Indicator matches regex @"^\d+\.\d+\.\d+\.\d+$"
    | distinct Indicator
);
let Blocklist_IPs = materialize(
    externaldata(Indicator:string)
    [@"https://lists.blocklist.de/lists/all.txt"]
    with (format="txt")
    | where Indicator matches regex @"^\d+\.\d+\.\d+\.\d+$"
    | distinct Indicator
);
let MaliciousIPs = materialize(
    union
        (TI_IPs | project MalIP = NetworkIP),
        (Feodo_IPs | project MalIP = Indicator),
        (SSLBL_IPs | project MalIP = Indicator),
        (Blocklist_IPs | project MalIP = Indicator)
    | distinct MalIP
);
let SystemPaths = dynamic([
    "\\ProgramData\\Microsoft\\",
    "\\Windows\\AppRepository\\",
    "\\Microsoft\\Diagnosis\\",
    "\\Windows\\System32\\config\\",
    "\\Program Files\\WindowsApps\\",
    "\\Windows\\WinSxS\\",
    "\\Windows\\servicing\\"
]);
DeviceNetworkEvents
| where TimeGenerated {TimeRange}
| where isempty(TargetDevice) or DeviceName has TargetDevice
| where RemoteIP in (MaliciousIPs)
| where InitiatingProcessFileName in~ (
    "chrome.exe", "msedge.exe", "firefox.exe",
    "brave.exe", "opera.exe", "tor.exe", "torbrowser.exe",
    "powershell.exe", "pwsh.exe",
    "curl.exe", "wget.exe", "certutil.exe", "bitsadmin.exe"
)
| join kind=inner (
    DeviceFileEvents
    | where TimeGenerated {TimeRange}
    | where ActionType in ("FileCreated", "FileDownloaded")
    | where
        // --- Credential / secret files ---
        FileName endswith ".env"
        or FileName endswith ".pem"
        or FileName endswith ".key"
        or FileName endswith ".pfx"
        or FileName endswith ".p12"
        or FileName endswith ".kdbx"
        or FileName endswith ".ppk"
        or FileName endswith ".ovpn"
        or FileName endswith ".rdp"
        // --- General config files ---
        or FileName endswith ".config"
        or FileName endswith ".conf"
        or FileName endswith ".cfg"
        or FileName endswith ".ini"
    | where FileName !in~ (
        ".ADOBE_WEBVIEW_FLAGS_SERVER.CONFIG",
        "ACSLEng.cfg",
        "LogTransport2.cfg",
        "STDeploy.exe.config"
    )
    | extend FileCategory = case(
        FileName endswith ".env" or FileName endswith ".pem" or FileName endswith ".key"
            or FileName endswith ".pfx" or FileName endswith ".p12"
            or FileName endswith ".kdbx" or FileName endswith ".ppk"
            or FileName endswith ".ovpn" or FileName endswith ".rdp", "🔑 Credential/Secret",
        "⚙️ General Config"
    )
    | project
        FileTimestamp = TimeGenerated,
        DeviceName,
        FileName,
        FolderPath,
        FileCategory,
        FileSHA256 = SHA256
) on DeviceName
| where abs(datetime_diff('second', TimeGenerated, FileTimestamp)) <= 600
// --- Exclude Microsoft system paths ---
| where not(FolderPath has_any (SystemPaths))
| extend RiskScore = case(
    FileCategory == "🔑 Credential/Secret", 10,
    8
)
| extend Severity = "🔴 Critical"
// --- Deduplicate ---
| summarize
    FirstSeen        = min(TimeGenerated),
    LastSeen         = max(TimeGenerated),
    ConnectionCount  = count(),
    RemotePorts      = make_set(RemotePort, 10),
    Processes        = make_set(InitiatingProcessFileName, 5)
    by DeviceName, RemoteIP, FileName, FolderPath, FileCategory, FileSHA256, Severity, RiskScore
| project
    FirstSeen,
    LastSeen,
    ConnectionCount,
    Severity,
    RiskScore,
    FileCategory,
    DeviceName,
    RemoteIP,
    RemotePorts,
    Processes,
    FileName,
    FolderPath,
    FileSHA256
| sort by RiskScore desc, LastSeen desc
```

## 🕸️ Webshell Detection
Grid. Needs IIS logs (W3CIISLog). The Hostname filter matches the IIS server's `Computer` name.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
// --- Command execution patterns (non-capturing groups) ---
let CmdPatterns = "(?i)(?:net(?:1)?(?:\\.exe)?(?:%20|\\s|\\+)+(?:user|group|localgroup|view|share))|(?:cmd(?:\\.exe)?(?:%20|\\s|\\+)+/c)|(?:powershell(?:\\.exe)?)|(?:whoami)|(?:ipconfig)|(?:systeminfo)|(?:tasklist)|(?:certutil)|(?:bitsadmin)|(?:nltest)|(?:wmic)|(?:reg(?:\\.exe)?(?:%20|\\s|\\+)+query)";
W3CIISLog
| where TimeGenerated {TimeRange}
| where isempty(TargetDevice) or Computer has TargetDevice
| where csUriQuery matches regex CmdPatterns
    or csUriStem matches regex CmdPatterns
    or csReferer matches regex CmdPatterns
| extend
    MatchedField = case(
        csUriQuery matches regex CmdPatterns, "csUriQuery",
        csUriStem matches regex CmdPatterns,  "csUriStem",
        csReferer matches regex CmdPatterns,  "csReferer",
        "Unknown"
    ),
    IsWebShellExt = (csUriStem has_any (".aspx", ".asp", ".ashx", ".asmx", ".php", ".jsp")),
    IsKnownWebShell = (csUriStem has_any (
        "cmd.aspx", "shell.aspx", "webshell", "antsword",
        "c99", "r57", "b374k", "wso",
        "eval", "tunnel.aspx"
    )),
    IsEncoded = (csUriQuery has_any ("%20", "%2f", "%5c", "base64", "FromBase64", "-enc", "-ec"))
| extend RiskScore = 2
                   + (toint(IsWebShellExt) * 2)
                   + (toint(IsKnownWebShell) * 4)
                   + (toint(IsEncoded) * 2)
| extend Severity = case(
    RiskScore >= 6, "🔴 Critical",
    RiskScore >= 4, "🟠 High",
    "🟡 Medium"
)
| summarize
    StartTime       = min(TimeGenerated),
    EndTime         = max(TimeGenerated),
    ConnectionCount = count(),
    DistinctUris    = dcount(csUriStem),
    SampleQueries   = make_set(csUriQuery, 10),
    StatusCodes     = make_set(scStatus, 10)
    by Computer, sSiteName, sIP, cIP, csUserName,
       csMethod, MatchedField,
       IsWebShellExt, IsKnownWebShell, IsEncoded,
       Severity, RiskScore
| project
    StartTime,
    EndTime,
    Severity,
    RiskScore,
    ConnectionCount,
    DistinctUris,
    Computer,
    sSiteName,
    sIP,
    cIP,
    csUserName,
    csMethod,
    MatchedField,
    IsWebShellExt,
    IsKnownWebShell,
    IsEncoded,
    StatusCodes,
    SampleQueries
| sort by RiskScore desc, ConnectionCount desc
```

## 🥷 EDR Evasions
Grid. `AntivirusScanCancelled` and `AntivirusEmergencyUpdatesInstalled` in section 8 can be noisy; remove them if needed.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let EdrProcesses = dynamic([
    "MsMpEng.exe", "MsSense.exe", "SenseIR.exe", "SenseCncProxy.exe",
    "CSFalconService.exe", "CSFalconContainer.exe",
    "SentinelAgent.exe", "SentinelServiceHost.exe", "SentinelStaticEngine.exe",
    "cb.exe", "RepMgr.exe", "RepUx.exe", "CylanceSvc.exe",
    "SophosHealth.exe", "SAVService.exe", "McShield.exe", "mfemms.exe",
    "ccSvcHst.exe", "SmcGui.exe", "xagt.exe", "TmCCSF.exe", "elastic-agent.exe"
]);
let EdrServices = dynamic([
    "WinDefend", "Sense", "WdNisSvc", "SecurityHealthService", "wscsvc",
    "CSFalconService", "SentinelAgent", "CbDefense", "CylanceSvc",
    "SAVService", "McAfeeFramework", "SepMasterService", "xagt"
]);
let VulnerableDrivers = dynamic([
    "rtcore64.sys", "rtkvhd64.sys", "gdrv.sys", "iqvw64e.sys", "dbutil_2_3.sys",
    "mhyprot2.sys", "procexp152.sys", "aswarpot.sys", "truesight.sys",
    "viragt64.sys", "kprocesshacker.sys", "gmer64.sys", "nvflash.sys",
    "elrawdsk.sys", "atillk64.sys", "speedfan.sys", "winio64.sys"
]);
let EdrKillerTools = dynamic([
    "aukill.exe", "terminator.exe", "edrkillshifter.exe", "edrsilencer.exe",
    "backstab.exe", "edrsandblast.exe", "gmer.exe", "processhacker.exe",
    "pchunter64.exe", "kdu.exe", "spyboy.exe", "zam64.sys"
]);
union isfuzzy=true
// 1. BYOVD - vulnerable signed driver loaded
(
    DeviceImageLoadEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where FileName has_any (VulnerableDrivers)
    | extend Technique = "🔴 BYOVD Vulnerable Driver Load",
             RiskScore = 9,
             Detail = substring(strcat("Driver: ", FileName, " | Path: ", FolderPath, " | By: ", InitiatingProcessFileName), 0, 300)
    | project TimeGenerated, Technique, RiskScore, DeviceName,
              AccountName = InitiatingProcessAccountName,
              ProcessName = InitiatingProcessFileName, Detail
),
// 1b. BYOVD - vulnerable driver dropped
(
    DeviceFileEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where FileName has_any (VulnerableDrivers)
    | where ActionType in ("FileCreated", "FileModified")
    | extend Technique = "🔴 BYOVD Vulnerable Driver Dropped",
             RiskScore = 9,
             Detail = substring(strcat("Driver: ", FileName, " | Path: ", FolderPath, " | By: ", InitiatingProcessFileName), 0, 300)
    | project TimeGenerated, Technique, RiskScore, DeviceName,
              AccountName = InitiatingProcessAccountName,
              ProcessName = InitiatingProcessFileName, Detail
),
// 2. EDR-killer tooling
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | extend CmdArgs = replace_regex(ProcessCommandLine, @'(?i)^\s*"?[^"]*?\.exe"?', "")
    | where tolower(FileName) in~ (EdrKillerTools)
        or (CmdArgs has_any (EdrKillerTools) and CmdArgs has_any (EdrProcesses))
    | extend Technique = "🔴 EDR-Killer Tool Execution",
             RiskScore = 10,
             Detail = substring(strcat(FileName, " | ", CmdArgs, " | Path: ", FolderPath), 0, 300)
    | project TimeGenerated, Technique, RiskScore, DeviceName,
              AccountName, ProcessName = FileName, Detail
),
// 3. EDR process termination
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | extend CmdArgs = replace_regex(ProcessCommandLine, @'(?i)^\s*"?[^"]*?\.exe"?', "")
    | where FileName in~ ("taskkill.exe", "tskill.exe", "wmic.exe", "powershell.exe", "pwsh.exe", "pskill.exe", "pskill64.exe")
    | where CmdArgs has_any (EdrProcesses)
    | where CmdArgs has_any ("/f", "/im", "/pid", "Stop-Process", "kill", "terminate", "-Force")
    | extend Technique = "🔴 EDR Process Termination",
             RiskScore = 9,
             Detail = substring(strcat(FileName, " | ", CmdArgs), 0, 300)
    | project TimeGenerated, Technique, RiskScore, DeviceName,
              AccountName, ProcessName = FileName, Detail
),
// 4. EDR service stop / disable
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | extend CmdArgs = replace_regex(ProcessCommandLine, @'(?i)^\s*"?[^"]*?\.exe"?', "")
    | where FileName in~ ("sc.exe", "net.exe", "net1.exe", "powershell.exe", "pwsh.exe", "reg.exe")
    | where CmdArgs has_any (EdrServices)
    | where CmdArgs has_any ("stop", "delete", "disabled", "start= disabled", "Stop-Service", "Set-Service", "config", "Remove-Service")
    | extend Technique = "🔴 EDR Service Stop / Disable",
             RiskScore = 9,
             Detail = substring(strcat(FileName, " | ", CmdArgs), 0, 300)
    | project TimeGenerated, Technique, RiskScore, DeviceName,
              AccountName, ProcessName = FileName, Detail
),
// 5. Defender tampering
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | extend CmdArgs = replace_regex(ProcessCommandLine, @'(?i)^\s*"?[^"]*?\.exe"?', "")
    | where CmdArgs has_any (
        "DisableRealtimeMonitoring", "DisableBehaviorMonitoring",
        "DisableIOAVProtection", "DisableScriptScanning",
        "DisableArchiveScanning", "DisableBlockAtFirstSeen",
        "DisableAntiSpyware", "DisableAntiVirus",
        "TamperProtection", "MpEnablePus",
        "Add-MpPreference -ExclusionPath", "Add-MpPreference -ExclusionProcess",
        "Add-MpPreference -ExclusionExtension",
        "AmsiScanBuffer", "amsiInitFailed", "AmsiUtils"
    )
    | extend IsExclusion = CmdArgs has "ExclusionPath" or CmdArgs has "ExclusionProcess" or CmdArgs has "ExclusionExtension"
    | extend Technique = iff(IsExclusion, "🟠 Defender Exclusion Added", "🔴 Defender Protection Disabled"),
             RiskScore = iff(IsExclusion, 7, 9),
             Detail = substring(strcat(FileName, " | ", CmdArgs), 0, 300)
    | project TimeGenerated, Technique, RiskScore, DeviceName,
              AccountName, ProcessName = FileName, Detail
),
// 6. Safe Mode abuse
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | extend CmdArgs = replace_regex(ProcessCommandLine, @'(?i)^\s*"?[^"]*?\.exe"?', "")
    | where CmdArgs has_any ("bcdedit", "safeboot", "bootstatuspolicy")
    | where CmdArgs has_any ("/set", "safeboot network", "safeboot minimal", "-set")
    | extend Technique = "🔴 Safe Mode Boot Configuration",
             RiskScore = 9,
             Detail = substring(strcat(FileName, " | ", CmdArgs), 0, 300)
    | project TimeGenerated, Technique, RiskScore, DeviceName,
              AccountName, ProcessName = FileName, Detail
),
// 7. Event log / telemetry tampering
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | extend CmdArgs = replace_regex(ProcessCommandLine, @'(?i)^\s*"?[^"]*?\.exe"?', "")
    | where CmdArgs has_any (
        "wevtutil cl", "wevtutil sl", "Clear-EventLog", "Remove-EventLog",
        "auditpol /clear", "auditpol /remove", "auditpol /set",
        "fsutil usn deletejournal", "EtwEventWrite", "PatchTraceLogging"
    )
    | extend Technique = "🔴 Event Log / ETW Tampering",
             RiskScore = 9,
             Detail = substring(strcat(FileName, " | ", CmdArgs), 0, 300)
    | project TimeGenerated, Technique, RiskScore, DeviceName,
              AccountName, ProcessName = FileName, Detail
),
// 8. Native Defender tamper events
(
    DeviceEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where ActionType in (
        "AntivirusDisabled", "AntivirusConfigurationChange",
        "TamperingAttempt", "SecurityLogCleared",
        "AntivirusScanCancelled", "AntivirusEmergencyUpdatesInstalled"
    )
    | extend Technique = "🔴 Native Defender Tamper Event",
             RiskScore = 9,
             Detail = substring(strcat(ActionType, " | ", tostring(AdditionalFields)), 0, 300)
    | project TimeGenerated, Technique, RiskScore, DeviceName,
              AccountName = InitiatingProcessAccountName,
              ProcessName = InitiatingProcessFileName, Detail
)
| extend Severity = case(
    RiskScore >= 9, "🔴 Critical",
    RiskScore >= 7, "🟠 High",
    "🟡 Medium"
)
| summarize
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    OccurrenceCount = count(),
    Details = make_set(Detail, 3)
    by Technique, Severity, RiskScore, DeviceName, AccountName, ProcessName
| project
    FirstSeen,
    Severity,
    OccurrenceCount,
    Technique,
    DeviceName,
    AccountName,
    ProcessName,
    Details,
    RiskScore,
    LastSeen
| sort by RiskScore desc, OccurrenceCount desc
```

## ⚡ Highly Executed PowerShell from External Sources
Grid. Tune the trusted-domain list to your environment.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
DeviceProcessEvents
| where TimeGenerated {TimeRange}
| where isempty(TargetDevice) or DeviceName has TargetDevice
| where FileName in~ ("powershell.exe", "pwsh.exe", "powershell_ise.exe")
// --- Web download methods ---
| where ProcessCommandLine has_any (
    "Invoke-WebRequest", "iwr", "wget", "curl",
    "DownloadFile", "DownloadString", "DownloadData",
    "Net.WebClient", "Net.Http", "HttpClient",
    "Start-BitsTransfer", "Invoke-RestMethod", "irm"
)
| where ProcessCommandLine has_any ("http://", "https://", "ftp://")
// --- HARD EXCLUSIONS: pure noise, removed entirely ---
| where not(ProcessCommandLine has_any (
    "microsoft.com", "windowsupdate.com", "office.com",
    "live.com", "azure.com", "azureedge.net",
    "nuget.org", "powershellgallery.com",
    "visualstudio.com", "msftconnecttest.com"
))
// --- Exclude connectivity checks ---
| where not(ProcessCommandLine has_any (
    "google.com", "gstatic.com", "connectivitycheck"
) and ProcessCommandLine has_any (
    "OpenRead", "CanRead", "GetResponse", "CheckConnectivity"
))
// --- Extract the URL & domain from the command ---
| extend ExtractedUrl = extract(@"(https?://[^\s'""\)]+)", 1, ProcessCommandLine)
| extend ExtractedDomain = tolower(extract(@"https?://([^/:\s'""\)]+)", 1, ProcessCommandLine))
// --- SCORING ALLOWLIST: legitimate but still visible if stacked ---
| extend IsKnownTrustedDomain = ExtractedDomain has_any (
    // CDNs & infrastructure commonly seen in legit scripts
    "akamai", "cloudfront.net", "fastly", "jsdelivr.net", "cdnjs",
    "amazonaws.com", "core.windows.net", "digicert.com",
    "letsencrypt.org", "sectigo.com", "verisign",
    // Package / dev ecosystems
    "python.org", "pypi.org", "pythonhosted.org",
    "nodejs.org", "npmjs.org", "chocolatey.org",
    "docker.io", "docker.com", "jenkins.io",
    "github.com", "githubusercontent.com",
    // Common vendor domains (tune to environment)
    "adobe.com", "mozilla.org", "ubuntu.com", "debian.org", "redhat.com"
)
// --- High-risk indicators ---
| extend
    IsExternalSource = iff(
        isnotempty(ExtractedDomain) and not(IsKnownTrustedDomain), "YES", ""),
    IsMaliciousFileType = ProcessCommandLine has_any (
        ".exe", ".ps1", ".bat", ".vbs", ".dll",
        ".msi", ".hta", ".js", ".lnk", ".zip", ".rar", ".scr"
    ),
    IsSuspiciousPath = ProcessCommandLine has_any (
        "\\temp\\", "\\tmp\\", "\\appdata\\",
        "\\public\\", "\\downloads\\", "\\programdata\\",
        "%temp%", "%appdata%", "%public%"
    ),
    IsEncoded = ProcessCommandLine has_any (
        "-enc", "-ec", "EncodedCommand",
        "FromBase64String", "ToBase64String",
        "[char]", "-join", "-replace"
    ),
    IsBypassAttempt = ProcessCommandLine has_any (
        "bypass", "unrestricted", "hidden",
        "noprofile", "noninteractive", "-nop", "-w hidden"
    ),
    IsChainedExecution = ProcessCommandLine has_any (
        "iex", "Invoke-Expression",
        "Start-Process", "& (", "| iex",
        ".Run(", "Shellexecute"
    ),
    IsRawIPorSuspiciousTLD = ProcessCommandLine matches regex
        @"https?://\d+\.\d+\.\d+\.\d+|\.tk|\.ru|\.cn|\.top|\.xyz|\.pw|\.cc|\.zip|\.mov",
    // --- parent process is a major phishing signal ---
    IsOfficeParent = InitiatingProcessFileName in~ (
        "winword.exe", "excel.exe", "powerpnt.exe",
        "outlook.exe", "onenote.exe", "mspub.exe", "msaccess.exe"
    ),
    IsScriptHostParent = InitiatingProcessFileName in~ (
        "wscript.exe", "cscript.exe", "mshta.exe", "cmd.exe"
    )
// --- Risk Score ---
| extend RiskScore = toint(IsMaliciousFileType)
                   + toint(IsSuspiciousPath)
                   + (iff(IsExternalSource == "YES", 1, 0) * 3)
                   + (toint(IsEncoded) * 2)
                   + (toint(IsBypassAttempt) * 2)
                   + (toint(IsChainedExecution) * 2)
                   + (toint(IsRawIPorSuspiciousTLD) * 3)
                   + (toint(IsOfficeParent) * 4)        // Office spawning PS = classic phishing
                   + (toint(IsScriptHostParent) * 2)
| where RiskScore >= 2
| extend Severity = case(
    RiskScore >= 7, "🔴 Critical",
    RiskScore >= 4, "🟠 High",
    "🟡 Medium"
)
// --- Deduplicate ---
| summarize
    FirstSeen       = min(TimeGenerated),
    LastSeen        = max(TimeGenerated),
    OccurrenceCount = count()
    by DeviceName, AccountName, ProcessCommandLine,
       ExtractedDomain, ExtractedUrl,
       InitiatingProcessFileName,
       IsExternalSource, IsMaliciousFileType, IsSuspiciousPath, IsEncoded,
       IsBypassAttempt, IsChainedExecution, IsRawIPorSuspiciousTLD,
       IsOfficeParent, IsScriptHostParent,
       Severity, RiskScore
| project
    FirstSeen,
    LastSeen,
    OccurrenceCount,
    Severity,
    RiskScore,
    DeviceName,
    AccountName,
    ParentProcess = InitiatingProcessFileName,
    ExtractedDomain,
    ExtractedUrl,
    ProcessCommandLine,
    IsExternalSource,
    IsOfficeParent,
    IsMaliciousFileType,
    IsSuspiciousPath,
    IsEncoded,
    IsBypassAttempt,
    IsChainedExecution,
    IsRawIPorSuspiciousTLD
| sort by RiskScore desc, OccurrenceCount desc
```

## ⚙️ Rare Process As Service
Grid. Requires a populated `KnownProcesses` watchlist, or everything `services.exe` spawns will show.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let WhiteList = materialize(_GetWatchlist('KnownProcesses') | project ProcessName = tolower(replace_string(trim(" ", tostring(processName)), " ", "")));
let KnownProc = toscalar(WhiteList | summarize make_set(ProcessName));
let GetServices = materialize (
DeviceProcessEvents
| where TimeGenerated {TimeRange}
| where isempty(TargetDevice) or DeviceName has TargetDevice
| where InitiatingProcessParentFileName contains "services.exe"
| where not(replace_string(tolower(InitiatingProcessFileName), " ", "") has_any (KnownProc))
| project TimeGenerated, DeviceName, StartedChildProcess = FileName, StartedChildProcessSHA1 = SHA1, StartedChildProcessCmdline = ProcessCommandLine, ServiceProcessSHA1 = InitiatingProcessSHA1, ServiceProcess = InitiatingProcessFileName, ServiceProcessCmdline = InitiatingProcessCommandLine, ServiceProcessID = InitiatingProcessId, ServiceProcessCreationTime = InitiatingProcessCreationTime, ServiceProcessUser = InitiatingProcessAccountName, ServiceProcessFolderPath = InitiatingProcessFolderPath
);
GetServices
| summarize RunCount = count() by ServiceProcess, DeviceName
| where RunCount < 6
| join kind = inner GetServices on ServiceProcess, DeviceName
| join kind = leftouter (
DeviceNetworkEvents
| where TimeGenerated {TimeRange}
| where InitiatingProcessParentFileName contains "services.exe"
| where not(replace_string(tolower(InitiatingProcessFileName), " ", "") has_any (KnownProc))
| project TimeGenerated, DeviceName, ServiceProcessSHA1 = InitiatingProcessSHA1, ServiceProcess = InitiatingProcessFileName, ServiceProcessCmdline = InitiatingProcessCommandLine, ServiceProcessID = InitiatingProcessId, ServiceProcessCreationTime = InitiatingProcessCreationTime, ServiceProcessUser = InitiatingProcessAccountName, NetworkAction = ActionType, RemoteIP, RemoteUrl
) on DeviceName, ServiceProcess, ServiceProcessCmdline, ServiceProcessCreationTime, ServiceProcessID, ServiceProcessUser, ServiceProcessSHA1
| join kind = leftouter (
DeviceFileEvents
| where TimeGenerated {TimeRange}
| where InitiatingProcessParentFileName contains "services.exe"
| where not(replace_string(tolower(InitiatingProcessFileName), " ", "") has_any (KnownProc))
| project TimeGenerated, DeviceName, ServiceProcessSHA1 = InitiatingProcessSHA1, ServiceProcess = InitiatingProcessFileName, ServiceProcessCmdline = InitiatingProcessCommandLine, ServiceProcessID = InitiatingProcessId, ServiceProcessCreationTime = InitiatingProcessCreationTime, ServiceProcessUser = InitiatingProcessAccountName, FileAction = ActionType, ModifiedFile = FileName, ModifiedFileSHA1 = SHA1, ModifiedFilePath = FolderPath
) on DeviceName, ServiceProcess, ServiceProcessCmdline, ServiceProcessCreationTime, ServiceProcessID, ServiceProcessUser, ServiceProcessSHA1
| join kind = leftouter (
DeviceImageLoadEvents
| where TimeGenerated {TimeRange}
| where InitiatingProcessParentFileName contains "services.exe"
| where not(replace_string(tolower(InitiatingProcessFileName), " ", "") has_any (KnownProc))
| project TimeGenerated, DeviceName, ServiceProcessSHA1 = InitiatingProcessSHA1, ServiceProcess = InitiatingProcessFileName, ServiceProcessCmdline = InitiatingProcessCommandLine, ServiceProcessID = InitiatingProcessId, ServiceProcessCreationTime = InitiatingProcessCreationTime, ServiceProcessUser = InitiatingProcessAccountName, LoadedDLL = FileName, LoadedDLLSHA1 = SHA1, LoadedDLLPath = FolderPath
) on DeviceName, ServiceProcess, ServiceProcessCmdline, ServiceProcessCreationTime, ServiceProcessID, ServiceProcessUser, ServiceProcessSHA1
| summarize FirstSeen = min(ServiceProcessCreationTime), ConnectedAddresses = make_set(RemoteIP, 100), ConnectedUrls = make_set(RemoteUrl, 100), FilesModified = make_set(ModifiedFile, 100), FileModFolderPath = make_set(ModifiedFilePath, 100), FileModSHA1s = make_set(ModifiedFileSHA1, 100), ChildProcesses = make_set(StartedChildProcess, 100), ChildCommandlines = make_set(StartedChildProcessCmdline, 100), DLLsLoaded = make_set(LoadedDLL, 100), DLLSHA1 = make_set(LoadedDLLSHA1, 100) by DeviceName, ServiceProcess, ServiceProcessCmdline, ServiceProcessCreationTime, ServiceProcessID, ServiceProcessUser, ServiceProcessSHA1, ServiceProcessFolderPath
// --- Risk signals for severity ---
| extend
    RanFromSuspiciousPath = ServiceProcessFolderPath has_any ("\\temp\\", "\\tmp\\", "\\appdata\\", "\\programdata\\", "\\public\\", "\\users\\", "\\downloads\\", "\\perflogs\\"),
    HasExternalNetwork = array_length(ConnectedAddresses) > 0 or array_length(ConnectedUrls) > 0,
    SpawnedChildren = array_length(ChildProcesses) > 0,
    ModifiedFiles = array_length(FilesModified) > 0
| extend Severity = case(
    RanFromSuspiciousPath and HasExternalNetwork, "🔴 High",
    RanFromSuspiciousPath or (HasExternalNetwork and SpawnedChildren), "🟠 Medium",
    "🟡 Low"
)
| project
    FirstSeen,
    Severity,
    DeviceName,
    ServiceProcess,
    ServiceProcessUser,
    ServiceProcessFolderPath,
    ServiceProcessCmdline,
    RanFromSuspiciousPath,
    HasExternalNetwork,
    ConnectedAddresses,
    ConnectedUrls,
    ChildProcesses,
    ChildCommandlines,
    FilesModified,
    FileModFolderPath,
    DLLsLoaded,
    ServiceProcessSHA1
| sort by Severity asc, FirstSeen desc
```

## 🖥️ Unapproved Remote Access Tools
Grid. TeamViewer and BeyondTrust are excluded as approved; edit the exclusion lists to match your sanctioned tools.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let HighAbuseTools = dynamic([
    "anydesk.exe", "rustdesk.exe", "quickassist.exe", "msra.exe",
    "aeroadmin.exe", "supremo.exe", "ammyy.exe", "aa_v3.exe",
    "getscreen.exe", "distant-desktop.exe", "litemanager.exe",
    "rutserv.exe", "rfusclient.exe"
]);
DeviceProcessEvents
| where TimeGenerated {TimeRange}
| where isempty(TargetDevice) or DeviceName has TargetDevice
| where FileName in~ (
    "AnyDesk.exe", "AnyDeskMSI.exe", "RustDesk.exe",
    "QuickAssist.exe", "msra.exe", "AeroAdmin.exe",
    "Supremo.exe", "SupremoHelper.exe", "ammyy.exe", "aa_v3.exe",
    "GetScreen.exe", "distant-desktop.exe", "LiteManager.exe",
    "ROMServer.exe", "ROMFUSClient.exe",
    "ScreenConnect.Client.exe", "ScreenConnect.ClientService.exe",
    "ConnectWiseControl.Client.exe", "connectwisecontrol.exe", "connectwisechat.exe",
    "SplashtopSOS.exe", "Splashtop.exe", "SRServer.exe", "SRManager.exe", "strwinclt.exe",
    "LogMeIn.exe", "LMIGuardianSvc.exe", "ramaint.exe",
    "GoToResolve.exe", "GoToAssist.exe", "g2ax_comm.exe",
    "ZohoAssist.exe", "ZA_Connect.exe", "ZMAgent.exe",
    "RemotePC.exe", "RPCSuite.exe", "RemotePCService.exe",
    "AteraAgent.exe", "Syncro.exe", "SyncroLive.Agent.Runner.exe",
    "NinjaRMMAgent.exe", "ninjarmm.exe", "AEMAgent.exe",
    "meshagent.exe", "dwagent.exe", "dwagsvc.exe",
    "RemoteUtilities.exe", "rutserv.exe", "rfusclient.exe",
    "Radmin.exe", "RServer3.exe", "famitrfc.exe",
    "winvnc.exe", "vncserver.exe", "vncviewer.exe",
    "tvnserver.exe", "uvnc_service.exe", "winvnc4.exe", "repeater.exe"
)
| where InitiatingProcessFileName !in~ ("TeamViewer.exe", "TeamViewer_Service.exe", "tv_w32.exe", "tv_x64.exe")
| where FileName !in~ ("TeamViewer.exe", "TeamViewer_Service.exe", "tv_w32.exe", "tv_x64.exe", "BeyondTrust.exe", "bomgar-scc.exe", "pbps.exe", "raserver.exe")
| extend LowerFile = tolower(FileName)
| extend
    SuspiciousPath = FolderPath has_any (@"\Downloads\", @"\Desktop\", @"\Temp\", @"\AppData\", @"\Public\", @"\ProgramData\"),
    IsHighAbuseTool = LowerFile in~ (HighAbuseTools),
    IsPortableExec = not(FolderPath has_any (@"\Program Files\", @"\Program Files (x86)\"))
| extend Severity = case(
    IsHighAbuseTool and SuspiciousPath, "🔴 Critical",
    IsHighAbuseTool or (SuspiciousPath and IsPortableExec), "🟠 High",
    SuspiciousPath or IsPortableExec, "🟡 Medium",
    "🟢 Low"
)
| summarize
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Executions = count(),
    Paths = make_set(FolderPath, 5),
    CommandLines = make_set(ProcessCommandLine, 3)
    by Severity, AccountName, DeviceName, FileName, SuspiciousPath, IsHighAbuseTool, IsPortableExec
| project
    FirstSeen,
    Severity,
    Executions,
    DeviceName,
    AccountName,
    FileName,
    IsHighAbuseTool,
    SuspiciousPath,
    IsPortableExec,
    Paths,
    CommandLines,
    LastSeen
| sort by Severity asc, Executions desc
```

---

# 👤 User Hunts

## 📎 Malicious Attachments
Grid. Pulls recent hashes live from abuse.ch MalwareBazaar. Needs the Defender for Office 365 email tables.

```kql
let TargetUser = tolower(trim(" ", "{UserPrincipalName}"));
// === MalwareBazaar - recent SHA256 hashes ===
let MalwareHashes = materialize(
    externaldata(Indicator:string)
    [@"https://bazaar.abuse.ch/export/txt/sha256/recent/"]
    with (format="txt")
    | where Indicator !startswith "#"
    | where string_size(Indicator) == 64 and Indicator matches regex @"^[A-Fa-f0-9]+$"
    | distinct Indicator
);
// === 1. Match malicious attachment hashes ===
let MaliciousAttachments =
EmailAttachmentInfo
| where TimeGenerated {TimeRange}
| where isnotempty(SHA256)
| join hint.strategy=broadcast kind=inner (MalwareHashes) on $left.SHA256 == $right.Indicator
| project AttachTime = TimeGenerated, SenderFromAddress, RecipientEmailAddress,
          FileName, FileType, SHA256, NetworkMessageId;
// === 2. Enrich with delivery outcome from EmailEvents ===
MaliciousAttachments
| join kind=inner (
    EmailEvents
    | where TimeGenerated {TimeRange}
    | project NetworkMessageId, EmailTime = TimeGenerated,
              Subject, EmailDirection,
              DeliveryAction, DeliveryLocation,
              ThreatTypes, Recipient = RecipientEmailAddress
) on NetworkMessageId
| where isempty(TargetUser) or tolower(Recipient) has TargetUser
// --- Classify exposure level ---
| extend ExposureLevel = case(
    DeliveryLocation in ("Inbox/folder", "Inbox"), "🔴 DELIVERED TO INBOX",
    DeliveryAction == "Delivered", "🔴 DELIVERED",
    DeliveryLocation == "Junk", "🟡 Junked",
    DeliveryAction in ("Blocked", "Replaced"), "🟢 Blocked",
    DeliveryLocation == "Quarantine", "🟢 Quarantined",
    "⚪ Unknown"
)
// --- Risk Score based on exposure ---
| extend RiskScore = case(
    ExposureLevel == "🔴 DELIVERED TO INBOX", 10,
    ExposureLevel == "🔴 DELIVERED", 9,
    ExposureLevel == "🟡 Junked", 5,
    2
)
// --- Check if the recipient CLICKED a URL (highest risk) ---
| join kind=leftouter (
    UrlClickEvents
    | where TimeGenerated {TimeRange}
    | project NetworkMessageId, ClickTime = TimeGenerated,
              ClickedUrl = Url, ClickAction = ActionType
) on NetworkMessageId
| extend WasClicked = isnotempty(ClickTime)
| extend RiskScore = iff(WasClicked, RiskScore + 3, RiskScore)
| extend Severity = case(
    RiskScore >= 10, "🔴 Critical",
    RiskScore >= 7,  "🟠 High",
    RiskScore >= 4,  "🟡 Medium",
    "🟢 Low"
)
// --- Deduplicate ---
| summarize
    FirstSeen    = min(AttachTime),
    LastSeen     = max(AttachTime),
    WasClicked   = max(WasClicked)
    by Severity, RiskScore, ExposureLevel,
       SenderFromAddress, Recipient, Subject,
       FileName, FileType, SHA256,
       DeliveryAction, DeliveryLocation
| project
    FirstSeen,
    Severity,
    RiskScore,
    ExposureLevel,
    WasClicked,
    Recipient,
    SenderFromAddress,
    Subject,
    FileName,
    FileType,
    DeliveryAction,
    DeliveryLocation,
    SHA256
| sort by RiskScore desc, FirstSeen desc
```

## 📲 MFA Spamming
Grid. 5+ denied prompts within 10 minutes. `UserCaved` = the user eventually approved one.

```kql
let TargetUser = tolower(trim(" ", "{UserPrincipalName}"));
let SpamWindow = 10m;
let MinFailedAttempts = 5;
// === Feed 1: Feodo Tracker - Botnet C2 IPs ===
let Feodo_IPs = materialize(
    externaldata(Indicator:string)
    [@"https://feodotracker.abuse.ch/downloads/ipblocklist.txt"]
    with (format="txt")
    | where Indicator matches regex @"^\d+\.\d+\.\d+\.\d+$"
    | distinct Indicator
);
// === Feed 2: Tor Exit Nodes ===
let Tor_IPs = materialize(
    externaldata(Indicator:string)
    [@"https://check.torproject.org/torbulkexitlist"]
    with (format="txt")
    | where Indicator matches regex @"^\d+\.\d+\.\d+\.\d+$"
    | distinct Indicator
);
// === Feed 3: Blocklist.de - Attacking IPs ===
let Blocklist_IPs = materialize(
    externaldata(Indicator:string)
    [@"https://lists.blocklist.de/lists/all.txt"]
    with (format="txt")
    | where Indicator matches regex @"^\d+\.\d+\.\d+\.\d+$"
    | distinct Indicator
);
// === Sentinel TI (kept from before) ===
let TI_IPs = ThreatIntelligenceIndicator
    | where TimeGenerated > ago(30d)
    | where Active == true and isnotempty(NetworkIP)
    | distinct NetworkIP;
SigninLogs
| where TimeGenerated {TimeRange}
| where isempty(TargetUser) or tolower(UserPrincipalName) has TargetUser
| extend
    DeviceDetail    = todynamic(DeviceDetail),
    LocationDetails = todynamic(LocationDetails)
| extend
    OS      = tostring(DeviceDetail.operatingSystem),
    Browser = tostring(DeviceDetail.browser),
    City    = tostring(LocationDetails.city),
    Region  = tostring(LocationDetails.countryOrRegion)
| where AuthenticationRequirement == "multiFactorAuthentication"
| mv-expand todynamic(AuthenticationDetails)
| extend AuthResult = tostring(parse_json(AuthenticationDetails).authenticationStepResultDetail)
// --- Aggregate per user + IP ---
| summarize
    FailedAttempts = countif(AuthResult has_any (
        "MFA denied; user declined the authentication",
        "MFA denied; user did not respond to mobile app notification",
        "MFA denied; duplicate authentication attempt",
        "user declined"
    )),
    SuccessfulAttempts = countif(AuthResult == "MFA successfully completed"),
    TotalPrompts   = count(),
    InvolvedOS     = make_set(OS, 5),
    InvolvedBrowser = make_set(Browser, 5),
    Cities         = make_set(City, 5),
    Regions        = make_set(Region, 5),
    Apps           = make_set(AppDisplayName, 10),
    StartTime      = min(TimeGenerated),
    EndTime        = max(TimeGenerated)
    by UserPrincipalName, IPAddress
| extend AuthenticationWindow = (EndTime - StartTime)
// --- Flag bombing ---
| where FailedAttempts >= MinFailedAttempts
    and AuthenticationWindow <= SpamWindow
// --- CRITICAL: did the user cave? ---
| extend UserCaved = SuccessfulAttempts > 0
// --- Enrich source IP against all feeds ---
| extend
    IsFeodoC2   = IPAddress in (Feodo_IPs),
    IsTorExit   = IPAddress in (Tor_IPs),
    IsBlocklist = IPAddress in (Blocklist_IPs),
    IsSentinelTI = IPAddress in (TI_IPs)
| extend IsMaliciousIP = IsFeodoC2 or IsTorExit or IsBlocklist or IsSentinelTI
| extend FeedMatches = strcat(
    iff(IsFeodoC2, "Feodo-C2 ", ""),
    iff(IsTorExit, "Tor-Exit ", ""),
    iff(IsBlocklist, "Blocklist.de ", ""),
    iff(IsSentinelTI, "Sentinel-TI ", "")
)
// --- Risk Score ---
| extend RiskScore = 5
                   + iff(UserCaved, 4, 0)
                   + iff(IsFeodoC2, 4, 0)          // C2 infra = strongest
                   + iff(IsTorExit, 3, 0)          // anonymized = very suspicious
                   + iff(IsBlocklist, 2, 0)        // attacking IP = supporting
                   + iff(FailedAttempts > 20, 2, 0)
                   + iff(array_length(Regions) > 1, 1, 0)
| extend Severity = case(
    UserCaved and IsMaliciousIP, "🔴 Critical - Likely Compromised",
    UserCaved,                    "🔴 Critical - User Approved",
    IsFeodoC2 or IsTorExit,       "🔴 Critical - Malicious Source",
    FailedAttempts > 20,          "🟠 High - Heavy Bombing",
    "🟡 Medium - MFA Spam"
)
| extend Name = tostring(split(UserPrincipalName, '@')[0]),
         UPNSuffix = tostring(split(UserPrincipalName, '@')[1])
| project
    StartTime,
    EndTime,
    Severity,
    RiskScore,
    UserPrincipalName,
    UserCaved,
    IsMaliciousIP,
    FeedMatches,
    FailedAttempts,
    SuccessfulAttempts,
    TotalPrompts,
    AuthenticationWindow,
    IPAddress,
    Regions,
    Cities,
    Apps,
    InvolvedOS,
    InvolvedBrowser
| sort by RiskScore desc, UserCaved desc, FailedAttempts desc
```

## ☠️ Sign-In From IOC
Grid. Malicious IPs come from Sentinel TI plus live Feodo C2 and blocklist.de feeds.

```kql
let TargetUser = tolower(trim(" ", "{UserPrincipalName}"));
// === Sentinel Threat Intel IPs ===
let TI_IPs = ThreatIntelligenceIndicator
    | where TimeGenerated > ago(30d)
    | where Active == true
    | where isnotempty(NetworkIP)
    | distinct NetworkIP;
// === abuse.ch Feodo Tracker - Botnet C2 IPs ===
let Feodo_IPs = materialize(
    externaldata(Indicator:string)
    [@"https://feodotracker.abuse.ch/downloads/ipblocklist.txt"]
    with (format="txt")
    | where Indicator matches regex @"^\d+\.\d+\.\d+\.\d+$"
    | distinct Indicator
);
// === blocklist.de - Known attacking IPs ===
let Blocklist_IPs = materialize(
    externaldata(Indicator:string)
    [@"https://lists.blocklist.de/lists/all.txt"]
    with (format="txt")
    | where Indicator matches regex @"^\d+\.\d+\.\d+\.\d+$"
    | distinct Indicator
);
// === Combine all malicious IPs ===
let MaliciousIPs = materialize(
    union
        (TI_IPs | project MalIP = NetworkIP, FeedSource = "Sentinel TI"),
        (Feodo_IPs | project MalIP = Indicator, FeedSource = "Feodo C2"),
        (Blocklist_IPs | project MalIP = Indicator, FeedSource = "Blocklist.de")
    | summarize FeedSource = make_set(FeedSource) by MalIP
);
// === Correlate against successful sign-ins ===
SigninLogs
| where TimeGenerated {TimeRange}
| where isempty(TargetUser) or tolower(UserPrincipalName) has TargetUser
| where ResultType == "0"                        // successful sign-ins only
| project TimeGenerated, UserPrincipalName, IPAddress,
          AppDisplayName, ClientAppUsed,
          Country = tostring(LocationDetails.countryOrRegion),
          City = tostring(LocationDetails.city),
          RiskLevelDuringSignIn, ConditionalAccessStatus, UserAgent
| join kind=inner (MaliciousIPs) on $left.IPAddress == $right.MalIP
| extend Severity = case(
    RiskLevelDuringSignIn in ("high", "medium"), "🔴 Critical",
    ConditionalAccessStatus == "success", "🟠 High",
    "🟠 High"
)
| summarize
    FirstSeen     = min(TimeGenerated),
    LastSeen      = max(TimeGenerated),
    SignInCount   = count(),
    Apps          = make_set(AppDisplayName, 10),
    Countries     = make_set(Country, 5),
    FeedSources   = take_any(FeedSource)
    by UserPrincipalName, IPAddress, Severity, RiskLevelDuringSignIn
| project
    FirstSeen,
    LastSeen,
    Severity,
    UserPrincipalName,
    MaliciousIP = IPAddress,
    FeedSources,
    SignInCount,
    Apps,
    Countries,
    RiskLevelDuringSignIn
| sort by Severity asc, LastSeen desc
```