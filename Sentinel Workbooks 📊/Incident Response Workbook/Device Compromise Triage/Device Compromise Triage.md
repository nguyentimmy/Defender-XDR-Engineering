# 🛡️ Device Compromise Triage

**On-demand post-compromise investigation for a single endpoint.**

Parameterized Microsoft Sentinel / Defender XDR queries for post-compromise investigation, risk-scored and severity-ranked.

Traditionally, working a suspect device or account means opening a dozen separate queries across process, registry, network, identity, and mailbox telemetry — then lining up timestamps by hand, and eyeballing which hits actually matter. During an active incident, that setup work is the bottleneck, not the analysis.

These consolidate it into a single parameterized view. Pick an entity, pick a time range, get a chronological timeline in seconds — sorted by risk, not just time, so the most dangerous activity surfaces first.

---

## 🎯 Why this exists

Investigating a suspect endpoint normally means running a dozen separate hunts — process, registry, network, and file telemetry — then correlating the results by hand and manually deciding what's worth chasing first. During an active incident that setup work is the bottleneck, not the analysis. This collapses ten detection categories into one parameterized, risk-ranked view.

Use it when a device surfaces in an alert, appears on the endpoint dashboard, or is named by a user under investigation.

---

## ⚖️ Risk Score

Every event gets a `RiskScore` (0–10) and a Severity label — 🔴 Critical / 🟠 High / 🟡 Medium / ⚪ Low — based on how dangerous the technique is, with a boost for high-confidence recon and hard signals. Results sort worst-first by default, so the top of the table is always what needs attention first.

---

## 🔍 What it searches for

| Category | Signals |
| --- | --- |
| **Persistence** | Run keys, RunOnce, Winlogon Shell/Userinit, scheduled tasks, service creation |
| **Credential Access** | LSASS dumping, Mimikatz, procdump, comsvcs, nanodump, pypykatz |
| **Defense Evasion** | Defender tampering, event log clearing, auditpol, USN journal deletion, AMSI/ETW bypass |
| **Ransomware Prep** | Shadow copy deletion, `bcdedit` recovery sabotage, backup catalog destruction |
| **Discovery** | AD enumeration, BloodHound/SharpHound, Kerberos/SPN recon, cloud identity recon, share/session and host enumeration |
| **Lateral Movement** | PsExec, WMI remote execution, PowerShell remoting, admin share access |
| **Network Egress** | LOLBins (PowerShell, rundll32, mshta, certutil) reaching external infrastructure |
| **Backdoor Shells** | Netcat/socat reverse shells, PowerShell TCP one-liners, named-pipe shells, web shells |
| **Remote Access** | Unauthorized RATs and tunneling tools (ngrok, chisel, frp, cloudflared) |
| **Defender Detections** | Native AV, ASR, Exploit Guard, and SmartScreen hits on the host |

## 📊 Visualization of the Dashboard
![alt text](image.png)

---
## 🔍 KQL
```kql
// ============================================================
// DEVICE COMPROMISE TRIAGE v4.5 - Workbook (Parameterized, Risk-Scored)
// ============================================================
let TargetDevice = "{DeviceName}";
let BenignParents = dynamic([
    "msedge.exe", "msedgewebview2.exe",
    "MicrosoftEdgeUpdate.exe", "IntuneManagementExtension.exe",
    "backgroundTaskHost.exe"
]);
let HardSignalKeywords = dynamic([
    "Credential Access", "Ransomware Prep", "Backdoor", "Defense Evasion",
    "Account Manipulation", "Registry Modification", "Malicious PowerShell"
]);
union isfuzzy=true
// ============================================================
// TA0002 EXECUTION -- T1059 malicious PowerShell (download/encode/hidden)
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where FileName in~ ("powershell.exe", "pwsh.exe")
    | where ProcessCommandLine has_any (
        "DownloadFile", "DownloadString", "DownloadData",
        "Invoke-Expression", "IEX", "iex(",
        "EncodedCommand", "-enc ", "-ec ",
        "FromBase64String",
        "Net.WebClient", "WebRequest", "Start-BitsTransfer",
        "Invoke-WebRequest", "curl ", "wget ")
        or (ProcessCommandLine has "-WindowStyle Hidden"
            and ProcessCommandLine has "-ExecutionPolicy Bypass")
        or (ProcessCommandLine has "-NonInteractive"
            and ProcessCommandLine has "-NoProfile"
            and ProcessCommandLine has_any ("http", "ftp", "\\\\"))
    | project TimeGenerated, Signal = "⚡ Malicious PowerShell", DeviceName,
              Account = AccountName,
              InitiatingProcess = InitiatingProcessFileName,
              InitiatingProcessCmd = InitiatingProcessCommandLine,
              ChildProcess = FileName,
              SHA256,
              Detail = strcat("PS: ", substring(ProcessCommandLine, 0, 250))
),
// ============================================================
// TA0003 PERSISTENCE -- T1547 autostart keys (registry-state source)
// ============================================================
(
    DeviceRegistryEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
    | where RegistryKey has_any (
        "CurrentVersion\\Run", "CurrentVersion\\RunOnce",
        "Winlogon\\Shell", "Winlogon\\Userinit", "Policies\\Explorer\\Run",
        "CurrentVersion\\RunServices", "CurrentVersion\\RunServicesOnce",
        "BootExecute", "AppInit_DLLs", "Image File Execution Options")
    | project TimeGenerated, Signal = "🔧 Registry Persistence", DeviceName,
              Account = InitiatingProcessAccountName,
              InitiatingProcess = InitiatingProcessFileName,
              InitiatingProcessCmd = InitiatingProcessCommandLine,
              ChildProcess = "",
              SHA256 = InitiatingProcessSHA256,
              Detail = strcat("Reg: ", RegistryValueName, " = ",
                             substring(RegistryValueData, 0, 200))
),
// ============================================================
// TA0003 PERSISTENCE -- T1053.005 / T1543 scheduled tasks & services
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where ProcessCommandLine has_any (
        "schtasks /create", "/sc onlogon", "/sc onstart",
        "/sc onstartup", "/ru system",
        "New-ScheduledTask", "Register-ScheduledTask",
        "sc create", "New-Service")
    | project TimeGenerated, Signal = "🔧 Task/Service Persistence", DeviceName,
              Account = AccountName,
              InitiatingProcess = InitiatingProcessFileName,
              InitiatingProcessCmd = InitiatingProcessCommandLine,
              ChildProcess = FileName,
              SHA256,
              Detail = strcat("Task/Svc: ", substring(ProcessCommandLine, 0, 250))
),
// ============================================================
// TA0003/TA0004 PERSISTENCE/PRIVESC -- T1098 account manipulation
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where (ProcessCommandLine has "localgroup" and
             ProcessCommandLine has_any ("/add", "/delete"))
        or (ProcessCommandLine has "net user" and
            ProcessCommandLine has_any ("/add", "/delete"))
        or ProcessCommandLine has "/active:yes"
        or ProcessCommandLine has "/active:no"
        or ProcessCommandLine has_any (
            "New-LocalUser", "Add-LocalGroupMember",
            "Set-LocalUser", "Enable-LocalUser", "Disable-LocalUser",
            "Remove-LocalGroupMember",
            "net localgroup administrators",
            "net localgroup \"remote desktop users\"")
    | project TimeGenerated, Signal = "👤 Account Manipulation", DeviceName,
              Account = AccountName,
              InitiatingProcess = InitiatingProcessFileName,
              InitiatingProcessCmd = InitiatingProcessCommandLine,
              ChildProcess = FileName,
              SHA256,
              Detail = strcat("Account: ", substring(ProcessCommandLine, 0, 250))
),
// ============================================================
// TA0005 DEFENSE EVASION -- T1112 persistence/RDP/AV registry mods (reg.exe)
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where FileName in~ ("reg.exe", "regedit.exe")
        and ProcessCommandLine has_any ("add", "delete", "import")
        and ProcessCommandLine has_any (
            "CurrentVersion\\Run", "CurrentVersion\\RunOnce",
            "Terminal Server", "fDenyTSConnections", "AllowTSConnections",
            "DisableAntiSpyware", "DisableAntiVirus",
            "Winlogon", "AppInit_DLLs", "Image File Execution Options",
            "SecurityProviders", "Lsa", "DisabledComponents")
    | project TimeGenerated, Signal = "📝 Registry Modification", DeviceName,
              Account = AccountName,
              InitiatingProcess = InitiatingProcessFileName,
              InitiatingProcessCmd = InitiatingProcessCommandLine,
              ChildProcess = FileName,
              SHA256,
              Detail = strcat("Reg mod: ", substring(ProcessCommandLine, 0, 250))
),
// ============================================================
// TA0005 DEFENSE EVASION -- T1562/T1070 impair defenses, clear logs, AMSI
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where ProcessCommandLine has_any (
        "DisableRealtimeMonitoring", "DisableBehaviorMonitoring",
        "Set-MpPreference", "Add-MpPreference -ExclusionPath",
        "DisableAntiSpyware", "DisableAntiVirus",
        "wevtutil cl", "Clear-EventLog", "auditpol /clear",
        "fsutil usn deletejournal", "TamperProtection",
        "AmsiScanBuffer", "amsiInitFailed",
        "Remove-MpPreference", "Set-MpPreference -Disable")
    | project TimeGenerated, Signal = "🥷 Defense Evasion", DeviceName,
              Account = AccountName,
              InitiatingProcess = InitiatingProcessFileName,
              InitiatingProcessCmd = InitiatingProcessCommandLine,
              ChildProcess = FileName,
              SHA256,
              Detail = strcat("Evasion: ", substring(ProcessCommandLine, 0, 250))
),
// ============================================================
// TA0006 CREDENTIAL ACCESS -- T1003.001 LSASS dumping / cred tooling
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where ProcessCommandLine has_any (
        "Mimikatz", "sekurlsa", "logonpasswords", "lsadump",
        "procdump", "comsvcs.dll", "MiniDumpWriteDump", "nanodump",
        "lsass.dmp", "Out-Minidump", "pypykatz", "lsassy",
        "Invoke-Mimikatz", "DumpCreds")
        or (ProcessCommandLine has "comsvcs" and ProcessCommandLine has "lsass")
        or (ProcessCommandLine has "\\lsass")
        or (FileName =~ "procdump.exe" and ProcessCommandLine has "lsass")
    | project TimeGenerated, Signal = "🔑 Credential Access", DeviceName,
              Account = AccountName,
              InitiatingProcess = InitiatingProcessFileName,
              InitiatingProcessCmd = InitiatingProcessCommandLine,
              ChildProcess = FileName,
              SHA256,
              Detail = strcat("Cred: ", substring(ProcessCommandLine, 0, 250))
),
// ============================================================
// TA0007 DISCOVERY -- T1087/T1069/T1558/T1082/T1016/T1018 recon
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | extend ReconCategory = case(
        ProcessCommandLine has_any (
            "net group \"domain admins\"", "net group \"enterprise admins\"",
            "net group \"domain controllers\"", "net localgroup administrators",
            "net accounts /domain", "dsquery", "dsget", "adfind",
            "Get-ADUser", "Get-ADGroup", "Get-ADComputer", "Get-ADDomain",
            "Get-DomainUser", "Get-NetUser", "Get-NetGroup",
            "Get-DomainController", "Get-NetDomainController"),
            "🔴 AD Enumeration",
        ProcessCommandLine has_any (
            "SharpHound", "Invoke-BloodHound", "-CollectionMethod",
            "bloodhound", "azurehound", "Get-DomainTrust", "Get-ForestTrust"),
            "🔴 BloodHound/AD Mapping",
        ProcessCommandLine has_any (
            "setspn -q", "setspn -l", "Get-DomainSPNTicket",
            "Invoke-Kerberoast", "GetUserSPNs", "Rubeus kerberoast"),
            "🔴 Kerberos/SPN Recon",
        ProcessCommandLine has_any (
            "az account", "az ad", "aws sts get-caller-identity",
            "aws iam", "gcloud auth", "Get-AzureADUser", "Get-MgUser",
            "Connect-AzAccount", "Get-AzRoleAssignment",
            "kubectl get secrets"),
            "🔴 Cloud/Identity Recon",
        ProcessCommandLine has_any (
            "net view", "net share", "net session", "net use",
            "Get-NetShare", "Get-NetSession", "Find-DomainShare",
            "PsLoggedon", "quser", "qwinsta", "query session"),
            "🟠 Share/Session Discovery",
        ProcessCommandLine has_any (
            "net user", "net localgroup", "whoami /priv", "whoami /groups",
            "whoami /all", "Get-LocalUser", "Get-LocalGroupMember",
            "cmdkey /list", "wmic useraccount"),
            "🟠 Local Account/Priv Enum",
        (ProcessCommandLine has_any (
            "Get-MpComputerStatus", "Get-MpPreference", "sc query windefend",
            "tasklist /svc", "fltmc", "driverquery")
            and ProcessCommandLine has_any (
                "defender", "crowdstrike", "sentinel",
                "cylance", "sophos", "mcafee", "falcon")),
            "🟠 Security Product Discovery",
        ProcessCommandLine has_any (
            "ipconfig", "arp -a", "arp /a", "route print", "netstat",
            "nltest /dclist", "nltest /domain_trusts", "nbtstat",
            "Resolve-DnsName", "ping -n"),
            "🟡 Network Discovery",
        ProcessCommandLine has_any (
            "systeminfo", "hostname", "wmic os", "wmic computersystem",
            "Get-ComputerInfo", "Get-WmiObject Win32_",
            "reg query", "wmic qfe", "wmic product"),
            "🟡 Host/System Enum",
        FileName in~ (
            "whoami.exe", "net.exe", "net1.exe", "nltest.exe",
            "systeminfo.exe", "ipconfig.exe", "arp.exe", "route.exe",
            "quser.exe", "tasklist.exe", "netstat.exe", "wmic.exe",
            "dsquery.exe"),
            "🟡 Recon Binary",
        ""
    )
    | where isnotempty(ReconCategory)
    | project TimeGenerated, Signal = "🔍 Discovery/Recon", DeviceName,
              Account = AccountName,
              InitiatingProcess = InitiatingProcessFileName,
              InitiatingProcessCmd = InitiatingProcessCommandLine,
              ChildProcess = FileName,
              SHA256,
              Detail = strcat(ReconCategory, ": ", FileName, " ",
                             substring(ProcessCommandLine, 0, 200))
),
// ============================================================
// TA0008 LATERAL MOVEMENT -- T1021 remote exec, PsExec, WMI, WinRM
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where FileName in~ ("psexec.exe", "psexesvc.exe", "paexec.exe")
        or ProcessCommandLine has_any (
            "Invoke-Command", "Enter-PSSession", "New-PSSession",
            "wmic /node", "\\admin$", "\\c$",
            "Invoke-WMIMethod", "Invoke-SMBExec",
            "winrs -r", "winrs.exe")
    | project TimeGenerated, Signal = "↔️ Lateral Movement", DeviceName,
              Account = AccountName,
              InitiatingProcess = InitiatingProcessFileName,
              InitiatingProcessCmd = InitiatingProcessCommandLine,
              ChildProcess = FileName,
              SHA256,
              Detail = strcat("Lateral: ", FileName, " ",
                             substring(ProcessCommandLine, 0, 200))
),
// ============================================================
// TA0011 COMMAND & CONTROL -- T1059/T1071 backdoor / reverse shell
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where ProcessCommandLine has_any (
            "nc.exe -e", "ncat", "-e cmd", "-e /bin/sh", "-e powershell",
            "socat", "/bin/bash -i", "bash -i", "sh -i",
            "Invoke-PowerShellTcp", "Nishang", "powercat",
            "Invoke-Shellcode", "Invoke-ReverseShell")
        or (ProcessCommandLine has "System.Net.Sockets.TCPClient"
            and ProcessCommandLine has_any ("GetStream", "sendback", "iex"))
        or (ProcessCommandLine has "\\\\.\\pipe\\"
            and ProcessCommandLine has_any ("cmd", "powershell"))
        or (ProcessCommandLine has_any ("python", "python3")
            and ProcessCommandLine has_any (
                "socket.socket", "SOCK_STREAM", "pty.spawn"))
        or (InitiatingProcessFileName in~ (
                "w3wp.exe", "httpd.exe", "nginx.exe",
                "tomcat.exe", "php-cgi.exe")
            and FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe"))
    | project TimeGenerated, Signal = "🐚 Backdoor / Reverse Shell", DeviceName,
              Account = AccountName,
              InitiatingProcess = InitiatingProcessFileName,
              InitiatingProcessCmd = InitiatingProcessCommandLine,
              ChildProcess = FileName,
              SHA256,
              Detail = strcat("Shell: ", FileName, " ",
                             substring(ProcessCommandLine, 0, 250))
),
// ============================================================
// TA0011 COMMAND & CONTROL -- T1071.001 LOLBin network egress
// ============================================================
(
    DeviceNetworkEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where InitiatingProcessFileName in~ (
        "powershell.exe", "pwsh.exe", "cmd.exe",
        "rundll32.exe", "regsvr32.exe", "mshta.exe",
        "wscript.exe", "cscript.exe", "certutil.exe")
    | where RemoteIPType == "Public"
    | where not(InitiatingProcessCommandLine contains "OpenRead"
        and InitiatingProcessCommandLine contains "CanRead")
    | where not(tolower(RemoteUrl) has_any (
        "google.com", "gstatic.com", "msftconnecttest.com",
        "msftncsi.com", "microsoft.com", "windowsupdate.com",
        "azure.com", "azureedge.net"))
    | project TimeGenerated, Signal = "🌐 LOLBin Network Egress", DeviceName,
              Account = InitiatingProcessAccountName,
              InitiatingProcess = InitiatingProcessFileName,
              InitiatingProcessCmd = InitiatingProcessCommandLine,
              ChildProcess = "",
              SHA256 = InitiatingProcessSHA256,
              Detail = strcat("Egress: ", InitiatingProcessFileName, " -> ",
                             coalesce(RemoteUrl, RemoteIP), ":", RemotePort)
),
// ============================================================
// TA0011 COMMAND & CONTROL -- T1219/T1572 remote tools & tunnels
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where FileName in~ (
        "AnyDesk.exe", "RustDesk.exe", "QuickAssist.exe", "AeroAdmin.exe",
        "Supremo.exe", "ammyy.exe", "aa_v3.exe", "GetScreen.exe",
        "ScreenConnect.Client.exe", "ConnectWiseControl.Client.exe",
        "SplashtopSOS.exe", "LogMeIn.exe", "GoToAssist.exe",
        "ZohoAssist.exe", "RemotePC.exe", "meshagent.exe", "dwagent.exe",
        "RemoteUtilities.exe", "rutserv.exe", "Radmin.exe",
        "winvnc.exe", "tvnserver.exe", "uvnc_service.exe", "vncviewer.exe",
        "ngrok.exe", "frpc.exe", "chisel.exe", "cloudflared.exe", "plink.exe")
    | where FileName !in~ (
        "TeamViewer.exe", "TeamViewer_Service.exe", "tv_w32.exe",
        "tv_x64.exe", "BeyondTrust.exe", "bomgar-scc.exe", "raserver.exe")
    | extend IsTunneler = FileName in~ (
        "ngrok.exe", "frpc.exe", "chisel.exe", "cloudflared.exe", "plink.exe")
    | project TimeGenerated,
              Signal = iff(IsTunneler, "🕳️ Tunneling Tool",
                                       "🖥️ Unauthorized Remote Tool"),
              DeviceName, Account = AccountName,
              InitiatingProcess = InitiatingProcessFileName,
              InitiatingProcessCmd = InitiatingProcessCommandLine,
              ChildProcess = FileName,
              SHA256,
              Detail = strcat(iff(IsTunneler, "Tunnel: ", "RAT: "),
                             FileName, " ", substring(ProcessCommandLine, 0, 200))
),
// ============================================================
// TA0040 IMPACT -- T1490 ransomware prep / recovery sabotage
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where ProcessCommandLine has_any (
        "vssadmin delete shadows", "wmic shadowcopy delete",
        "Win32_ShadowCopy", "bcdedit /set recoveryenabled no",
        "bcdedit /set safeboot", "wbadmin delete catalog",
        "vssadmin resize shadowstorage", "diskshadow",
        "del /s /f /q", "cipher /w")
    | project TimeGenerated, Signal = "💥 Ransomware Prep", DeviceName,
              Account = AccountName,
              InitiatingProcess = InitiatingProcessFileName,
              InitiatingProcessCmd = InitiatingProcessCommandLine,
              ChildProcess = FileName,
              SHA256,
              Detail = strcat("Recovery sabotage: ",
                             substring(ProcessCommandLine, 0, 250))
),
// ============================================================
// CROSS-CUTTING -- native Defender detections on this host
// ============================================================
(
    DeviceEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where ActionType has_any (
        "AntivirusDetection", "AntivirusReport",
        "SecurityLogCleared", "AsrLsassCredentialTheftBlocked",
        "ExploitGuardNetworkProtectionBlocked", "SmartScreenUrlWarning",
        "TamperingAttempt", "AntivirusDetectionNotBlocked")
    | project TimeGenerated, Signal = "🛡️ Defender Detection", DeviceName,
              Account = InitiatingProcessAccountName,
              InitiatingProcess = InitiatingProcessFileName,
              InitiatingProcessCmd = InitiatingProcessCommandLine,
              ChildProcess = FileName,
              SHA256,
              Detail = strcat(ActionType, " | ",
                             substring(tostring(AdditionalFields), 0, 200))
),
// ============================================================
// v4.1 MDE ALERTS -- custom detection rules + built-in EDR/AV alerts
// One row per alert per device. Severity comes from the alert itself.
// ============================================================
(
    AlertInfo
    | where TimeGenerated {TimeRange}
    | summarize arg_max(TimeGenerated, *) by AlertId
    | join kind=inner (
        AlertEvidence
        | where TimeGenerated {TimeRange}
        | where isnotempty(DeviceName)
        | where isempty(TargetDevice) or DeviceName has TargetDevice
        | summarize Account = take_anyif(AccountName, isnotempty(AccountName)),
                    Cmd = take_anyif(ProcessCommandLine, isnotempty(ProcessCommandLine)),
                    Proc = take_anyif(FileName, isnotempty(FileName)),
                    Hash = take_anyif(SHA256, isnotempty(SHA256))
                    by AlertId, DeviceName
    ) on AlertId
    | project TimeGenerated,
              Signal = case(Severity =~ "High", "🚨 Alert (High)",
                            Severity =~ "Medium", "🚨 Alert (Medium)",
                            Severity =~ "Low", "🚨 Alert (Low)",
                            "🚨 Alert (Info)"),
              DeviceName,
              Account = tostring(Account),
              InitiatingProcess = "",
              InitiatingProcessCmd = tostring(Cmd),
              ChildProcess = tostring(Proc),
              SHA256 = tostring(Hash),
              Detail = strcat(DetectionSource, " | ", Title)
),
// ============================================================
// LINUX CREDENTIAL ACCESS -- T1003.008 / T1552 / T1555
// shadow file, cracking tools, key and cloud credential files, /proc scraping
// (sudo wrapper rows excluded; the child process row still shows)
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where FileName !in~ ("sudo", "su")
    | where ProcessCommandLine has_any ("/etc/shadow", "/etc/gshadow", "/etc/security/opasswd")
        or FileName in~ ("john", "hashcat", "hydra", "medusa", "ncrack", "patator",
                         "unshadow", "mimipenguin", "lazagne", "gcore")
        or (FileName in~ ("cat", "less", "more", "head", "tail", "cp", "scp", "base64",
                          "strings", "xxd", "tar", "zip", "grep", "curl")
            and ProcessCommandLine has_any ("id_rsa", "id_ed25519", "id_ecdsa",
                "credentials", ".kube/config", ".docker/config.json",
                ".git-credentials", ".netrc", ".pgpass", ".my.cnf")
            and ProcessCommandLine has_any (".aws", ".ssh", ".kube", ".docker", ".git-credentials",
                ".netrc", ".pgpass", ".my.cnf"))
        or (FileName in~ ("cat", "strings", "grep", "dd", "xxd")
            and ProcessCommandLine has "/proc/"
            and ProcessCommandLine has_any ("environ", "mem", "maps"))
        or (FileName =~ "gdb" and ProcessCommandLine contains " -p ")
    | project TimeGenerated, Signal = "🔑 Credential Access", DeviceName,
              Account = AccountName,
              InitiatingProcess = InitiatingProcessFileName,
              InitiatingProcessCmd = InitiatingProcessCommandLine,
              ChildProcess = FileName,
              SHA256,
              Detail = strcat("Linux cred: ", FileName, " ",
                             substring(ProcessCommandLine, 0, 220))
),
// ============================================================
// LINUX ACCOUNT MANIPULATION -- T1136.001 / T1098
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where FileName !in~ ("sudo", "su")
    | where FileName in~ ("useradd", "adduser", "userdel", "deluser", "usermod", "groupadd",
                          "gpasswd", "chpasswd", "passwd", "vipw", "visudo", "newusers")
        or (FileName in~ ("tee", "sed", "echo", "printf", "cp", "mv")
            and ProcessCommandLine has_any ("/etc/passwd", "/etc/sudoers", "NOPASSWD"))
    | project TimeGenerated, Signal = "👤 Account Manipulation", DeviceName,
              Account = AccountName,
              InitiatingProcess = InitiatingProcessFileName,
              InitiatingProcessCmd = InitiatingProcessCommandLine,
              ChildProcess = FileName,
              SHA256,
              Detail = strcat("Linux account: ", FileName, " ",
                             substring(ProcessCommandLine, 0, 220))
),
// ============================================================
// LINUX PERSISTENCE (process view) -- T1053.003 / T1543.002 / T1098.004 / T1556
// Excludes your own baseline: /etc/cron.d/mdatp and enabling auditd/mdatp/cron
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where FileName !in~ ("sudo", "su")
    | where (FileName =~ "crontab" and not(ProcessCommandLine has_any (" -l", "-l ")))
        or FileName in~ ("at", "batch", "update-rc.d", "chkconfig")
        or ProcessCommandLine has_any ("/etc/crontab", "/var/spool/cron", "/etc/rc.local",
                                       "/etc/ld.so.preload", "/etc/init.d/",
                                       "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly")
        or (ProcessCommandLine has "authorized_keys"
            and FileName in~ ("tee", "cp", "mv", "sed", "echo", "ssh-copy-id", "cat"))
        or (FileName in~ ("tee", "sed", "cp", "mv")
            and ProcessCommandLine has_any (".bashrc", ".bash_profile", ".profile", "/etc/profile.d",
                "/etc/environment", "/etc/update-motd.d", "/etc/pam.d", "/lib/security",
                "/lib64/security", "/etc/ssh/sshd_config"))
        or (FileName =~ "systemctl" and ProcessCommandLine has_any ("enable", "daemon-reload")
            and not(ProcessCommandLine has_any ("auditd", "mdatp", "crond", "cron.service")))
        or ProcessCommandLine has "/etc/systemd/system/"
    | where not(ProcessCommandLine has "/etc/cron.d/mdatp")
    | where not(ProcessCommandLine has "run-parts")
    | project TimeGenerated, Signal = "🔧 Task/Service Persistence", DeviceName,
              Account = AccountName,
              InitiatingProcess = InitiatingProcessFileName,
              InitiatingProcessCmd = InitiatingProcessCommandLine,
              ChildProcess = FileName,
              SHA256,
              Detail = strcat("Linux persist: ", FileName, " ",
                             substring(ProcessCommandLine, 0, 220))
),
// ============================================================
// LINUX PERSISTENCE + LOG TAMPERING (file view)
// Catches redirects (echo ... >> file) and history/log deletion that the
// process view cannot see. Package managers and cloud agents are excluded;
// if this is noisy on a server, extend the InitiatingProcessFileName list.
// ============================================================
(
    DeviceFileEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where ActionType in ("FileCreated", "FileModified", "FileRenamed", "FileDeleted")
    | where InitiatingProcessFileName !in~ ("dpkg", "apt", "apt-get", "rpm", "dnf", "yum",
                                            "unattended-upgr", "mdatp", "wdavdaemon",
                                            "waagent", "cloud-init", "systemd", "systemctl")
        or ActionType == "FileDeleted"
    | extend IsPersistPath =
            FolderPath startswith "/etc/cron"
            or FolderPath startswith "/var/spool/cron"
            or FolderPath startswith "/etc/systemd/system"
            or FolderPath startswith "/etc/sudoers.d"
            or FolderPath startswith "/etc/profile.d"
            or FolderPath startswith "/etc/pam.d"
            or (FolderPath has ".ssh" and FileName =~ "authorized_keys")
            or FileName in~ ("rc.local", "ld.so.preload", "sudoers", "sshd_config",
                             ".bashrc", ".bash_profile", ".profile")
    | extend IsLogWipe = ActionType == "FileDeleted"
            and (FileName in~ (".bash_history", ".zsh_history", "auth.log", "secure",
                               "syslog", "messages", "wtmp", "btmp", "lastlog", "audit.log")
                 or FolderPath startswith "/var/log")
    | where (IsPersistPath and ActionType != "FileDeleted") or IsLogWipe
    | where not(FileName == "mdatp" and FolderPath startswith "/etc/cron.d")
    | project TimeGenerated,
              Signal = iff(IsLogWipe, "🥷 Defense Evasion", "🔧 Task/Service Persistence"),
              DeviceName,
              Account = InitiatingProcessAccountName,
              InitiatingProcess = InitiatingProcessFileName,
              InitiatingProcessCmd = InitiatingProcessCommandLine,
              ChildProcess = "",
              SHA256 = InitiatingProcessSHA256,
              Detail = strcat(iff(IsLogWipe, "Linux log/history wipe: ", "Linux persist file: "),
                             ActionType, " ", FolderPath, "/", FileName)
),
// ============================================================
// LINUX DEFENSE EVASION -- T1562.001 / T1070 / T1222 / T1014 / T1547.006
// Note: "history -c" / "unset HISTFILE" are shell builtins and never appear here;
// the file view above catches the resulting deletion/truncation instead.
// Package maintainer scripts for mdatp are excluded (upgrades stop the service).
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where FileName !in~ ("sudo", "su")
    | where not(InitiatingProcessCommandLine has_any ("mdatp.prerm", "mdatp.postinst",
                                                      "mdatp.postrm", "mdatp.preinst"))
    | where ProcessCommandLine has_any (
            "HISTFILE=/dev/null", "HISTSIZE=0", "HISTFILESIZE=0", "history -c",
            "auditctl -e 0", "auditctl -D", "setenforce 0", "ufw disable",
            "iptables -F", "iptables --flush", "LD_PRELOAD=", "journalctl --vacuum",
            "real-time-protection --value disabled", "behavior-monitoring --value disabled",
            "passive-mode --value enabled", "mdatp exclusion")
        or (FileName in~ ("systemctl", "service")
            and ProcessCommandLine has_any ("stop", "disable", "mask")
            and ProcessCommandLine has_any ("auditd", "mdatp", "falcon-sensor", "rsyslog",
                "syslog-ng", "apparmor", "firewalld", "ufw", "fail2ban", "wdavdaemon", "osqueryd"))
        or (FileName in~ ("kill", "pkill", "killall")
            and ProcessCommandLine has_any ("mdatp", "wdavdaemon", "falcon-sensor", "falcond",
                "auditd", "rsyslogd", "syslog-ng", "osqueryd"))
        or (FileName in~ ("shred", "truncate", "rm", "ln")
            and ProcessCommandLine has_any (".bash_history", ".zsh_history", "/var/log/",
                                            "wtmp", "btmp", "lastlog"))
        or ProcessCommandLine matches regex @"chattr\s+[-+][a-zA-Z]*[ia]"
        or ProcessCommandLine matches regex @"touch\s+(-[a-zA-Z]*[rtd]\b|--(date|reference))"
        or FileName in~ ("insmod", "rmmod")
        or (FileName =~ "bpftool" and ProcessCommandLine has "prog")
    | project TimeGenerated, Signal = "🥷 Defense Evasion", DeviceName,
              Account = AccountName,
              InitiatingProcess = InitiatingProcessFileName,
              InitiatingProcessCmd = InitiatingProcessCommandLine,
              ChildProcess = FileName,
              SHA256,
              Detail = strcat("Linux evasion: ", FileName, " ",
                             substring(ProcessCommandLine, 0, 220))
),
// ============================================================
// LINUX PRIVILEGE ESCALATION -- T1548.001 / T1611 / T1068
// setuid, capabilities, container escape, GTFOBins shells, public exploits
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where FileName !in~ ("sudo", "su")
    | where (FileName =~ "chmod"
             and ProcessCommandLine matches regex @"chmod\s+(-[A-Za-z]+\s+)*([ugoa]*\+[rwxXt]*s|[46][0-7][0-7][0-7])(\s|$)")
        or FileName in~ ("setcap", "pkexec")
        or (FileName in~ ("nsenter", "unshare", "capsh", "debugfs")
            and InitiatingProcessFileName in~ ("bash", "sh", "zsh", "dash"))
        or (FileName =~ "docker"
            and (ProcessCommandLine has "--privileged" or ProcessCommandLine contains "-v /:"
                 or ProcessCommandLine has "docker.sock" or ProcessCommandLine has "--pid=host"))
        or ProcessCommandLine has_any ("chroot /host", "/var/run/docker.sock")
        or ProcessCommandLine has_any ("pwnkit", "dirtycow", "dirty_pipe", "CVE-2021-4034",
                                       "CVE-2022-0847", "CVE-2021-3156", "CVE-2016-5195")
        or ProcessCommandLine contains "-exec /bin/sh" or ProcessCommandLine contains "-exec /bin/bash"
        or ProcessCommandLine contains ":!/bin/"
        or (FileName in~ ("awk", "gawk", "mawk") and ProcessCommandLine has "BEGIN"
            and ProcessCommandLine has "system")
        or (ProcessCommandLine has "os.system" and ProcessCommandLine has_any ("/bin/sh", "/bin/bash"))
    | project TimeGenerated, Signal = "⬆️ Privilege Escalation", DeviceName,
              Account = AccountName,
              InitiatingProcess = InitiatingProcessFileName,
              InitiatingProcessCmd = InitiatingProcessCommandLine,
              ChildProcess = FileName,
              SHA256,
              Detail = strcat("Linux privesc: ", FileName, " ",
                             substring(ProcessCommandLine, 0, 220))
),
// ============================================================
// LINUX REVERSE SHELL / BACKDOOR -- T1059.004 / T1095 / T1505.003
// bash and nc one-liners, python/perl/php/ruby/awk sockets, web server children
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where FileName !in~ ("sudo", "su")
    | where ProcessCommandLine has_any ("/dev/tcp/", "/dev/udp/", "mkfifo", "pty.spawn")
        or (FileName in~ ("nc", "ncat", "netcat", "nc.traditional", "nc.openbsd")
            and (ProcessCommandLine contains " -e " or ProcessCommandLine contains " -c "
                 or ProcessCommandLine has_any ("-lvp", "-nlvp", "-lp", "-l")))
        or (FileName =~ "socat" and ProcessCommandLine has_any ("exec", "EXEC", "pty"))
        or (ProcessCommandLine has "openssl" and ProcessCommandLine has "s_client"
            and ProcessCommandLine has_any ("/bin/sh", "/bin/bash", "mkfifo"))
        or (FileName startswith "python" and ProcessCommandLine has "socket"
            and ProcessCommandLine has "connect"
            and ProcessCommandLine has_any ("/bin/sh", "/bin/bash", "subprocess", "dup2"))
        or (FileName =~ "perl" and ProcessCommandLine has_any ("socket", "fsockopen")
            and ProcessCommandLine has_any ("exec", "/bin/sh", "/bin/bash", "STDIN"))
        or (FileName in~ ("php", "ruby", "lua", "node")
            and ProcessCommandLine has_any ("fsockopen", "TCPSocket", "socket.tcp", "net.Socket")
            and ProcessCommandLine has_any ("/bin/sh", "/bin/bash", "exec", "spawn"))
        or (FileName in~ ("awk", "gawk") and ProcessCommandLine has "inet" and ProcessCommandLine has "tcp")
        or (InitiatingProcessFileName in~ ("apache2", "httpd", "nginx", "lighttpd", "php-cgi")
                or InitiatingProcessFileName startswith "php-fpm")
            and FileName in~ ("sh", "bash", "dash", "zsh", "curl", "wget", "nc", "ncat",
                              "python", "python3", "perl", "id", "whoami", "uname", "cat", "ls")
    | project TimeGenerated, Signal = "🐚 Backdoor / Reverse Shell", DeviceName,
              Account = AccountName,
              InitiatingProcess = InitiatingProcessFileName,
              InitiatingProcessCmd = InitiatingProcessCommandLine,
              ChildProcess = FileName,
              SHA256,
              Detail = strcat("Linux shell: ", InitiatingProcessFileName, " -> ", FileName, " ",
                             substring(ProcessCommandLine, 0, 200))
),
// ============================================================
// LINUX DOWNLOAD & EXECUTE / OBFUSCATION -- T1105 / T1027 / T1204
// curl|sh one-liners, drops into /tmp, run-from-/tmp, decode-and-run, memfd
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where FileName !in~ ("sudo", "su")
    | where ProcessCommandLine matches regex @"(curl|wget)\s[^|]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b"
        or ProcessCommandLine matches regex @"base64\s+(-d|--decode)[^|]*\|\s*(sudo\s+)?(ba|z|da)?sh"
        or (ProcessCommandLine has "eval" and ProcessCommandLine has_any ("curl", "wget", "base64"))
        or (FileName startswith "python" and ProcessCommandLine has "base64"
            and ProcessCommandLine has_any ("exec", "eval", "b64decode"))
        or (FileName in~ ("curl", "wget")
            and ProcessCommandLine has_any ("/tmp/", "/dev/shm", "/var/tmp"))
        or (FileName =~ "chmod" and ProcessCommandLine contains "+x"
            and ProcessCommandLine has_any ("/tmp/", "/dev/shm", "/var/tmp"))
        or FolderPath matches regex @"^/(tmp|dev/shm|var/tmp)/"
        or ((FileName in~ ("bash", "sh", "dash", "zsh", "perl", "ruby") or FileName startswith "python")
            and ProcessCommandLine matches regex @"\s/(tmp|dev/shm|var/tmp)/\S")
        or ProcessCommandLine has "memfd:" or FolderPath has "(deleted)"
    | project TimeGenerated, Signal = "⬇️ Download & Execute", DeviceName,
              Account = AccountName,
              InitiatingProcess = InitiatingProcessFileName,
              InitiatingProcessCmd = InitiatingProcessCommandLine,
              ChildProcess = FileName,
              SHA256,
              Detail = strcat("Linux dl/exec: ", FileName, " ",
                             substring(ProcessCommandLine, 0, 220))
),
// ============================================================
// LINUX OFFENSIVE TOOL DOWNLOAD / INSTALL -- T1588.002
// package installs, git clones and downloads of well-known attack tooling
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where FileName !in~ ("sudo", "su")
    | where FileName in~ ("apt", "apt-get", "dnf", "yum", "pip", "pip3", "git", "curl", "wget", "snap", "gem", "go")
    | where ProcessCommandLine has_any ("nmap", "hydra", "john", "hashcat", "metasploit",
            "msfvenom", "msfconsole", "sqlmap", "aircrack-ng", "ettercap", "bettercap", "nikto",
            "gobuster", "masscan", "responder", "impacket", "crackmapexec", "netexec", "evil-winrm",
            "linpeas", "PEASS", "LinEnum", "lazagne", "mimipenguin", "chisel", "ligolo", "sliver",
            "pwncat", "proxychains", "sshuttle", "pspy", "kali-linux")
    | project TimeGenerated, Signal = "🛠️ Offensive Tool Install", DeviceName,
              Account = AccountName,
              InitiatingProcess = InitiatingProcessFileName,
              InitiatingProcessCmd = InitiatingProcessCommandLine,
              ChildProcess = FileName,
              SHA256,
              Detail = strcat("Linux tool: ", FileName, " ",
                             substring(ProcessCommandLine, 0, 220))
),
// ============================================================
// LINUX TUNNELING / PIVOTING -- T1572 / T1090
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where FileName !in~ ("sudo", "su")
    | where FileName in~ ("ngrok", "chisel", "frpc", "frps", "cloudflared", "ligolo-agent",
                          "ligolo-proxy", "proxychains", "proxychains4", "sshuttle", "iodine",
                          "iodined", "dnscat", "dnscat2", "gost", "revsocks", "rpivot")
        or (FileName in~ ("ssh", "autossh")
            and ProcessCommandLine matches regex @"\s-[A-Za-z]*[RDL]\s*[A-Za-z0-9\[\]\.:*-]+")
    | project TimeGenerated, Signal = "🕳️ Tunneling Tool", DeviceName,
              Account = AccountName,
              InitiatingProcess = InitiatingProcessFileName,
              InitiatingProcessCmd = InitiatingProcessCommandLine,
              ChildProcess = FileName,
              SHA256,
              Detail = strcat("Linux tunnel: ", FileName, " ",
                             substring(ProcessCommandLine, 0, 200))
),
// ============================================================
// LINUX LATERAL MOVEMENT -- T1021 / T1550
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where FileName !in~ ("sudo", "su")
    | where FileName in~ ("sshpass", "ssh-keyscan", "smbclient", "rpcclient", "evil-winrm",
                          "xfreerdp", "xfreerdp3", "rdesktop", "psexec.py", "wmiexec.py",
                          "smbexec.py", "atexec.py", "dcomexec.py", "secretsdump.py",
                          "impacket-psexec", "impacket-wmiexec", "impacket-smbexec",
                          "impacket-secretsdump", "crackmapexec", "netexec", "nxc")
    | project TimeGenerated, Signal = "↔️ Lateral Movement", DeviceName,
              Account = AccountName,
              InitiatingProcess = InitiatingProcessFileName,
              InitiatingProcessCmd = InitiatingProcessCommandLine,
              ChildProcess = FileName,
              SHA256,
              Detail = strcat("Linux lateral: ", FileName, " ",
                             substring(ProcessCommandLine, 0, 200))
),
// ============================================================
// LINUX COLLECTION / EXFIL -- T1560 / T1048 / T1567
// staging archives in /tmp, upload via curl/wget/scp, raw disk reads, cloud drops
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where FileName !in~ ("sudo", "su")
    | where (FileName in~ ("tar", "zip", "7z", "7za", "7zr", "rar")
             and ProcessCommandLine has_any ("/tmp/", "/dev/shm", "/var/tmp")
             and ProcessCommandLine has_any ("/etc", "/home", "/root", ".ssh", "/var/www", "/var/lib/mysql"))
        or (FileName =~ "curl"
            and ProcessCommandLine matches regex @"(--upload-file|\s-T\s|--data-binary\s+@|\s-F\s+\S*@|\s-d\s+@)")
        or (FileName =~ "wget" and ProcessCommandLine has "--post-file")
        or (FileName in~ ("scp", "rsync", "sftp") and ProcessCommandLine contains "@"
            and ProcessCommandLine has_any ("/etc/", "/home/", "/root/", ".ssh", "/var/www"))
        or (FileName =~ "dd" and ProcessCommandLine matches regex @"if=/dev/(sd|nvme|vd|xvd|mem|kmem)")
        or FileName in~ ("rclone", "megacmd", "mega-put", "megatools")
        or (FileName in~ ("curl", "wget")
            and ProcessCommandLine has_any ("transfer.sh", "pastebin", "file.io", "anonfiles", "gofile",
                "0x0.st", "termbin", "webhook.site", "pipedream", "requestbin", "interact.sh", "oast"))
    | project TimeGenerated, Signal = "📤 Exfil/Collection", DeviceName,
              Account = AccountName,
              InitiatingProcess = InitiatingProcessFileName,
              InitiatingProcessCmd = InitiatingProcessCommandLine,
              ChildProcess = FileName,
              SHA256,
              Detail = strcat("Linux exfil: ", FileName, " ",
                             substring(ProcessCommandLine, 0, 220))
),
// ============================================================
// LINUX CRYPTOMINER -- T1496
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where FileName in~ ("xmrig", "minerd", "cpuminer", "ethminer", "cgminer", "bfgminer",
                          "nbminer", "t-rex", "lolminer", "minergate-cli", "kdevtmpfsi", "kinsing")
        or ProcessCommandLine has_any ("stratum+tcp", "stratum+ssl", "stratum2+tcp", "--donate-level",
                "cryptonight", "randomx", "nicehash", "minexmr", "supportxmr", "nanopool",
                "moneroocean", "c3pool", "hashvault", "2miners")
    | project TimeGenerated, Signal = "⛏️ Cryptominer", DeviceName,
              Account = AccountName,
              InitiatingProcess = InitiatingProcessFileName,
              InitiatingProcessCmd = InitiatingProcessCommandLine,
              ChildProcess = FileName,
              SHA256,
              Detail = strcat("Linux miner: ", FileName, " ",
                             substring(ProcessCommandLine, 0, 200))
),
// ============================================================
// LINUX DESTRUCTIVE IMPACT / RANSOMWARE PREP -- T1485 / T1561 / T1529 / T1490
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where FileName !in~ ("sudo", "su")
    | where ProcessCommandLine matches regex @"rm\s+(-[a-zA-Z]+\s+)*(--no-preserve-root|/\*|/\s*$)"
        or ProcessCommandLine has "--no-preserve-root"
        or ((FileName in~ ("mkfs", "wipefs") or FileName startswith "mkfs.")
            and ProcessCommandLine has "/dev/")
        or (FileName =~ "dd"
            and ProcessCommandLine matches regex @"if=/dev/(zero|urandom|random).*of=/dev/(sd|nvme|vd|xvd)")
        or (FileName =~ "shred" and ProcessCommandLine has "/dev/")
        or ProcessCommandLine has_any ("esxcli vm process kill", "vim-cmd vmsvc/power.off",
                                       "vim-cmd vmsvc/snapshot.removeall")
    | project TimeGenerated, Signal = "💥 Ransomware Prep", DeviceName,
              Account = AccountName,
              InitiatingProcess = InitiatingProcessFileName,
              InitiatingProcessCmd = InitiatingProcessCommandLine,
              ChildProcess = FileName,
              SHA256,
              Detail = strcat("Linux impact: ", FileName, " ",
                             substring(ProcessCommandLine, 0, 220))
),
// ============================================================
// LINUX DISCOVERY -- T1046 / T1087.001 / T1082 / T1040 / T1552.005
// The red/orange/yellow prefix in Detail feeds the existing DiscoveryBoost scoring.
// The yellow tier only counts when an interactive shell or script is the parent, so
// cloud agents (waagent, cloud-init) do not flood the results.
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where FileName !in~ ("sudo", "su")
    | extend ReconCategory = case(
        FileName in~ ("nmap", "masscan", "zmap", "rustscan", "nikto", "gobuster", "dirb", "ffuf",
                      "wfuzz", "wpscan", "nuclei", "whatweb", "sqlmap", "enum4linux", "enum4linux-ng",
                      "smbmap", "crackmapexec", "netexec", "nxc", "responder", "bloodhound-python",
                      "ldapdomaindump", "kerbrute", "hping3")
            or ProcessCommandLine has_any ("linpeas", "linenum", "pspy", "linux-exploit-suggester",
                                           "traitor", "unix-privesc-check"),
            "🔴 Scanner/Offensive Tool",
        (FileName =~ "find" and ProcessCommandLine has_any ("-perm", "-writable", "id_rsa", "authorized_keys", ".pem"))
            or (FileName =~ "getcap" and ProcessCommandLine has "-r")
            or (FileName in~ ("grep", "egrep") and ProcessCommandLine has_any ("-r", "-ri", "-R")
                and ProcessCommandLine has_any ("password", "passwd", "secret", "api_key", "token")),
            "🟠 Filesystem Secret/Perm Hunt",
        ProcessCommandLine has_any ("/etc/passwd", "/etc/group", "/etc/sudoers", "lastlog")
            or (FileName =~ "getent" and ProcessCommandLine has_any ("passwd", "group")),
            "🟠 Local Account Enum",
        FileName in~ ("tcpdump", "tshark", "ettercap", "bettercap", "dsniff"),
            "🟠 Packet Capture/Sniffing",
        FileName in~ ("arp-scan", "nbtscan", "fping", "showmount", "snmpwalk", "snmp-check", "ldapsearch")
            or (FileName in~ ("nc", "ncat", "netcat") and ProcessCommandLine matches regex @"\s-[a-zA-Z]*z")
            or (FileName =~ "dig" and ProcessCommandLine has "axfr"),
            "🟠 Network/Service Enum",
        FileName in~ ("curl", "wget")
            and ProcessCommandLine has_any ("169.254.169.254", "metadata.google.internal",
                                            "metadata/identity/oauth2", "meta-data", "api/token")
            and not(ProcessCommandLine has "no_proxy")
            and InitiatingProcessFileName in~ ("bash", "sh", "zsh", "dash"),
            "🟠 Cloud Metadata Query",
        FileName in~ ("uname", "whoami", "id", "ifconfig", "netstat", "ss", "arp", "ip", "ps",
                      "env", "printenv", "lsmod", "last", "lastb", "who", "w", "lsof",
                      "hostnamectl", "lsb_release")
            and InitiatingProcessCommandLine in~ ("bash", "-bash", "sh", "-sh", "zsh", "-zsh",
                                                  "dash", "-dash", "/bin/bash", "/bin/sh"),
            "🟡 Host/System Enum",
        "")
    | where isnotempty(ReconCategory)
    | project TimeGenerated, Signal = "🔍 Discovery/Recon", DeviceName,
              Account = AccountName,
              InitiatingProcess = InitiatingProcessFileName,
              InitiatingProcessCmd = InitiatingProcessCommandLine,
              ChildProcess = FileName,
              SHA256,
              Detail = strcat(ReconCategory, ": ", FileName, " ",
                             substring(ProcessCommandLine, 0, 200))
),
// --- Schema pin keeps union column order and types stable ---
(
    datatable(TimeGenerated:datetime, Signal:string, DeviceName:string,
              Account:string, InitiatingProcess:string,
              InitiatingProcessCmd:string, ChildProcess:string,
              SHA256:string, Detail:string)[]
)
// ============================================================
// NOISE SUPPRESSION - hard signals bypass this entirely
// ============================================================
| extend IsHardSignal = Signal has_any (HardSignalKeywords)
| extend IsBenignParent =
    InitiatingProcess in~ (BenignParents)
    or InitiatingProcessCmd contains
        "\\Microsoft Intune Management Extension\\Content\\DetectionScripts\\"
    or (InitiatingProcessCmd contains "-ExecutionPolicy AllSigned"
        and InitiatingProcessCmd contains "SessionState.LanguageMode")
    or InitiatingProcessCmd contains "--msedgewebview"
    or InitiatingProcessCmd contains "hpatchmonTask"
    or InitiatingProcessCmd contains "RunCommandExtension"
    or Account =~ "mdatp"
    or InitiatingProcessCmd contains "runuser -u mdatp"
    or InitiatingProcessCmd contains "/var/lib/dpkg/info/mdatp."
    or (InitiatingProcess =~ "svchost.exe"
        and (InitiatingProcessCmd contains "-s DPS"
             or InitiatingProcessCmd contains "-s SysMain"
             or InitiatingProcessCmd contains "-s DiagTrack"))
| where IsHardSignal or not(IsBenignParent)
// ============================================================
// RISK SCORING - base weight per signal type + situational modifiers
// ============================================================
| extend BaseScore = case(
    Signal contains "Alert (High)", 8,
    Signal contains "Alert (Medium)", 6,
    Signal contains "Alert (Low)", 4,
    Signal contains "Alert (Info)", 3,
    Signal has "Privilege Escalation", 7,
    Signal has "Download & Execute", 7,
    Signal has "Cryptominer", 7,
    Signal has "Exfil", 6,
    Signal has "Offensive Tool", 5,
    Signal has "Credential Access", 9,
    Signal has "Ransomware Prep", 9,
    Signal has "Backdoor", 9,
    Signal has "Defense Evasion", 7,
    Signal has "Registry Modification", 7,
    Signal has "Lateral Movement", 7,
    Signal has "Tunneling Tool", 7,
    Signal has "Registry Persistence", 6,
    Signal has "Task/Service Persistence", 6,
    Signal has "Account Manipulation", 6,
    Signal has "Malicious PowerShell", 6,
    Signal has "LOLBin Network Egress", 6,
    Signal has "Defender Detection" and Detail startswith "AntivirusReport", 4,
    Signal has "Defender Detection", 6,
    Signal has "Unauthorized Remote Tool", 5,
    Signal has "Discovery/Recon", 4,
    3
)
| extend DiscoveryBoost = case(
    Signal has "Discovery/Recon" and Detail has "🔴", 3,
    Signal has "Discovery/Recon" and Detail has "🟠", 2,
    0
)
| extend RiskScore = min_of(BaseScore + DiscoveryBoost + iff(IsHardSignal, 2, 0), 10)
| extend Severity = case(RiskScore >= 9, "🔴 Critical",
                         RiskScore >= 7, "🟠 High",
                         RiskScore >= 5, "🟡 Medium", "⚪ Low")
| extend InitiatingProcessCmd = substring(InitiatingProcessCmd, 0, 120)
| extend Detail = substring(Detail, 0, 150)
| summarize LastSeen = max(TimeGenerated), Hits = count()
    by Severity, RiskScore, Signal, DeviceName, Account, Detail,
       InitiatingProcess, InitiatingProcessCmd, ChildProcess, SHA256,
       TimeBin = bin(TimeGenerated, 1m)
| project TimeGenerated = LastSeen, Severity, RiskScore, Signal, DeviceName, Account, Detail,
          Hits, InitiatingProcess, InitiatingProcessCmd, ChildProcess, SHA256
| sort by RiskScore desc, TimeGenerated desc
```
