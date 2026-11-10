# 📤 Data Exfiltration Hunt

**Fleet-wide or targeted hunt for data leaving the environment, across Windows, Linux, and Microsoft 365.**

Parameterized Microsoft Sentinel / Defender XDR workbook that pulls every exfiltration signal into one risk-scored, severity-ranked table.

---

## 🎯 Why this exists

Exfiltration rarely trips a single high-confidence alert. It looks like ordinary work: zipping a folder, syncing to cloud storage, copying to a USB drive, forwarding mail. Hunting it normally means checking endpoint, file, network, email, and SharePoint data separately and stitching the pieces together by hand.

This workbook collapses all of it into a single view:

- **Catches the noisier activity that may go undetected.** Many of these signals never reach the bar for an alert on their own: a password-protected archive, an upload to a paste site, a bulk SharePoint download, a new forwarding rule. Here they show up together, so the pattern becomes obvious.
- **One view instead of many alerts.** Rather than clicking through separate alerts and log tables, you get one risk-ranked table that is easier to read and faster to act on.
- **Export-ready.** Results can be exported (CSV or Excel) straight from the workbook for an IR report, HR or legal case, or ticket.

Use it for a fleet sweep, an insider-risk case (departing employee, HR referral), or to check whether a compromised device or account moved data out.

---

## ⚖️ Risk Score

Every row gets a `RiskScore` (0–10, capped) and a Severity label: 🔴 Critical / 🟠 High / 🟡 Medium / ⚪ Low. Scores rise with stronger indicators: password-protected or encrypted archives, anonymous file hosts, webhooks, personal webmail, external forwarding targets, and anonymous sharing links. Repeated activity from the same device, account, and process is collapsed into one row with an **EventCount**.

---

## 🔍 What it searches for

| Category | Signals |
| --- | --- |
| **Cloud & Web Uploads** | File-sharing, paste, and anonymous hosts, personal cloud storage, webhooks (Discord, Slack, Telegram, ngrok) (sanctioned M365 storage excluded) |
| **Exfil Tooling** | rclone, MEGA, AzCopy, AWS/Azure/GCP CLIs, s3cmd, WinSCP/FTP; Linux scp, rsync, sftp, lftp to remote hosts; curl/wget only when uploading |
| **PowerShell Uploads** | WebClient UploadFile/UploadData, Invoke-WebRequest/RestMethod with -InFile or POST/PUT |
| **Archiving & Encryption** | Mass or password-protected archives (7-Zip, WinRAR, zip, tar, Compress-Archive), gpg and openssl encryption, archives of sensitive paths (user folders, .pst, .kdbx, keys, /home, /etc, .ssh, databases) |
| **Local Staging** | Archives dropped in Temp, Public, ProgramData, /tmp, /dev/shm, /var/tmp above a size threshold |
| **Removable Media** | Windows USB mounts, Linux mount/udisksctl, bulk writes to external drives (D–Z, /media, /run/media, /mnt) |
| **Linux Exfil Channels** | /dev/tcp redirects, netcat/socat file sends, tar piped over SSH, raw disk reads with dd, base64 piped to curl/nc |
| **DNS & ICMP Tunneling** | iodine, dnscat2, dns2tcp, ptunnel, icmpsh, DNSExfiltrator |
| **SharePoint & OneDrive** | Bulk file downloads, external and anonymous sharing links |
| **Email** | Outbound attachments to external or personal webmail, inbox and transport forwarding rules, command-line mail with attachments (mail, mutt, swaks, Send-MailMessage) |
| **Webhook URLs** | Discord, Telegram, Slack and similar webhook URLs in any command line, caught even when the network URL is empty |
| **Ad Hoc File Servers** | python http.server, uploadserver, php -S, netcat or ncat serving files for the attacker to pull |
| **Code Repositories** | git push to an explicit URL, new git remotes, gh repo create |
| **Network Volume** | High connection fan-out per process (proxy for volume, since Defender has no byte counts) |

---

## 🚀 How to use it

1. Set **TimeRange**. Leave **DeviceName** and **UserPrincipalName** empty for a fleet sweep, or fill one in to scope to a device or user.
2. Read top-down: highest risk first, then look for the same user or device across several categories.
3. Pivot on any row in Defender or Purview for full context (files, destinations, recipients).
4. Export the results and attach them to the case.

> 💡 One row is rarely proof. Archive → staging → upload (or USB, or forwarding) by the same user in a short window is the pattern to act on.

---

## 🛠️ Tuning

- **InternalDomains:** replace the placeholders with your mail domains, or every outbound email looks external.
- **SanctionedCloud:** add any approved storage (Box, Dropbox, Google Drive) your organization uses.
- **Thresholds:** `ArchiveThreshold`, `AttachThreshold`, `DownloadThreshold`, `UsbWriteThreshold`, `StagingMB`, and `ConnFanoutThreshold` sit at the top of the query.
- **SystemNoise:** add backup agents or tools that legitimately write to data drives (`/mnt` on Azure Linux VMs and D: data disks can be noisy).
- **Linux URLs:** `RemoteUrl` is often empty on Linux network events, so Linux uploads are caught mainly through the tooling and channel sections.

---

## 📊 Visualization of the Dashboard
![alt text](image.png)

---

## 🔍 KQL

```kql
// ============================================================
// DATA EXFILTRATION HUNT - Workbook (Parameterized, Windows + Linux)
// ============================================================
// MITRE ATT&CK:
//   Tactic:    Collection, Exfiltration
//   Technique: T1567.002 - Exfiltration to Cloud Storage
//              T1567.003 - Exfiltration to Text Storage Sites
//              T1567.004 - Exfiltration Over Webhook
//              T1048     - Exfiltration Over Alternative Protocol (incl. DNS/ICMP tunnels)
//              T1041     - Exfiltration Over C2 / raw sockets
//              T1052.001 - Exfiltration over USB
//              T1537     - Transfer Data to Cloud Account
//              T1560.001 - Archive Collected Data via Utility
//              T1114.003 - Email Collection: Forwarding Rule
//              T1074.001 - Local Data Staging
//              T1567.001 - Exfiltration to Code Repository
//              T1048.003 - Exfiltration Over Unencrypted Non-C2 Protocol (CLI email, ad hoc servers)
// ============================================================
// PARAMETERS: {TimeRange} (required), {DeviceName} and {UserPrincipalName}
// are OPTIONAL scoping filters - leave both empty for a fleet-wide sweep.
// Curly braces are avoided inside strings (the workbook treats them as parameters).
// ============================================================
let TargetDevice = "{DeviceName}";
let TargetUser = "{UserPrincipalName}";
// --- Tunable thresholds ---
let ArchiveThreshold = 5;
let AttachThreshold = 10;
let DownloadThreshold = 50;
let ConnFanoutThreshold = 1000;
let UsbWriteThreshold = 20;
let StagingMB = 50;
// --- Sanctioned corporate cloud storage ---
let SanctionedCloud = dynamic([
    "sharepoint.com", "onedrive.com", "office.com",
    "microsoft.com", "windows.net"
]);
// --- Internal mail domains (EDIT THESE) ---
let InternalDomains = dynamic([
    "yourdomain1.com", "yourdomain2.com"
]);
// --- Package managers, agents and system processes excluded from staging/write noise ---
let SystemNoise = dynamic([
    "dpkg", "apt", "apt-get", "rpm", "dnf", "yum", "unattended-upgr", "logrotate",
    "snapd", "waagent", "cloud-init", "mdatp", "wdavdaemon", "run-parts", "cron",
    "MsMpEng.exe", "svchost.exe", "System", "TiWorker.exe", "msiexec.exe",
    "OneDrive.exe", "Teams.exe", "ms-teams.exe", "sqlservr.exe", "setup.exe"
]);
union isfuzzy=true
// ============================================================
// 1. UPLOADS TO FILE-SHARING / PASTE / WEBHOOK / PERSONAL CLOUD (Windows + Linux)
// ============================================================
(
    DeviceNetworkEvents
    | where TimeGenerated {TimeRange}
    | where ActionType == "ConnectionSuccess"
    | where isnotempty(RemoteUrl)
    | where RemoteUrl has_any (
        "wetransfer.com", "mega.nz", "mega.io", "megaupload",
        "anonfiles.com", "transfer.sh", "filebin.net", "file.io",
        "ufile.io", "gofile.io", "pixeldrain.com", "bayfiles.com",
        "sendspace.com", "mediafire.com", "zippyshare.com",
        "catbox.moe", "temp.sh", "0x0.st", "uguu.se", "bashupload.com",
        "oshi.at", "tmpfiles.org", "file.coffee",
        "pastebin.com", "paste.ee", "ghostbin.com", "rentry.co",
        "controlc.com", "dpaste.com", "hastebin.com", "privatebin",
        "gist.github.com", "termbin.com",
        "api.telegram.org", "discord.com", "discordapp.com", "hooks.slack.com",
        "webhook.site", "pipedream.net", "requestbin",
        "interact.sh", "oast.", "ngrok.io", "ngrok-free.app",
        "dropbox.com", "box.com", "drive.google.com", "icloud.com",
        "pcloud.com", "sync.com", "tresorit.com", "degoo.com"
    )
    | where not(RemoteUrl has_any (SanctionedCloud))
    // Desktop Discord app is normal chat traffic - webhook abuse comes from scripts and tools
    | where not(RemoteUrl has "discord" and InitiatingProcessFileName in~ ("discord.exe", "update.exe", "discord"))
    | extend IsPasteSite = RemoteUrl has_any ("pastebin", "paste.ee", "ghostbin", "rentry", "controlc",
        "dpaste", "hastebin", "privatebin", "gist.github", "termbin")
    | extend IsAnonHost = RemoteUrl has_any ("anonfiles", "transfer.sh", "filebin", "file.io", "ufile",
        "gofile", "catbox", "temp.sh", "0x0.st", "uguu", "bayfiles", "bashupload", "oshi.at", "tmpfiles")
    | extend IsWebhook = RemoteUrl has_any ("api.telegram.org", "discord", "hooks.slack.com", "webhook.site", "pipedream",
        "requestbin", "interact.sh", "oast.", "ngrok")
    | summarize
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated),
        EventCount = count(),
        Destinations = make_set(RemoteUrl, 10),
        AnyPaste = max(IsPasteSite),
        AnyAnon = max(IsAnonHost),
        AnyHook = max(IsWebhook)
        by DeviceName, Account = InitiatingProcessAccountName, Process = InitiatingProcessFileName
    | extend Signal = "☁️ Upload to File-Sharing / Paste / Webhook",
             RiskScore = 5 + (toint(AnyAnon) * 3) + (toint(AnyPaste) * 2) + (toint(AnyHook) * 3),
             Detail = substring(strcat("Destinations: ", tostring(Destinations)), 0, 300)
    | project FirstSeen, LastSeen, Signal, RiskScore, DeviceName, Account, Process, EventCount, Detail
),
// ============================================================
// 2. EXFIL TOOLING - rclone, MEGA, cloud CLIs, scp/rsync/sftp, curl/wget uploads (Windows + Linux)
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where FileName !in~ ("sudo", "su")
    | extend CmdArgs = replace_regex(ProcessCommandLine, @'(?i)^\s*"?[^"]*?\.exe"?', "")
    | where FileName in~ (
        "rclone.exe", "megacmd.exe", "megaclient.exe", "mega.exe",
        "winscp.exe", "winscp.com", "psftp.exe", "pscp.exe",
        "filezilla.exe", "ftp.exe", "tftp.exe",
        "aws.exe", "azcopy.exe", "gsutil.exe", "s3cmd.exe",
        "curl.exe", "wget.exe",
        "rclone", "megacmd", "mega-put", "megatools", "azcopy", "gsutil", "s3cmd",
        "aws", "az", "gcloud", "scp", "sftp", "rsync", "lftp", "ncftpput", "ftp",
        "curl", "wget", "smbclient"
    )
    | where CmdArgs has_any ("copy", "sync", "move", "upload", "put", "mput",
            "--transfers", "s3://", "gs://", "b2:", "remote:", "cp", "blob")
        or CmdArgs contains " -T "
        or CmdArgs contains " -F "
        or CmdArgs contains "--upload-file"
        or CmdArgs contains "--data-binary @"
        or CmdArgs contains "--post-file"
        or (FileName in~ ("scp", "rsync", "sftp", "lftp", "pscp.exe", "psftp.exe") and CmdArgs contains "@")
    | where not(FileName in~ ("curl", "wget", "curl.exe", "wget.exe")
                and not(CmdArgs contains " -T " or CmdArgs contains " -F " or CmdArgs contains "--upload-file"
                        or CmdArgs contains "--data-binary @" or CmdArgs contains "--post-file"
                        or CmdArgs contains " -d @"))
    | extend IsHighRiskTool = FileName in~ ("rclone.exe", "megacmd.exe", "megaclient.exe", "mega.exe",
        "azcopy.exe", "rclone", "megacmd", "mega-put", "megatools", "azcopy")
    | summarize
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated),
        EventCount = count(),
        Commands = make_set(substring(CmdArgs, 0, 200), 3),
        AnyHighRisk = max(IsHighRiskTool)
        by DeviceName, Account = AccountName, Process = FileName
    | extend Signal = "🚚 Exfiltration Tooling",
             RiskScore = 6 + (toint(AnyHighRisk) * 3),
             Detail = substring(strcat("Cmds: ", tostring(Commands)), 0, 300)
    | project FirstSeen, LastSeen, Signal, RiskScore, DeviceName, Account, Process, EventCount, Detail
),
// ============================================================
// 3. POWERSHELL UPLOADS - WebClient / Invoke-WebRequest / Invoke-RestMethod (Windows)
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where FileName in~ ("powershell.exe", "pwsh.exe", "pwsh")
    | where ProcessCommandLine has_any ("UploadFile", "UploadData", "UploadString", "UploadValues")
        or (ProcessCommandLine has_any ("Invoke-WebRequest", "Invoke-RestMethod", "iwr", "irm")
            and (ProcessCommandLine contains "-InFile" or ProcessCommandLine contains "-Method Post"
                 or ProcessCommandLine contains "-Method Put"))
    | summarize
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated),
        EventCount = count(),
        Commands = make_set(substring(ProcessCommandLine, 0, 200), 3)
        by DeviceName, Account = AccountName, Process = FileName
    | extend Signal = "⚡ PowerShell Upload",
             RiskScore = 7,
             Detail = substring(strcat("Cmds: ", tostring(Commands)), 0, 300)
    | project FirstSeen, LastSeen, Signal, RiskScore, DeviceName, Account, Process, EventCount, Detail
),
// ============================================================
// 4. MASS ARCHIVING / STAGING / ENCRYPTION (Windows + Linux; password or encryption = stronger)
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where InitiatingProcessFileName !in~ (SystemNoise)
    | where FileName in~ (
        "7z.exe", "7za.exe", "7zG.exe", "winrar.exe", "rar.exe",
        "zip.exe", "tar.exe", "WinZip.exe", "wzzip.exe", "PeaZip.exe",
        "makecab.exe", "compact.exe",
        "tar", "zip", "7z", "7za", "7zr", "rar", "gzip", "bzip2", "xz", "split",
        "gpg", "gpg2", "openssl"
    )
    | extend CmdArgs = replace_regex(ProcessCommandLine, @'(?i)^\s*"?[^"]*?\.exe"?', "")
    // " a " is a single term to has_any - must use contains
    | where CmdArgs contains " a "
        or CmdArgs contains "-mx"
        or CmdArgs contains "-r "
        or CmdArgs has_any ("compress", "archive", "-tzip", "-t7z", "cvf", "czf", "cjf", "cJf",
                            "zcvf", "--create", "-czf", "-cvzf")
        or (FileName in~ ("gpg", "gpg2")
            and (CmdArgs contains " -c " or CmdArgs contains "--symmetric"
                 or CmdArgs contains " -e " or CmdArgs contains "--encrypt"))
        or (FileName =~ "openssl" and CmdArgs has "enc")
        or (FileName in~ ("gzip", "bzip2", "xz", "split")
            and CmdArgs has_any ("/home/", "/root", "/etc/", "/var/www", ".sql", ".bak"))
    | extend IsPasswordProtected =
            (FileName !in~ ("tar", "tar.exe") and CmdArgs matches regex @"(?i)\s-(?:hp|p)\S")
            or CmdArgs matches regex @"\s-(?:P|e)\s"
            or FileName in~ ("gpg", "gpg2", "openssl")
    | extend IsSensitiveTarget = CmdArgs has_any (
        "\\Documents", "\\Desktop", "\\Downloads", "\\Users\\",
        ".pst", ".ost", ".kdbx", ".pem", ".key", "\\Finance", "\\HR",
        "/home/", "/root", "/etc/", ".ssh", "/var/www", "/var/lib/mysql",
        "/var/lib/postgresql", ".sql", ".bak", "id_rsa"
    )
    | summarize
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated),
        EventCount = count(),
        Commands = make_set(substring(CmdArgs, 0, 200), 3),
        AnyPassword = max(IsPasswordProtected),
        AnySensitive = max(IsSensitiveTarget)
        by DeviceName, Account = AccountName, Process = FileName
    | where EventCount > ArchiveThreshold or AnyPassword == true or AnySensitive == true
    | extend Signal = "📦 Mass Archiving / Staging",
             RiskScore = 4 + (toint(AnyPassword) * 4) + (toint(AnySensitive) * 2),
             Detail = substring(strcat(iff(AnyPassword, "PASSWORD/ENCRYPTED | ", ""), "Cmds: ", tostring(Commands)), 0, 300)
    | project FirstSeen, LastSeen, Signal, RiskScore, DeviceName, Account, Process, EventCount, Detail
),
// ============================================================
// 5. ARCHIVES DROPPED IN STAGING PATHS - Temp, Public, ProgramData, /tmp, /dev/shm (Windows + Linux)
// ============================================================
(
    DeviceFileEvents
    | where TimeGenerated {TimeRange}
    | where ActionType in ("FileCreated", "FileRenamed")
    | where InitiatingProcessFileName !in~ (SystemNoise)
    | where FileName matches regex @"(?i)\.(zip|7z|rar|tar|tgz|gz|bz2|xz|cab|gpg|enc)$"
    | where FolderPath contains @"\Temp\" or FolderPath contains @"\Users\Public\"
        or FolderPath contains @"\ProgramData\" or FolderPath contains @"\$Recycle"
        or FolderPath startswith "/tmp/" or FolderPath startswith "/dev/shm"
        or FolderPath startswith "/var/tmp"
    | summarize
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated),
        EventCount = count(),
        TotalMB = round(sum(FileSize) / 1048576.0, 1),
        Files = make_set(FileName, 5)
        by DeviceName, Account = InitiatingProcessAccountName, Process = InitiatingProcessFileName
    | where TotalMB >= StagingMB or EventCount >= ArchiveThreshold
    | extend Signal = "🗂️ Archive Staged in Temp Path",
             RiskScore = 5 + iff(TotalMB >= 500, 2, 0),
             Detail = substring(strcat(tostring(TotalMB), " MB | Files: ", tostring(Files)), 0, 300)
    | project FirstSeen, LastSeen, Signal, RiskScore, DeviceName, Account, Process, EventCount, Detail
),
// ============================================================
// 6a. REMOVABLE MEDIA MOUNTED (Windows)
// ============================================================
(
    DeviceEvents
    | where TimeGenerated {TimeRange}
    | where ActionType in ("UsbDriveMounted", "UsbDriveMount", "PnpDeviceConnected")
    | where tostring(AdditionalFields) has_any ("USB", "Removable", "DriveLetter")
    | summarize
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated),
        EventCount = count(),
        Details = make_set(substring(tostring(AdditionalFields), 0, 150), 3)
        by DeviceName, Account = InitiatingProcessAccountName, Process = InitiatingProcessFileName
    | extend Signal = "🔌 Removable Media Mounted",
             RiskScore = 4,
             Detail = substring(strcat("Device: ", tostring(Details)), 0, 300)
    | project FirstSeen, LastSeen, Signal, RiskScore, DeviceName, Account, Process, EventCount, Detail
),
// ============================================================
// 6b. REMOVABLE MEDIA MOUNTED (Linux) - mount / udisksctl on block devices
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where FileName !in~ ("sudo", "su")
    | where (FileName =~ "mount" and ProcessCommandLine has_any ("/dev/sd", "/media/", "/run/media/")
             and not(ProcessCommandLine has_any ("/dev/sda", "/dev/sdb1 /mnt")))
        or (FileName =~ "udisksctl" and ProcessCommandLine has "mount")
    | summarize
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated),
        EventCount = count(),
        Commands = make_set(substring(ProcessCommandLine, 0, 150), 3)
        by DeviceName, Account = AccountName, Process = FileName
    | extend Signal = "🔌 Removable Media Mounted",
             RiskScore = 4,
             Detail = substring(strcat("Linux mount: ", tostring(Commands)), 0, 300)
    | project FirstSeen, LastSeen, Signal, RiskScore, DeviceName, Account, Process, EventCount, Detail
),
// ============================================================
// 6c. BULK WRITES TO EXTERNAL / NON-SYSTEM DRIVE (Windows D-Z, Linux /media /run/media /mnt)
// ============================================================
(
    DeviceFileEvents
    | where TimeGenerated {TimeRange}
    | where ActionType in ("FileCreated", "FileModified")
    | where InitiatingProcessFileName !in~ (SystemNoise)
    | where FolderPath matches regex @"^[D-Zd-z]:\\"
        or FolderPath startswith "/media/" or FolderPath startswith "/run/media/"
        or FolderPath startswith "/mnt/"
    | where not(FolderPath startswith "\\\\")
    | summarize
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated),
        EventCount = count(),
        Files = make_set(FileName, 5),
        Paths = make_set(substring(FolderPath, 0, 80), 3)
        by DeviceName, Account = InitiatingProcessAccountName, Process = InitiatingProcessFileName
    | where EventCount > UsbWriteThreshold
    | extend Signal = "🔌 Bulk Writes to External Drive",
             RiskScore = 6,
             Detail = substring(strcat("Paths: ", tostring(Paths), " | Files: ", tostring(Files)), 0, 300)
    | project FirstSeen, LastSeen, Signal, RiskScore, DeviceName, Account, Process, EventCount, Detail
),
// ============================================================
// 7. LINUX RAW-SOCKET / SSH / DISK EXFIL CHANNELS
// /dev/tcp redirects, netcat/socat file sends, piping archives over ssh, raw disk reads
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where FileName !in~ ("sudo", "su")
    | where (ProcessCommandLine has_any ("/dev/tcp/", "/dev/udp/")
             and ProcessCommandLine has_any ("cat", "tar", "dd", "base64", "<"))
        or (ProcessCommandLine has_any ("nc", "ncat", "netcat", "socat")
            and ProcessCommandLine contains "<")
        or (FileName =~ "ssh" and ProcessCommandLine contains "cat >")
        or (ProcessCommandLine has "tar" and ProcessCommandLine contains "| ssh")
        or (FileName =~ "dd" and ProcessCommandLine matches regex @"if=/dev/(sd|nvme|vd|xvd|mem|kmem)")
        or (ProcessCommandLine has "base64" and ProcessCommandLine has_any ("curl", "wget", "nc"))
    | summarize
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated),
        EventCount = count(),
        Commands = make_set(substring(ProcessCommandLine, 0, 200), 3)
        by DeviceName, Account = AccountName, Process = FileName
    | extend Signal = "🐧 Linux Exfil Channel",
             RiskScore = 8,
             Detail = substring(strcat("Cmds: ", tostring(Commands)), 0, 300)
    | project FirstSeen, LastSeen, Signal, RiskScore, DeviceName, Account, Process, EventCount, Detail
),
// ============================================================
// 8. DNS / ICMP TUNNELING TOOLS (Windows + Linux)
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where FileName in~ ("iodine", "iodined", "dnscat", "dnscat2", "dns2tcp", "dns2tcpc",
                          "ptunnel", "ptunnel-ng", "icmpsh", "hans",
                          "iodine.exe", "dnscat2.exe", "dns2tcpc.exe", "icmpsh.exe", "ptunnel.exe")
        or ProcessCommandLine has_any ("dnscat", "iodine", "dns2tcp", "ptunnel", "icmpsh",
                                       "Invoke-DNSExfiltrator", "DNSExfiltrator")
    | summarize
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated),
        EventCount = count(),
        Commands = make_set(substring(ProcessCommandLine, 0, 200), 3)
        by DeviceName, Account = AccountName, Process = FileName
    | extend Signal = "🕳️ DNS/ICMP Tunneling Tool",
             RiskScore = 8,
             Detail = substring(strcat("Cmds: ", tostring(Commands)), 0, 300)
    | project FirstSeen, LastSeen, Signal, RiskScore, DeviceName, Account, Process, EventCount, Detail
),
// ============================================================
// 9. BULK SHAREPOINT / ONEDRIVE DOWNLOAD
// ============================================================
(
    OfficeActivity
    | where TimeGenerated {TimeRange}
    | where Operation in ("FileDownloaded", "FileSyncDownloadedFull", "FileSyncDownloadedPartial")
    | summarize
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated),
        EventCount = count(),
        UniqueFiles = dcount(OfficeObjectId),
        SourceIPs = make_set(ClientIP, 5)
        by Account = UserId, Process = tostring(UserAgent)
    | where EventCount > DownloadThreshold
    | extend Signal = "📥 Bulk Cloud File Download",
             RiskScore = 5,
             DeviceName = "",
             Detail = substring(strcat("Files: ", tostring(UniqueFiles), " | IPs: ", tostring(SourceIPs)), 0, 300)
    | project FirstSeen, LastSeen, Signal, RiskScore, DeviceName, Account, Process, EventCount, Detail
),
// ============================================================
// 10. EXTERNAL / ANONYMOUS SHARING LINKS (SharePoint / OneDrive)
// ============================================================
(
    OfficeActivity
    | where TimeGenerated {TimeRange}
    | where Operation in ("AnonymousLinkCreated", "SecureLinkCreated", "AddedToSecureLink",
                          "SharingInvitationCreated", "SharingSet", "CompanyLinkCreated")
    | extend TargetType = tostring(column_ifexists("TargetUserOrGroupType", "")),
             TargetName = tostring(column_ifexists("TargetUserOrGroupName", ""))
    | where Operation == "AnonymousLinkCreated" or TargetType =~ "Guest" or TargetName has "#ext#"
    | summarize
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated),
        EventCount = count(),
        AnyAnonymous = max(Operation == "AnonymousLinkCreated"),
        Targets = make_set(TargetName, 5),
        Items = make_set(OfficeObjectId, 5)
        by Account = UserId
    | extend Signal = "🔗 External / Anonymous Sharing Link",
             RiskScore = 5 + (toint(AnyAnonymous) * 2),
             DeviceName = "",
             Process = "",
             Detail = substring(strcat(iff(AnyAnonymous, "ANONYMOUS LINK | ", ""),
                      "Targets: ", tostring(Targets), " | Items: ", tostring(Items)), 0, 300)
    | project FirstSeen, LastSeen, Signal, RiskScore, DeviceName, Account, Process, EventCount, Detail
),
// ============================================================
// 11. OUTBOUND ATTACHMENTS TO EXTERNAL DOMAINS
// ============================================================
(
    EmailEvents
    | where TimeGenerated {TimeRange}
    | where EmailDirection == "Outbound"
    | where AttachmentCount > 0
    | extend RecipientDomain = tolower(tostring(split(RecipientEmailAddress, "@")[1]))
    | where isnotempty(RecipientDomain)
    | where not(RecipientDomain has_any (InternalDomains))
    | extend IsPersonalWebmail = RecipientDomain has_any (
        "gmail.com", "outlook.com", "hotmail.com", "yahoo.com",
        "aol.com", "proton.me", "protonmail.com", "gmx.com",
        "mail.ru", "yandex.com", "tutanota.com", "icloud.com"
    )
    | summarize
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated),
        EventCount = count(),
        TotalAttach = sum(AttachmentCount),
        UniqueRecipients = dcount(RecipientEmailAddress),
        RecipientDomains = make_set(RecipientDomain, 10),
        AnyPersonal = max(IsPersonalWebmail)
        by Account = SenderFromAddress
    | where TotalAttach > AttachThreshold
    | extend Signal = "📧 Outbound Attachments to External",
             RiskScore = 4 + (toint(AnyPersonal) * 3),
             DeviceName = "",
             Process = "",
             Detail = substring(strcat("Attachments: ", tostring(TotalAttach),
                      " | Recipients: ", tostring(UniqueRecipients),
                      " | Domains: ", tostring(RecipientDomains)), 0, 300)
    | project FirstSeen, LastSeen, Signal, RiskScore, DeviceName, Account, Process, EventCount, Detail
),
// ============================================================
// 12. MAIL FORWARDING RULES - classic BEC exfil
// ============================================================
(
    OfficeActivity
    | where TimeGenerated {TimeRange}
    | where Operation in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules",
        "Set-Mailbox", "Set-TransportRule", "New-TransportRule")
    | extend Params = tostring(Parameters)
    | where Params has_any ("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo",
        "ForwardingSmtpAddress", "DeliverToMailboxAndForward", "BlindCopyTo")
    | extend ForwardsExternal = not(Params has_any (InternalDomains))
    | summarize
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated),
        EventCount = count(),
        Operations = make_set(Operation, 5),
        SourceIPs = make_set(ClientIP, 5),
        Samples = make_set(substring(Params, 0, 200), 2),
        AnyExternal = max(ForwardsExternal)
        by Account = UserId
    | extend Signal = "📬 Mail Forwarding Rule Created",
             RiskScore = 6 + (toint(AnyExternal) * 3),
             DeviceName = "",
             Process = "",
             Detail = substring(strcat(iff(AnyExternal, "EXTERNAL TARGET | ", ""),
                      tostring(Operations), " | IPs: ", tostring(SourceIPs),
                      " | ", tostring(Samples)), 0, 300)
    | project FirstSeen, LastSeen, Signal, RiskScore, DeviceName, Account, Process, EventCount, Detail
),
// ============================================================
// 13. CONNECTION FAN-OUT (volume proxy - Defender has no byte counts)
// ============================================================
(
    DeviceNetworkEvents
    | where TimeGenerated {TimeRange}
    | where ActionType == "ConnectionSuccess"
    | where RemoteIPType == "Public"
    | where not(InitiatingProcessFileName in~ (
        "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe",
        "msedgewebview2.exe", "teams.exe", "ms-teams.exe", "outlook.exe",
        "onedrive.exe", "svchost.exe", "backgroundtaskhost.exe",
        "searchapp.exe", "widgets.exe", "officeclicktorun.exe",
        "chrome", "firefox", "code", "waagent", "wdavdaemon", "mdatp",
        "apt", "apt-get", "http", "https", "snapd", "dnf", "yum", "systemd-resolved"
    ))
    | summarize
        EventCount = count(),
        UniqueRemoteIPs = dcount(RemoteIP),
        UniqueDomains = dcount(RemoteUrl),
        TopDestinations = make_set(RemoteIP, 5)
        by DeviceName, Account = InitiatingProcessAccountName,
           Process = InitiatingProcessFileName, HourBin = bin(TimeGenerated, 1h)
    | where EventCount > ConnFanoutThreshold
    | extend Signal = "📡 High Connection Fan-Out (volume proxy)",
             RiskScore = 4,
             FirstSeen = HourBin,
             LastSeen = HourBin + 1h,
             Detail = substring(strcat("Conns/hr: ", tostring(EventCount),
                      " | Unique IPs: ", tostring(UniqueRemoteIPs),
                      " | Domains: ", tostring(UniqueDomains)), 0, 300)
    | project FirstSeen, LastSeen, Signal, RiskScore, DeviceName, Account, Process, EventCount, Detail
),
// ============================================================
// 14. WEBHOOK / BOT API URL IN COMMAND LINE (Windows + Linux)
// Catches Discord/Telegram/Slack webhook exfil even when RemoteUrl is empty
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where FileName !in~ ("sudo", "su")
    | where ProcessCommandLine matches regex @"(?i)(discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|hooks\.slack\.com/services|webhook\.site|pipedream\.net|ngrok-free\.app|ngrok\.io)"
    | where FileName !in~ ("chrome.exe", "msedge.exe", "firefox.exe", "chrome", "firefox")
    | summarize
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated),
        EventCount = count(),
        Commands = make_set(substring(ProcessCommandLine, 0, 200), 3)
        by DeviceName, Account = AccountName, Process = FileName
    | extend Signal = "🪝 Webhook URL in Command Line",
             RiskScore = 8,
             Detail = substring(strcat("Cmds: ", tostring(Commands)), 0, 300)
    | project FirstSeen, LastSeen, Signal, RiskScore, DeviceName, Account, Process, EventCount, Detail
),
// ============================================================
// 15. POWERSHELL / .NET ARCHIVING (Windows) - Compress-Archive, ZipFile
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where FileName in~ ("powershell.exe", "pwsh.exe", "pwsh")
    | where ProcessCommandLine has_any ("Compress-Archive", "CreateFromDirectory", "ZipFile")
    | extend IsSensitiveTarget = ProcessCommandLine has_any ("\\Documents", "\\Desktop", "\\Downloads",
        "\\Users\\", ".pst", ".kdbx", "\\Finance", "\\HR", "\\\\")
    | summarize
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated),
        EventCount = count(),
        Commands = make_set(substring(ProcessCommandLine, 0, 200), 3),
        AnySensitive = max(IsSensitiveTarget)
        by DeviceName, Account = AccountName, Process = FileName
    | extend Signal = "📦 PowerShell Archiving",
             RiskScore = 5 + (toint(AnySensitive) * 2),
             Detail = substring(strcat("Cmds: ", tostring(Commands)), 0, 300)
    | project FirstSeen, LastSeen, Signal, RiskScore, DeviceName, Account, Process, EventCount, Detail
),
// ============================================================
// 16. PULL-STYLE EXFIL - ad hoc web/file servers on the host (Windows + Linux)
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where FileName !in~ ("sudo", "su")
    | where ProcessCommandLine has_any ("http.server", "SimpleHTTPServer", "uploadserver", "updog", "pyftpdlib")
        or (FileName startswith "php" and ProcessCommandLine contains " -S ")
        or (FileName startswith "ruby" and ProcessCommandLine has "httpd")
        or (FileName =~ "busybox" and ProcessCommandLine has "httpd")
        or (FileName in~ ("nc", "ncat", "netcat", "nc.exe", "ncat.exe")
            and ProcessCommandLine matches regex @"\s-\w*l" and ProcessCommandLine contains "<")
        or (FileName in~ ("ncat", "ncat.exe") and ProcessCommandLine has "--send-only")
    | summarize
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated),
        EventCount = count(),
        Commands = make_set(substring(ProcessCommandLine, 0, 200), 3)
        by DeviceName, Account = AccountName, Process = FileName
    | extend Signal = "🌐 Ad Hoc File Server",
             RiskScore = 6,
             Detail = substring(strcat("Cmds: ", tostring(Commands)), 0, 300)
    | project FirstSeen, LastSeen, Signal, RiskScore, DeviceName, Account, Process, EventCount, Detail
),
// ============================================================
// 17. GIT PUSH TO A NEW / EXPLICIT REMOTE (Windows + Linux)
// Normal pushes to an existing remote are ignored; adding a remote or pushing to a URL is not
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where FileName in~ ("git", "git.exe", "gh", "gh.exe")
    | where (ProcessCommandLine has "remote" and ProcessCommandLine has_any ("add", "set-url"))
        or (ProcessCommandLine has "push" and ProcessCommandLine has_any ("http://", "https://", "git@"))
        or (FileName in~ ("gh", "gh.exe") and ProcessCommandLine has "repo" and ProcessCommandLine has "create")
    | extend IsPush = ProcessCommandLine has "push"
    | summarize
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated),
        EventCount = count(),
        Commands = make_set(substring(ProcessCommandLine, 0, 200), 3),
        AnyPush = max(IsPush)
        by DeviceName, Account = AccountName, Process = FileName
    | extend Signal = "🧑‍💻 Git Push / New Remote",
             RiskScore = 4 + (toint(AnyPush) * 2),
             Detail = substring(strcat("Cmds: ", tostring(Commands)), 0, 300)
    | project FirstSeen, LastSeen, Signal, RiskScore, DeviceName, Account, Process, EventCount, Detail
),
// ============================================================
// 18. COMMAND-LINE EMAIL WITH ATTACHMENTS (Windows + Linux)
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where FileName !in~ ("sudo", "su")
    | where (FileName in~ ("mail", "mailx", "s-nail", "mutt", "swaks", "sendemail", "msmtp", "sendmail")
             and (ProcessCommandLine matches regex @"\s-(a|A)\s" or ProcessCommandLine has_any ("--attach", "--attach-type")))
        or (FileName in~ ("powershell.exe", "pwsh.exe", "pwsh")
            and ProcessCommandLine has "Send-MailMessage" and ProcessCommandLine has "Attachment")
        or (FileName in~ ("powershell.exe", "pwsh.exe", "pwsh")
            and ProcessCommandLine has "SmtpClient" and ProcessCommandLine has "Attachment")
    | summarize
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated),
        EventCount = count(),
        Commands = make_set(substring(ProcessCommandLine, 0, 200), 3)
        by DeviceName, Account = AccountName, Process = FileName
    | extend Signal = "✉️ Command-Line Email with Attachment",
             RiskScore = 6,
             Detail = substring(strcat("Cmds: ", tostring(Commands)), 0, 300)
    | project FirstSeen, LastSeen, Signal, RiskScore, DeviceName, Account, Process, EventCount, Detail
),
// --- Schema pin so union stays stable when a section is empty ---
(
    datatable(FirstSeen:datetime, LastSeen:datetime, Signal:string, RiskScore:long,
              DeviceName:string, Account:string, Process:string,
              EventCount:long, Detail:string)[]
)
// ============================================================
// PARAMETER SCOPING (post-union)
// A device selection drops identity-only rows (blank DeviceName).
// A user selection matches on the local part so it works against both
// full UPNs (mailbox sections) and short usernames (endpoint sections).
// Both empty = fleet-wide sweep.
// ============================================================
| extend UserLocalPart = tostring(split(TargetUser, "@")[0])
| where isempty(TargetDevice) or DeviceName has TargetDevice
| where isempty(TargetUser) or Account has UserLocalPart
// ============================================================
// CONSOLIDATE & SCORE
// ============================================================
| extend RiskScore = min_of(RiskScore, 10)
| extend Severity = case(
    RiskScore >= 9, "🔴 Critical",
    RiskScore >= 7, "🟠 High",
    RiskScore >= 5, "🟡 Medium",
    "⚪ Low"
)
| project
    FirstSeen,
    Severity,
    RiskScore,
    Signal,
    DeviceName,
    Account,
    Process,
    EventCount,
    Detail,
    LastSeen
| extend
    timestamp = FirstSeen,
    HostCustomEntity = DeviceName,
    AccountCustomEntity = Account
| sort by RiskScore desc, EventCount desc
```
