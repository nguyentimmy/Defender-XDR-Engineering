
# 📧 Email Investigation

**On-demand investigation of one email or campaign: who sent it, who got it, who clicked and whether it's still sitting in a mailbox.**

Fill in any combination of **Sender**, **Recipient**, **Subject** or **Message ID** at the top of the page. Every panel scopes to the matching messages. Use it when a user reports a phishing email, an MDO alert names a message, or you need to scope a campaign before purging.

> **Disclaimer:** This workbook does not replace alert triage. Alerts and incidents should still be investigated for a deeper investigation.

---

## Why this exists

Email investigations span six tables: `EmailEvents`, `EmailUrlInfo`, `EmailAttachmentInfo`, `UrlClickEvents`, `EmailPostDeliveryEvents` and the device tables for attachments that landed on disk. Threat Explorer covers some of it, but not the device side or a sender's 30-day history.

This page answers the scoping questions in order:

| Question | Panel |
| --- | --- |
| How big is it, and is anything still in an inbox? | 📊 Email Summary |
| When did it arrive, and was it a burst? | 📈 Delivery Over Time |
| Who got it, who clicked and who still has it? | 👥 Recipients |
| What exactly was delivered, and did it pass SPF, DKIM and DMARC? | 📬 Messages |
| Which links were in it, and were they clicked? | 🔗 URLs |
| Did an attachment reach a device or run? | 📎 Attachments |
| Who clicked, from where, and was the click blocked? | 🖱️ Clicks |
| Was it removed by ZAP or an admin? | 🧹 Post-Delivery Actions |
| Is the sender new, spoofed or sending to others? | 📤 Sender Profile |

At least one filter has to be filled in, or the panels return nothing. Filters use **contains**, so a domain (`@contoso-billing.com`) or part of a subject works. Message ID takes either the `NetworkMessageId` or the `InternetMessageId`, with or without the angle brackets.

---

## 📊 Email Summary

Headline counts for the matching messages. **⚠️ Threats Still in Inbox** is the one to act on first: threat messages delivered to an inbox with no removal afterwards.

**Visualization:** Tiles (Title: `Metric`, Left: `Value`)

```kql
let Sender = trim(@"\s+", "{EmailSender:escape}");
let Recipient = trim(@"\s+", "{EmailRecipient:escape}");
let SubjectText = trim(@"\s+", "{EmailSubject:escape}");
let MessageId = trim(@"[\s<>]+", "{EmailMessageId:escape}");
let Msgs = EmailEvents
    | where TimeGenerated {TimeRange}
    | where isnotempty(Sender) or isnotempty(Recipient) or isnotempty(SubjectText) or isnotempty(MessageId)
    | where isempty(Sender) or SenderFromAddress contains Sender or SenderMailFromAddress contains Sender or SenderDisplayName contains Sender
    | where isempty(Recipient) or RecipientEmailAddress contains Recipient
    | where isempty(SubjectText) or Subject contains SubjectText
    | where isempty(MessageId) or NetworkMessageId == MessageId or InternetMessageId contains MessageId;
let Ids = Msgs | distinct NetworkMessageId;
let C = toscalar(UrlClickEvents
    | where TimeGenerated between ({TimeRange:start} .. now())
    | where NetworkMessageId in (Ids)
    | summarize Clicks = count(), Reached = countif(ActionType == "ClickAllowed" or IsClickedThrough == true)
    | project pack_all());
let Removed = EmailPostDeliveryEvents
    | where TimeGenerated between ({TimeRange:start} .. now())
    | where NetworkMessageId in (Ids)
    | where Action matches regex "(?i)delete|junk|quarantine"
    | distinct NetworkMessageId, RecipientEmailAddress = tolower(RecipientEmailAddress)
    | extend IsRemoved = true;
Msgs
| extend RecipientEmailAddress = tolower(RecipientEmailAddress)
| lookup kind=leftouter Removed on NetworkMessageId, RecipientEmailAddress
| extend IsRemoved = coalesce(IsRemoved, false), IsThreat = isnotempty(ThreatTypes)
| summarize Messages = dcount(NetworkMessageId), Recipients = dcount(RecipientEmailAddress), Senders = dcount(SenderFromAddress),
            Threats = countif(IsThreat),
            Inbox = countif(DeliveryAction == "Delivered" and DeliveryLocation has "Inbox"),
            Junk = countif(DeliveryLocation has "Junk"),
            Blocked = countif(DeliveryAction == "Blocked"),
            Removed = countif(IsRemoved),
            ThreatInInbox = countif(IsThreat and DeliveryAction == "Delivered" and DeliveryLocation has "Inbox" and not(IsRemoved))
| extend Clicks = coalesce(tolong(C.Clicks), 0), Reached = coalesce(tolong(C.Reached), 0)
| project Rows = pack_array(
    bag_pack("Metric", "📨 Messages", "Value", Messages),
    bag_pack("Metric", "👥 Recipients", "Value", Recipients),
    bag_pack("Metric", "📤 Senders", "Value", Senders),
    bag_pack("Metric", "☣️ Threat Deliveries", "Value", Threats),
    bag_pack("Metric", "📥 In Inbox", "Value", Inbox),
    bag_pack("Metric", "🗑️ In Junk", "Value", Junk),
    bag_pack("Metric", "⛔ Blocked", "Value", Blocked),
    bag_pack("Metric", "🧹 Removed After Delivery", "Value", Removed),
    bag_pack("Metric", "⚠️ Threats Still in Inbox", "Value", ThreatInInbox),
    bag_pack("Metric", "🖱️ Clicks", "Value", Clicks),
    bag_pack("Metric", "🔓 Clicks That Reached the URL", "Value", Reached))
| mv-expand Rows
| project Metric = tostring(Rows.Metric), Value = tolong(Rows.Value)
```

---

## 📈 Delivery Over Time

Matching deliveries over the time range, split by verdict. A tight spike to many recipients is a campaign; a slow trickle from one sender is usually a conversation or a newsletter.

**Visualization:** Time chart

```kql
let Sender = trim(@"\s+", "{EmailSender:escape}");
let Recipient = trim(@"\s+", "{EmailRecipient:escape}");
let SubjectText = trim(@"\s+", "{EmailSubject:escape}");
let MessageId = trim(@"[\s<>]+", "{EmailMessageId:escape}");
EmailEvents
| where TimeGenerated {TimeRange}
| where isnotempty(Sender) or isnotempty(Recipient) or isnotempty(SubjectText) or isnotempty(MessageId)
| where isempty(Sender) or SenderFromAddress contains Sender or SenderMailFromAddress contains Sender or SenderDisplayName contains Sender
| where isempty(Recipient) or RecipientEmailAddress contains Recipient
| where isempty(SubjectText) or Subject contains SubjectText
| where isempty(MessageId) or NetworkMessageId == MessageId or InternetMessageId contains MessageId
| extend Verdict = case(ThreatTypes has "Malware", "Malware", ThreatTypes has "Phish", "Phish", ThreatTypes has "Spam", "Spam", "Clean")
| summarize Deliveries = count() by bin(TimeGenerated, {TimeRange:grain}), Verdict
| render timechart
```

---

## 👥 Recipients

One row per recipient, ranked by exposure: reached the URL, click blocked, still in the inbox, removed, or never delivered. This is the list to work from when resetting passwords and purging.

**Visualization:** Grid

```kql
let Sender = trim(@"\s+", "{EmailSender:escape}");
let Recipient = trim(@"\s+", "{EmailRecipient:escape}");
let SubjectText = trim(@"\s+", "{EmailSubject:escape}");
let MessageId = trim(@"[\s<>]+", "{EmailMessageId:escape}");
let Msgs = EmailEvents
    | where TimeGenerated {TimeRange}
    | where isnotempty(Sender) or isnotempty(Recipient) or isnotempty(SubjectText) or isnotempty(MessageId)
    | where isempty(Sender) or SenderFromAddress contains Sender or SenderMailFromAddress contains Sender or SenderDisplayName contains Sender
    | where isempty(Recipient) or RecipientEmailAddress contains Recipient
    | where isempty(SubjectText) or Subject contains SubjectText
    | where isempty(MessageId) or NetworkMessageId == MessageId or InternetMessageId contains MessageId;
let Ids = Msgs | distinct NetworkMessageId;
let Clicks = UrlClickEvents
    | where TimeGenerated between ({TimeRange:start} .. now())
    | where NetworkMessageId in (Ids)
    | summarize Clicks = count(),
                Reached = countif(ActionType == "ClickAllowed" or IsClickedThrough == true),
                LastClick = max(TimeGenerated)
             by RecipientEmailAddress = tolower(AccountUpn);
let Removed = EmailPostDeliveryEvents
    | where TimeGenerated between ({TimeRange:start} .. now())
    | where NetworkMessageId in (Ids)
    | where Action matches regex "(?i)delete|junk|quarantine"
    | summarize Removed = dcount(NetworkMessageId), RemovedBy = make_set(ActionType, 3)
             by RecipientEmailAddress = tolower(RecipientEmailAddress);
Msgs
| extend RecipientEmailAddress = tolower(RecipientEmailAddress)
| summarize Messages = dcount(NetworkMessageId),
            Threats = dcountif(NetworkMessageId, isnotempty(ThreatTypes)),
            InInbox = dcountif(NetworkMessageId, DeliveryAction == "Delivered" and DeliveryLocation has "Inbox"),
            Blocked = dcountif(NetworkMessageId, DeliveryAction == "Blocked"),
            FirstReceived = min(TimeGenerated), LastReceived = max(TimeGenerated)
         by RecipientEmailAddress
| lookup kind=leftouter Clicks on RecipientEmailAddress
| lookup kind=leftouter Removed on RecipientEmailAddress
| extend Clicks = coalesce(Clicks, 0), Reached = coalesce(Reached, 0), Removed = coalesce(Removed, 0)
| extend SevRank = case(Reached > 0, 1, Clicks > 0, 2, InInbox > Removed, 3, Removed > 0, 4, 5)
| extend Status = case(SevRank == 1, "🔴 Reached URL", SevRank == 2, "🟠 Click Blocked", SevRank == 3, "🟡 Still in Inbox",
                       SevRank == 4, "🟢 Removed", "⚪ Junk / Blocked")
| sort by SevRank asc, Threats desc, LastReceived desc
| project Status, RecipientEmailAddress, Messages, Threats, InInbox, Blocked, Removed, RemovedBy, Clicks, Reached, LastClick,
          FirstReceived, LastReceived
```

**💡 Tips**

- 🔴 **Reached URL**: revoke sessions and check sign-ins in **User Investigation** for the time after **LastClick**.
- 🟡 **Still in Inbox**: purge the message (Threat Explorer or `New-ComplianceSearchAction -Purge`) before someone clicks it.

---

## 📬 Messages

Every matching delivery, one row per recipient, with the verdict, delivery location, authentication results and what happened after delivery. Threats that were clicked or are still in an inbox sort to the top.

**Visualization:** Grid

```kql
let Sender = trim(@"\s+", "{EmailSender:escape}");
let Recipient = trim(@"\s+", "{EmailRecipient:escape}");
let SubjectText = trim(@"\s+", "{EmailSubject:escape}");
let MessageId = trim(@"[\s<>]+", "{EmailMessageId:escape}");
let Msgs = EmailEvents
    | where TimeGenerated {TimeRange}
    | where isnotempty(Sender) or isnotempty(Recipient) or isnotempty(SubjectText) or isnotempty(MessageId)
    | where isempty(Sender) or SenderFromAddress contains Sender or SenderMailFromAddress contains Sender or SenderDisplayName contains Sender
    | where isempty(Recipient) or RecipientEmailAddress contains Recipient
    | where isempty(SubjectText) or Subject contains SubjectText
    | where isempty(MessageId) or NetworkMessageId == MessageId or InternetMessageId contains MessageId;
let Ids = Msgs | distinct NetworkMessageId;
let Clicks = UrlClickEvents
    | where TimeGenerated between ({TimeRange:start} .. now())
    | where NetworkMessageId in (Ids)
    | summarize Clicks = count(), Reached = countif(ActionType == "ClickAllowed" or IsClickedThrough == true)
             by NetworkMessageId, RecipientEmailAddress = tolower(AccountUpn);
let Post = EmailPostDeliveryEvents
    | where TimeGenerated between ({TimeRange:start} .. now())
    | where NetworkMessageId in (Ids)
    | summarize PostDelivery = make_set(strcat(Action, " (", ActionType, ")"), 3)
             by NetworkMessageId, RecipientEmailAddress = tolower(RecipientEmailAddress);
Msgs
| extend RecipientEmailAddress = tolower(RecipientEmailAddress)
| lookup kind=leftouter Clicks on NetworkMessageId, RecipientEmailAddress
| lookup kind=leftouter Post on NetworkMessageId, RecipientEmailAddress
| extend Clicks = coalesce(Clicks, 0), Reached = coalesce(Reached, 0), WasActioned = coalesce(array_length(PostDelivery), 0) > 0
| extend Auth = parse_json(AuthenticationDetails)
| extend SPF = tostring(Auth.SPF), DKIM = tostring(Auth.DKIM), DMARC = tostring(Auth.DMARC), CompAuth = tostring(Auth.CompAuth)
| extend IsThreat = isnotempty(ThreatTypes)
| extend SevRank = case(
    IsThreat and Reached > 0, 1,
    IsThreat and DeliveryAction == "Delivered" and DeliveryLocation has "Inbox" and not(WasActioned), 2,
    IsThreat and DeliveryAction == "Delivered", 3,
    IsThreat, 4,
    5)
| extend Severity = case(SevRank == 1, "🔴 Threat Clicked", SevRank == 2, "🟠 Threat in Inbox", SevRank == 3, "🟡 Threat Delivered",
                         SevRank == 4, "⚪ Threat Blocked", "🟢 No Threat Detected")
| sort by SevRank asc, TimeGenerated desc
| project TimeGenerated, Severity, RecipientEmailAddress, SenderFromAddress, SenderMailFromAddress, SenderDisplayName, Subject,
          EmailDirection, DeliveryAction, DeliveryLocation, ThreatTypes, DetectionMethods, SPF, DKIM, DMARC, CompAuth,
          SenderIPv4, UrlCount, AttachmentCount, Clicks, Reached, PostDelivery, NetworkMessageId, InternetMessageId
```

**💡 Tips**

- **SenderFromAddress ≠ SenderMailFromAddress** with a DMARC fail is classic spoofing. A pass on all three from a lookalike domain is a registered phishing domain.
- **🟢 No Threat Detected** on a message a user reported means MDO missed it. Submit it to Microsoft and block the sender or URL yourself.

---

## 🔗 URLs

Every link in the matching messages, with how many messages carried it and how often it was clicked. A URL that reached the user is the one to block and to hunt for in proxy or firewall logs.

**Visualization:** Grid

```kql
let Sender = trim(@"\s+", "{EmailSender:escape}");
let Recipient = trim(@"\s+", "{EmailRecipient:escape}");
let SubjectText = trim(@"\s+", "{EmailSubject:escape}");
let MessageId = trim(@"[\s<>]+", "{EmailMessageId:escape}");
let Ids = EmailEvents
    | where TimeGenerated {TimeRange}
    | where isnotempty(Sender) or isnotempty(Recipient) or isnotempty(SubjectText) or isnotempty(MessageId)
    | where isempty(Sender) or SenderFromAddress contains Sender or SenderMailFromAddress contains Sender or SenderDisplayName contains Sender
    | where isempty(Recipient) or RecipientEmailAddress contains Recipient
    | where isempty(SubjectText) or Subject contains SubjectText
    | where isempty(MessageId) or NetworkMessageId == MessageId or InternetMessageId contains MessageId
    | distinct NetworkMessageId;
let Clicks = UrlClickEvents
    | where TimeGenerated between ({TimeRange:start} .. now())
    | where NetworkMessageId in (Ids)
    | summarize Clicks = count(),
                Reached = countif(ActionType == "ClickAllowed" or IsClickedThrough == true),
                BlockedClicks = countif(ActionType has "Blocked"),
                Clickers = make_set(AccountUpn, 5)
             by Url;
EmailUrlInfo
| where TimeGenerated {TimeRange}
| where NetworkMessageId in (Ids)
| summarize Messages = dcount(NetworkMessageId), FoundIn = make_set(UrlLocation, 3) by Url, UrlDomain
| lookup kind=leftouter Clicks on Url
| extend Clicks = coalesce(Clicks, 0), Reached = coalesce(Reached, 0), BlockedClicks = coalesce(BlockedClicks, 0)
| extend Status = case(Reached > 0, "🔴 Reached", BlockedClicks > 0, "🟠 Click Blocked", Clicks > 0, "🟡 Clicked", "⚪ Not Clicked")
| sort by Reached desc, Clicks desc, Messages desc
| project Status, UrlDomain, Url, FoundIn, Messages, Clicks, Reached, BlockedClicks, Clickers
```

---

## 📎 Attachments

Every attachment in the matching messages, checked against the device tables. **🔴 Executed** means a device ran a file with the same SHA256, so the investigation moves to **Device Investigation**.

**Visualization:** Grid

```kql
let Sender = trim(@"\s+", "{EmailSender:escape}");
let Recipient = trim(@"\s+", "{EmailRecipient:escape}");
let SubjectText = trim(@"\s+", "{EmailSubject:escape}");
let MessageId = trim(@"[\s<>]+", "{EmailMessageId:escape}");
let Ids = EmailEvents
    | where TimeGenerated {TimeRange}
    | where isnotempty(Sender) or isnotempty(Recipient) or isnotempty(SubjectText) or isnotempty(MessageId)
    | where isempty(Sender) or SenderFromAddress contains Sender or SenderMailFromAddress contains Sender or SenderDisplayName contains Sender
    | where isempty(Recipient) or RecipientEmailAddress contains Recipient
    | where isempty(SubjectText) or Subject contains SubjectText
    | where isempty(MessageId) or NetworkMessageId == MessageId or InternetMessageId contains MessageId
    | distinct NetworkMessageId;
let Files = EmailAttachmentInfo
    | where TimeGenerated {TimeRange}
    | where NetworkMessageId in (Ids)
    | summarize Messages = dcount(NetworkMessageId), Recipients = dcount(RecipientEmailAddress),
                ThreatTypes = make_set_if(ThreatTypes, isnotempty(ThreatTypes), 3),
                DetectionMethods = make_set_if(DetectionMethods, isnotempty(DetectionMethods), 3)
             by FileName, FileType, SHA256;
let Hashes = Files | where isnotempty(SHA256) | distinct SHA256;
let OnDisk = DeviceFileEvents
    | where TimeGenerated between ({TimeRange:start} .. now())
    | where SHA256 in (Hashes)
    | summarize DevicesWithFile = dcount(DeviceName), Devices = make_set(DeviceName, 5) by SHA256;
let Ran = DeviceProcessEvents
    | where TimeGenerated between ({TimeRange:start} .. now())
    | where SHA256 in (Hashes)
    | summarize DevicesExecuted = dcount(DeviceName) by SHA256;
Files
| lookup kind=leftouter OnDisk on SHA256
| lookup kind=leftouter Ran on SHA256
| extend DevicesWithFile = coalesce(DevicesWithFile, 0), DevicesExecuted = coalesce(DevicesExecuted, 0)
| extend RiskRank = case(DevicesExecuted > 0, 1, DevicesWithFile > 0, 2, array_length(ThreatTypes) > 0, 3, 4)
| extend Risk = case(RiskRank == 1, "🔴 Executed", RiskRank == 2, "🟠 On Disk", RiskRank == 3, "🟡 Malicious, Not on Disk", "🟢 No Threat Detected")
| sort by RiskRank asc, Messages desc
| project Risk, FileName, FileType, SHA256, Messages, Recipients, ThreatTypes, DetectionMethods, DevicesWithFile, DevicesExecuted, Devices
```

---

## 🖱️ Clicks

Every Safe Links click on a link from the matching messages, including clicks after the time range ends. **IPAddress** is where the click came from, which helps tell a user's click from a sandbox or a forwarded copy.

**Visualization:** Grid

```kql
let Sender = trim(@"\s+", "{EmailSender:escape}");
let Recipient = trim(@"\s+", "{EmailRecipient:escape}");
let SubjectText = trim(@"\s+", "{EmailSubject:escape}");
let MessageId = trim(@"[\s<>]+", "{EmailMessageId:escape}");
let Ids = EmailEvents
    | where TimeGenerated {TimeRange}
    | where isnotempty(Sender) or isnotempty(Recipient) or isnotempty(SubjectText) or isnotempty(MessageId)
    | where isempty(Sender) or SenderFromAddress contains Sender or SenderMailFromAddress contains Sender or SenderDisplayName contains Sender
    | where isempty(Recipient) or RecipientEmailAddress contains Recipient
    | where isempty(SubjectText) or Subject contains SubjectText
    | where isempty(MessageId) or NetworkMessageId == MessageId or InternetMessageId contains MessageId
    | distinct NetworkMessageId;
UrlClickEvents
| where TimeGenerated between ({TimeRange:start} .. now())
| where NetworkMessageId in (Ids)
| extend Result = case(IsClickedThrough == true, "🔴 Clicked Through Warning", ActionType == "ClickAllowed", "🟠 Allowed",
                       ActionType has "Blocked", "🟢 Blocked", ActionType)
| sort by TimeGenerated desc
| project TimeGenerated, Result, AccountUpn, Url, ActionType, IsClickedThrough, IPAddress, Workload, ThreatTypes, DetectionMethods, NetworkMessageId
```

---

## 🧹 Post-Delivery Actions

Everything that happened to the matching messages after they were delivered: ZAP, admin remediation, moves to junk or quarantine, and redelivery. Includes actions taken after the time range ends.

**Visualization:** Grid

```kql
let Sender = trim(@"\s+", "{EmailSender:escape}");
let Recipient = trim(@"\s+", "{EmailRecipient:escape}");
let SubjectText = trim(@"\s+", "{EmailSubject:escape}");
let MessageId = trim(@"[\s<>]+", "{EmailMessageId:escape}");
let Ids = EmailEvents
    | where TimeGenerated {TimeRange}
    | where isnotempty(Sender) or isnotempty(Recipient) or isnotempty(SubjectText) or isnotempty(MessageId)
    | where isempty(Sender) or SenderFromAddress contains Sender or SenderMailFromAddress contains Sender or SenderDisplayName contains Sender
    | where isempty(Recipient) or RecipientEmailAddress contains Recipient
    | where isempty(SubjectText) or Subject contains SubjectText
    | where isempty(MessageId) or NetworkMessageId == MessageId or InternetMessageId contains MessageId
    | distinct NetworkMessageId;
EmailPostDeliveryEvents
| where TimeGenerated between ({TimeRange:start} .. now())
| where NetworkMessageId in (Ids)
| sort by TimeGenerated desc
| project TimeGenerated, RecipientEmailAddress, Action, ActionType, ActionTrigger, ActionResult, DeliveryLocation,
          ThreatTypes, DetectionMethods, NetworkMessageId
```

---

## 📤 Sender Profile

30-day history for each sender in the matching messages: when they first showed up, how many people they mail, and whether they fail DMARC or use a different MailFrom domain. A brand-new sender that mails many people is a strong phishing signal.

**Visualization:** Grid

```kql
let Sender = trim(@"\s+", "{EmailSender:escape}");
let Recipient = trim(@"\s+", "{EmailRecipient:escape}");
let SubjectText = trim(@"\s+", "{EmailSubject:escape}");
let MessageId = trim(@"[\s<>]+", "{EmailMessageId:escape}");
let Senders = EmailEvents
    | where TimeGenerated {TimeRange}
    | where isnotempty(Sender) or isnotempty(Recipient) or isnotempty(SubjectText) or isnotempty(MessageId)
    | where isempty(Sender) or SenderFromAddress contains Sender or SenderMailFromAddress contains Sender or SenderDisplayName contains Sender
    | where isempty(Recipient) or RecipientEmailAddress contains Recipient
    | where isempty(SubjectText) or Subject contains SubjectText
    | where isempty(MessageId) or NetworkMessageId == MessageId or InternetMessageId contains MessageId
    | distinct SenderFromAddress;
EmailEvents
| where TimeGenerated > ago(30d)
| where SenderFromAddress in (Senders)
| extend DMARC = tostring(parse_json(AuthenticationDetails).DMARC)
| summarize FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated),
            Messages = dcount(NetworkMessageId), Recipients = dcount(RecipientEmailAddress),
            Threats = dcountif(NetworkMessageId, isnotempty(ThreatTypes)),
            DmarcFails = countif(DMARC == "fail"),
            DisplayNames = make_set(SenderDisplayName, 5), MailFromDomains = make_set(SenderMailFromDomain, 5),
            SenderIPs = make_set(SenderIPv4, 5), Directions = make_set(EmailDirection, 3)
         by SenderFromAddress, SenderFromDomain
| extend Flags = strcat_array(set_difference(pack_array(
        iff(FirstSeen > ago(7d), "🆕 New sender", ""),
        iff(DmarcFails > 0, "❌ DMARC fail", ""),
        iff(array_length(set_difference(MailFromDomains, pack_array(SenderFromDomain))) > 0, "🔀 MailFrom mismatch", ""),
        iff(array_length(DisplayNames) > 1, "🎭 Multiple display names", ""),
        iff(Threats > 0, "☣️ Sent threats", "")), dynamic([""])), ", ")
| sort by Threats desc, Recipients desc
| take 50
| project SenderFromAddress, Flags, FirstSeen, LastSeen, Messages, Recipients, Threats, DmarcFails, DisplayNames,
          MailFromDomains, SenderIPs, Directions
```

**💡 Tips**

- **🆕 New sender** + **🔀 MailFrom mismatch** + many recipients: block the sender domain in the Tenant Allow/Block List.
- An internal sender with **☣️ Sent threats** may be a compromised mailbox. Check that account in **User Investigation**.
