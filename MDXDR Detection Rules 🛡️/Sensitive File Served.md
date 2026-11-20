let Allowlist = dynamic([]);   // internal scanners that are expected to hit these paths
let SensitivePaths = @"(?i)(/\.env|/\.git(/|$)|/\.aws/|/\.ssh/|/\.htpasswd|/\.npmrc|/\.dockercfg|/\.docker/|/\.kube/|wp-config\.php|/web\.config|/appsettings(\.\w+)?\.json|id_rsa|\.(sql|bak)$)";
W3CIISLog
| where TimeGenerated > ago(2h)
| where ingestion_time() > ago(1h)
| where cIP !in (Allowlist)
| where csUriStem matches regex SensitivePaths
| where tostring(scStatus) startswith "2"
| summarize Hits = count(),
            Paths = make_set(csUriStem, 20),
            MaxBytes = max(scBytes),
            UserAgents = make_set(csUserAgent, 5),
            Site = take_any(csHost),
            FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated)
         by SourceIP = cIP, WebServer = Computer
| extend FirstPath = tostring(Paths[0])
