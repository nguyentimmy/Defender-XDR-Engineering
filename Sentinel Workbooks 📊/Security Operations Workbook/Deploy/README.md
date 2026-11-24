# 🚀 Deploy the Security Operations Workbook

One workbook, six tabs, built straight from the dashboard pages in this folder: every `kql` block becomes a panel.

| File | Use it for |
|---|---|
| 📦 `azuredeploy.json` | ARM template: Deploy to Azure button, `az deployment` or a pipeline |
| 🧩 `SecurityOperationsWorkbook.json` | Gallery template to paste into the Workbooks **Advanced Editor** |
| 🛠️ `build_workbook.py` | Rebuilds both files after you change any dashboard page |

> ⚠️ This workbook does not replace alert triage. Alerts and incidents should still be investigated for a deeper investigation.

---

## 🖱️ Option 1: Deploy to Azure

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fnguyentimmy%2FDefender-XDR-Engineering%2Fmain%2FSentinel%2520Workbooks%2520%25F0%259F%2593%258A%2FSecurity%2520Operations%2520Workbook%2FDeploy%2Fazuredeploy.json)

1. Pick the subscription and the resource group of your Sentinel workspace.
2. Paste the workspace **Resource ID** (Log Analytics workspace > **Properties** or **JSON View**).
3. **Review + create**. The workbook appears in **Sentinel > Workbooks > My workbooks**.

## 💻 Option 2: Azure CLI

```bash
az deployment group create \
  --resource-group <sentinel-rg> \
  --template-file azuredeploy.json \
  --parameters workspaceResourceId="/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<workspace>"
```

To update an existing copy instead of creating a new one, pass the same `workbookId` (the GUID at the end of the workbook's resource ID).

## 📋 Option 3: Paste into Sentinel

1. **Sentinel > Workbooks > Add workbook > Edit > Advanced Editor** (`</>`).
2. Replace the contents with `SecurityOperationsWorkbook.json` and select **Apply**.
3. **Save**, and choose the resource group and workspace.

---

## 🔄 After editing a dashboard page

```bash
python3 build_workbook.py
```

The script reads every dashboard page, so a changed or new `kql` block shows up as a panel on the next build. Commit the regenerated JSON files with the page change.

The panel title comes from the heading above each block, and the chart type from the first line under it (`Grid`, `Tiles`, `Pie chart`, `Time chart`, `Line chart` or `Bar chart`). For tiles, add `Title: \`Col\`, Left: \`Col\`` to pick the columns (default `Metric` and `Value`).

## 🗂️ Layout

| Tab | Sub-tabs |
|---|---|
| 🖥️ Detection Dashboard | 🚨 Alert Dashboard · 🗂️ Incident Dashboard |
| 🛡️ EDR Dashboard | 🦠 AV Dashboard · 🧱 ASR Dashboard |
| 🔍 Incident Response Dashboard | 🖥️ Device Investigation · 👤 User Investigation · 📤 Data Exfil |
| 📊 KPI Metrics Dashboard | |
| 🎯 Threat Hunt Dashboard | 📅 Daily Hunts · 🤖 AI Autonomous Threats Hunts |
| 📡 SIEM Dashboard | |

One parameter bar at the top drives every tab: **Time Range**, **Hostname**, **User**, **User UPN** and **Analyst**. Leave the text filters empty for a fleet-wide view.

## 📌 Notes

- Charts render at half width so two sit side by side. Grids and tiles use the full width.
- Colors, column renderers (bars, thresholds) and cell links aren't generated. Set them in the workbook editor after deploying if you want them.
- Some panels need extra data: SIEM health panels need `SentinelHealth`, User Info needs UEBA (`IdentityInfo`), and the web panels need IIS or Application Gateway logs.
