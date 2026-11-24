#!/usr/bin/env python3
"""
Builds the Security Operations Workbook from the dashboard markdown files.

Every ```kql block in the dashboard pages becomes a workbook query step. The panel
title comes from the heading above the block and the visualization from the text
under the heading (Grid, Tiles, Pie chart, Time chart, Line chart, Bar chart).

Outputs (next to this script):
  SecurityOperationsWorkbook.json   gallery template, paste into Workbooks > Advanced Editor
  azuredeploy.json                  ARM template for "Deploy to Azure" or az deployment

Run from anywhere:  python3 build_workbook.py
"""
import json
import re
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent  # Security Operations Workbook/
NS = uuid.UUID("5d6f0b1e-7a43-4a7e-9a52-0c1f3c6f6a10")  # stable ids between builds

TABS = [
    ("detection", "🖥️ Detection Dashboard", [
        ("alerts", "🚨 Alert Dashboard", "Detection Dashboard/Alert Dashboard.md"),
        ("incidents", "🗂️ Incident Dashboard", "Detection Dashboard/Incident Dashboard.md"),
    ]),
    ("edr", "🛡️ EDR Dashboard", [
        ("av", "🦠 AV Dashboard", "EDR Dashboard/AV Dashboard.md"),
        ("asr", "🧱 ASR Dashboard", "EDR Dashboard/ASR Dashboard.md"),
    ]),
    ("ir", "🔍 Incident Response Dashboard", [
        ("device", "🖥️ Device Investigation", "Incident Response Dashboard/Device Investigation.md"),
        ("user", "👤 User Investigation", "Incident Response Dashboard/User Investigation.md"),
        ("exfil", "📤 Data Exfil", "Incident Response Dashboard/Data Exfil.md"),
    ]),
    ("kpi", "📊 KPI Metrics Dashboard", [
        ("kpi", "📊 KPI Metrics", "KPI Metrics Dashboard/KPI Metrics Dashboard.md"),
    ]),
    ("hunt", "🎯 Threat Hunt Dashboard", [
        ("daily", "📅 Daily Hunts", "Threat Hunt Dashboard/Daily Hunts.md"),
        ("ai", "🤖 AI Autonomous Threats Hunts", "Threat Hunt Dashboard/AI Autonomous Threats Hunts.md"),
    ]),
    ("siem", "📡 SIEM Dashboard", [
        ("siem", "📡 SIEM Health", "SIEM Dashboard/SIEM Dashboard.md"),
    ]),
]

DISCLAIMER = ("> ⚠️ This workbook does not replace alert triage. Alerts and incidents should still be "
              "investigated for a deeper investigation.")


def sid(*parts):
    return str(uuid.uuid5(NS, "/".join(parts)))


def detect_viz(section_text, query):
    m = re.search(r"\*\*Visualization:\*\*\s*([^\n·]+)", section_text)
    hint = m.group(1) if m else next((l for l in section_text.splitlines() if l.strip()), "")
    h = hint.lower()
    if "tile" in h:
        return "tiles"
    if "time chart" in h or "timechart" in h:
        return "timechart"
    if "line chart" in h or "linechart" in h:
        return "linechart"
    if "bar chart" in h or "column chart" in h or "barchart" in h:
        return "barchart"
    if "pie" in h:
        return "piechart"
    if "grid" in h:
        return "table"
    r = re.search(r"\|\s*render\s+(\w+)", query)
    if r:
        return {"timechart": "timechart", "linechart": "linechart", "piechart": "piechart",
                "columnchart": "barchart", "barchart": "barchart"}.get(r.group(1), "table")
    return "table"


def tile_columns(section_text):
    cols = {}
    for key in ("Title", "Left", "Bottom"):
        m = re.search(key + r"\s*[:=]\s*`([^`]+)`", section_text)
        if m:
            cols[key] = m.group(1)
    cols.setdefault("Title", "Metric")
    cols.setdefault("Left", "Value")
    return cols


def strip_render(q):
    return "\n".join(l for l in q.splitlines() if not re.match(r"^\s*\|\s*render\b", l)).strip()


def parse_panels(md_path, page_title):
    text = md_path.read_text(encoding="utf-8").replace("\r\n", "\n")
    panels, heading, section = [], page_title, []
    in_block, block = False, []
    for line in text.split("\n"):
        if in_block:
            if line.strip().startswith("```"):
                q = "\n".join(block)
                sec = "\n".join(section)
                title = heading
                if re.fullmatch(r"(🔍\s*)?KQL", heading.strip()):
                    title = f"🧭 {page_title} Timeline"
                title = re.sub(r"\s+Panel$", "", title)
                panels.append({"title": title, "query": q, "viz": detect_viz(sec, q), "section": sec})
                in_block, block = False, []
            else:
                block.append(line)
            continue
        if line.startswith("```kql"):
            in_block = True
            continue
        m = re.match(r"^#{2,3}\s+(.*)$", line)
        if m:
            heading = re.sub(r"^(\W*?)\s*\d+\.\s+", r"\1 ", m.group(1)).strip()
            section = []
        else:
            section.append(line)
    return panels


def query_item(tab, page, idx, p):
    viz = p["viz"]
    content = {
        "version": "KqlItem/1.0",
        "query": strip_render(p["query"]),
        "size": 0 if viz == "table" else 1,
        "title": p["title"],
        "timeContextFromParameter": "TimeRange",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "visualization": viz,
    }
    if viz == "table":
        content["gridSettings"] = {"filter": True, "rowLimit": 1000}
    if viz == "tiles":
        c = tile_columns(p["section"])
        ts = {"titleContent": {"columnMatch": c["Title"], "formatter": 1},
              "leftContent": {"columnMatch": c["Left"], "formatter": 1},
              "showBorder": True}
        if "Bottom" in c:
            ts["subtitleContent"] = {"columnMatch": c["Bottom"], "formatter": 1}
        content["tileSettings"] = ts
    item = {"type": 3, "content": content, "name": f"{tab}-{page}-{idx:02d}"}
    if viz in ("piechart", "barchart", "timechart", "linechart"):
        item["customWidth"] = "50"
    return item


def text_item(md, name):
    return {"type": 1, "content": {"json": md}, "name": name}


def tabs_item(param, links, name, style="tabs"):
    return {
        "type": 11,
        "content": {
            "version": "LinkItem/1.0",
            "style": style,
            "links": [{"id": sid(name, v), "cellValue": param, "linkTarget": "parameter",
                       "linkLabel": label, "subTarget": v, "style": "link"} for v, label in links],
        },
        "name": name,
    }


def group_item(name, items, cond_param, cond_value):
    return {
        "type": 12,
        "content": {"version": "NotebookGroup/1.0", "groupType": "editable", "items": items},
        "conditionalVisibility": {"parameterName": cond_param, "comparison": "isEqualTo", "value": cond_value},
        "name": name,
    }


def parameters_item():
    def text(name, label, desc):
        return {"id": sid("param", name), "version": "KqlParameterItem/1.0", "name": name, "label": label,
                "type": 1, "description": desc, "value": "", "timeContext": {"durationMs": 86400000}}
    durations = [3600000, 14400000, 43200000, 86400000, 259200000, 604800000, 1209600000, 2592000000]
    return {
        "type": 9,
        "content": {
            "version": "KqlParameterItem/1.0",
            "crossComponentResources": [],
            "parameters": [
                {"id": sid("param", "TimeRange"), "version": "KqlParameterItem/1.0", "name": "TimeRange",
                 "label": "Time Range", "type": 4, "isRequired": True, "value": {"durationMs": 604800000},
                 "typeSettings": {"selectableValues": [{"durationMs": d} for d in durations], "allowCustom": True}},
                text("DeviceName", "Hostname", "Device name or part of it. Leave empty for all devices."),
                text("UserName", "User", "UPN or name part. Leave empty for all users (Alert Dashboard)."),
                text("UserPrincipalName", "User UPN", "Full UPN for User Investigation and user hunts."),
                text("Owner", "Analyst", "Incident owner name or email (Incident Dashboard). Leave empty for all."),
            ],
            "style": "pills",
            "queryType": 0,
            "resourceType": "microsoft.operationalinsights/workspaces",
        },
        "name": "parameters",
    }


def build():
    items = [
        text_item("# 📊 Security Operations Workbook\n" + DISCLAIMER, "header"),
        parameters_item(),
        tabs_item("selectedTab", [(t, label) for t, label, _ in TABS], "tabs"),
    ]
    counts = {}
    for tab, tab_label, pages in TABS:
        tab_items = []
        sub_param = f"{tab}View"
        if len(pages) > 1:
            tab_items.append(tabs_item(sub_param, [(p, l) for p, l, _ in pages], f"{tab}-subtabs"))
        for page, page_label, rel in pages:
            panels = parse_panels(ROOT / rel, page_label.split(" ", 1)[1])
            counts[rel] = len(panels)
            page_items = [query_item(tab, page, i, p) for i, p in enumerate(panels, 1)]
            if len(pages) > 1:
                tab_items.append(group_item(f"{tab}-{page}-group", page_items, sub_param, page))
            else:
                tab_items.extend(page_items)
        items.append(group_item(f"{tab}-group", tab_items, "selectedTab", tab))

    # Default the tab parameters so the workbook doesn't open blank.
    for tab, _, pages in TABS:
        if len(pages) > 1:
            items[1]["content"]["parameters"].append({
                "id": sid("param", f"{tab}View"), "version": "KqlParameterItem/1.0", "name": f"{tab}View",
                "type": 1, "value": pages[0][0], "isHiddenWhenLocked": True,
                "timeContext": {"durationMs": 86400000}})
    items[1]["content"]["parameters"].append({
        "id": sid("param", "selectedTab"), "version": "KqlParameterItem/1.0", "name": "selectedTab",
        "type": 1, "value": TABS[0][0], "isHiddenWhenLocked": True, "timeContext": {"durationMs": 86400000}})

    workbook = {
        "version": "Notebook/1.0",
        "items": items,
        "fallbackResourceIds": [],
        "fromTemplateId": "sentinel-UserWorkbook",
        "$schema": "https://github.com/Microsoft/Application-Insights-Workbooks/blob/master/schema/workbook.json",
    }
    (HERE / "SecurityOperationsWorkbook.json").write_text(
        json.dumps(workbook, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    arm = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {
            "workspaceResourceId": {
                "type": "string",
                "metadata": {"description": "Resource ID of the Sentinel Log Analytics workspace, e.g. /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<name>"},
            },
            "workbookDisplayName": {"type": "string", "defaultValue": "Security Operations Workbook"},
            "workbookId": {"type": "string", "defaultValue": "[newGuid()]",
                           "metadata": {"description": "Keep the same GUID to update an existing workbook in place."}},
        },
        "resources": [{
            "type": "microsoft.insights/workbooks",
            "apiVersion": "2022-04-01",
            "name": "[parameters('workbookId')]",
            "location": "[resourceGroup().location]",
            "kind": "shared",
            "properties": {
                "displayName": "[parameters('workbookDisplayName')]",
                "serializedData": json.dumps(workbook, ensure_ascii=False),
                "version": "1.0",
                "sourceId": "[parameters('workspaceResourceId')]",
                "category": "sentinel",
            },
        }],
        "outputs": {"workbookId": {"type": "string", "value": "[resourceId('microsoft.insights/workbooks', parameters('workbookId'))]"}},
    }
    (HERE / "azuredeploy.json").write_text(json.dumps(arm, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return counts


if __name__ == "__main__":
    for rel, n in build().items():
        print(f"{n:3d} panels  {rel}")
