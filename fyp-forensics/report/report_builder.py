#!/usr/bin/env python3
"""
report_builder.py  -  ForensicX Report Builder  (v4.0)
=======================================================
Generates professional, human-readable forensic reports.

KEY CHANGES from previous versions:
  - PDF is a structured report, NOT a raw data dump
  - Sysmon Event IDs translated to plain English
  - Only high/critical risk processes shown in detail
  - Executive summary + verdict on page 1
  - Cover page, table of contents, glossary
  - Max ~25-35 pages regardless of data size
  - forensic_report.json auto-generated (NEVER overwrites correlation.json)
  - Risk data auto-loaded from disk if not passed as arguments
    so orchestrator call build_all_reports(data) still works unchanged
"""

import os
import json
import re
import textwrap
import logging
from datetime import datetime

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, PageBreak,
    Table, TableStyle, HRFlowable, KeepTogether
)

LOG = logging.getLogger("report_builder")
LOG.setLevel(logging.INFO)

# ── Colour palette ─────────────────────────────────────────────────────────
C_NAVY    = colors.HexColor("#1a2744")
C_BLUE    = colors.HexColor("#1f4e79")
C_MID     = colors.HexColor("#2e75b6")
C_RED     = colors.HexColor("#c00000")
C_ORANGE  = colors.HexColor("#ed7d31")
C_AMBER   = colors.HexColor("#ffc000")
C_DKGREEN = colors.HexColor("#375623")
C_GREEN   = colors.HexColor("#70ad47")
C_GREY    = colors.HexColor("#404040")
C_LTGREY  = colors.HexColor("#f2f2f2")
C_MIDGREY = colors.HexColor("#d9d9d9")
C_WHITE   = colors.white

# ── Sysmon EID -> plain English ─────────────────────────────────────────────
SYSMON_EID = {
    "1":   "Program Started",
    "2":   "File Timestamp Modified",
    "3":   "Network Connection Made",
    "4":   "Monitoring Service State Change",
    "5":   "Program Stopped",
    "6":   "Driver Loaded into System",
    "7":   "Library (DLL) Loaded",
    "8":   "Remote Thread Injection (HIGH RISK)",
    "9":   "Raw Disk Read",
    "10":  "Process Memory Access (credential risk)",
    "11":  "File Created",
    "12":  "Registry Key Created or Deleted",
    "13":  "Registry Value Modified",
    "14":  "Registry Key Renamed",
    "15":  "File Stream Created",
    "16":  "Monitoring Config Changed",
    "17":  "Named Pipe Created",
    "22":  "DNS Query (domain lookup)",
    "23":  "File Deleted",
    "25":  "Process Tampering Detected",
    "255": "Monitoring Error",
}

SOURCE_LABEL = {
    "sysmon":   "Windows Activity Log",
    "memory":   "Memory Analysis",
    "snapshot": "File System Snapshot",
    "cloud":    "Cloud Storage",
    "network":  "Network Monitor",
}

SOURCE_DESC = {
    "sysmon":   "Records every program started, file opened, and network connection made",
    "memory":   "Examines what was running in RAM at collection time",
    "snapshot": "Compares disk contents before and after the incident",
    "cloud":    "Tracks files uploaded or downloaded to Google Drive / OneDrive",
    "network":  "Captures connections made to and from this machine",
}

def risk_fg(level):
    l = (level or "").upper()
    if l == "CRITICAL": return C_RED
    if l == "HIGH":     return C_ORANGE
    if l == "MEDIUM":   return C_AMBER
    return C_GREEN

def risk_bg(level):
    l = (level or "").upper()
    if l == "CRITICAL": return colors.HexColor("#fff0f0")
    if l == "HIGH":     return colors.HexColor("#fff4ee")
    if l == "MEDIUM":   return colors.HexColor("#fffbe6")
    return colors.HexColor("#f0fff4")

def fmt_time(ts):
    if not ts or str(ts).strip() in ("", "None", "No time", "N/A", "unknown"):
        return "Unknown"
    try:
        if isinstance(ts, (int, float)):
            ms = ts > 1e10
            return datetime.fromtimestamp(ts / 1000 if ms else ts).strftime("%d %b %Y  %H:%M:%S")
        clean = str(ts).replace("Z","").split("+")[0].strip()
        dt = datetime.fromisoformat(clean)
        return dt.strftime("%d %b %Y  %H:%M:%S")
    except Exception:
        return str(ts)[:19]

def translate_detail(detail, source=""):
    if not detail or str(detail).strip() in ("", "None", "unknown"):
        return "Activity recorded (no detail available)"
    d = str(detail)
    # Translate EID references
    d = re.sub(r"Sysmon EID (\d+)",
               lambda m: SYSMON_EID.get(m.group(1), f"Event {m.group(1)}"), d)
    d = re.sub(r"\bEID[:\s]+(\d+)",
               lambda m: SYSMON_EID.get(m.group(1), f"Event {m.group(1)}"), d)
    # Shorten long Windows paths - keep last 2 path components
    def shorten(m):
        p = m.group(0)
        if len(p) > 70:
            parts = p.replace("\\","/").split("/")
            return ".../" + "/".join(parts[-2:]) if len(parts) > 2 else p
        return p
    d = re.sub(r"[A-Za-z]:\\[^\s|,;\"']{50,}", shorten, d)
    return d.strip()

def _auto_load(path, default=None):
    if path and os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return default

def build_executive_summary(correlated, ep_risk=None, cl_risk=None, cl_corr=None):
    total_proc   = len(correlated)
    total_events = sum(len(v) for v in correlated.values())
    sources = {}
    for evs in correlated.values():
        for e in evs:
            s = e.get("source","unknown")
            sources[s] = sources.get(s,0) + 1

    SUSPECT = ["encrypt","ransom","shadow","vss","wbadmin","bcdedit",
               ".locked",".crypt","mimikatz","procdump","lsass",
               "powershell -e","cmd /c del","wipe","base64"]
    suspect = sum(1 for evs in correlated.values() for e in evs
                  if any(kw in str(e.get("details","")).lower() for kw in SUSPECT))
    ioc_hits = sum(1 for evs in correlated.values() for e in evs if e.get("ioc_hit"))

    ep_level = "UNKNOWN"
    if isinstance(ep_risk, dict):
        ep_level = ep_risk.get("endpoint_risk_level",
                   ep_risk.get("risk_level","UNKNOWN")).upper()

    cl_level = "UNKNOWN"
    if isinstance(cl_risk, dict) and cl_risk:
        lvls = [v.get("risk_level","LOW").upper() for v in cl_risk.values()]
        cl_level = "HIGH" if "HIGH" in lvls else "MEDIUM" if "MEDIUM" in lvls else "LOW"

    chains      = len(cl_corr) if cl_corr else 0
    high_chains = sum(1 for c in (cl_corr or []) if c.get("confidence") == "HIGH")

    for_overall = [ep_level, cl_level]
    if "CRITICAL" in for_overall or ioc_hits > 0: overall = "CRITICAL"
    elif "HIGH" in for_overall or suspect > 10:   overall = "HIGH"
    elif "MEDIUM" in for_overall or suspect > 0:  overall = "MEDIUM"
    elif "LOW" in for_overall:                    overall = "LOW"
    else: overall = "UNDETERMINED"

    return dict(
        total_processes=total_proc, total_events=total_events,
        event_sources=sources, suspicious_events=suspect, ioc_hits=ioc_hits,
        cloud_chains=chains, high_chains=high_chains,
        endpoint_risk=ep_level, cloud_risk=cl_level, overall_risk=overall,
    )


# ─── Style factory ─────────────────────────────────────────────────────────
def _S():
    b = getSampleStyleSheet()
    def ps(name, **kw): return ParagraphStyle(name, parent=b["Normal"], **kw)
    return {
        "title":  ps("TI", fontName="Helvetica-Bold", fontSize=26, leading=32,
                     textColor=C_WHITE, spaceAfter=6),
        "sub":    ps("SU", fontName="Helvetica", fontSize=12, textColor=colors.HexColor("#b8d0f0"),
                     spaceAfter=4),
        "meta":   ps("ME", fontName="Helvetica", fontSize=9,  textColor=colors.HexColor("#7090b8"),
                     spaceAfter=3),
        "h1":     ps("H1", fontName="Helvetica-Bold", fontSize=13, leading=17,
                     textColor=C_BLUE, spaceBefore=12, spaceAfter=5),
        "h2":     ps("H2", fontName="Helvetica-Bold", fontSize=10.5, leading=14,
                     textColor=C_MID, spaceBefore=8, spaceAfter=4),
        "body":   ps("BD", fontName="Helvetica", fontSize=9.5, leading=14,
                     textColor=C_GREY, spaceAfter=5),
        "small":  ps("SM", fontName="Helvetica", fontSize=8, leading=11,
                     textColor=colors.HexColor("#606060"), spaceAfter=3),
        "mono":   ps("MO", fontName="Courier", fontSize=8, leading=11,
                     textColor=C_GREY),
        "caption":ps("CA", fontName="Helvetica-Oblique", fontSize=8,
                     textColor=colors.HexColor("#888888"), spaceAfter=3),
        "verdict_hi": ps("VH", fontName="Helvetica-Bold", fontSize=11,
                         textColor=C_RED, spaceAfter=4),
        "verdict_md": ps("VM", fontName="Helvetica-Bold", fontSize=11,
                         textColor=C_ORANGE, spaceAfter=4),
        "verdict_lo": ps("VL", fontName="Helvetica-Bold", fontSize=11,
                         textColor=C_DKGREEN, spaceAfter=4),
    }


def _tbl(header_color=C_BLUE, alt=True, fontsize=8.5):
    cmds = [
        ("BACKGROUND",    (0,0),(-1,0),  header_color),
        ("TEXTCOLOR",     (0,0),(-1,0),  C_WHITE),
        ("FONTNAME",      (0,0),(-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0,0),(-1,-1), fontsize),
        ("TOPPADDING",    (0,0),(-1,-1), 5),
        ("BOTTOMPADDING", (0,0),(-1,-1), 5),
        ("LEFTPADDING",   (0,0),(-1,-1), 7),
        ("RIGHTPADDING",  (0,0),(-1,-1), 7),
        ("GRID",          (0,0),(-1,-1), 0.4, C_MIDGREY),
        ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
    ]
    if alt:
        cmds.append(("ROWBACKGROUNDS",(0,1),(-1,-1),[C_WHITE,C_LTGREY]))
    return TableStyle(cmds)


# ─── PDF ───────────────────────────────────────────────────────────────────
def build_pdf_report(correlated, out_path, endpoint_risk=None,
                     cloud_risk=None, cloud_corr=None):
    """
    Structured, human-readable PDF report.
    Risk data auto-loaded from disk if not passed.
    """
    rd = os.path.dirname(out_path)
    if endpoint_risk is None:
        endpoint_risk = _auto_load(os.path.join(rd,"endpoint_risk_summary.json"))
    if cloud_risk is None:
        cloud_risk = _auto_load(os.path.join(rd,"cloud_risk_summary.json"))
    if cloud_corr is None:
        cloud_corr = _auto_load(os.path.join(rd,"cloud_endpoint_correlations.json"), [])

    sm   = build_executive_summary(correlated, endpoint_risk, cloud_risk, cloud_corr)
    now  = datetime.now().strftime("%d %B %Y at %H:%M")
    S    = _S()
    E    = []
    risk = sm["overall_risk"]
    ep   = endpoint_risk or {}

    total_p   = ep.get("total_processes",        sm["total_processes"])
    crit_ct   = ep.get("critical_risk_processes", 0)
    high_ct   = ep.get("high_risk_processes",    0)
    med_ct    = ep.get("medium_risk_processes",  0)
    low_ct    = ep.get("low_risk_processes",     0)
    max_sc    = ep.get("max_risk_score",         0)
    reasons   = ep.get("decision_reason",        [])
    proc_dets = ep.get("process_details",        {})

    def hr(c=C_MID, t=0.8): E.append(HRFlowable(width="100%",thickness=t,color=c,spaceAfter=7,spaceBefore=3))
    def sec(title):
        E.append(Spacer(1,6)); hr(); E.append(Paragraph(title, S["h1"]))
    def body(t):  E.append(Paragraph(t, S["body"]))
    def small(t): E.append(Paragraph(t, S["small"]))

    VERDICTS = {
        "CRITICAL": "Severe malicious activity confirmed — immediate containment required.",
        "HIGH":     "Significant threat detected — investigation strongly recommended.",
        "MEDIUM":   "Suspicious activity found — manual review recommended.",
        "LOW":      "No significant threats detected during the analysis window.",
        "UNDETERMINED": "Risk level could not be fully determined from available data.",
    }
    ACTIONS = {
        "CRITICAL": [
            ("IMMEDIATELY","Disconnect this computer from the internet and any shared drives"),
            ("IMMEDIATELY","Do NOT restart or shut down — this preserves forensic evidence"),
            ("URGENT",     "Contact your IT security team or a cyber forensic specialist"),
            ("URGENT",     "Check all other computers on the same network"),
            ("CAUTION",    "Do not pay any ransom without consulting a professional"),
        ],
        "HIGH": [
            ("URGENT",    "Review the high-risk processes listed in Section 7"),
            ("URGENT",    "Run a full malware scan using an offline or bootable scanner"),
            ("FOLLOW UP", "Check for any new user accounts or changed passwords"),
            ("FOLLOW UP", "Inspect cloud storage for large or unexpected file uploads"),
        ],
        "MEDIUM": [
            ("REVIEW",  "Verify the flagged processes against your known installed software"),
            ("CHECK",   "Run a targeted antivirus and spyware scan"),
            ("MONITOR", "Re-run this analysis in 24 hours to confirm the situation"),
        ],
        "LOW": [
            ("ROUTINE","Continue standard monitoring and patch management"),
            ("ROUTINE","Confirm all backups are recent and tested"),
        ],
    }

    # ── COVER PAGE ───────────────────────────────────────────────────────────
    cover_bg = Table([[""]], colWidths=[7*inch], rowHeights=[3*inch])
    cover_bg.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,-1),C_NAVY),
        ("TOPPADDING",(0,0),(-1,-1),0),("BOTTOMPADDING",(0,0),(-1,-1),0),
        ("LEFTPADDING",(0,0),(-1,-1),0),("RIGHTPADDING",(0,0),(-1,-1),0),
    ]))
    E.append(cover_bg)
    E.append(Spacer(1,-3*inch))

    ct = Table([
        [Paragraph("FORENSIC ANALYSIS REPORT", S["title"])],
        [Paragraph("Digital Incident Investigation Summary", S["sub"])],
        [Spacer(1,12)],
        [Paragraph(f"Generated: {now}", S["meta"])],
        [Paragraph(f"Processes Analysed: {total_p:,}  \u00b7  Total Events: {sm['total_events']:,}", S["meta"])],
    ], colWidths=[7*inch])
    ct.setStyle(TableStyle([
        ("LEFTPADDING",(0,0),(-1,-1),28),("TOPPADDING",(0,0),(-1,-1),22),
        ("BOTTOMPADDING",(0,0),(-1,-1),4),("BACKGROUND",(0,0),(-1,-1),colors.transparent),
    ]))
    E.append(ct)
    E.append(Spacer(1,0.3*inch))

    badge = Table([[f"Overall Risk: {risk}"]], colWidths=[2.6*inch])
    badge.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,-1),risk_fg(risk)),
        ("TEXTCOLOR", (0,0),(-1,-1),C_WHITE),
        ("FONTNAME",  (0,0),(-1,-1),"Helvetica-Bold"),
        ("FONTSIZE",  (0,0),(-1,-1),13),
        ("ALIGN",     (0,0),(-1,-1),"CENTER"),
        ("TOPPADDING",(0,0),(-1,-1),9),("BOTTOMPADDING",(0,0),(-1,-1),9),
        ("LEFTPADDING",(0,0),(-1,-1),14),("RIGHTPADDING",(0,0),(-1,-1),14),
    ]))
    E.append(badge)
    E.append(Spacer(1,0.2*inch))

    vstyle = S["verdict_hi"] if risk in ("CRITICAL","HIGH") else \
             S["verdict_md"] if risk == "MEDIUM" else S["verdict_lo"]
    E.append(Paragraph(VERDICTS.get(risk,""), vstyle))
    hr(C_MIDGREY, 0.5)
    small(
        "This report was produced automatically by ForensicX. All findings should be "
        "reviewed by a qualified security professional before any action is taken. "
        "This document is confidential."
    )
    E.append(PageBreak())

    # ── SECTION 1: EXECUTIVE SUMMARY ─────────────────────────────────────────
    sec("1.  Executive Summary")
    body(
        "ForensicX analysed digital activity recorded on a computer system to identify "
        "signs of malware, ransomware, or unauthorised access. The table below "
        "summarises the key findings."
    )
    E.append(Spacer(1,5))

    ICON = {"CRITICAL":"[!!!]","HIGH":"[!!]","MEDIUM":"[!]","LOW":"[OK]","UNKNOWN":"[?]","UNDETERMINED":"[?]"}
    sum_data = [
        ["Item", "Finding", "Meaning"],
        ["Overall Threat Level",       risk,
         "Immediate action needed" if risk in ("CRITICAL","HIGH")
         else "Review recommended" if risk == "MEDIUM" else "Routine monitoring"],
        ["Processes Analysed",         f"{total_p:,}",             "-"],
        ["Total Recorded Events",      f"{sm['total_events']:,}",  "-"],
        ["Critical-Risk Processes",    str(crit_ct), "[!!!] Immediate attention" if crit_ct else "[OK]"],
        ["High-Risk Processes",        str(high_ct), "[!!] Urgent review"        if high_ct else "[OK]"],
        ["Medium-Risk Processes",      str(med_ct),  "[!] Should be reviewed"    if med_ct  else "[OK]"],
        ["Low-Risk Processes",         str(low_ct),  "[OK] Normal activity"                         ],
        ["Known Threat Indicators",    str(sm["ioc_hits"]),
         "[!!!] Matched known malware" if sm["ioc_hits"] else "[OK] No matches"],
        ["Cloud Attack Links",         str(sm["cloud_chains"]),
         f"[!!] {sm['high_chains']} HIGH confidence" if sm["high_chains"] else str(sm["cloud_chains"])],
        ["Endpoint Risk",              sm["endpoint_risk"], "-"],
        ["Cloud Risk",                 sm["cloud_risk"],    "-"],
        ["Highest Process Score",      str(max_sc),         "-"],
    ]
    cmds = list(_tbl(C_BLUE)._cmds)
    RISK_ROWS = {"CRITICAL": colors.HexColor("#fff0f0"),
                 "HIGH":     colors.HexColor("#fff4ee"),
                 "MEDIUM":   colors.HexColor("#fffbe6")}
    for i, row in enumerate(sum_data[1:], 1):
        clr = RISK_ROWS.get(str(row[1]).upper()) or RISK_ROWS.get(
              next((k for k in RISK_ROWS if k in str(row[2]).upper()), ""), None)
        if clr: cmds.append(("BACKGROUND",(0,i),(-1,i),clr))
    t = Table(sum_data, colWidths=[2.4*inch, 1.7*inch, 3.0*inch])
    t.setStyle(TableStyle(cmds))
    E.append(t)
    E.append(PageBreak())

    # ── SECTION 2: WHAT THIS REPORT CONTAINS ─────────────────────────────────
    sec("2.  What This Report Contains")
    body(
        "This report was produced by ForensicX, an automated digital forensic tool. "
        "It analyses activity recorded by Windows security monitoring software (Sysmon), "
        "memory analysis tools, filesystem snapshots, and cloud storage logs. "
    )
    body(
        "The report focuses on the most important findings. Routine system processes "
        "are summarised rather than listed in full. The complete raw dataset is "
        "available in the accompanying JSON files for technical review."
    )
    E.append(Spacer(1,5))

    # ── SECTION 3: KEY FINDINGS AT A GLANCE ──────────────────────────────────
    sec("3.  Key Findings at a Glance")
    bar_total = max(total_p,1)
    bd = [
        ["Risk Level", "Count", "% of Total", "What it means"],
        ["CRITICAL", str(crit_ct), f"{crit_ct/bar_total*100:.1f}%",
         "Active threat — behaved like known malware"],
        ["HIGH",     str(high_ct), f"{high_ct/bar_total*100:.1f}%",
         "Highly suspicious — needs immediate investigation"],
        ["MEDIUM",   str(med_ct),  f"{med_ct/bar_total*100:.1f}%",
         "Unusual behaviour — should be reviewed"],
        ["LOW",      str(low_ct),  f"{low_ct/bar_total*100:.1f}%",
         "Normal or expected system activity"],
    ]
    bd_cmds = list(_tbl(C_NAVY)._cmds)
    ROW_BKGD = [colors.HexColor("#fff0f0"),colors.HexColor("#fff4ee"),
                colors.HexColor("#fffbe6"),colors.HexColor("#f0fff4")]
    for i,clr in enumerate(ROW_BKGD,1):
        bd_cmds += [("BACKGROUND",(0,i),(-1,i),clr),
                    ("TEXTCOLOR",(0,i),(0,i),risk_fg(bd[i][0])),
                    ("FONTNAME",(0,i),(0,i),"Helvetica-Bold")]
    t2 = Table(bd, colWidths=[1.1*inch, 0.7*inch, 1.0*inch, 4.3*inch])
    t2.setStyle(TableStyle(bd_cmds))
    E.append(t2)
    E.append(Spacer(1,10))

    src_data = [["Data Source", "Events Collected", "What it recorded"]]
    for src, cnt in sm["event_sources"].items():
        src_data.append([
            SOURCE_LABEL.get(src.lower(), src.upper()),
            f"{cnt:,}",
            SOURCE_DESC.get(src.lower(), "Activity records"),
        ])
    E.append(Table(src_data, colWidths=[1.7*inch,1.2*inch,4.2*inch],
                   style=_tbl(C_BLUE)))
    E.append(PageBreak())

    # ── SECTION 4: WHY THIS RISK LEVEL ───────────────────────────────────────
    sec("4.  Why This Risk Level Was Assigned")
    body(
        "The risk level is calculated automatically from the behaviour of every "
        "process observed. The following specific findings contributed to the verdict:"
    )
    E.append(Spacer(1,5))
    if reasons:
        r_data = [["#","Finding"]] + [[str(i),r] for i,r in enumerate(reasons,1)]
        E.append(Table(r_data, colWidths=[0.4*inch,6.7*inch], style=_tbl(C_BLUE)))
    else:
        body("No specific reasons were recorded.")

    # ── SECTION 5: RECOMMENDED ACTIONS ───────────────────────────────────────
    sec("5.  Recommended Actions")
    act_list = ACTIONS.get(risk, ACTIONS["LOW"])
    a_data   = [["Priority","Action"]] + list(act_list)
    a_cmds   = list(_tbl(C_BLUE)._cmds)
    PRI_CLR  = {"IMMEDIATELY":colors.HexColor("#fff0f0"),
                "URGENT":     colors.HexColor("#fff4ee"),
                "CAUTION":    colors.HexColor("#fffbe6")}
    for i,(p,_) in enumerate(act_list,1):
        if p in PRI_CLR: a_cmds.append(("BACKGROUND",(0,i),(-1,i),PRI_CLR[p]))
    E.append(Table(a_data, colWidths=[1.2*inch,5.9*inch], style=TableStyle(a_cmds)))
    E.append(PageBreak())

    # ── SECTION 6: DATA SOURCES ───────────────────────────────────────────────
    sec("6.  Data Sources Used in This Analysis")
    body(
        "Evidence was collected from the following sources. "
        "Each one provides a different view of what happened on the system."
    )
    E.append(Spacer(1,5))
    te = max(sm["total_events"],1)
    s2 = [["Source","Plain-English Description","Events","% of Total"]]
    for src,cnt in sm["event_sources"].items():
        s2.append([SOURCE_LABEL.get(src.lower(),src.upper()),
                   SOURCE_DESC.get(src.lower(),"Activity records"),
                   f"{cnt:,}", f"{cnt/te*100:.1f}%"])
    E.append(Table(s2, colWidths=[1.6*inch,3.5*inch,0.9*inch,0.9*inch], style=_tbl(C_BLUE)))
    E.append(PageBreak())

    # ── SECTION 7: HIGH-RISK PROCESS DETAILS ─────────────────────────────────
    sec("7.  High-Risk Process Details")
    body(
        "A <b>process</b> is a program running on the computer. The following "
        "processes were flagged as HIGH or CRITICAL risk. "
        "Up to 10 notable events are shown per process with plain-language descriptions."
    )
    body(
        "<i>Routine Windows system processes with no suspicious behaviour are "
        "excluded from this section. Full data is in correlation.json.</i>"
    )
    E.append(Spacer(1,6))

    LORDER = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}
    if proc_dets:
        risky = {k:v for k,v in proc_dets.items()
                 if v.get("risk_level","LOW").upper() in ("CRITICAL","HIGH")}
        sorted_r = sorted(risky.items(),
                          key=lambda x:(-float(x[1].get("risk_score",0)),
                                        LORDER.get(x[1].get("risk_level","LOW"),9)))[:20]
    else:
        sorted_r = sorted(correlated.items(), key=lambda x:len(x[1]), reverse=True)[:15]
        sorted_r = [(k,{"risk_level":"UNKNOWN","risk_score":len(v),
                        "events_count":len(v)}) for k,v in sorted_r]

    if not sorted_r:
        body("No high or critical-risk processes were identified.")
    else:
        for n,(key,info) in enumerate(sorted_r,1):
            lvl  = info.get("risk_level","UNKNOWN").upper()
            sc   = float(info.get("risk_score",0))
            ev_c = info.get("events_count", len(correlated.get(key,[])))

            hdr = Table([[
                Paragraph(f"Process {n}: {key}",
                          ParagraphStyle("ph",parent=S["h2"],textColor=C_WHITE,
                                         fontName="Helvetica-Bold")),
                Paragraph(f"Risk: {lvl}  |  Score: {sc:.0f}  |  Events: {ev_c:,}",
                          ParagraphStyle("phs",parent=S["small"],textColor=C_WHITE)),
            ]], colWidths=[4.5*inch,2.6*inch])
            hdr.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,-1),risk_fg(lvl)),
                ("LEFTPADDING",(0,0),(-1,-1),9),("RIGHTPADDING",(0,0),(-1,-1),9),
                ("TOPPADDING",(0,0),(-1,-1),6),("BOTTOMPADDING",(0,0),(-1,-1),6),
                ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
            ]))

            evs = correlated.get(key,[])
            rows = [["Time","Source","What Happened"]]
            shown = 0
            for e in evs:
                if shown >= 10: break
                det = translate_detail(str(e.get("details","")), e.get("source",""))
                if det == "Activity recorded (no detail available)" and shown >= 3:
                    continue
                rows.append([fmt_time(e.get("time")),
                              SOURCE_LABEL.get(e.get("source","").lower(),"Unknown"),
                              det[:180]])
                shown += 1
            if len(evs) > 10:
                rows.append(["","",
                    f"... and {len(evs)-10} more events (see correlation.json for full data)"])

            ev_cmds = list(_tbl(colors.HexColor("#444444"))._cmds)
            ev_cmds.append(("BACKGROUND",(0,1),(-1,-1),risk_bg(lvl)))
            ev_cmds.append(("FONTSIZE",(0,1),(-1,-1),8))
            evt = Table(rows, colWidths=[1.4*inch,1.5*inch,4.2*inch],
                        style=TableStyle(ev_cmds))

            E.append(KeepTogether([hdr, evt, Spacer(1,10)]))

        small(f"Showing {len(sorted_r)} of {crit_ct+high_ct} high/critical-risk processes.")

    E.append(PageBreak())

    # ── SECTION 8: CLOUD ACTIVITY ─────────────────────────────────────────────
    sec("8.  Cloud Activity Summary")
    if cloud_risk and isinstance(cloud_risk, dict):
        body(
            "The following cloud storage accounts were analysed. "
            "HIGH risk means an unusually large number of files were accessed or "
            "uploaded in a short period — a common indicator of data theft."
        )
        E.append(Spacer(1,5))
        cl_data = [["Account","Risk","Events","Max Burst","Key Finding"]]
        for _,info in sorted(cloud_risk.items(),
                              key=lambda x:LORDER.get(x[1].get("risk_level","LOW"),9)):
            lvl = info.get("risk_level","LOW").upper()
            rsn = "; ".join(info.get("risk_reasons",[])[:2]) or "No significant risk indicators"
            cl_data.append([
                f"{info.get('provider','?').upper()} - {info.get('owner','?')}",
                lvl, str(info.get("total_events",0)), str(info.get("max_burst",0)),
                rsn[:90],
            ])
        cl_cmds = list(_tbl(C_BLUE)._cmds)
        for i,row in enumerate(cl_data[1:],1):
            cl_cmds.append(("BACKGROUND",(0,i),(-1,i),risk_bg(row[1])))
        E.append(Table(cl_data, colWidths=[2.0*inch,0.7*inch,0.7*inch,0.7*inch,3.0*inch],
                       style=TableStyle(cl_cmds)))
    else:
        body("No cloud activity data was available for this analysis.")

    if cloud_corr:
        E.append(Spacer(1,10))
        E.append(Paragraph("Cloud-to-Endpoint Attack Chains", S["h2"]))
        body(
            "An 'attack chain' occurs when a file downloaded from cloud storage is "
            "immediately opened by a suspicious local process — a strong indicator "
            "of phishing or malware delivery."
        )
        E.append(Spacer(1,5))
        ch_data = [["Confidence","Provider","File","Local Process","Gap"]]
        for lnk in cloud_corr[:15]:
            ch_data.append([
                lnk.get("confidence","?"),
                lnk.get("cloud_provider","?").upper(),
                str(lnk.get("file_name","?"))[-38:],
                str(lnk.get("endpoint_process","?"))[-32:],
                f"{lnk.get('timestamp_diff_seconds','?')}s",
            ])
        ch_cmds = list(_tbl(C_BLUE)._cmds)
        for i,row in enumerate(ch_data[1:],1):
            ch_cmds.append(("BACKGROUND",(0,i),(-1,i),risk_bg(row[0])))
        E.append(Table(ch_data, colWidths=[0.9*inch,1.1*inch,2.3*inch,2.0*inch,0.8*inch],
                       style=TableStyle(ch_cmds)))
        if len(cloud_corr) > 15:
            small(f"Showing 15 of {len(cloud_corr)} chains. See cloud_endpoint_correlations.json for all.")

    E.append(PageBreak())

    # ── SECTION 9: GLOSSARY ───────────────────────────────────────────────────
    sec("9.  Glossary — Plain-English Definitions")
    body("This section explains the technical terms used in this report.")
    E.append(Spacer(1,5))
    glossary = [
        ["Term","Explanation"],
        ["Process",               "A program running on the computer (e.g. chrome.exe, powershell.exe)"],
        ["Risk Score",            "A number from the process behaviour analysis. Higher = more suspicious."],
        ["Sysmon",                "A Microsoft tool that records detailed activity on Windows computers."],
        ["IOC",                   "Indicator of Compromise: a known fingerprint of a malicious file or server."],
        ["Entropy",               "How random file data is. Very high entropy (>7.5) suggests encryption."],
        ["Snapshot",              "A record of all files at a moment in time, used to detect changes."],
        ["Cloud Burst",           "An unusually high number of cloud file operations in a short window."],
        ["Attack Chain",          "A cloud download followed immediately by suspicious local execution."],
        ["CRITICAL / HIGH",       "Requires immediate attention — strong evidence of malicious activity."],
        ["MEDIUM",                "Suspicious but not conclusive — manual review recommended."],
        ["LOW",                   "Expected normal behaviour — no immediate action needed."],
        ["Program Started (EID1)","A new program or process was launched on the computer."],
        ["Network Connection Made","The program connected to a remote server or IP address."],
        ["File Created",          "A new file was written to the disk by this process."],
        ["Registry Modified",     "Windows settings (registry) were changed by this process."],
        ["Remote Thread Injection","One process injected code into another — a high-risk attack technique."],
    ]
    E.append(Table(glossary, colWidths=[2.0*inch,5.1*inch], style=_tbl(C_NAVY)))

    E.append(Spacer(1,14))
    hr(C_MIDGREY,0.5)
    small(
        f"Report generated by ForensicX  \u00b7  {now}  \u00b7  "
        "Automated analysis — review by a qualified security professional is recommended "
        "before any legal or disciplinary action is taken."
    )

    # ── BUILD PDF ─────────────────────────────────────────────────────────────
    doc = SimpleDocTemplate(
        out_path, pagesize=letter,
        rightMargin=0.72*inch, leftMargin=0.72*inch,
        topMargin=0.6*inch,   bottomMargin=0.6*inch,
        title="ForensicX Forensic Analysis Report",
        author="ForensicX", subject=f"Endpoint Risk: {risk}",
    )
    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#aaaaaa"))
        canvas.drawRightString(
            doc.pagesize[0]-0.5*inch, 0.3*inch,
            f"ForensicX Forensic Analysis Report  \u00b7  Page {doc.page}  \u00b7  {now}"
        )
        canvas.restoreState()

    doc.build(E, onFirstPage=footer, onLaterPages=footer)
    LOG.info("PDF report written: %s", out_path)


# ─── TXT ───────────────────────────────────────────────────────────────────
def build_txt_report(correlated, out_path, endpoint_risk=None,
                     cloud_risk=None, cloud_corr=None):
    rd = os.path.dirname(out_path)
    if endpoint_risk is None: endpoint_risk = _auto_load(os.path.join(rd,"endpoint_risk_summary.json"))
    if cloud_risk    is None: cloud_risk    = _auto_load(os.path.join(rd,"cloud_risk_summary.json"))
    if cloud_corr    is None: cloud_corr    = _auto_load(os.path.join(rd,"cloud_endpoint_correlations.json"),[])

    sm   = build_executive_summary(correlated, endpoint_risk, cloud_risk, cloud_corr)
    now  = datetime.now().strftime("%d %B %Y at %H:%M:%S")
    risk = sm["overall_risk"]
    ep   = endpoint_risk or {}

    VERDICTS_TXT = {
        "CRITICAL": "IMMEDIATE ACTION REQUIRED - Strong evidence of active malware or ransomware.",
        "HIGH":     "URGENT REVIEW NEEDED - Significant suspicious activity detected.",
        "MEDIUM":   "REVIEW RECOMMENDED - Some unusual behaviour requires investigation.",
        "LOW":      "NO SIGNIFICANT THREATS - System activity appears normal.",
    }

    with open(out_path,"w",encoding="utf-8") as f:
        W=lambda s="":f.write(s+"\n")
        L=lambda c="=":W(c*80)

        L();W("  FORENSICX FORENSIC ANALYSIS REPORT");W(f"  Generated: {now}");L()
        W(f"  OVERALL RISK: {risk}")
        W(f"  {VERDICTS_TXT.get(risk,'')}")
        W();L();W()

        W("SECTION 1 - EXECUTIVE SUMMARY");L("-")
        W(f"  Processes Analysed   : {sm['total_processes']:,}")
        W(f"  Total Events         : {sm['total_events']:,}")
        W(f"  Overall Risk Level   : {risk}")
        W(f"  Endpoint Risk        : {sm['endpoint_risk']}")
        W(f"  Cloud Risk           : {sm['cloud_risk']}")
        W(f"  Known Threat Matches : {sm['ioc_hits']}")
        W(f"  Cloud Attack Links   : {sm['cloud_chains']} ({sm['high_chains']} HIGH confidence)")
        W();L();W()

        W("SECTION 2 - WHY THIS RISK LEVEL WAS ASSIGNED");L("-")
        for i,r in enumerate(ep.get("decision_reason",[]),1):
            W(f"  {i}. {r}")
        W();L();W()

        W("SECTION 3 - HIGH-RISK PROCESSES");L("-")
        proc_d = ep.get("process_details",{})
        LORDER={"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}
        if proc_d:
            risky = {k:v for k,v in proc_d.items()
                     if v.get("risk_level","LOW").upper() in ("CRITICAL","HIGH")}
            sorted_r = sorted(risky.items(),
                              key=lambda x:(-float(x[1].get("risk_score",0)),
                                            LORDER.get(x[1].get("risk_level","LOW"),9)))[:20]
        else: sorted_r=[]

        for key,info in sorted_r:
            lvl=info.get("risk_level","?").upper()
            sc =float(info.get("risk_score",0))
            W(f"\n  [{lvl}] {key}  (score: {sc:.0f})")
            W("  "+"-"*60)
            for e in correlated.get(key,[])[:8]:
                t=fmt_time(e.get("time"))
                d=translate_detail(str(e.get("details","")),e.get("source",""))
                W(textwrap.fill(f"  > {t}: {d}",width=78,subsequent_indent="      "))
        W();L();W()

        W("SECTION 4 - CLOUD ACTIVITY");L("-")
        if cloud_risk:
            for _,v in cloud_risk.items():
                lvl=v.get("risk_level","LOW").upper()
                W(f"  [{lvl}] {v.get('provider','?').upper()} - {v.get('owner','?')}")
                W(f"  Events: {v.get('total_events',0)}  |  Max burst: {v.get('max_burst',0)}")
                for r in v.get("risk_reasons",[]): W(f"    - {r}")
                W()
        else: W("  No cloud data available.")
        W();L()
        W(f"\nEND OF REPORT  -  ForensicX  -  {now}"); L()

    LOG.info("TXT report written: %s", out_path)


# ─── JSON ──────────────────────────────────────────────────────────────────
def build_json_report(correlated, out_path, endpoint_risk=None,
                      cloud_risk=None, cloud_corr=None):
    """
    CRITICAL: writes to forensic_report.json - NEVER correlation.json.
    """
    rd = os.path.dirname(out_path)
    if endpoint_risk is None: endpoint_risk = _auto_load(os.path.join(rd,"endpoint_risk_summary.json"))
    if cloud_risk    is None: cloud_risk    = _auto_load(os.path.join(rd,"cloud_risk_summary.json"))
    if cloud_corr    is None: cloud_corr    = _auto_load(os.path.join(rd,"cloud_endpoint_correlations.json"),[])

    sm = build_executive_summary(correlated, endpoint_risk, cloud_risk, cloud_corr)
    report = {
        "metadata":            {"generated_at":datetime.now().isoformat(),"version":"4.0","tool":"ForensicX"},
        "executive_summary":   sm,
        "endpoint_risk":       endpoint_risk,
        "cloud_risk":          cloud_risk,
        "cloud_attack_chains": cloud_corr or [],
        "statistics": {
            "total_processes": len(correlated),
            "total_events":    sum(len(v) for v in correlated.values()),
            "most_active":     max(correlated.items(),key=lambda x:len(x[1]))[0] if correlated else None,
        },
        "process_timeline": correlated,
    }
    with open(out_path,"w",encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    LOG.info("JSON report written: %s", out_path)


# ─── BUILD ALL ──────────────────────────────────────────────────────────────
def build_all_reports(correlated, out_dir="report",
                      endpoint_risk=None, cloud_risk=None, cloud_corr=None):
    """
    Orchestrator calls this as: build_all_reports(correlation_result)
    Risk data is auto-loaded from disk inside each builder.
    """
    os.makedirs(out_dir, exist_ok=True)
    txt  = os.path.join(out_dir,"correlation.txt")
    pdf  = os.path.join(out_dir,"correlation.pdf")
    jsn  = os.path.join(out_dir,"forensic_report.json")   # NEVER correlation.json

    build_txt_report( correlated, txt,  endpoint_risk, cloud_risk, cloud_corr)
    build_pdf_report( correlated, pdf,  endpoint_risk, cloud_risk, cloud_corr)
    build_json_report(correlated, jsn,  endpoint_risk, cloud_risk, cloud_corr)

    return {"txt": txt, "pdf": pdf, "json": jsn}


# ─── Test ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    sample = {
        "powershell.exe|1234": [
            {"source":"sysmon","time":"2026-02-10T10:30:00",
             "details":"Process created: powershell.exe -enc ZABsAA...","tag":"PROCESS-CREATE"},
            {"source":"memory","time":"2026-02-10T10:30:05",
             "details":"Suspicious memory injection detected","tag":"MEMORY-INJECT"},
        ],
        "vssadmin.exe|5678": [
            {"source":"sysmon","time":"2026-02-10T10:32:00",
             "details":"vssadmin.exe delete shadows /all /quiet","tag":"PROCESS-CREATE"},
        ],
    }
    ep = {"endpoint_risk_level":"CRITICAL","total_processes":2,
          "critical_risk_processes":1,"high_risk_processes":1,
          "medium_risk_processes":0,"low_risk_processes":0,"max_risk_score":330,
          "decision_reason":["Critical ransomware behaviour detected"],
          "process_details":{
              "powershell.exe|1234":{"risk_level":"CRITICAL","risk_score":330,"events_count":2},
              "vssadmin.exe|5678":  {"risk_level":"HIGH",    "risk_score":180,"events_count":1},
          }}
    paths = build_all_reports(sample,"test_reports",endpoint_risk=ep)
    for k,p in paths.items(): print(f"  {k}: {p}")