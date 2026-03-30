"""
Endpoint Risk Summary — Dashboard Page
Fixed: HTML was rendering as raw source in newer Streamlit versions.
Complex HTML blocks now use st.components.v1.html() which always renders correctly.
"""
import sys
import os
import json
import streamlit as st
import streamlit.components.v1 as components
import pandas as pd

# ── Path fix ─────────────────────────────────────────────────────────────────
_PAGE_DIR = os.path.dirname(os.path.abspath(__file__))
_DASH_DIR = os.path.abspath(os.path.join(_PAGE_DIR, ".."))
ROOT_DIR  = os.path.abspath(os.path.join(_PAGE_DIR, "../.."))
if _DASH_DIR not in sys.path:
    sys.path.insert(0, _DASH_DIR)

DATA_FILE = os.path.join(ROOT_DIR, "report", "endpoint_risk_summary.json")

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Endpoint Risk Summary",
    page_icon="🛡️",
    layout="wide"
)

# ── Page background ───────────────────────────────────────────────────────────
st.markdown("""
<style>
html, body,
[data-testid="stAppViewContainer"],
[data-testid="stMain"],
section[data-testid="stMain"] > div { background-color: #0a0e1a !important; }
[data-testid="stSidebar"] { background-color: #0d1220 !important; border-right:1px solid #1e2840; }
footer { display: none; }
</style>
""", unsafe_allow_html=True)

# ── Load ──────────────────────────────────────────────────────────────────────
def load_summary():
    if not os.path.exists(DATA_FILE):
        return None
    try:
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return None

summary = load_summary()

if not summary:
    st.warning("No endpoint risk summary found.")
    st.info(f"Run the forensic pipeline to generate results.\nExpected: `{DATA_FILE}`")
    st.stop()

# ── Data ──────────────────────────────────────────────────────────────────────
risk        = summary.get("endpoint_risk_level", "UNKNOWN").upper()
total       = summary.get("total_processes",         0)
critical_ct = summary.get("critical_risk_processes", 0)
high_ct     = summary.get("high_risk_processes",     0)
medium_ct   = summary.get("medium_risk_processes",   0)
low_ct      = summary.get("low_risk_processes",      0)
max_score   = summary.get("max_risk_score",          0)
reasons     = summary.get("decision_reason",         [])
generated   = str(summary.get("generated_at", ""))[:19].replace("T", "  ")
proc_details= summary.get("process_details",         {})

RISK_CFG = {
    "CRITICAL": {"hex": "#ff2d55", "glow": "rgba(255,45,85,0.35)",  "icon": "&#9760;", "gauge": 95, "action": "RESPOND NOW"},
    "HIGH":     {"hex": "#ff6b35", "glow": "rgba(255,107,53,0.35)", "icon": "!",        "gauge": 72, "action": "INVESTIGATE"},
    "MEDIUM":   {"hex": "#ffc300", "glow": "rgba(255,195,0,0.30)",  "icon": "~",        "gauge": 45, "action": "REVIEW"},
    "LOW":      {"hex": "#00d48a", "glow": "rgba(0,212,138,0.30)",  "icon": "&#10003;", "gauge": 15, "action": "MONITOR"},
    "UNKNOWN":  {"hex": "#8e9aaf", "glow": "rgba(142,154,175,0.2)","icon": "?",         "gauge": 0,  "action": "RERUN PIPELINE"},
}
cfg    = RISK_CFG.get(risk, RISK_CFG["UNKNOWN"])
C      = cfg["hex"]
GLOW   = cfg["glow"]
GAUGE  = cfg["gauge"]
ACTION = cfg["action"]
ICON   = cfg["icon"]

VERDICTS = {
    "CRITICAL": "Severe malicious activity confirmed. Critical-level processes consistent with active ransomware, data destruction, or full system compromise were detected.",
    "HIGH":     "Significant threats detected. Multiple high-risk processes exhibited behaviour associated with malware, credential harvesting, or unauthorised data access.",
    "MEDIUM":   "Suspicious activity detected. Some processes showed unusual behaviour that warrants manual review — could be legitimate software triggering heuristics.",
    "LOW":      "No significant threats detected. Endpoint activity falls within expected norms. No indicators of compromise were identified at this threshold.",
    "UNKNOWN":  "Risk level could not be determined. The pipeline may not have completed successfully or no processes were analysed.",
}
ACTIONS = {
    "CRITICAL": ["Isolate this machine from the network immediately",
                 "Do NOT restart — preserve machine state for forensics",
                 "Engage incident response team or forensic specialist",
                 "Audit all accounts that touched this machine",
                 "Do not pay any ransom without consulting a professional"],
    "HIGH":     ["Review flagged processes in the Process Explorer page",
                 "Run a full malware scan using an offline scanner",
                 "Check for unauthorised accounts or privilege escalation",
                 "Inspect cloud storage activity for data exfiltration"],
    "MEDIUM":   ["Review flagged processes to confirm if they are expected",
                 "Check recently installed software and scheduled tasks",
                 "Run a targeted malware scan",
                 "Monitor machine for further suspicious activity"],
    "LOW":      ["Continue routine monitoring and patching",
                 "Ensure backups are current and tested",
                 "Re-run pipeline after the next analysis window"],
    "UNKNOWN":  ["Re-run the forensic pipeline and check for errors"],
}

verdict_text = VERDICTS.get(risk, VERDICTS["UNKNOWN"])
actions_list = ACTIONS.get(risk,  ACTIONS["UNKNOWN"])

FONTS = "https://fonts.googleapis.com/css2?family=Rajdhani:wght@400;600;700&family=IBM+Plex+Mono:wght@400;600&family=Inter:wght@400;500;600&display=swap"

# ═══════════════════════════════════════════════════════════════════════════
# 1 — HERO BANNER
# ═══════════════════════════════════════════════════════════════════════════
hero_html = f"""<!DOCTYPE html><html><head>
<link href="{FONTS}" rel="stylesheet">
<style>
*{{margin:0;padding:0;box-sizing:border-box;}}
body{{background:transparent;font-family:'Inter',sans-serif;}}
.hero{{
  background:linear-gradient(135deg,#0d1525 0%,#111827 60%,#0a0f1e 100%);
  border:1px solid {C}44;border-radius:16px;padding:2rem 2.4rem;
  position:relative;overflow:hidden;
  box-shadow:0 0 60px {GLOW};
}}
.hero::before{{
  content:'';position:absolute;inset:0;
  background:radial-gradient(ellipse at 25% 50%,{C}10 0%,transparent 60%);
  pointer-events:none;
}}
.grid{{display:grid;grid-template-columns:160px 1fr 200px;gap:2rem;align-items:center;}}
.badge{{
  display:flex;flex-direction:column;align-items:center;
  background:{C}14;border:2px solid {C}55;border-radius:12px;
  padding:1.2rem 1rem;box-shadow:0 0 30px {GLOW};
  animation:pulse 2.8s ease-in-out infinite;
}}
@keyframes pulse{{
  0%,100%{{border-color:{C}55;box-shadow:0 0 20px {GLOW};}}
  50%{{border-color:{C}cc;box-shadow:0 0 45px {GLOW};}}
}}
.badge-icon{{font-family:'IBM Plex Mono',monospace;font-size:2.4rem;color:{C};font-weight:600;line-height:1;margin-bottom:0.5rem;}}
.badge-level{{font-family:'IBM Plex Mono',monospace;font-size:1.3rem;font-weight:600;color:{C};letter-spacing:0.1em;}}
.badge-sub{{font-family:'Inter',sans-serif;font-size:0.65rem;color:#8e9aaf;text-transform:uppercase;letter-spacing:0.12em;margin-top:0.3rem;}}
.eyebrow{{font-family:'Rajdhani',sans-serif;font-size:0.78rem;font-weight:700;color:#4a5a7a;text-transform:uppercase;letter-spacing:0.14em;margin-bottom:0.6rem;}}
.verdict{{font-family:'Inter',sans-serif;font-size:0.95rem;color:#b8c4d8;line-height:1.75;max-width:480px;}}
.meta{{font-family:'IBM Plex Mono',monospace;font-size:0.68rem;color:#3a4560;margin-top:1.2rem;letter-spacing:0.04em;}}
.g-section{{display:flex;flex-direction:column;gap:0.6rem;}}
.g-label{{font-family:'Rajdhani',sans-serif;font-size:0.68rem;font-weight:700;color:#4a5a7a;text-transform:uppercase;letter-spacing:0.12em;}}
.g-track{{background:#1a2236;border-radius:999px;height:10px;overflow:hidden;border:1px solid #232f47;}}
.g-fill{{height:100%;width:0%;background:linear-gradient(90deg,{C}77,{C});border-radius:999px;box-shadow:0 0 10px {GLOW};animation:grow 1.4s cubic-bezier(0.22,1,0.36,1) forwards;animation-delay:0.3s;}}
@keyframes grow{{from{{width:0%;}}to{{width:{GAUGE}%;}}}}
.g-score{{font-family:'IBM Plex Mono',monospace;font-size:0.75rem;color:{C};}}
.action-tag{{display:inline-block;background:{C}18;border:1px solid {C}44;border-radius:6px;padding:0.3rem 0.8rem;font-family:'IBM Plex Mono',monospace;font-size:0.78rem;font-weight:600;color:{C};letter-spacing:0.08em;margin-top:0.4rem;}}
</style></head><body>
<div class="hero">
  <div class="grid">
    <div class="badge">
      <div class="badge-icon">{ICON}</div>
      <div class="badge-level">{risk}</div>
      <div class="badge-sub">Risk Level</div>
    </div>
    <div>
      <div class="eyebrow">Endpoint Threat Assessment</div>
      <div class="verdict">{verdict_text}</div>
      <div class="meta">Analysis generated: {generated} &nbsp;&middot;&nbsp; {total:,} processes evaluated</div>
    </div>
    <div class="g-section">
      <div class="g-label">Threat Level</div>
      <div class="g-track"><div class="g-fill"></div></div>
      <div class="g-score">Max score: {max_score}</div>
      <br>
      <div class="g-label">Recommended Action</div>
      <div class="action-tag">{ACTION}</div>
    </div>
  </div>
</div>
</body></html>"""

components.html(hero_html, height=215, scrolling=False)

# ═══════════════════════════════════════════════════════════════════════════
# 2 — STAT CARDS
# ═══════════════════════════════════════════════════════════════════════════
stat_html = f"""<!DOCTYPE html><html><head>
<link href="{FONTS}" rel="stylesheet">
<style>
*{{margin:0;padding:0;box-sizing:border-box;}}
body{{background:transparent;padding:4px 0;}}
.cards{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;}}
.card{{background:#0d1525;border:1px solid #1e2840;border-radius:12px;padding:1.2rem 1.4rem;}}
.val{{font-family:'IBM Plex Mono',monospace;font-size:2.1rem;font-weight:600;line-height:1.1;}}
.lbl{{font-family:'Inter',sans-serif;font-size:0.68rem;color:#4a5a7a;text-transform:uppercase;letter-spacing:0.1em;margin-top:0.3rem;}}
</style></head><body>
<div class="cards">
  <div class="card"><div class="val" style="color:#6aabff">{total:,}</div><div class="lbl">Total Processes</div></div>
  <div class="card"><div class="val" style="color:#ff2d55">{critical_ct:,}</div><div class="lbl">Critical Risk</div></div>
  <div class="card"><div class="val" style="color:#ff6b35">{high_ct:,}</div><div class="lbl">High Risk</div></div>
  <div class="card"><div class="val" style="color:#ffc300">{medium_ct:,}</div><div class="lbl">Medium Risk</div></div>
  <div class="card"><div class="val" style="color:#00d48a">{low_ct:,}</div><div class="lbl">Low Risk</div></div>
</div>
</body></html>"""

components.html(stat_html, height=112, scrolling=False)

# ═══════════════════════════════════════════════════════════════════════════
# 3 — DISTRIBUTION BAR
# ═══════════════════════════════════════════════════════════════════════════
def pct(n): return (n / total * 100) if total > 0 else 0

segs = [
    (critical_ct, "#ff2d55", "CRITICAL"),
    (high_ct,     "#ff6b35", "HIGH"),
    (medium_ct,   "#ffc300", "MEDIUM"),
    (low_ct,      "#00d48a", "LOW"),
]

bar_segs_html = "".join(
    f'<div title="{lbl}: {cnt} ({pct(cnt):.1f}%)" style="width:{pct(cnt)}%;background:{color};'
    f'display:flex;align-items:center;justify-content:center;'
    f'font-family:IBM Plex Mono,monospace;font-size:0.7rem;font-weight:600;color:#000a;">'
    f'{"" if pct(cnt) < 6 else str(cnt)}</div>'
    for cnt, color, lbl in segs if pct(cnt) > 0
) or '<div style="width:100%;background:#1a2236;"></div>'

legend_html = "".join(
    f'<div style="display:flex;align-items:center;gap:6px;font-family:Inter,sans-serif;font-size:0.75rem;color:#8e9aaf;">'
    f'<div style="width:10px;height:10px;border-radius:3px;background:{color};flex-shrink:0;"></div>{lbl}: {cnt}</div>'
    for cnt, color, lbl in segs if cnt > 0
)

dist_html = f"""<!DOCTYPE html><html><head>
<link href="{FONTS}" rel="stylesheet">
<style>*{{margin:0;padding:0;box-sizing:border-box;}}body{{background:transparent;}}</style>
</head><body>
<div style="font-family:'Rajdhani',sans-serif;font-size:0.75rem;font-weight:700;color:#4a5a7a;
  text-transform:uppercase;letter-spacing:0.14em;border-left:3px solid {C};
  padding-left:0.65rem;margin-bottom:12px;">Risk Distribution</div>
<div style="display:flex;border-radius:8px;overflow:hidden;height:28px;border:1px solid #1e2840;margin-bottom:10px;">
  {bar_segs_html}
</div>
<div style="display:flex;gap:20px;flex-wrap:wrap;">{legend_html}</div>
</body></html>"""

components.html(dist_html, height=100, scrolling=False)

# ═══════════════════════════════════════════════════════════════════════════
# 4 — REASONS + ACTIONS
# ═══════════════════════════════════════════════════════════════════════════
reasons_html = "".join(
    f'<div style="background:#111827;border:1px solid #1e2840;border-left:3px solid {C}77;'
    f'border-radius:8px;padding:0.7rem 1rem;font-family:Inter,sans-serif;font-size:0.87rem;'
    f'color:#b8c4d8;display:flex;align-items:flex-start;gap:10px;margin-bottom:8px;">'
    f'<div style="width:7px;height:7px;border-radius:50%;background:{C};flex-shrink:0;margin-top:5px;"></div>'
    f'{r}</div>'
    for r in reasons
) or (
    f'<div style="background:#111827;border:1px solid #1e2840;border-left:3px solid {C}77;'
    f'border-radius:8px;padding:0.7rem 1rem;font-family:Inter,sans-serif;font-size:0.87rem;color:#b8c4d8;">'
    f'No specific reasons recorded.</div>'
)

actions_html = "".join(
    f'<div style="display:flex;gap:10px;align-items:flex-start;margin-bottom:10px;">'
    f'<span style="font-family:IBM Plex Mono,monospace;font-size:0.68rem;color:{C};'
    f'background:{C}18;border:1px solid {C}33;border-radius:4px;padding:2px 7px;flex-shrink:0;">{i}</span>'
    f'<span style="font-family:Inter,sans-serif;font-size:0.87rem;color:#b8c4d8;">{a}</span></div>'
    for i, a in enumerate(actions_list, 1)
)

two_col_html = f"""<!DOCTYPE html><html><head>
<link href="{FONTS}" rel="stylesheet">
<style>
*{{margin:0;padding:0;box-sizing:border-box;}}
body{{background:transparent;}}
.sh{{font-family:'Rajdhani',sans-serif;font-size:0.75rem;font-weight:700;color:#4a5a7a;
  text-transform:uppercase;letter-spacing:0.14em;border-left:3px solid {C};padding-left:0.65rem;margin-bottom:14px;}}
.grid{{display:grid;grid-template-columns:1fr 1fr;gap:28px;}}
.panel{{background:{C}0d;border:1px solid {C}2e;border-radius:12px;padding:1.2rem 1.4rem;}}
</style></head><body>
<div class="grid">
  <div><div class="sh">Why This Risk Level Was Assigned</div>{reasons_html}</div>
  <div><div class="sh">Recommended Actions</div><div class="panel">{actions_html}</div></div>
</div>
</body></html>"""

two_col_height = max(len(reasons), len(actions_list)) * 56 + 90
components.html(two_col_html, height=two_col_height, scrolling=False)

# ═══════════════════════════════════════════════════════════════════════════
# 5 — TOP RISK PROCESSES TABLE
# ═══════════════════════════════════════════════════════════════════════════
if proc_details:
    LEVEL_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_procs = sorted(
        proc_details.items(),
        key=lambda x: (-float(x[1].get("risk_score", 0)),
                       LEVEL_ORDER.get(x[1].get("risk_level","LOW"), 9))
    )[:30]

    max_s = max((float(v.get("risk_score", 0)) for _, v in sorted_procs), default=1) or 1

    BAR_C = {"CRITICAL":"#ff2d55","HIGH":"#ff6b35","MEDIUM":"#ffc300","LOW":"#00d48a"}
    PILL_S = {
        "CRITICAL": "background:#ff2d5520;color:#ff2d55;border:1px solid #ff2d5540;",
        "HIGH":     "background:#ff6b3520;color:#ff6b35;border:1px solid #ff6b3540;",
        "MEDIUM":   "background:#ffc30020;color:#ffc300;border:1px solid #ffc30040;",
        "LOW":      "background:#00d48a20;color:#00d48a;border:1px solid #00d48a40;",
    }

    rows_html = ""
    for key, info in sorted_procs:
        lvl   = info.get("risk_level","LOW").upper()
        score = float(info.get("risk_score", 0))
        ev_ct = info.get("events_count", 0)
        bw    = int(score / max_s * 100)
        bc    = BAR_C.get(lvl, "#8e9aaf")
        pill  = PILL_S.get(lvl, "")
        dk    = ("&hellip;" + key[-50:]) if len(key) > 52 else key

        rows_html += f"""<tr>
          <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
            font-family:'IBM Plex Mono',monospace;font-size:0.8rem;color:#b8c4d8;
            padding:0.55rem 0.75rem;border-bottom:1px solid #111827;" title="{key}">{dk}</td>
          <td style="padding:0.55rem 0.75rem;border-bottom:1px solid #111827;">
            <span style="display:inline-block;border-radius:999px;padding:2px 10px;
              font-family:'IBM Plex Mono',monospace;font-size:0.68rem;font-weight:600;
              letter-spacing:0.06em;{pill}">{lvl}</span></td>
          <td style="padding:0.55rem 0.75rem;border-bottom:1px solid #111827;">
            <div style="display:flex;align-items:center;gap:8px;">
              <div style="background:#1a2236;border-radius:999px;height:6px;width:90px;overflow:hidden;flex-shrink:0;">
                <div style="height:100%;width:{bw}%;background:{bc};border-radius:999px;"></div>
              </div>
              <span style="font-family:'IBM Plex Mono',monospace;font-size:0.78rem;color:{bc};">{score:.1f}</span>
            </div></td>
          <td style="font-family:'IBM Plex Mono',monospace;font-size:0.8rem;color:#4a5a7a;
            padding:0.55rem 0.75rem;border-bottom:1px solid #111827;">{ev_ct:,}</td>
        </tr>"""

    table_html = f"""<!DOCTYPE html><html><head>
<link href="{FONTS}" rel="stylesheet">
<style>
*{{margin:0;padding:0;box-sizing:border-box;}}
body{{background:transparent;}}
.sh{{font-family:'Rajdhani',sans-serif;font-size:0.75rem;font-weight:700;color:#4a5a7a;
  text-transform:uppercase;letter-spacing:0.14em;border-left:3px solid {C};
  padding-left:0.65rem;margin-bottom:14px;}}
table{{width:100%;border-collapse:collapse;}}
th{{font-family:'Rajdhani',sans-serif;font-size:0.72rem;font-weight:700;text-transform:uppercase;
  letter-spacing:0.1em;color:#4a5a7a;border-bottom:1px solid #1e2840;
  padding:0.5rem 0.75rem;text-align:left;}}
tr:hover td{{background:#111827!important;}}
</style></head><body>
<div class="sh">Top Risk Processes</div>
<table>
  <thead><tr><th>Process</th><th>Risk Level</th><th>Score</th><th>Events</th></tr></thead>
  <tbody>{rows_html}</tbody>
</table>
</body></html>"""

    tbl_height = min(len(sorted_procs) * 44 + 90, 1400)
    components.html(table_html, height=tbl_height, scrolling=True)

    export_rows = [
        {"Process": k, "Risk Level": v.get("risk_level",""),
         "Risk Score": v.get("risk_score",0), "Events": v.get("events_count",0)}
        for k, v in proc_details.items()
    ]
    df_e = pd.DataFrame(export_rows).sort_values("Risk Score", ascending=False)
    st.download_button(
        "📥 Export All Process Risk Data as CSV",
        df_e.to_csv(index=False),
        "endpoint_risk_processes.csv", "text/csv",
        use_container_width=True
    )
else:
    st.info("No per-process detail data available in the summary file.")

# ── Footer ────────────────────────────────────────────────────────────────────
components.html(
    f'<div style="margin-top:8px;padding-top:12px;border-top:1px solid #1e2840;'
    f'font-family:IBM Plex Mono,monospace;font-size:0.68rem;color:#2a3550;">'
    f'ForensicX &nbsp;&middot;&nbsp; Endpoint Risk Summary &nbsp;&middot;&nbsp; {generated}</div>',
    height=38
)