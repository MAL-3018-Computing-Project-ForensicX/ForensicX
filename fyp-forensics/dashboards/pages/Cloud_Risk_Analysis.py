"""
Cloud Risk Analysis — Dashboard Page
Cloud account behaviour analysis, burst detection, and risk scoring.
"""
import os
import sys
import json
import streamlit as st
import pandas as pd

# ── Path fix ─────────────────────────────────────────────────────────────────
_PAGE_DIR    = os.path.dirname(os.path.abspath(__file__))
_DASH_DIR    = os.path.abspath(os.path.join(_PAGE_DIR, ".."))
PROJECT_ROOT = os.path.abspath(os.path.join(_PAGE_DIR, "../.."))
if _DASH_DIR not in sys.path:
    sys.path.insert(0, _DASH_DIR)

RISK_FILE = os.path.join(PROJECT_ROOT, "report", "cloud_risk_summary.json")

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(page_title="Cloud Risk Analysis", page_icon="☁️", layout="wide")

st.title("☁️ Cloud Behaviour & Risk Analysis")
st.caption("Per-account cloud activity analysis — detects unusual upload/download bursts, suspicious timing, and data exfiltration patterns")

# ── Load ──────────────────────────────────────────────────────────────────────
def load_cloud_risk():
    if not os.path.exists(RISK_FILE):
        return None
    try:
        with open(RISK_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return None

data = load_cloud_risk()

if not data:
    st.warning("⚠️ No cloud risk data found.")
    st.info(f"Run the forensic pipeline to generate cloud analysis.\n\nExpected file: `{RISK_FILE}`")
    st.stop()

# ── Summary metrics ───────────────────────────────────────────────────────────
total_accounts = len(data)
high_risk      = sum(1 for v in data.values() if v.get("risk_level") == "HIGH")
medium_risk    = sum(1 for v in data.values() if v.get("risk_level") == "MEDIUM")
low_risk       = total_accounts - high_risk - medium_risk
total_events   = sum(v.get("total_events", 0) for v in data.values())

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Cloud Accounts",    total_accounts)
c2.metric("🔴 High Risk",      high_risk)
c3.metric("🟡 Medium Risk",    medium_risk)
c4.metric("🟢 Low Risk",       low_risk)
c5.metric("Total Cloud Events",f"{total_events:,}")

if high_risk > 0:
    st.error(f"🚨 {high_risk} cloud account(s) flagged HIGH risk — potential data exfiltration")

st.divider()

# ── Risk overview table ───────────────────────────────────────────────────────
st.markdown("### 📋 Account Risk Overview")

overview_rows = []
for key, info in data.items():
    risk = info.get("risk_level","LOW")
    icon = "🔴" if risk == "HIGH" else "🟡" if risk == "MEDIUM" else "🟢"
    overview_rows.append({
        "Risk":         f"{icon} {risk}",
        "Provider":     info.get("provider","?").upper(),
        "Owner":        info.get("owner","?"),
        "Events":       info.get("total_events", 0),
        "Max Burst":    info.get("max_burst", 0),
        "Risk Reasons": len(info.get("risk_reasons",[])),
    })

df_overview = pd.DataFrame(overview_rows)
df_overview = df_overview.sort_values("Risk", ascending=True)
st.dataframe(df_overview, use_container_width=True, hide_index=True)

# ── Risk level bar chart ──────────────────────────────────────────────────────
st.markdown("### 📊 Risk Distribution")
risk_counts = {"HIGH": high_risk, "MEDIUM": medium_risk, "LOW": low_risk}
st.bar_chart(risk_counts)

st.divider()

# ── Detailed per-account view ─────────────────────────────────────────────────
st.markdown("### 🔍 Detailed Account Analysis")

# Sort: HIGH first
sorted_accounts = sorted(
    data.items(),
    key=lambda x: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(x[1].get("risk_level","LOW"), 3)
)

for key, info in sorted_accounts:
    provider = info.get("provider","unknown").upper()
    owner    = info.get("owner","unknown")
    risk     = info.get("risk_level","LOW")
    icon     = "🔴" if risk == "HIGH" else "🟡" if risk == "MEDIUM" else "🟢"

    with st.expander(
        f"{icon} {provider} | {owner} — Risk: {risk} | Events: {info.get('total_events',0)}",
        expanded=(risk == "HIGH")
    ):
        col1, col2 = st.columns(2)

        with col1:
            st.markdown("**Account Details**")
            st.markdown(f"- **Provider:** `{provider}`")
            st.markdown(f"- **Owner:** `{owner}`")
            st.markdown(f"- **Risk Level:** `{risk}`")
            st.markdown(f"- **Total Events:** `{info.get('total_events',0)}`")
            st.markdown(f"- **Max Burst Activity:** `{info.get('max_burst',0)}` events/window")

            time_range = info.get("time_range",{})
            if time_range:
                first = str(time_range.get("first",""))[:19]
                last  = str(time_range.get("last",""))[:19]
                st.markdown(f"- **Activity Window:** `{first}` → `{last}`")

        with col2:
            st.markdown("**⚠️ Why This Account Was Flagged**")
            reasons = info.get("risk_reasons",[])
            if reasons:
                for r in reasons:
                    st.markdown(f"- {r}")
            else:
                st.markdown("*No risk indicators detected — account appears normal*")

        # Burst windows
        bursts = info.get("burst_windows",[])
        if bursts:
            st.markdown("**📈 Burst Activity Windows**")
            st.caption("A burst means an unusually high number of events in a short time — a common sign of automated exfiltration")
            burst_rows = []
            for b in bursts:
                burst_rows.append({
                    "Events in Window": b.get("count",0),
                    "Window Start":     str(b.get("start",""))[:19],
                    "Window End":       str(b.get("end",""))[:19],
                })
            st.dataframe(burst_rows, use_container_width=True, hide_index=True)

        # Plain-language verdict
        st.markdown("---")
        if risk == "HIGH":
            st.error(
                "🚨 **What this means:** This cloud account showed behaviour consistent with data theft. "
                "An unusually large number of files were accessed or downloaded in a short period. "
                "You should immediately check what files were accessed and whether any sensitive data "
                "left the organisation."
            )
        elif risk == "MEDIUM":
            st.warning(
                "⚠️ **What this means:** This account showed some unusual activity that doesn't fully "
                "match normal behaviour. It may be worth reviewing the activity window to confirm "
                "whether it was legitimate."
            )
        else:
            st.success(
                "✅ **What this means:** This account showed no unusual behaviour during the analysis window."
            )

# ── Export ────────────────────────────────────────────────────────────────────
st.divider()
if overview_rows:
    st.download_button(
        "📥 Export Cloud Risk Summary as CSV",
        pd.DataFrame(overview_rows).to_csv(index=False),
        "cloud_risk_summary.csv", "text/csv",
        use_container_width=True
    )