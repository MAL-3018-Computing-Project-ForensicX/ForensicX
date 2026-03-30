import sys
import os
import json
import pandas as pd
import streamlit as st
from datetime import datetime

# ============================================================
# PATH RESOLUTION — FIX
# This page lives at: dashboards/pages/1_Endpoint_Behavior.py
# Project root is therefore TWO levels up (../../).
#
# FIX 1: ROOT_DIR was os.path.join(__file__, "..") which resolved to
#         dashboards/ instead of the project root.
# FIX 2: DATA_PATH was a bare relative string "report/..." which
#         resolves from wherever Streamlit was launched, not the
#         project root. Now uses an absolute path so it works
#         regardless of the launch directory.
# ============================================================
_PAGE_DIR   = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR    = os.path.abspath(os.path.join(_PAGE_DIR, "../.."))   # FIX: was ".."
DATA_PATH   = os.path.join(ROOT_DIR, "report", "endpoint_risk_summary.json")

if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# ========================================
# PAGE CONFIG
# ========================================
st.set_page_config(
    page_title="Endpoint Behavior Analysis",
    page_icon="🧬",
    layout="wide"
)

# Custom CSS
st.markdown("""
<style>
    .risk-critical {
        background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
        color: white; padding: 1rem; border-radius: 0.5rem; font-weight: 700;
    }
    .risk-high {
        background: linear-gradient(135deg, #e67e22 0%, #d35400 100%);
        color: white; padding: 1rem; border-radius: 0.5rem; font-weight: 700;
    }
    .risk-medium {
        background: linear-gradient(135deg, #f39c12 0%, #e67e22 100%);
        color: white; padding: 1rem; border-radius: 0.5rem; font-weight: 700;
    }
    .risk-low {
        background: linear-gradient(135deg, #27ae60 0%, #229954 100%);
        color: white; padding: 1rem; border-radius: 0.5rem; font-weight: 700;
    }
    .indicator-badge {
        background: #3498db; color: white; padding: 0.25rem 0.5rem;
        border-radius: 0.25rem; font-size: 0.85rem; margin: 0.25rem;
        display: inline-block;
    }
    .process-card {
        background: #f8f9fa; padding: 1rem; border-radius: 0.5rem;
        border-left: 4px solid #3498db; margin: 0.5rem 0;
    }
</style>
""", unsafe_allow_html=True)

# ========================================
# HEADER
# ========================================
st.title("Endpoint Behavior Analysis")
st.caption("Deep dive into process behavior and risk indicators")

# ========================================
# LOAD DATA
# ========================================
if not os.path.exists(DATA_PATH):
    st.error("❌ Endpoint behavior report not found")
    st.info("**How to fix:** Run the forensic pipeline from the main dashboard with 'Endpoint Behavior Analysis' enabled")
    st.caption(f"Expected file: `{DATA_PATH}`")
    st.stop()

try:
    with open(DATA_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
except Exception as e:
    st.error(f"❌ Error loading report: {e}")
    st.stop()

# ========================================
# SIDEBAR - NAVIGATION & INFO
# ========================================
st.sidebar.title("Analysis View")
view_mode = st.sidebar.radio(
    "Select View",
    ["Summary Dashboard", "Process List", "Detailed Analysis", "Statistics"]
)

st.sidebar.markdown("---")
st.sidebar.markdown("### Data Info")
st.sidebar.write(f"**Report Type:** Endpoint Behavior")
st.sidebar.write(f"**Data Structure:** {type(data).__name__}")

if isinstance(data, dict) and "generated_at" in data:
    st.sidebar.write(f"**Generated:** {data.get('generated_at', 'Unknown')[:19]}")

# ========================================
# DETERMINE DATA STRUCTURE
# ========================================
is_endpoint_summary = isinstance(data, dict) and "endpoint_risk_level" in data
is_process_level    = isinstance(data, dict) and not is_endpoint_summary

process_data = {}

if is_endpoint_summary and "process_details" in data:
    process_data = data.get("process_details", {})
elif is_process_level:
    process_data = {k: v for k, v in data.items() if isinstance(v, dict) and "risk_level" in v}

# ========================================
# VIEW 1: SUMMARY DASHBOARD
# ========================================
if view_mode == "Summary Dashboard":

    if is_endpoint_summary:
        risk_level = data.get("endpoint_risk_level", "UNKNOWN")

        st.markdown("## Overall Risk Assessment")

        if risk_level == "CRITICAL":
            st.markdown('<div class="risk-critical">🚨 CRITICAL RISK DETECTED</div>', unsafe_allow_html=True)
            st.error("**Immediate action required!** System shows clear signs of malicious activity.")
        elif risk_level == "HIGH":
            st.markdown('<div class="risk-high">⚠️ HIGH RISK DETECTED</div>', unsafe_allow_html=True)
            st.warning("**Investigation required.** Multiple suspicious indicators detected.")
        elif risk_level == "MEDIUM":
            st.markdown('<div class="risk-medium">⚠️ MEDIUM RISK DETECTED</div>', unsafe_allow_html=True)
            st.info("**Review recommended.** Some suspicious behavior detected.")
        else:
            st.markdown('<div class="risk-low">✅ LOW RISK - SYSTEM APPEARS CLEAN</div>', unsafe_allow_html=True)
            st.success("No significant malicious indicators detected.")

        st.markdown("---")
        st.markdown("### Key Metrics")

        col1, col2, col3, col4, col5 = st.columns(5)

        with col1:
            total = data.get("total_processes", 0)
            st.metric("Total Processes", f"{total:,}", help="Unique processes analyzed")

        with col2:
            critical = data.get("critical_risk_processes", 0)
            st.metric("Critical Risk", critical,
                      delta="⚠️" if critical > 0 else "✅",
                      help="Processes with CRITICAL risk level")

        with col3:
            high = data.get("high_risk_processes", 0)
            st.metric("High Risk", high,
                      delta="⚠️" if high > 0 else "✅",
                      help="Processes with HIGH risk level")

        with col4:
            medium = data.get("medium_risk_processes", 0)
            st.metric("Medium Risk", medium, help="Processes with MEDIUM risk level")

        with col5:
            max_score = data.get("max_risk_score", 0)
            st.metric("Max Risk Score", max_score, help="Highest risk score (140+ = CRITICAL)")

        # Risk score bar
        st.markdown("### Risk Score Distribution")

        if max_score > 0:
            score_pct = min(max_score / 200 * 100, 100)

            if max_score >= 140:
                color, label = "#e74c3c", "CRITICAL (140+)"
            elif max_score >= 80:
                color, label = "#e67e22", "HIGH (80-139)"
            elif max_score >= 40:
                color, label = "#f39c12", "MEDIUM (40-79)"
            else:
                color, label = "#27ae60", "LOW (0-39)"

            st.markdown(f"""
            <div style="background:#ecf0f1;border-radius:0.5rem;padding:0.5rem;">
                <div style="background:{color};width:{score_pct}%;height:30px;border-radius:0.25rem;
                            display:flex;align-items:center;justify-content:center;
                            color:white;font-weight:600;">
                    {max_score} — {label}
                </div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("---")
        st.markdown("### 🔍 Analysis Findings")

        reasons = data.get("decision_reason", [])
        if reasons:
            for idx, reason in enumerate(reasons, 1):
                if any(w in reason.lower() for w in ["critical", "high", "malicious"]):
                    icon, color = "🚨", "#e74c3c"
                elif any(w in reason.lower() for w in ["medium", "suspicious"]):
                    icon, color = "⚠️", "#f39c12"
                else:
                    icon, color = "ℹ️", "#3498db"

                st.markdown(f"""
                <div style="background:{color}15;border-left:4px solid {color};
                            padding:1rem;border-radius:0.25rem;margin:0.5rem 0;">
                    <strong>{icon} Finding #{idx}:</strong> {reason}
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No specific findings to report")

        st.markdown("---")

        if process_data:
            st.markdown("### Process Summary")
            st.caption("Showing top processes by risk score")

            rows = []
            for proc_name, proc_info in process_data.items():
                rows.append({
                    "Process":    proc_name,
                    "Risk Level": proc_info.get("risk_level", "UNKNOWN"),
                    "Risk Score": proc_info.get("risk_score", 0),
                    "Events":     proc_info.get("events_count", 0)
                })

            if rows:
                df = pd.DataFrame(rows).sort_values("Risk Score", ascending=False)

                def color_risk_level(val):
                    return {
                        "CRITICAL": "background-color:#e74c3c;color:white;font-weight:bold",
                        "HIGH":     "background-color:#e67e22;color:white;font-weight:bold",
                        "MEDIUM":   "background-color:#f39c12;color:white;font-weight:bold",
                        "LOW":      "background-color:#27ae60;color:white;font-weight:bold",
                    }.get(val, "")

                styled = df.head(20).style.applymap(color_risk_level, subset=["Risk Level"])
                st.dataframe(styled, use_container_width=True, height=400)

    else:
        st.warning("⚠️ Unexpected data format in the report file.")
        st.json(data)

# ========================================
# VIEW 2: PROCESS LIST
# ========================================
elif view_mode == "Process List":

    st.markdown("## 📋 Process List")

    if not process_data:
        st.error("❌ No process data available")
        st.stop()

    rows = []
    for proc_name, proc_info in process_data.items():
        rows.append({
            "Process":    proc_name,
            "Risk Level": proc_info.get("risk_level", "UNKNOWN"),
            "Risk Score": proc_info.get("risk_score", 0),
            "Events":     proc_info.get("events_count", 0)
        })

    df = pd.DataFrame(rows).sort_values("Risk Score", ascending=False)

    st.markdown("### Filters")
    col1, col2, col3 = st.columns(3)

    with col1:
        risk_filter = st.multiselect("Risk Level",
                                     options=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                                     default=[])
    with col2:
        min_score = st.number_input("Min Risk Score", min_value=0, max_value=300, value=0)
    with col3:
        search_term = st.text_input("Search Process", placeholder="e.g., chrome.exe")

    filtered_df = df.copy()
    if risk_filter:
        filtered_df = filtered_df[filtered_df["Risk Level"].isin(risk_filter)]
    if min_score > 0:
        filtered_df = filtered_df[filtered_df["Risk Score"] >= min_score]
    if search_term:
        filtered_df = filtered_df[filtered_df["Process"].str.contains(search_term, case=False, na=False)]

    sort_by  = st.selectbox("Sort By", ["Risk Score", "Events", "Process"], index=0)
    sort_asc = st.checkbox("Ascending", value=False)
    filtered_df = filtered_df.sort_values(sort_by, ascending=sort_asc)

    st.markdown(f"### Results: {len(filtered_df)} / {len(df)} processes")

    def color_risk(val):
        return {
            "CRITICAL": "background-color:#e74c3c;color:white;font-weight:bold",
            "HIGH":     "background-color:#e67e22;color:white;font-weight:bold",
            "MEDIUM":   "background-color:#f39c12;color:white;font-weight:bold",
            "LOW":      "background-color:#27ae60;color:white;font-weight:bold",
        }.get(val, "")

    styled_df = filtered_df.style.applymap(color_risk, subset=["Risk Level"])
    st.dataframe(styled_df, use_container_width=True, height=600)

    st.download_button(
        label="Export to CSV",
        data=filtered_df.to_csv(index=False).encode("utf-8"),
        file_name=f"process_list_{datetime.now():%Y%m%d_%H%M%S}.csv",
        mime="text/csv"
    )

# ========================================
# VIEW 3: DETAILED ANALYSIS
# ========================================
elif view_mode == "Detailed Analysis":

    st.markdown("## Process Deep Dive")
    st.caption("Analyze individual process behavior and events")

    if not process_data:
        st.error("❌ No process data available")
        st.stop()

    process_list = sorted(process_data.keys(),
                          key=lambda x: process_data[x].get("risk_score", 0),
                          reverse=True)

    selected_process = st.selectbox(
        "Select Process for Analysis",
        process_list,
        format_func=lambda x: f"{x} (Score: {process_data[x].get('risk_score', 0)})"
    )

    if selected_process:
        proc_info  = process_data[selected_process]
        risk_level = proc_info.get("risk_level", "UNKNOWN")
        risk_score = proc_info.get("risk_score", 0)

        st.markdown("---")
        st.markdown(f"### {selected_process}")

        if risk_level == "CRITICAL":
            st.markdown(f'<div class="risk-critical">🚨 CRITICAL RISK — Score: {risk_score}</div>', unsafe_allow_html=True)
        elif risk_level == "HIGH":
            st.markdown(f'<div class="risk-high">⚠️ HIGH RISK — Score: {risk_score}</div>', unsafe_allow_html=True)
        elif risk_level == "MEDIUM":
            st.markdown(f'<div class="risk-medium">⚠️ MEDIUM RISK — Score: {risk_score}</div>', unsafe_allow_html=True)
        else:
            st.markdown(f'<div class="risk-low">✅ LOW RISK — Score: {risk_score}</div>', unsafe_allow_html=True)

        st.markdown("---")

        col1, col2, col3 = st.columns(3)
        col1.metric("Risk Score",   risk_score)
        col2.metric("Risk Level",   risk_level)
        col3.metric("Total Events", proc_info.get("events_count", 0))

        st.info("ℹ️ This view shows aggregated process summary. For full event details, check the Event Timeline page.")

        st.markdown("### Available Information")
        for field, value in proc_info.items():
            if field not in ("risk_score", "risk_level", "events_count") and value is not None:
                st.write(f"**{field.replace('_', ' ').title()}:** {value}")

# ========================================
# VIEW 4: STATISTICS
# ========================================
elif view_mode == "Statistics":

    st.markdown("## Statistical Analysis")
    st.caption("Aggregate statistics and distributions")

    if not process_data:
        st.error("❌ No process data available")
        st.stop()

    scores       = [p.get("risk_score", 0)  for p in process_data.values()]
    risk_levels  = [p.get("risk_level", "UNKNOWN") for p in process_data.values()]
    event_counts = [p.get("events_count", 0) for p in process_data.values()]

    st.markdown("### Risk Score Statistics")
    col1, col2, col3, col4, col5 = st.columns(5)

    col1.metric("Total Processes", len(scores))
    col2.metric("Average Score",   f"{sum(scores)/len(scores):.1f}" if scores else "0")
    col3.metric("Median Score",    f"{sorted(scores)[len(scores)//2]:.0f}" if scores else "0")
    col4.metric("Max Score",       max(scores) if scores else 0)
    col5.metric("Total Events",    sum(event_counts))

    st.markdown("---")
    st.markdown("### Risk Level Distribution")

    from collections import Counter
    risk_counts = Counter(risk_levels)

    col1, col2 = st.columns(2)

    with col1:
        df_risk = pd.DataFrame({
            "Risk Level": list(risk_counts.keys()),
            "Count":      list(risk_counts.values())
        })
        st.bar_chart(df_risk.set_index("Risk Level"))

    with col2:
        for level, count in risk_counts.most_common():
            pct = count / len(risk_levels) * 100 if risk_levels else 0
            st.write(f"**{level}:** {count} processes ({pct:.1f}%)")

    st.markdown("---")
    st.markdown("### Risk Score Distribution")
    st.line_chart(pd.DataFrame({"Risk Score": sorted(scores, reverse=True)}))

    st.markdown("### Score Range Breakdown")
    ranges = {
        "0–39   (LOW)":      sum(1 for s in scores if s < 40),
        "40–79  (MEDIUM)":   sum(1 for s in scores if 40 <= s < 80),
        "80–139 (HIGH)":     sum(1 for s in scores if 80 <= s < 140),
        "140+   (CRITICAL)": sum(1 for s in scores if s >= 140),
    }
    for range_name, count in ranges.items():
        pct = count / len(scores) * 100 if scores else 0
        st.write(f"**{range_name}:** {count} processes ({pct:.1f}%)")

# ========================================
# FOOTER
# ========================================
st.markdown("---")
st.caption(f"📁 Report: `{DATA_PATH}`")
st.caption("🧬 Endpoint Behavior Analysis Dashboard")