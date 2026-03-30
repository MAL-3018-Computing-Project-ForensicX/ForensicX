"""
Cloud ↔ Endpoint Attack Chain — Dashboard Page
Visual attack chain linking cloud file events to endpoint process activity.
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

DATA_FILE = os.path.join(PROJECT_ROOT, "report", "cloud_endpoint_correlations.json")

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(page_title="Cloud ↔ Endpoint Attack Chain", page_icon="🔗", layout="wide")

st.title("🔗 Cloud ↔ Endpoint Attack Chain")
st.caption("Links between cloud file activity and local process execution — shows how attackers move from cloud to endpoint")

# ── Load ──────────────────────────────────────────────────────────────────────
def load_data():
    if not os.path.exists(DATA_FILE):
        return []
    try:
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return []

data = load_data()

if not data:
    st.warning("⚠️ No cloud–endpoint correlations found.")
    st.info(f"Run the forensic pipeline to generate attack chains.\n\nExpected file: `{DATA_FILE}`")
    st.stop()

# ── Summary metrics ───────────────────────────────────────────────────────────
total_links  = len(data)
high_conf    = sum(1 for x in data if x.get("confidence") == "HIGH")
medium_conf  = sum(1 for x in data if x.get("confidence") == "MEDIUM")
low_conf     = total_links - high_conf - medium_conf
providers    = list({x.get("cloud_provider", "unknown") for x in data})

c1, c2, c3, c4 = st.columns(4)
c1.metric("Total Attack Links", total_links)
c2.metric("🔴 High Confidence",   high_conf)
c3.metric("🟡 Medium Confidence", medium_conf)
c4.metric("🟢 Low / Weak",        low_conf)

if high_conf > 0:
    st.error(f"🚨 {high_conf} high-confidence attack chain(s) detected — immediate review recommended")

st.divider()

# ── Filters ───────────────────────────────────────────────────────────────────
col1, col2 = st.columns(2)
with col1:
    conf_filter = st.multiselect(
        "Filter by Confidence",
        options=["HIGH", "MEDIUM", "LOW"],
        default=[]
    )
with col2:
    prov_filter = st.multiselect(
        "Filter by Cloud Provider",
        options=sorted(providers),
        default=[]
    )

filtered = data
if conf_filter:
    filtered = [x for x in filtered if x.get("confidence") in conf_filter]
if prov_filter:
    filtered = [x for x in filtered if x.get("cloud_provider") in prov_filter]

st.markdown(f"Showing **{len(filtered)}** of {total_links} attack chain(s)")
st.divider()

# ── Attack chain view mode ────────────────────────────────────────────────────
view_mode = st.radio("View Mode", ["Cards", "Table"], horizontal=True)

if view_mode == "Cards":
    for idx, link in enumerate(filtered, 1):
        conf  = link.get("confidence", "UNKNOWN")
        icon  = "🔴" if conf == "HIGH" else "🟡" if conf == "MEDIUM" else "🟢"
        tdiff = link.get("timestamp_diff_seconds", "?")

        with st.expander(
            f"{icon} Attack Chain #{idx} — {link.get('cloud_provider','?').upper()} → "
            f"`{link.get('endpoint_process','?')}` | Confidence: {conf} | Δt = {tdiff}s",
            expanded=(conf == "HIGH")
        ):
            left, arrow, right = st.columns([5, 1, 5])

            with left:
                st.markdown("#### ☁️ Cloud Event")
                st.markdown(f"**Provider:** `{link.get('cloud_provider', 'N/A')}`")
                st.markdown(f"**Account/Owner:** `{link.get('cloud_owner', 'N/A')}`")
                st.markdown(f"**File:** `{link.get('file_name', 'N/A')}`")
                st.markdown(f"**Cloud Time:** `{str(link.get('cloud_time','N/A'))[:19]}`")

            with arrow:
                st.markdown("<br><br><div style='text-align:center;font-size:2rem'>→</div>",
                            unsafe_allow_html=True)

            with right:
                st.markdown("#### 💻 Endpoint Event")
                st.markdown(f"**Process:** `{link.get('endpoint_process', 'N/A')}`")
                st.markdown(f"**PID:** `{link.get('pid', 'N/A')}`")
                st.markdown(f"**Endpoint Time:** `{str(link.get('endpoint_time','N/A'))[:19]}`")
                st.markdown(f"**Time Gap:** `{tdiff} seconds`")

            # ── Analyst verdict ───────────────────────────────────────────────
            st.markdown("---")
            if conf == "HIGH":
                st.error(
                    "🚨 **HIGH CONFIDENCE** — A file was downloaded from the cloud and a suspicious "
                    "process launched within seconds. This is a strong indicator of malicious document "
                    "execution or phishing payload delivery."
                )
            elif conf == "MEDIUM":
                st.warning(
                    "⚠️ **MEDIUM CONFIDENCE** — Suspicious timing correlation between cloud activity "
                    "and local process. Could be coincidental but warrants investigation."
                )
            else:
                st.info(
                    "ℹ️ **LOW CONFIDENCE** — Weak temporal link. These events may not be related."
                )

            # Extra details
            extra = {k: v for k, v in link.items()
                     if k not in ("confidence","cloud_provider","cloud_owner","file_name",
                                  "endpoint_process","pid","timestamp_diff_seconds",
                                  "cloud_time","endpoint_time")}
            if extra:
                with st.expander("🔍 Raw Fields"):
                    st.json(extra)

else:  # Table view
    rows = []
    for link in filtered:
        rows.append({
            "Confidence":      link.get("confidence","?"),
            "Provider":        link.get("cloud_provider","?"),
            "Owner":           link.get("cloud_owner","?"),
            "File":            link.get("file_name","?"),
            "Process":         link.get("endpoint_process","?"),
            "PID":             link.get("pid","?"),
            "Time Gap (s)":    link.get("timestamp_diff_seconds","?"),
        })
    df = pd.DataFrame(rows)
    st.dataframe(df, use_container_width=True, hide_index=True, height=400)

st.divider()

# ── Confidence breakdown chart ────────────────────────────────────────────────
st.markdown("### 📊 Confidence Breakdown")
conf_counts = {"HIGH": high_conf, "MEDIUM": medium_conf, "LOW": low_conf}
st.bar_chart(conf_counts)

# ── Export ────────────────────────────────────────────────────────────────────
if filtered:
    rows = [{
        "Confidence": x.get("confidence"),
        "Provider": x.get("cloud_provider"),
        "Owner": x.get("cloud_owner"),
        "File": x.get("file_name"),
        "Process": x.get("endpoint_process"),
        "PID": x.get("pid"),
        "Time_Gap_Seconds": x.get("timestamp_diff_seconds"),
    } for x in filtered]
    st.download_button(
        "📥 Export Attack Chains as CSV",
        pd.DataFrame(rows).to_csv(index=False),
        "attack_chains.csv", "text/csv",
        use_container_width=True
    )