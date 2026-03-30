"""
Process Explorer — Dashboard Page
Drill into per-process event timelines from the correlation engine.
"""
import sys
import os
import streamlit as st
import pandas as pd

# ── Path fix ─────────────────────────────────────────────────────────────────
_PAGE_DIR = os.path.dirname(os.path.abspath(__file__))
_DASH_DIR = os.path.abspath(os.path.join(_PAGE_DIR, ".."))
if _DASH_DIR not in sys.path:
    sys.path.insert(0, _DASH_DIR)

from libs.data_loader import load_correlation

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(page_title="Process Explorer", page_icon="🔬", layout="wide")

st.title("🔬 Process Explorer")
st.caption("Inspect every event recorded for each process — sorted by activity level")

# ── Load ──────────────────────────────────────────────────────────────────────
cor = load_correlation()

if not cor:
    st.error("❌ Correlation data not found.")
    st.info("Run the forensic pipeline from the main dashboard first.")
    st.stop()

# ── Sidebar search ────────────────────────────────────────────────────────────
st.sidebar.markdown("## 🔍 Search")
search = st.sidebar.text_input("Filter process name", placeholder="e.g. powershell")

proc_list = sorted(cor.keys())
if search:
    proc_list = [p for p in proc_list if search.lower() in p.lower()]

st.sidebar.markdown(f"**{len(proc_list)}** / {len(cor)} processes shown")

# ── Summary ───────────────────────────────────────────────────────────────────
total_events = sum(len(v) for v in cor.values())
c1, c2, c3 = st.columns(3)
c1.metric("Total Processes",    len(cor))
c2.metric("Total Events",       f"{total_events:,}")
c3.metric("Matching Search",    len(proc_list))

st.divider()

if not proc_list:
    st.warning("No processes match the search term.")
    st.stop()

# ── Process selector (sorted by event count so highest-risk are first) ────────
proc_options = sorted(proc_list, key=lambda p: len(cor.get(p, [])), reverse=True)
proc_labels  = {p: f"{p}  ({len(cor.get(p, []))} events)" for p in proc_options}

selected = st.selectbox(
    "Select a process to explore:",
    proc_options,
    format_func=lambda p: proc_labels[p]
)

events = cor.get(selected, [])

if not events:
    st.info("No events recorded for this process.")
    st.stop()

# ── Build DataFrame ───────────────────────────────────────────────────────────
rows = []
for e in events:
    rows.append({
        "Time":    e.get("time",    ""),
        "Source":  e.get("source",  "unknown"),
        "Tag":     e.get("tag",     ""),
        "PID":     str(e.get("pid","?")),
        "Details": str(e.get("details",""))[:300],
    })
df = pd.DataFrame(rows)

# ── Process quick stats ───────────────────────────────────────────────────────
st.markdown(f"### `{selected}`")
c1, c2, c3, c4 = st.columns(4)
c1.metric("Events",         len(df))
c2.metric("Event Types",    df["Tag"].nunique()    if not df.empty else 0)
c3.metric("Data Sources",   df["Source"].nunique() if not df.empty else 0)
c4.metric("First Seen",     str(df["Time"].iloc[0])[:19] if not df.empty and df["Time"].any() else "N/A")

st.divider()

# ── Tag filter ────────────────────────────────────────────────────────────────
all_tags = sorted(df["Tag"].unique().tolist())
tag_filter = st.multiselect("Filter by event tag", all_tags, default=[])
fdf = df[df["Tag"].isin(tag_filter)] if tag_filter else df

# ── Event table ───────────────────────────────────────────────────────────────
st.markdown(f"**{len(fdf)} events shown**")
st.dataframe(fdf, use_container_width=True, hide_index=True, height=450)

# ── Charts ────────────────────────────────────────────────────────────────────
st.divider()
col1, col2 = st.columns(2)
with col1:
    st.markdown("### Event Type Frequency")
    if not fdf.empty:
        st.bar_chart(fdf["Tag"].value_counts())
with col2:
    st.markdown("### Source Breakdown")
    if not fdf.empty:
        st.bar_chart(fdf["Source"].value_counts())

# ── Export ────────────────────────────────────────────────────────────────────
st.divider()
if not fdf.empty:
    safe_name = selected.replace("|","_").replace("/","_").replace("\\","_")
    st.download_button(
        "📥 Export Events as CSV",
        fdf.to_csv(index=False),
        f"process_{safe_name}.csv", "text/csv",
        use_container_width=True
    )