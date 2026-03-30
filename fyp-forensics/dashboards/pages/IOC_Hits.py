"""
IOC Hits — Dashboard Page
Events that matched known Indicators of Compromise (hashes, IPs, domains).
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

from libs.data_loader import load_correlation, load_iocs

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(page_title="IOC Hits", page_icon="🎯", layout="wide")

st.title("🎯 IOC Hits Overview")
st.caption("Events matching known Indicators of Compromise — file hashes, IP addresses, and domains flagged as malicious")

# ── Load ──────────────────────────────────────────────────────────────────────
cor  = load_correlation()
iocs = load_iocs()

if not cor:
    st.error("❌ No correlation data found.")
    st.info("Run the forensic pipeline from the main dashboard first.")
    st.stop()

# ── Extract IOC hits ──────────────────────────────────────────────────────────
ioc_rows = []
for proc, events in cor.items():
    for e in events:
        if e.get("ioc_hit"):
            details_str = str(e.get("details", "")).lower()
            ioc_type = (
                "Hash"   if "hash"   in details_str else
                "IP"     if "ip"     in details_str else
                "Domain" if "domain" in details_str else
                "Other"
            )
            ioc_rows.append({
                "Process":  proc,
                "Time":     e.get("time", ""),
                "Tag":      e.get("tag", ""),
                "IOC Type": ioc_type,
                "Details":  str(e.get("details", ""))[:300],
            })

df = pd.DataFrame(ioc_rows)

# ── Summary ───────────────────────────────────────────────────────────────────
c1, c2, c3 = st.columns(3)
c1.metric("IOC Hits Found",     len(df))
c2.metric("Known IOCs Loaded",  len(iocs))
c3.metric("Affected Processes", df["Process"].nunique() if not df.empty else 0)

if not df.empty:
    st.error(f"🚨 {len(df)} IOC hit(s) found across {df['Process'].nunique()} process(es) — review immediately")

st.divider()

if df.empty:
    st.success("✅ No IOC hits detected.")
    st.info(
        "This means none of the processes or files matched any known malicious indicator "
        "in the IOC reference list."
    )
    if iocs:
        with st.expander(f"📋 Loaded IOC Reference List ({len(iocs)} entries)"):
            st.json(iocs[:50])
    st.stop()

# ── Filters ───────────────────────────────────────────────────────────────────
col1, col2 = st.columns(2)
with col1:
    type_filter = st.multiselect("Filter by IOC Type", df["IOC Type"].unique().tolist(), default=[])
with col2:
    proc_filter = st.multiselect("Filter by Process",  sorted(df["Process"].unique().tolist()), default=[])

fdf = df.copy()
if type_filter:
    fdf = fdf[fdf["IOC Type"].isin(type_filter)]
if proc_filter:
    fdf = fdf[fdf["Process"].isin(proc_filter)]

# ── Table ─────────────────────────────────────────────────────────────────────
st.markdown(f"### Results: {len(fdf)} hit(s)")
st.dataframe(fdf, use_container_width=True, hide_index=True, height=400)

# ── Charts ────────────────────────────────────────────────────────────────────
st.divider()
col1, col2 = st.columns(2)
with col1:
    st.markdown("### IOC Type Breakdown")
    st.bar_chart(fdf["IOC Type"].value_counts())
with col2:
    st.markdown("### Event Tag Breakdown")
    st.bar_chart(fdf["Tag"].value_counts())

# ── IOC reference ─────────────────────────────────────────────────────────────
if iocs:
    with st.expander(f"📋 Known IOC Reference List ({len(iocs)} entries)"):
        st.json(iocs[:100])

# ── Export ────────────────────────────────────────────────────────────────────
st.divider()
st.download_button(
    "📥 Export IOC Hits as CSV",
    fdf.to_csv(index=False),
    "ioc_hits.csv", "text/csv",
    use_container_width=True
)