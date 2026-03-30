"""
Event Timeline Page
Chronological reconstruction of forensic events.

FIX: path = "report/correlation.json" was a bare relative string that
     resolves from wherever Streamlit is launched, not the project root.
     Now uses an absolute path derived from __file__ so it always
     finds the correct file regardless of the launch directory.
"""
import streamlit as st
import pandas as pd
import json
import os
from datetime import datetime
import warnings
warnings.filterwarnings("ignore")

# ============================================================
# PATH RESOLUTION — FIX
# This page lives at: dashboards/pages/Event_Timeline.py
# Project root is TWO levels up (../../).
# ============================================================
_PAGE_DIR    = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR     = os.path.abspath(os.path.join(_PAGE_DIR, "../.."))
CORR_PATH    = os.path.join(ROOT_DIR, "report", "correlation.json")

# ══════════════════════════════════════════════════════════════════════════════
# PAGE CONFIG
# ══════════════════════════════════════════════════════════════════════════════
st.set_page_config(
    page_title="Event Timeline",
    page_icon="📅",
    layout="wide"
)

# ══════════════════════════════════════════════════════════════════════════════
# HEADER
# ══════════════════════════════════════════════════════════════════════════════
st.title("Event Timeline")
st.caption("Chronological reconstruction of forensic events")

# ══════════════════════════════════════════════════════════════════════════════
# TIMESTAMP PARSER
# ══════════════════════════════════════════════════════════════════════════════
def parse_timestamp(value):
    """Parse timestamp to timezone-naive pandas Timestamp."""
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return pd.NaT

    if isinstance(value, (int, float)) and not pd.isna(value):
        try:
            return pd.Timestamp(datetime.fromtimestamp(value))
        except Exception:
            return pd.NaT

    if isinstance(value, pd.Timestamp):
        return value.tz_localize(None) if (hasattr(value, "tz") and value.tz) else value

    if isinstance(value, str):
        s = value.strip()
        if not s:
            return pd.NaT
        try:
            if s.endswith(("Z", "z")):
                s = s[:-1]
            if "+" in s:
                s = s.split("+")[0]
            # Strip trailing tz offset of the form -HH:MM (only if followed by colon)
            if s.count("-") > 2:
                parts = s.rsplit("-", 1)
                if ":" in parts[-1]:
                    s = parts[0]

            s = s.upper().replace(" UTC", "").replace(" GMT", "").strip()
            s = s.replace("T", " ")

            if "." in s:
                dt, micro = s.rsplit(".", 1)
                micro = "".join(c for c in micro if c.isdigit())[:6].ljust(6, "0")
                s = f"{dt}.{micro}" if micro else dt

            return pd.Timestamp(datetime.fromisoformat(s.replace(" ", "T", 1)))
        except Exception:
            return pd.NaT

    return pd.NaT


# ══════════════════════════════════════════════════════════════════════════════
# LOAD DATA
# ══════════════════════════════════════════════════════════════════════════════
def load_data():
    """Load and flatten timeline data from correlation.json."""
    # FIX: was path = "report/correlation.json" (relative)
    #      Now uses CORR_PATH (absolute, derived from __file__)
    if not os.path.exists(CORR_PATH):
        return None, f"correlation.json not found\nExpected: {CORR_PATH}"

    try:
        with open(CORR_PATH, "r", encoding="utf-8") as f:
            corr = json.load(f)
    except Exception as e:
        return None, f"Error reading file: {e}"

    rows = []
    for proc, events in corr.items():
        if isinstance(events, list):
            for ev in events:
                rows.append({
                    "process_key": proc,
                    "source":      ev.get("source",  "unknown"),
                    "tag":         ev.get("tag",     "UNKNOWN"),
                    "name":        ev.get("name",    ""),
                    "pid":         str(ev.get("pid", "")),
                    "details":     str(ev.get("details", ""))[:300],
                    "_time":       ev.get("time", "")
                })

    if not rows:
        return None, "No events found in correlation.json"

    df = pd.DataFrame(rows)
    df["timestamp"] = df["_time"].apply(parse_timestamp)
    df = df.drop(columns=["_time"])
    df = df.dropna(subset=["timestamp"])

    if df.empty:
        return None, "No parseable timestamps in correlation.json"

    # Force timezone-naive
    if hasattr(df["timestamp"].dtype, "tz") and df["timestamp"].dtype.tz:
        df["timestamp"] = df["timestamp"].dt.tz_localize(None)

    df = df.sort_values("timestamp").reset_index(drop=True)

    # Cap at 20 000 rows for performance
    if len(df) > 20000:
        df = df.tail(20000).reset_index(drop=True)

    return df, None


# ══════════════════════════════════════════════════════════════════════════════
# LOAD
# ══════════════════════════════════════════════════════════════════════════════
with st.spinner("Loading timeline data..."):
    df, error = load_data()

if df is None:
    st.error(f"❌ {error}")
    st.info("Run the pipeline from the main dashboard first.")
    st.stop()

st.success(f"✅ Loaded {len(df):,} events")

# ══════════════════════════════════════════════════════════════════════════════
# FILTERS
# ══════════════════════════════════════════════════════════════════════════════
st.markdown("---")
st.markdown("### 🔍 Filters")

col1, col2, col3 = st.columns(3)

with col1:
    sources     = ["All"] + sorted(df["source"].unique().tolist())
    sel_source  = st.selectbox("Source", sources)

with col2:
    tags        = ["All"] + sorted(df["tag"].unique().tolist())
    sel_tag     = st.selectbox("Tag", tags)

with col3:
    processes   = ["All"] + sorted(df["process_key"].unique().tolist())
    sel_process = st.selectbox("Process", processes)

# Apply dropdown filters
fdf = df.copy()
if sel_source  != "All": fdf = fdf[fdf["source"]      == sel_source]
if sel_tag     != "All": fdf = fdf[fdf["tag"]          == sel_tag]
if sel_process != "All": fdf = fdf[fdf["process_key"]  == sel_process]

# Time slider
t_min = df["timestamp"].min().to_pydatetime()
t_max = df["timestamp"].max().to_pydatetime()

time_range = st.slider(
    "Time Range",
    min_value=t_min,
    max_value=t_max,
    value=(t_min, t_max),
    format="YYYY-MM-DD HH:mm"
)

t0  = pd.Timestamp(time_range[0])
t1  = pd.Timestamp(time_range[1])
fdf = fdf[(fdf["timestamp"] >= t0) & (fdf["timestamp"] <= t1)]

# ══════════════════════════════════════════════════════════════════════════════
# METRICS
# ══════════════════════════════════════════════════════════════════════════════
st.markdown("---")

col1, col2, col3, col4 = st.columns(4)
col1.metric("Events",    f"{len(fdf):,}")
col2.metric("Processes", fdf["process_key"].nunique())

if not fdf.empty:
    span   = fdf["timestamp"].max() - fdf["timestamp"].min()
    span_h = span.total_seconds() / 3600
    span_s = f"{span_h:.1f}h" if span_h >= 1 else f"{span.total_seconds()/60:.0f}m"
else:
    span_s = "N/A"

col3.metric("Span",    span_s)
col4.metric("Sources", fdf["source"].nunique())

# ══════════════════════════════════════════════════════════════════════════════
# CHART
# ══════════════════════════════════════════════════════════════════════════════
st.markdown("---")
st.markdown("### 📈 Timeline")

if not fdf.empty:
    chart_df        = fdf.copy()
    chart_df["hour"] = chart_df["timestamp"].dt.floor("H")
    pivot           = chart_df.groupby(["hour", "tag"]).size().reset_index(name="count")
    pivot           = pivot.pivot(index="hour", columns="tag", values="count").fillna(0)
    st.area_chart(pivot, use_container_width=True, height=300)
else:
    st.info("No events match current filters")

# ══════════════════════════════════════════════════════════════════════════════
# EVENT TABLE
# ══════════════════════════════════════════════════════════════════════════════
st.markdown("---")
st.markdown("### 📋 Events")

if not fdf.empty:
    PAGE        = 50
    total_pages = max(1, (len(fdf) - 1) // PAGE + 1)
    page        = st.number_input("Page", 1, total_pages, 1)

    start    = (page - 1) * PAGE
    end      = start + PAGE
    page_df  = fdf.iloc[start:end].copy()

    disp              = page_df[["timestamp", "source", "tag", "name", "pid", "details"]].copy()
    disp["timestamp"] = disp["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")

    st.dataframe(disp, use_container_width=True, hide_index=True, height=400)
    st.caption(f"Page {page}/{total_pages} · Showing {start+1}–{min(end, len(fdf))} of {len(fdf):,}")
else:
    st.warning("No events to display — adjust filters.")

# ══════════════════════════════════════════════════════════════════════════════
# EXPORT
# ══════════════════════════════════════════════════════════════════════════════
st.markdown("---")

if not fdf.empty:
    export              = fdf.copy()
    export["timestamp"] = export["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")

    col1, col2 = st.columns(2)

    with col1:
        st.download_button(
            "📥 CSV",
            export.to_csv(index=False),
            f"timeline_{datetime.now():%Y%m%d_%H%M%S}.csv",
            "text/csv",
            use_container_width=True
        )

    with col2:
        st.download_button(
            "📥 JSON",
            export.to_json(orient="records", indent=2),
            f"timeline_{datetime.now():%Y%m%d_%H%M%S}.json",
            "application/json",
            use_container_width=True
        )

# ══════════════════════════════════════════════════════════════════════════════
# FOOTER
# ══════════════════════════════════════════════════════════════════════════════
st.markdown("---")
st.caption(f"📅 Event Timeline · {len(fdf):,} events")
st.caption(f"📁 Source: `{CORR_PATH}`")