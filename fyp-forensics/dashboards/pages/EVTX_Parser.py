"""
EVTX Parser — Dashboard Page
GUI wrapper for Evtx_parser.py.
Upload a Windows .evtx log file, choose which Sysmon Event IDs to extract,
and download the results as JSON for use in the pipeline.
"""
import sys
import os
import json
import tempfile
import streamlit as st
import pandas as pd

# ── Path fix ─────────────────────────────────────────────────────────────────
_PAGE_DIR    = os.path.dirname(os.path.abspath(__file__))
_DASH_DIR    = os.path.abspath(os.path.join(_PAGE_DIR, ".."))
PROJECT_ROOT = os.path.abspath(os.path.join(_PAGE_DIR, "../.."))
if _DASH_DIR not in sys.path:
    sys.path.insert(0, _DASH_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(page_title="EVTX Parser", page_icon="📋", layout="wide")

st.title("📋 EVTX Log Parser")
st.caption(
    "Upload a Windows Event Log (.evtx) file to extract Sysmon events. "
    "The output JSON can be saved to `data/logs/` and used as input to the forensic pipeline."
)

# ── Import parse_evtx ─────────────────────────────────────────────────────────
try:
    from modules.parse_evtx import parse_evtx, extract_event_fields
    HAS_PARSER = True
except ImportError:
    HAS_PARSER = False

if not HAS_PARSER:
    st.error("❌ `parse_evtx.py` module not found in project root.")
    st.info(f"Expected location: `{os.path.join(PROJECT_ROOT, 'modules', 'parse_evtx.py')}`")
    st.stop()

# ── Sysmon Event ID reference ─────────────────────────────────────────────────
SYSMON_IDS = {
    "1":  "Process Create",
    "2":  "File Creation Time Changed",
    "3":  "Network Connection",
    "5":  "Process Terminated",
    "6":  "Driver Loaded",
    "7":  "Image Loaded (DLL)",
    "8":  "CreateRemoteThread",
    "10": "ProcessAccess (credential dumping)",
    "11": "File Create",
    "12": "Registry Create/Delete",
    "13": "Registry Set Value",
    "15": "File Create Stream Hash",
    "17": "Pipe Created",
    "22": "DNS Query",
    "23": "File Delete",
    "25": "Process Tampering",
}

# ── Upload ────────────────────────────────────────────────────────────────────
st.markdown("### 1️⃣ Upload EVTX File")
uploaded = st.file_uploader(
    "Drop your .evtx Windows Event Log here",
    type=["evtx"],
    help="Typically found at C:\\Windows\\System32\\winevt\\Logs\\ on Windows systems"
)

if not uploaded:
    st.info(
        "💡 **Where to find EVTX files:**\n"
        "- Sysmon log: `C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx`\n"
        "- System log: `C:\\Windows\\System32\\winevt\\Logs\\System.evtx`\n"
        "- Security log: `C:\\Windows\\System32\\winevt\\Logs\\Security.evtx`"
    )
    st.stop()

st.success(f"✅ Uploaded: **{uploaded.name}** ({uploaded.size:,} bytes)")

# ── Event ID selection ────────────────────────────────────────────────────────
st.markdown("### 2️⃣ Choose Event IDs to Extract")
st.caption("Leave all unchecked to extract ALL events (may be large)")

col1, col2 = st.columns(2)
selected_ids = []

id_list = list(SYSMON_IDS.items())
half = len(id_list) // 2

with col1:
    for eid, desc in id_list[:half]:
        if st.checkbox(f"Event ID {eid} — {desc}", key=f"eid_{eid}"):
            selected_ids.append(eid)

with col2:
    for eid, desc in id_list[half:]:
        if st.checkbox(f"Event ID {eid} — {desc}", key=f"eid_{eid}"):
            selected_ids.append(eid)

filter_ids = selected_ids if selected_ids else None

if filter_ids:
    st.info(f"Extracting Event IDs: {', '.join(filter_ids)}")
else:
    st.warning("No Event IDs selected — ALL events will be extracted.")

# ── Parse ─────────────────────────────────────────────────────────────────────
st.markdown("### 3️⃣ Parse")

if st.button("🔍 Parse EVTX File", type="primary", use_container_width=True):
    with st.spinner("Parsing events — this may take a moment for large files..."):
        try:
            # Write uploaded file to temp location
            with tempfile.NamedTemporaryFile(suffix=".evtx", delete=False) as tmp_in:
                tmp_in.write(uploaded.read())
                tmp_in_path = tmp_in.name

            tmp_out_path = tmp_in_path.replace(".evtx", ".json")

            parse_evtx(tmp_in_path, tmp_out_path, filter_ids=filter_ids)

            with open(tmp_out_path, "r", encoding="utf-8") as f:
                events = json.load(f)

            os.unlink(tmp_in_path)
            os.unlink(tmp_out_path)

            st.session_state["parsed_events"] = events
            st.session_state["parsed_filename"] = uploaded.name.replace(".evtx", ".json")
            st.success(f"✅ Extracted **{len(events):,}** events from `{uploaded.name}`")

        except Exception as exc:
            st.error(f"❌ Parsing failed: {exc}")
            st.info("Make sure `python-evtx` and `lxml` are installed:\n```\npip install python-evtx lxml\n```")

# ── Results ───────────────────────────────────────────────────────────────────
if "parsed_events" in st.session_state:
    events   = st.session_state["parsed_events"]
    out_name = st.session_state.get("parsed_filename", "events.json")

    if not events:
        st.warning("No events matched the selected filters.")
        st.stop()

    st.divider()
    st.markdown("### 4️⃣ Results")

    # ── Summary ───────────────────────────────────────────────────────────────
    event_id_counts = {}
    for e in events:
        eid = str(e.get("event_id","?"))
        event_id_counts[eid] = event_id_counts.get(eid, 0) + 1

    c1, c2 = st.columns(2)
    c1.metric("Total Events Extracted", f"{len(events):,}")
    c2.metric("Unique Event IDs Found", len(event_id_counts))

    st.markdown("#### Event ID Breakdown")
    eid_rows = []
    for eid, cnt in sorted(event_id_counts.items(), key=lambda x: x[1], reverse=True):
        desc = SYSMON_IDS.get(eid, "Unknown / Non-Sysmon")
        eid_rows.append({"Event ID": eid, "Description": desc, "Count": cnt})
    st.dataframe(eid_rows, use_container_width=True, hide_index=True)
    st.bar_chart({r["Event ID"]: r["Count"] for r in eid_rows})

    # ── Preview table ─────────────────────────────────────────────────────────
    st.markdown("#### Preview (first 100 events)")
    preview_rows = []
    for e in events[:100]:
        data_fields = e.get("data", {})
        preview_rows.append({
            "Event ID":   e.get("event_id",""),
            "Time":       str(e.get("time",""))[:19],
            "Process":    data_fields.get("Image","") or data_fields.get("ProcessName",""),
            "PID":        data_fields.get("ProcessId",""),
            "CommandLine":str(data_fields.get("CommandLine",""))[:120],
        })
    st.dataframe(preview_rows, use_container_width=True, hide_index=True, height=350)

    # ── Download ──────────────────────────────────────────────────────────────
    st.divider()
    st.markdown("### 5️⃣ Save Output")
    st.caption(
        f"Save this file to your project at:\n"
        f"`{os.path.join(PROJECT_ROOT, 'data', 'logs', out_name)}`\n"
        "then use it as the Sysmon input when running the pipeline."
    )

    st.download_button(
        f"📥 Download {out_name}",
        data=json.dumps(events, indent=2, ensure_ascii=False),
        file_name=out_name,
        mime="application/json",
        use_container_width=True
    )