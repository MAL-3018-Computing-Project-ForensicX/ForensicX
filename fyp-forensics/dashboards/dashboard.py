"""
dashboard.py — ForensicX Main Dashboard
In this version:
  - Added Memory_Analysis.py page (new Volatility 3 GUI)
  - Added Volatility pslist.txt path input in Analysis Configuration
  - Removed redundant "Sysmon Network" input field (covered by Sysmon All)
  - Added nav card for Memory Analysis
  - Cloud token cache inputs removed from here (handled in google_drive.py / onedrive.py)
"""
import sys
import os
import streamlit as st
from datetime import datetime

# ── Path setup ────────────────────────────────────────────────────────────────
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# ── Page config (MUST be first Streamlit command) ─────────────────────────────
st.set_page_config(
    page_title="ForensicX Dashboard",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── Orchestrator import ───────────────────────────────────────────────────────
try:
    from modules.orchestrator import run_pipeline
    HAS_ORCHESTRATOR = True
except ImportError as e:
    HAS_ORCHESTRATOR = False
    run_pipeline = None

# ── CSS ───────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
.main-header { font-size:2.4rem; font-weight:700; color:#1f4e79; margin-bottom:0.3rem; }
.sub-header  { font-size:1.05rem; color:#666; margin-bottom:1.5rem; }
.nav-card    {
    background: linear-gradient(135deg, #1f4e79 0%, #2e75b6 100%);
    color: white; padding:1.2rem; border-radius:0.5rem;
    text-align:center; margin-bottom:0.8rem;
}
.nav-card-green {
    background: linear-gradient(135deg, #375623 0%, #70ad47 100%);
    color: white; padding:1.2rem; border-radius:0.5rem;
    text-align:center; margin-bottom:0.8rem;
}
.nav-card-purple {
    background: linear-gradient(135deg, #4a235a 0%, #8e44ad 100%);
    color: white; padding:1.2rem; border-radius:0.5rem;
    text-align:center; margin-bottom:0.8rem;
}
</style>
""", unsafe_allow_html=True)

# ── Sidebar: page navigation ──────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🔒 ForensicX")
    st.markdown("---")

    pages_dir = os.path.join(os.path.dirname(__file__), "pages")

    PAGE_GROUPS = {
        "📊 Analysis": [
            ("Event_Timeline.py",        "🕐 Event Timeline"),
            ("Endpoint_Risk_Summary.py", "🛡️ Endpoint Risk"),
            ("Process_Explorer.py",      "🔬 Process Explorer"),
            ("IOC_Hits.py",              "🎯 IOC Hits"),
        ],
        "☁️ Cloud": [
            ("Cloud_Attack_Chain.py",  "🔗 Attack Chain"),
            ("Cloud_Risk_Analysis.py", "☁️ Cloud Risk"),
        ],
        "📁 Filesystem": [
            ("Snapshot_Manager.py",  "📁 Snapshot Manager"),
            ("Snapshot_Changes.py",  "📸 Snapshot Changes"),
        ],
        "🛠️ Tools": [
            ("EVTX_Parser.py",      "📋 EVTX Parser"),
            ("Memory_Analysis.py",  "🧠 Memory Analysis"),  # ← NEW
        ],
        "📄 Reports": [
            ("Reports.py", "📄 Reports & Evidence"),
        ],
    }

    for group, pages in PAGE_GROUPS.items():
        st.markdown(f"**{group}**")
        for fname, label in pages:
            fpath = os.path.join(pages_dir, fname)
            if os.path.exists(fpath):
                st.page_link(f"pages/{fname}", label=label)
            else:
                st.caption(f"  _(missing: {fname})_")
        st.markdown("")

    st.markdown("---")
    st.caption(f"Last refreshed: {datetime.now():%H:%M:%S}")

# ── Header ────────────────────────────────────────────────────────────────────
st.markdown('<h1 class="main-header">🔒 ForensicX Dashboard</h1>', unsafe_allow_html=True)
st.markdown(
    '<p class="sub-header">Unified digital forensic framework for ransomware & cloud attack detection</p>',
    unsafe_allow_html=True
)

# ── Quick nav cards ───────────────────────────────────────────────────────────
st.markdown("### Quick Navigation")

def page_exists(fname):
    return os.path.exists(os.path.join(pages_dir, fname))

# Row 1
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.markdown('<div class="nav-card"><h3>🕐 Timeline</h3><p>Chronological events</p></div>',
                unsafe_allow_html=True)
    if page_exists("Event_Timeline.py") and st.button("Open Timeline", use_container_width=True, key="btn_timeline"):
        st.switch_page("pages/Event_Timeline.py")

with col2:
    st.markdown('<div class="nav-card"><h3>🛡️ Risk Summary</h3><p>Threat scores</p></div>',
                unsafe_allow_html=True)
    if page_exists("Endpoint_Risk_Summary.py") and st.button("Open Risk Summary", use_container_width=True, key="btn_risk"):
        st.switch_page("pages/Endpoint_Risk_Summary.py")

with col3:
    st.markdown('<div class="nav-card"><h3>🔗 Attack Chain</h3><p>Cloud exfiltration</p></div>',
                unsafe_allow_html=True)
    if page_exists("Cloud_Attack_Chain.py") and st.button("Open Attack Chain", use_container_width=True, key="btn_cloud"):
        st.switch_page("pages/Cloud_Attack_Chain.py")

with col4:
    st.markdown('<div class="nav-card-purple"><h3>🧠 Memory</h3><p>Volatility 3 analysis</p></div>',
                unsafe_allow_html=True)
    if page_exists("Memory_Analysis.py") and st.button("Open Memory Analysis", use_container_width=True, key="btn_mem"):
        st.switch_page("pages/Memory_Analysis.py")

# Row 2
col5, col6, col7, col8 = st.columns(4)

with col5:
    st.markdown('<div class="nav-card-green"><h3>📋 EVTX Parser</h3><p>Parse .evtx logs</p></div>',
                unsafe_allow_html=True)
    if page_exists("EVTX_Parser.py") and st.button("Open EVTX Parser", use_container_width=True, key="btn_evtx"):
        st.switch_page("pages/EVTX_Parser.py")

with col6:
    st.markdown('<div class="nav-card-green"><h3>📁 Snapshots</h3><p>Take & compare</p></div>',
                unsafe_allow_html=True)
    if page_exists("Snapshot_Manager.py") and st.button("Open Snapshot Manager", use_container_width=True, key="btn_snap"):
        st.switch_page("pages/Snapshot_Manager.py")

with col7:
    st.markdown('<div class="nav-card"><h3>🔬 Processes</h3><p>Explore per-process</p></div>',
                unsafe_allow_html=True)
    if page_exists("Process_Explorer.py") and st.button("Open Process Explorer", use_container_width=True, key="btn_proc"):
        st.switch_page("pages/Process_Explorer.py")

with col8:
    st.markdown('<div class="nav-card"><h3>📄 Reports</h3><p>Download outputs</p></div>',
                unsafe_allow_html=True)
    if page_exists("Reports.py") and st.button("Open Reports", use_container_width=True, key="btn_reports"):
        st.switch_page("pages/Reports.py")

st.markdown("---")

# ── Analysis configuration ────────────────────────────────────────────────────
with st.expander("⚙️ Analysis Configuration", expanded=True):

    st.markdown("#### Data Sources")
    col1, col2 = st.columns(2)
    with col1:
        snapshots = st.checkbox("Filesystem Snapshots", value=True)
        sysmon    = st.checkbox("Sysmon Logs",          value=True)
        memory    = st.checkbox("Memory Analysis (Volatility)", value=False,
                                help="Reads report/pslist.txt — run Volatility first via Memory Analysis page")
    with col2:
        behavior  = st.checkbox("Behavior Analysis",   value=True)
        cloud     = st.checkbox("Cloud Metadata",       value=False,
                                help="Collects from Google Drive & OneDrive — requires login each time")
        reports   = st.checkbox("Generate Reports",     value=True)

    st.markdown("#### Input File Paths")
    col1, col2 = st.columns(2)
    with col1:
        sysmon_all      = st.text_input(
            "Sysmon All Events (JSON)",
            "data/logs/sysmon_all.json",
            help="Main Sysmon log file — covers all event types including network"
        )
        before_snapshot = st.text_input("Before Snapshot", "snapshots/before.json")

    with col2:
        # ── CHANGED: replaced Sysmon Network with Volatility pslist path ──────
        pslist_path     = st.text_input(
            "Volatility pslist.txt",
            "report/pslist.txt",
            help="Output from: vol -f memory.raw windows.pslist > report/pslist.txt"
        )
        after_snapshot  = st.text_input("After Snapshot",  "snapshots/after.json")

    st.caption(
        "ℹ️ **Sysmon All** already captures network events (EID 3). "
        "A separate Sysmon Network file is not needed. "
        "For memory analysis, generate `pslist.txt` from the 🧠 Memory Analysis page first."
    )


def make_abs(path):
    return path if os.path.isabs(path) else os.path.abspath(os.path.join(parent_dir, path))


config = {
    "snapshots": snapshots,
    "sysmon":    sysmon,
    "memory":    memory,
    "behavior":  behavior,
    "cloud":     cloud,
    "cloud_endpoint": cloud,
    "reports":   reports,
    "paths": {
        "sysmon_all":      make_abs(sysmon_all),
        "sysmon_network":  "",           # intentionally empty — covered by sysmon_all
        "before_snapshot": make_abs(before_snapshot),
        "after_snapshot":  make_abs(after_snapshot),
        "pslist":          make_abs(pslist_path),   # ← NEW field for orchestrator
    }
}

# ── Run button ────────────────────────────────────────────────────────────────
col1, col2, col3 = st.columns([1, 2, 1])
with col2:
    run_btn = st.button(
        "🚀 Run Forensic Analysis",
        type="primary",
        use_container_width=True,
        disabled=not HAS_ORCHESTRATOR
    )

if not HAS_ORCHESTRATOR:
    st.warning("⚠️ Orchestrator module not found — cannot run pipeline from dashboard.")

if run_btn and HAS_ORCHESTRATOR:
    with st.spinner("Running analysis pipeline..."):
        try:
            result = run_pipeline(config)
            if result.get("success"):
                st.success("✅ Analysis complete!")
                stats = result.get("stats", {})
                if stats:
                    s1, s2, s3, s4 = st.columns(4)
                    s1.metric("Events",       f"{stats.get('endpoint_events', 0):,}")
                    s2.metric("Processes",    f"{stats.get('behavior_processes', 0):,}")
                    s3.metric("High Risk",    stats.get("high_risk_processes", 0))
                    s4.metric("Cloud Events", stats.get("cloud_risk_entries", 0))

                st.markdown("#### View Results")
                r1, r2, r3 = st.columns(3)
                with r1:
                    if page_exists("Event_Timeline.py") and st.button("→ Timeline", use_container_width=True):
                        st.switch_page("pages/Event_Timeline.py")
                with r2:
                    if page_exists("Endpoint_Risk_Summary.py") and st.button("→ Risk Summary", use_container_width=True):
                        st.switch_page("pages/Endpoint_Risk_Summary.py")
                with r3:
                    if page_exists("Reports.py") and st.button("→ Reports", use_container_width=True):
                        st.switch_page("pages/Reports.py")
            else:
                st.error(f"❌ Analysis failed: {result.get('message', 'Unknown error')}")
                for err in result.get("errors", []):
                    st.write(f"- {err}")
        except Exception as exc:
            st.error(f"❌ Pipeline error: {exc}")

# ── File status ───────────────────────────────────────────────────────────────
with st.expander("📂 Input File Status"):
    col1, col2 = st.columns(2)

    def check_file(col, filepath, label):
        if filepath and os.path.exists(filepath):
            col.success(f"✅ {label} ({os.path.getsize(filepath):,} B)")
        else:
            col.error(f"❌ {label}: not found")

    with col1:
        check_file(col1, config["paths"]["sysmon_all"],      "Sysmon All")
        check_file(col1, config["paths"]["before_snapshot"], "Before Snapshot")

    with col2:
        check_file(col2, config["paths"]["pslist"],          "Volatility pslist.txt")
        check_file(col2, config["paths"]["after_snapshot"],  "After Snapshot")

st.markdown("---")
st.caption(f"ForensicX Dashboard  ·  {datetime.now():%Y-%m-%d %H:%M:%S}")