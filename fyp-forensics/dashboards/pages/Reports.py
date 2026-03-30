"""
Reports & Evidence — Dashboard Page
Download all generated reports and inspect the chain-of-custody manifest.
FIX: relative paths → absolute paths.
FIX: "forensic_report.pdf" → "correlation.pdf" (actual output filename).
"""
import sys
import os
import json
import streamlit as st

# ── Path fix ─────────────────────────────────────────────────────────────────
_PAGE_DIR  = os.path.dirname(os.path.abspath(__file__))
_DASH_DIR  = os.path.abspath(os.path.join(_PAGE_DIR, ".."))
ROOT_DIR   = os.path.abspath(os.path.join(_PAGE_DIR, "../.."))
REPORT_DIR = os.path.join(ROOT_DIR, "report")
if _DASH_DIR not in sys.path:
    sys.path.insert(0, _DASH_DIR)

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(page_title="Reports & Evidence", page_icon="📄", layout="wide")

st.title("📄 Reports & Evidence")
st.caption("Download forensic reports and inspect the chain-of-custody evidence manifest")

# ── Report file definitions ───────────────────────────────────────────────────
# FIX: was "forensic_report.pdf" — actual pipeline output is "correlation.pdf"
REPORT_FILES = [
    {
        "path":  os.path.join(REPORT_DIR, "correlation.pdf"),
        "label": "📑 Full Forensic Report",
        "ext":   "PDF",
        "desc":  "Complete analysis with executive summary, process timeline, and risk assessment. "
                 "Recommended for sharing with management or non-technical stakeholders.",
        "mime":  "application/pdf",
    },
    {
        "path":  os.path.join(REPORT_DIR, "correlation.txt"),
        "label": "📝 Text Report",
        "ext":   "TXT",
        "desc":  "Plain-text version of the full report. Suitable for archiving or pasting into tickets.",
        "mime":  "text/plain",
    },
    {
        "path":  os.path.join(REPORT_DIR, "forensic_report.json"),
        "label": "🗂️ Forensic Report Data",
        "ext":   "JSON",
        "desc":  "Structured report data with metadata and executive summary. Used by external tools.",
        "mime":  "application/json",
    },
    {
        "path":  os.path.join(REPORT_DIR, "correlation.json"),
        "label": "⚙️ Raw Correlation Data",
        "ext":   "JSON",
        "desc":  "Raw process-event correlation output from the pipeline (used by dashboard pages).",
        "mime":  "application/json",
    },
    {
        "path":  os.path.join(REPORT_DIR, "endpoint_risk_summary.json"),
        "label": "🛡️ Endpoint Risk Summary",
        "ext":   "JSON",
        "desc":  "Per-process risk scores and overall endpoint risk level.",
        "mime":  "application/json",
    },
    {
        "path":  os.path.join(REPORT_DIR, "cloud_risk_summary.json"),
        "label": "☁️ Cloud Risk Summary",
        "ext":   "JSON",
        "desc":  "Cloud account behaviour analysis and burst activity findings.",
        "mime":  "application/json",
    },
    {
        "path":  os.path.join(REPORT_DIR, "cloud_endpoint_correlations.json"),
        "label": "🔗 Cloud-Endpoint Correlations",
        "ext":   "JSON",
        "desc":  "Linked cloud and endpoint events forming attack chains.",
        "mime":  "application/json",
    },
    {
        "path":  os.path.join(REPORT_DIR, "manifest.json"),
        "label": "🔏 Evidence Manifest",
        "ext":   "JSON",
        "desc":  "SHA-256 hashes and audit trail for all forensic artifacts (chain of custody).",
        "mime":  "application/json",
    },
]

available = [r for r in REPORT_FILES if os.path.exists(r["path"])]
missing   = [r for r in REPORT_FILES if not os.path.exists(r["path"])]

c1, c2 = st.columns(2)
c1.metric("Reports Available", len(available))
c2.metric("Not Yet Generated", len(missing))

if missing:
    with st.expander(f"⚠️ {len(missing)} file(s) not yet generated — run the pipeline"):
        for r in missing:
            st.write(f"- **{r['label']}** (`{os.path.basename(r['path'])}`)")

st.divider()

# ── Download section ──────────────────────────────────────────────────────────
st.markdown("### 📥 Download Reports")

for r in REPORT_FILES:
    exists = os.path.exists(r["path"])
    size   = f"{os.path.getsize(r['path']):,} bytes" if exists else "not generated"

    col1, col2 = st.columns([4, 1])
    with col1:
        status = "✅" if exists else "❌"
        st.markdown(f"**{status} {r['label']}** `[{r['ext']}]` — {size}")
        st.caption(r["desc"])
    with col2:
        if exists:
            with open(r["path"], "rb") as fh:
                st.download_button(
                    "⬇️ Download",
                    data=fh,
                    file_name=os.path.basename(r["path"]),
                    mime=r["mime"],
                    use_container_width=True,
                    key=f"dl_{os.path.basename(r['path'])}"
                )
        else:
            st.button("Unavailable", disabled=True, use_container_width=True,
                      key=f"na_{os.path.basename(r['path'])}")
    st.markdown("---")

# ── Evidence Manifest preview ─────────────────────────────────────────────────
st.markdown("### 🔏 Evidence Chain-of-Custody")
st.caption(
    "The manifest records the SHA-256 hash of every forensic artifact so you can prove "
    "the files have not been tampered with since collection."
)

manifest_path = os.path.join(REPORT_DIR, "manifest.json")
if os.path.exists(manifest_path):
    try:
        manifest   = json.load(open(manifest_path, "r", encoding="utf-8"))
        artifacts  = manifest.get("artifacts", [])
        audit_log  = manifest.get("audit", [])
        generated  = manifest.get("generated", "Unknown")

        mc1, mc2, mc3 = st.columns(3)
        mc1.metric("Artifacts Tracked", len(artifacts))
        mc2.metric("Audit Entries",     len(audit_log))
        mc3.metric("Manifest Created",  str(generated)[:19])

        if artifacts:
            st.markdown("#### Tracked Artifacts")
            rows = [{
                "File":    os.path.basename(a.get("path","")),
                "Role":    a.get("role",""),
                "SHA-256": (str(a.get("sha256",""))[:24]+"…") if a.get("sha256") else "N/A",
                "Size":    f"{a.get('size',0):,} B" if a.get("size") else "N/A",
                "Added":   str(a.get("added",""))[:19],
            } for a in artifacts]
            st.dataframe(rows, use_container_width=True, hide_index=True)

        if audit_log:
            st.markdown("#### Audit Trail")
            st.dataframe([{
                "Time":   str(e.get("time",""))[:19],
                "Actor":  e.get("actor",""),
                "Action": e.get("action",""),
                "Note":   e.get("note",""),
            } for e in audit_log], use_container_width=True, hide_index=True)

        with st.expander("🔍 View Raw Manifest JSON"):
            st.json(manifest)

    except Exception as exc:
        st.error(f"Error reading manifest: {exc}")
else:
    st.warning("⚠️ manifest.json not found — run the pipeline to generate it.")

st.markdown("---")
st.caption(f"📁 Report directory: `{REPORT_DIR}`")