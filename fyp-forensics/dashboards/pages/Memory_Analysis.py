"""
Memory Analysis (Volatility 3) — Dashboard Page

GUI wrapper for Volatility 3 memory forensics.
Users can:
  1. Upload a memory dump OR point to a local path
  2. Run a SINGLE plugin  OR  run ALL plugins at once
  3. View structured results with filter & download
  4. Load a previously-generated result file (e.g. report/pslist.txt)
  5. Generate a combined report when running all plugins (single file)

Project paths:
  memory dumps  →  data/memory_dumps/
  results       →  report/<plugin>.txt
  combined      →  report/combined_memory_report.txt
"""

import sys
import os
import subprocess
import tempfile
import re
import streamlit as st
import pandas as pd
from datetime import datetime

# ── Path fix ─────────────────────────────────────────────────────────────────
_PAGE_DIR    = os.path.dirname(os.path.abspath(__file__))
_DASH_DIR    = os.path.abspath(os.path.join(_PAGE_DIR, ".."))
PROJECT_ROOT = os.path.abspath(os.path.join(_PAGE_DIR, "../.."))
REPORT_DIR   = os.path.join(PROJECT_ROOT, "report")
MEMORY_DIR   = os.path.join(PROJECT_ROOT, "data", "memory_dumps")
if _DASH_DIR not in sys.path:
    sys.path.insert(0, _DASH_DIR)

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(page_title="Memory Analysis", page_icon="🧠", layout="wide")

st.title("🧠 Memory Analysis — Volatility 3")
st.caption(
    "Run Volatility 3 memory forensic plugins directly from the dashboard. "
    "Upload a memory dump or point to one on disk, then choose a plugin or run all."
)

# ── Plugin catalogue ──────────────────────────────────────────────────────────
PLUGINS = {
    "windows.pslist":               "Process List — running processes at dump time",
    "windows.psscan":               "Process Scan — finds hidden/unlinked processes",
    "windows.cmdline":              "Command Lines — full command line of each process",
    "windows.dlllist":              "DLL List — loaded DLLs per process",
    "windows.netscan":              "Network Scan — open connections & listening ports",
    "windows.netstat":              "Netstat — active connections (Win 8+)",
    "windows.malfind":              "Malfind — injected/suspicious memory regions",
    "windows.handles":              "Handles — open handles per process",
    "windows.svcscan":              "Service Scan — installed Windows services",
    "windows.registry.hivelist":    "Registry Hive List — mounted registry hives",
    "windows.filescan":             "File Scan — open file objects in memory",
}

# Output filename mapping (legacy-compatible names for pipeline use)
PLUGIN_FILENAMES = {
    "windows.pslist":            "pslist.txt",
    "windows.psscan":            "psscan.txt",
    "windows.cmdline":           "cmdline.txt",
    "windows.dlllist":           "dlllist.txt",
    "windows.netscan":           "netscan.txt",
    "windows.netstat":           "netstat.txt",
    "windows.malfind":           "malfind.txt",
    "windows.handles":           "handles.txt",
    "windows.svcscan":           "svcscan.txt",
    "windows.registry.hivelist": "hivelist.txt",
    "windows.filescan":          "filescan.txt",
}

# ── Helpers ───────────────────────────────────────────────────────────────────

def find_vol3():
    for cmd in ["vol", "vol3", "volatility3"]:
        try:
            result = subprocess.run(
                [cmd, "--help"], capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 or "volatility" in (result.stdout + result.stderr).lower():
                return cmd
        except Exception:
            continue
    return None


def run_volatility(vol_cmd, memory_path, plugin, extra_args=""):
    cmd = [vol_cmd, "-f", memory_path, plugin]
    if extra_args.strip():
        cmd += extra_args.strip().split()
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "ERROR: Analysis timed out after 5 minutes.", 1
    except Exception as e:
        return "", f"ERROR: {e}", 1


def parse_vol_output(raw_text):
    """Parse Volatility 3 tab/space-separated text table → (headers, rows)."""
    lines = [l for l in raw_text.splitlines() if l.strip()]
    header_line = None
    data_lines  = []
    for line in lines:
        if line.startswith("*") or "Progress" in line or "Stacking" in line:
            continue
        if header_line is None:
            header_line = line
        else:
            if not line.startswith("---"):
                data_lines.append(line)

    if not header_line:
        return [], []

    headers = re.split(r'\s{2,}|\t', header_line.strip())
    headers = [h.strip() for h in headers if h.strip()]

    rows = []
    for line in data_lines:
        parts = re.split(r'\s{2,}|\t', line.strip(), maxsplit=max(len(headers) - 1, 1))
        parts = [p.strip() for p in parts]
        while len(parts) < len(headers):
            parts.append("")
        rows.append(dict(zip(headers, parts)))

    return headers, rows


def get_out_path(plugin):
    fname = PLUGIN_FILENAMES.get(plugin, plugin.replace(".", "_") + ".txt")
    return os.path.join(REPORT_DIR, fname)


# ── Check Volatility ──────────────────────────────────────────────────────────
vol_cmd       = find_vol3()
vol_available = vol_cmd is not None

if not vol_available:
    st.warning(
        "⚠️ Volatility 3 not found on PATH. "
        "You can still **load existing result files** below. "
        "To enable live analysis: `pip install volatility3`"
    )
else:
    st.success(f"✅ Volatility 3 detected: `{vol_cmd}`")

st.divider()

# ── TABS ──────────────────────────────────────────────────────────────────────
tab1, tab2, tab3 = st.tabs(["🔬 Run Analysis", "📂 Load Existing Result", "📋 Plugin Reference"])

# ═══════════════════════════════════════════════════════════════════════════════
# TAB 1 — RUN ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════
with tab1:

    if not vol_available:
        st.error("❌ Volatility 3 is not installed. Use the Load Existing Result tab.")
        st.stop()

    # ── Step 1: Memory dump source ────────────────────────────────────────────
    st.markdown("### Step 1 — Memory Dump Source")

    source_mode = st.radio(
        "How to provide the memory dump?",
        ["Upload file", "Enter local path"],
        horizontal=True
    )

    memory_path = None
    tmp_path    = None

    if source_mode == "Upload file":
        uploaded = st.file_uploader(
            "Upload memory dump",
            type=["raw", "mem", "dmp", "vmem", "bin"],
        )
        if uploaded:
            suffix   = os.path.splitext(uploaded.name)[1] or ".raw"
            tf       = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
            tf.write(uploaded.read())
            tf.flush()
            tf.close()
            memory_path = tf.name
            tmp_path    = tf.name
            st.success(f"✅ Uploaded: **{uploaded.name}** ({uploaded.size:,} bytes)")
    else:
        existing = []
        if os.path.exists(MEMORY_DIR):
            for f in os.listdir(MEMORY_DIR):
                if f.endswith((".raw", ".mem", ".dmp", ".vmem", ".bin")):
                    existing.append(os.path.join(MEMORY_DIR, f))
        if existing:
            for d in existing:
                st.caption(f"📁 Found: `{d}` ({os.path.getsize(d)/(1024*1024):.1f} MB)")

        manual = st.text_input(
            "Full path to memory dump",
            value=existing[0] if existing else os.path.join(MEMORY_DIR, "memory.raw"),
        )
        if manual:
            if not os.path.isabs(manual):
                manual = os.path.join(PROJECT_ROOT, manual)
            if os.path.exists(manual):
                st.success(f"✅ Found: `{manual}` ({os.path.getsize(manual)/(1024*1024):.1f} MB)")
                memory_path = manual
            else:
                st.error(f"❌ File not found: `{manual}`")

    st.divider()

    # ── Step 2: Plugin selection ──────────────────────────────────────────────
    st.markdown("### Step 2 — Choose Plugin(s)")

    run_mode = st.radio(
        "Run mode",
        ["Single plugin", "All plugins (batch)"],
        horizontal=True,
        help="'All plugins' runs every plugin one by one and saves each result to report/"
    )

    plugins_to_run = []
    combined_report = False

    if run_mode == "Single plugin":
        col1, col2 = st.columns([1, 2])
        with col1:
            selected = st.selectbox(
                "Plugin",
                list(PLUGINS.keys()),
            )
        with col2:
            st.info(f"**What this does:** {PLUGINS[selected]}")

        extra_args = st.text_input(
            "Additional arguments (optional)",
            placeholder="e.g. --pid 1234",
        )
        plugins_to_run = [(selected, extra_args)]

    else:
        st.info(
            "**All plugins** will run in sequence. Each result is saved to `report/<plugin>.txt`. "
            "This may take several minutes depending on memory dump size."
        )
        # Optionally let user deselect specific ones
        with st.expander("⚙️ Customise — deselect plugins you don't need", expanded=False):
            selected_all = {}
            for p, desc in PLUGINS.items():
                selected_all[p] = st.checkbox(f"`{p}` — {desc}", value=True, key=f"chk_{p}")
        plugins_to_run = [
            (p, "") for p, checked in selected_all.items() if checked
        ] if "selected_all" in dir() else [
            (p, "") for p in PLUGINS
        ]

        # New: checkbox for combined report
        combined_report = st.checkbox(
            "Generate combined report (single file with all plugins)",
            value=True,
            help="Creates a single report file `combined_memory_report.txt` in report/ with all plugin outputs."
        )

    save_result = st.checkbox(
        "Save results to report/ directory",
        value=True,
        help="Saves each plugin output so the pipeline can use them"
    )

    st.divider()

    # ── Step 3: Run ───────────────────────────────────────────────────────────
    st.markdown("### Step 3 — Run")

    if not memory_path:
        st.warning("⚠️ Please provide a memory dump in Step 1 first.")
    else:
        if run_mode == "Single plugin":
            btn_label = f"🔬 Run {plugins_to_run[0][0]}"
        else:
            btn_label = f"🔬 Run All {len(plugins_to_run)} Plugins"

        run_btn = st.button(btn_label, type="primary", use_container_width=True)

        if run_btn:
            os.makedirs(REPORT_DIR, exist_ok=True)

            all_results = {}   # plugin → {"raw": str, "headers": list, "rows": list, "saved_to": str}
            errors      = {}
            all_stdouts = {}   # for combined report

            progress_bar = st.progress(0.0, text="Starting…")
            status_box   = st.empty()

            for idx, (plugin, extra) in enumerate(plugins_to_run):
                pct = idx / len(plugins_to_run)
                progress_bar.progress(pct, text=f"Running {plugin}…")
                status_box.caption(f"`{vol_cmd} -f {os.path.basename(memory_path)} {plugin}`")

                stdout, stderr, rc = run_volatility(vol_cmd, memory_path, plugin, extra)

                if rc != 0 and not stdout:
                    errors[plugin] = stderr or f"Exit code {rc}"
                    continue

                if stdout:
                    all_stdouts[plugin] = stdout

                saved_to = ""
                if save_result and stdout:
                    out_path = get_out_path(plugin)
                    with open(out_path, "w", encoding="utf-8") as f:
                        f.write(stdout)
                    saved_to = out_path

                headers, rows = parse_vol_output(stdout)
                all_results[plugin] = {
                    "raw":      stdout,
                    "headers":  headers,
                    "rows":     rows,
                    "saved_to": saved_to,
                    "stderr":   stderr,
                }

            progress_bar.progress(1.0, text="Done!")
            status_box.empty()

            # Clean up temp file
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass

            # Generate combined report if requested and any plugins succeeded
            combined_text = ""
            combined_path = ""
            if run_mode == "All plugins (batch)" and combined_report and all_stdouts:
                combined_path = os.path.join(REPORT_DIR, "combined_memory_report.txt")
                with open(combined_path, "w", encoding="utf-8") as f:
                    f.write(f"# Combined Memory Analysis Report\n")
                    f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"# Memory dump: {os.path.basename(memory_path)}\n")
                    f.write(f"# Plugins run: {len(all_stdouts)} of {len(plugins_to_run)}\n\n")
                    for plugin, out in all_stdouts.items():
                        f.write(f"\n{'='*60}\n")
                        f.write(f"## Plugin: {plugin}\n")
                        f.write(f"{'='*60}\n\n")
                        f.write(out)
                        f.write("\n\n")
                with open(combined_path, "r", encoding="utf-8") as f:
                    combined_text = f.read()
                st.success(f"✅ Combined report saved to `{combined_path}`")

            # Store in session state
            st.session_state["mem_results"]      = all_results
            st.session_state["mem_errors"]       = errors
            st.session_state["mem_run_time"]     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            st.session_state["mem_dump_name"]    = os.path.basename(memory_path)
            st.session_state["combined_report_text"] = combined_text
            st.session_state["combined_report_path"] = combined_path

            if all_results:
                st.success(f"✅ Completed {len(all_results)} plugin(s) successfully.")
            if errors:
                st.error(f"❌ {len(errors)} plugin(s) failed.")
                for p, msg in errors.items():
                    st.caption(f"  `{p}`: {msg[:200]}")

        # ── Display results ───────────────────────────────────────────────────
        if "mem_results" in st.session_state and st.session_state["mem_results"]:
            results  = st.session_state["mem_results"]
            run_time = st.session_state.get("mem_run_time", "")
            dump_nm  = st.session_state.get("mem_dump_name", "")
            combined_text = st.session_state.get("combined_report_text", "")
            combined_path = st.session_state.get("combined_report_path", "")

            st.divider()
            st.markdown(f"### Results — `{dump_nm}` at {run_time}")

            # If multiple plugins, show a tab per plugin
            if len(results) == 1:
                plugin_tabs = [list(results.keys())[0]]
            else:
                plugin_tabs = list(results.keys())

            if len(plugin_tabs) > 1:
                result_tabs = st.tabs([p.split(".")[-1] for p in plugin_tabs])
                tab_map     = dict(zip(plugin_tabs, result_tabs))
            else:
                tab_map = {plugin_tabs[0]: st.container()}

            for plugin, container in tab_map.items():
                with container:
                    data = results[plugin]
                    rows = data["rows"]

                    # Saved path info
                    if data["saved_to"]:
                        st.caption(f"💾 Saved to `{data['saved_to']}`")

                    if data.get("stderr") and "error" in data["stderr"].lower():
                        with st.expander("⚠️ Warnings"):
                            st.code(data["stderr"][:2000])

                    if rows:
                        df = pd.DataFrame(rows)
                        st.metric("Rows", f"{len(df):,}")

                        # Quick suspicious-process highlight for pslist/psscan
                        if plugin in ("windows.pslist", "windows.psscan"):
                            sus_names = ["cmd.exe","powershell","wscript","cscript",
                                         "mshta","certutil","rundll32","regsvr32"]
                            name_col = next(
                                (c for c in df.columns if "image" in c.lower() or "name" in c.lower()),
                                None
                            )
                            if name_col:
                                susp = df[df[name_col].str.lower().str.contains(
                                    "|".join(sus_names), na=False)]
                                if not susp.empty:
                                    st.warning(
                                        f"⚠️ {len(susp)} potentially suspicious process name(s) found"
                                    )

                        search = st.text_input(
                            "🔍 Filter", key=f"search_{plugin}",
                            placeholder="e.g. powershell"
                        )
                        if search:
                            mask = df.apply(
                                lambda c: c.astype(str).str.contains(search, case=False, na=False)
                            ).any(axis=1)
                            df = df[mask]

                        st.dataframe(df, use_container_width=True, hide_index=True, height=420)

                        col1, col2 = st.columns(2)
                        with col1:
                            st.download_button(
                                "📥 CSV",
                                df.to_csv(index=False),
                                f"{plugin.replace('.','_')}.csv",
                                "text/csv",
                                use_container_width=True,
                                key=f"csv_{plugin}"
                            )
                        with col2:
                            st.download_button(
                                "📥 TXT",
                                data["raw"],
                                f"{plugin.replace('.','_')}.txt",
                                "text/plain",
                                use_container_width=True,
                                key=f"txt_{plugin}"
                            )
                        with st.expander("📄 Raw output"):
                            st.code(data["raw"][:8000], language="text")
                    else:
                        st.warning("No structured data found. Showing raw output:")
                        st.code(data["raw"][:5000])

            # Show combined report section if it exists
            if combined_text:
                st.divider()
                st.markdown("### Combined Report")
                if combined_path:
                    st.caption(f"💾 Saved to `{combined_path}`")
                with st.expander("📄 View Combined Report", expanded=False):
                    st.code(combined_text[:20000], language="text")
                col1, col2 = st.columns(2)
                with col1:
                    st.download_button(
                        "📥 Download Combined Report (TXT)",
                        combined_text,
                        "combined_memory_report.txt",
                        "text/plain",
                        use_container_width=True
                    )

# ═══════════════════════════════════════════════════════════════════════════════
# TAB 2 — LOAD EXISTING RESULT
# ═══════════════════════════════════════════════════════════════════════════════
with tab2:

    st.markdown("### Load a Previously Saved Volatility Result")
    st.caption(
        "Load output files generated by CLI (e.g. `vol -f memory.raw windows.pslist > report/pslist.txt`) "
        "or from a previous run of this page."
    )

    # Show available files in report/
    existing_txts = []
    if os.path.exists(REPORT_DIR):
        for f in sorted(os.listdir(REPORT_DIR)):
            if f.endswith(".txt"):
                existing_txts.append(os.path.join(REPORT_DIR, f))

    if existing_txts:
        st.markdown(f"**{len(existing_txts)} text file(s) in `{REPORT_DIR}`:**")
        for f in existing_txts:
            st.caption(f"  📄 `{os.path.basename(f)}` ({os.path.getsize(f):,} bytes)")
        st.markdown("")

    load_mode = st.radio(
        "Source",
        ["Select from report/", "Upload file", "Enter path"],
        horizontal=True
    )

    loaded_text  = None
    loaded_label = None

    if load_mode == "Select from report/":
        if existing_txts:
            chosen = st.selectbox("Choose file", existing_txts, format_func=os.path.basename)
            if st.button("📂 Load", use_container_width=True):
                with open(chosen, "r", encoding="utf-8", errors="ignore") as f:
                    loaded_text  = f.read()
                loaded_label = os.path.basename(chosen)
                st.success(f"✅ Loaded `{loaded_label}`")
        else:
            st.info("No .txt files found in report/ yet.")

    elif load_mode == "Upload file":
        up = st.file_uploader("Upload .txt result", type=["txt"])
        if up:
            loaded_text  = up.read().decode("utf-8", errors="ignore")
            loaded_label = up.name
            st.success(f"✅ Loaded `{loaded_label}`")

    else:
        mp = st.text_input("Path", value=os.path.join(REPORT_DIR, "pslist.txt"))
        if st.button("📂 Load file"):
            if os.path.exists(mp):
                with open(mp, "r", encoding="utf-8", errors="ignore") as f:
                    loaded_text  = f.read()
                loaded_label = os.path.basename(mp)
                st.success(f"✅ Loaded `{loaded_label}`")
            else:
                st.error(f"❌ Not found: `{mp}`")

    if loaded_text:
        st.session_state["loaded_vol_text"]  = loaded_text
        st.session_state["loaded_vol_label"] = loaded_label

    if "loaded_vol_text" in st.session_state:
        raw   = st.session_state["loaded_vol_text"]
        label = st.session_state.get("loaded_vol_label", "result.txt")

        st.divider()
        st.markdown(f"### Viewing: `{label}`")

        _, rows = parse_vol_output(raw)
        if rows:
            df = pd.DataFrame(rows)
            st.metric("Rows", f"{len(df):,}")

            s = st.text_input("🔍 Filter", key="tab2_filter")
            if s:
                mask = df.apply(lambda c: c.astype(str).str.contains(s, case=False, na=False)).any(axis=1)
                df = df[mask]

            st.dataframe(df, use_container_width=True, hide_index=True, height=500)

            col1, col2 = st.columns(2)
            with col1:
                st.download_button("📥 CSV", df.to_csv(index=False), label.replace(".txt", ".csv"),
                                   "text/csv", use_container_width=True)
            with col2:
                st.download_button("📥 TXT", raw, label, "text/plain", use_container_width=True)
        else:
            st.warning("Could not parse structured data. Showing raw:")
            st.code(raw[:8000])

        if st.button("🗑️ Clear"):
            del st.session_state["loaded_vol_text"]
            del st.session_state["loaded_vol_label"]
            st.rerun()

# ═══════════════════════════════════════════════════════════════════════════════
# TAB 3 — PLUGIN REFERENCE
# ═══════════════════════════════════════════════════════════════════════════════
with tab3:
    st.markdown("### Volatility 3 Plugin Reference")

    st.dataframe(
        [{"Plugin": k, "Output File": PLUGIN_FILENAMES[k], "Description": v}
         for k, v in PLUGINS.items()],
        use_container_width=True, hide_index=True
    )

    st.divider()
    st.markdown("### CLI Quick Reference")
    st.code(
        "# Install\npip install volatility3\n\n"
        "# Single plugin\nvol -f data/memory_dumps/memory.raw windows.pslist > report/pslist.txt\n\n"
        "# All key plugins at once (bash)\n"
        "for plugin in pslist psscan cmdline netscan malfind svcscan; do\n"
        "  vol -f memory.raw windows.$plugin > report/$plugin.txt\n"
        "done\n\n"
        "# Generate combined report (if you run all plugins manually)\n"
        "cat report/pslist.txt report/psscan.txt report/cmdline.txt > report/combined_report.txt",
        language="bash"
    )

    st.divider()
    st.info(
        "**Pipeline integration:** After running `windows.pslist` and saving the result, "
        "enable **Memory Analysis** in the dashboard and set the **Volatility pslist.txt** "
        "path to `report/pslist.txt`. The pipeline will read it in Stage 1."
    )

# ── Footer ────────────────────────────────────────────────────────────────────
st.divider()
st.caption(f"🧠 Memory Analysis — Volatility 3 | Project root: `{PROJECT_ROOT}`")