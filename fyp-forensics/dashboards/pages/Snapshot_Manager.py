"""
Snapshot Manager — Dashboard Page
GUI wrapper for snapshots.py (take snapshots) and compare.py (compare snapshots).
Take before/after filesystem snapshots directly from the dashboard,
then compare them to detect added, modified, and deleted files.

FIX applied to compare logic: was after_files[f]["hash"] != after_files[f]["hash"]
     (always False) — now correctly compares before vs after hashes.
"""
import sys
import os
import json
import math
import hashlib
import time
import streamlit as st
import pandas as pd

# ── Path fix ─────────────────────────────────────────────────────────────────
_PAGE_DIR    = os.path.dirname(os.path.abspath(__file__))
_DASH_DIR    = os.path.abspath(os.path.join(_PAGE_DIR, ".."))
PROJECT_ROOT = os.path.abspath(os.path.join(_PAGE_DIR, "../.."))
SNAP_DIR     = os.path.join(PROJECT_ROOT, "snapshots")
if _DASH_DIR not in sys.path:
    sys.path.insert(0, _DASH_DIR)

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(page_title="Snapshot Manager", page_icon="📁", layout="wide")

st.title("📁 Snapshot Manager")
st.caption(
    "Take filesystem snapshots (before and after an incident) and compare them "
    "to detect exactly which files were added, changed, or deleted."
)

# ── Inline snapshot functions (mirrors snapshots.py + fixed compare.py) ──────

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    for c in freq.values():
        p = c / len(data)
        entropy -= p * math.log2(p)
    return entropy


def hash_file(path: str):
    h = hashlib.sha256()
    entropy = 0.0
    try:
        with open(path, "rb") as f:
            chunk = f.read(1024 * 1024)
            if chunk:
                h.update(chunk)
                entropy = shannon_entropy(chunk)
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
    except (PermissionError, OSError):
        return None, 0.0
    return h.hexdigest(), round(entropy, 4)


def take_snapshot(dir_path: str, out_file: str, progress_callback=None):
    """Walk dir_path, hash every file, save JSON snapshot."""
    data = {"timestamp": time.time(), "directory": dir_path, "files": []}
    all_files = []
    for root, dirs, files in os.walk(dir_path):
        # Skip common noise directories
        dirs[:] = [d for d in dirs if d not in (".git","__pycache__","node_modules",".venv")]
        for name in files:
            all_files.append(os.path.join(root, name))

    for i, fpath in enumerate(all_files):
        if progress_callback:
            progress_callback(i / max(len(all_files), 1), fpath)
        fhash, entropy = hash_file(fpath)
        if fhash is None:
            continue
        try:
            data["files"].append({
                "path":    fpath,
                "hash":    fhash,
                "entropy": entropy,
                "size":    os.path.getsize(fpath),
                "mtime":   os.path.getmtime(fpath),
            })
        except OSError:
            pass

    os.makedirs(os.path.dirname(out_file), exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    return len(data["files"])


def compare_snapshots(before_path: str, after_path: str):
    """
    Compare two snapshot files.
    FIX: was `after_files[f]["hash"] != after_files[f]["hash"]` (always False).
    Correct: `before_files[f]["hash"] != after_files[f]["hash"]`.
    """
    before = json.load(open(before_path, "r", encoding="utf-8"))
    after  = json.load(open(after_path,  "r", encoding="utf-8"))

    before_files = {f["path"]: f for f in before.get("files", [])}
    after_files  = {f["path"]: f for f in after.get("files",  [])}

    added, deleted, modified = [], [], []

    for f in after_files:
        if f not in before_files:
            added.append({
                "path":    f,
                "size":    after_files[f].get("size", 0),
                "entropy": after_files[f].get("entropy", 0),
                "hash":    after_files[f].get("hash",""),
            })

    for f in before_files:
        if f not in after_files:
            deleted.append({
                "path":    f,
                "size":    before_files[f].get("size", 0),
                "hash":    before_files[f].get("hash",""),
            })

    for f in after_files:
        if f in before_files:
            # FIX: compare before vs after (was after vs after — always equal)
            if before_files[f]["hash"] != after_files[f]["hash"]:
                ent_before = before_files[f].get("entropy", 0)
                ent_after  = after_files[f].get("entropy",  0)
                modified.append({
                    "path":           f,
                    "size":           after_files[f].get("size", 0),
                    "entropy_before": round(ent_before, 3),
                    "entropy_after":  round(ent_after,  3),
                    "entropy_delta":  round(ent_after - ent_before, 3),
                    "hash_before":    before_files[f].get("hash",""),
                    "hash_after":     after_files[f].get("hash",""),
                })

    return added, modified, deleted


# ── Tabs ──────────────────────────────────────────────────────────────────────
tab1, tab2, tab3 = st.tabs(["📸 Take Snapshot", "🔍 Compare Snapshots", "📋 View Existing Snapshots"])

# ═══ TAB 1: Take Snapshot ════════════════════════════════════════════════════
with tab1:
    st.markdown("### Take a Filesystem Snapshot")
    st.info(
        "**When to use:** Take a BEFORE snapshot before running a suspicious file, "
        "then take an AFTER snapshot once you suspect ransomware or malware activity. "
        "Compare the two in the next tab to see exactly what changed."
    )

    col1, col2 = st.columns(2)
    with col1:
        snap_dir = st.text_input(
            "Directory to snapshot",
            value=PROJECT_ROOT,
            help="Full path to the directory you want to snapshot"
        )
    with col2:
        snap_type = st.radio("Snapshot type", ["Before (pre-incident)", "After (post-incident)"], horizontal=True)
        out_name  = "before.json" if "Before" in snap_type else "after.json"
        out_path  = os.path.join(SNAP_DIR, out_name)

    st.markdown(f"Output will be saved to: `{out_path}`")

    if not os.path.isdir(snap_dir):
        st.error(f"❌ Directory does not exist: `{snap_dir}`")
    else:
        # Estimate size
        try:
            file_count = sum(len(files) for _, _, files in os.walk(snap_dir))
            st.caption(f"~{file_count:,} files found in directory")
        except Exception:
            pass

        if st.button(f"📸 Take {snap_type.split(' ')[0]} Snapshot", type="primary", use_container_width=True):
            progress_bar  = st.progress(0.0, text="Scanning files...")
            status_text   = st.empty()

            def _progress(pct, current_file):
                label = os.path.basename(current_file)[:60]
                progress_bar.progress(min(pct, 1.0), text=f"Hashing: {label}")
                status_text.caption(f"`{current_file}`")

            try:
                n = take_snapshot(snap_dir, out_path, progress_callback=_progress)
                progress_bar.progress(1.0, text="Done!")
                status_text.empty()
                st.success(f"✅ Snapshot saved: **{n:,}** files → `{out_path}`")
            except Exception as exc:
                st.error(f"❌ Snapshot failed: {exc}")

# ═══ TAB 2: Compare Snapshots ════════════════════════════════════════════════
with tab2:
    st.markdown("### Compare Before & After Snapshots")

    before_path = os.path.join(SNAP_DIR, "before.json")
    after_path  = os.path.join(SNAP_DIR, "after.json")

    col1, col2 = st.columns(2)
    with col1:
        before_in = st.text_input("Before snapshot path", value=before_path)
        if os.path.exists(before_in):
            b_meta = json.load(open(before_in))
            ts = b_meta.get("timestamp","?")
            try:
                from datetime import datetime
                ts = datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                pass
            st.success(f"✅ Found: {len(b_meta.get('files',[]))} files — taken {ts}")
        else:
            st.error("Before snapshot not found")

    with col2:
        after_in = st.text_input("After snapshot path", value=after_path)
        if os.path.exists(after_in):
            a_meta = json.load(open(after_in))
            ts = a_meta.get("timestamp","?")
            try:
                from datetime import datetime
                ts = datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                pass
            st.success(f"✅ Found: {len(a_meta.get('files',[]))} files — taken {ts}")
        else:
            st.error("After snapshot not found")

    both_exist = os.path.exists(before_in) and os.path.exists(after_in)

    if both_exist and st.button("🔍 Compare Snapshots", type="primary", use_container_width=True):
        with st.spinner("Comparing snapshots..."):
            try:
                added, modified, deleted = compare_snapshots(before_in, after_in)
                st.session_state["snap_added"]    = added
                st.session_state["snap_modified"] = modified
                st.session_state["snap_deleted"]  = deleted
            except Exception as exc:
                st.error(f"❌ Compare failed: {exc}")

    if "snap_added" in st.session_state:
        added    = st.session_state["snap_added"]
        modified = st.session_state["snap_modified"]
        deleted  = st.session_state["snap_deleted"]

        high_entropy = [m for m in modified if m.get("entropy_after",0) > 7.5]

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Files Added",       len(added))
        c2.metric("Files Modified",    len(modified))
        c3.metric("Files Deleted",     len(deleted))
        c4.metric("🔴 High Entropy",   len(high_entropy))

        if high_entropy:
            st.error(
                f"🚨 {len(high_entropy)} modified file(s) have entropy >7.5 — "
                "content appears encrypted. This is a strong ransomware indicator."
            )

        # Added
        st.markdown("#### ➕ Added Files")
        if added:
            st.dataframe(added, use_container_width=True, hide_index=True, height=250)
        else:
            st.success("No files were added.")

        # Modified with entropy charts
        st.markdown("#### ✏️ Modified Files")
        if modified:
            st.dataframe(modified, use_container_width=True, hide_index=True, height=280)

            df_mod = pd.DataFrame(modified)
            df_mod["File"] = df_mod["path"].apply(lambda x: ("…"+str(x)[-35:]) if len(str(x))>35 else str(x))

            col1, col2 = st.columns(2)
            with col1:
                st.caption("Entropy Before vs After")
                st.bar_chart(df_mod[["File","entropy_before","entropy_after"]].set_index("File"),
                             use_container_width=True, height=280)
            with col2:
                st.caption("Entropy Change (Δ) — positive = more random = likely encrypted")
                st.bar_chart(df_mod[["File","entropy_delta"]].set_index("File"),
                             use_container_width=True, height=280)
        else:
            st.success("No files were modified.")

        # Deleted
        st.markdown("#### ❌ Deleted Files")
        if deleted:
            st.dataframe(deleted, use_container_width=True, hide_index=True, height=250)
        else:
            st.success("No files were deleted.")

        # Export
        st.divider()
        col1, col2, col3 = st.columns(3)
        with col1:
            if added:
                st.download_button("📥 Added CSV",   pd.DataFrame(added).to_csv(index=False),
                                   "snap_added.csv", "text/csv", use_container_width=True)
        with col2:
            if modified:
                st.download_button("📥 Modified CSV", pd.DataFrame(modified).to_csv(index=False),
                                   "snap_modified.csv","text/csv", use_container_width=True)
        with col3:
            if deleted:
                st.download_button("📥 Deleted CSV",  pd.DataFrame(deleted).to_csv(index=False),
                                   "snap_deleted.csv","text/csv", use_container_width=True)

# ═══ TAB 3: View Existing Snapshots ══════════════════════════════════════════
with tab3:
    st.markdown("### View Existing Snapshot Files")

    for snap_name in ["before.json", "after.json"]:
        snap_path = os.path.join(SNAP_DIR, snap_name)
        with st.expander(f"📄 {snap_name}" + (" ✅" if os.path.exists(snap_path) else " ❌ Not found")):
            if not os.path.exists(snap_path):
                st.warning(f"No snapshot found at `{snap_path}`")
                continue
            try:
                snap = json.load(open(snap_path, "r", encoding="utf-8"))
                files = snap.get("files", [])
                ts    = snap.get("timestamp","?")
                try:
                    from datetime import datetime
                    ts = datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    pass

                st.markdown(f"- **Taken:** {ts}")
                st.markdown(f"- **Directory:** `{snap.get('directory','?')}`")
                st.markdown(f"- **Files recorded:** {len(files):,}")

                if files:
                    avg_ent = sum(f.get("entropy",0) for f in files) / len(files)
                    st.markdown(f"- **Average entropy:** {avg_ent:.3f}")
                    df = pd.DataFrame([{
                        "File":    os.path.basename(f["path"]),
                        "Path":    f["path"],
                        "Size":    f.get("size",0),
                        "Entropy": round(f.get("entropy",0), 3),
                        "Hash":    str(f.get("hash",""))[:20]+"…",
                    } for f in files[:500]])
                    st.dataframe(df, use_container_width=True, hide_index=True, height=300)
                    if len(files) > 500:
                        st.caption(f"(showing first 500 of {len(files):,} files)")
            except Exception as exc:
                st.error(f"Error reading snapshot: {exc}")