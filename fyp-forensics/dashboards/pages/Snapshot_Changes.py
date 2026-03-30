"""
Snapshot Changes — Dashboard Page
Filesystem changes between before/after snapshots extracted from correlation data.
FIX: entropy variable was computed but never visualised (now shown as chart).
FIX: crash on empty DataFrame when no events of a type exist.
FIX: libs import path fixed.
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
st.set_page_config(page_title="Snapshot Changes", page_icon="📸", layout="wide")

st.title("📸 Snapshot File Change Viewer")
st.caption(
    "Files added, modified, or deleted between filesystem snapshots. "
    "High entropy on modified files is a strong ransomware indicator."
)

# ── Load ──────────────────────────────────────────────────────────────────────
cor = load_correlation()

if not cor:
    st.error("❌ Correlation data not found.")
    st.info("Run the forensic pipeline from the main dashboard first.")
    st.stop()

# ── Collect snapshot events ───────────────────────────────────────────────────
adds, mods, dels = [], [], []

for proc, events in cor.items():
    for e in events:
        tag = e.get("tag","")
        if tag not in ("SNAPSHOT-ADD","SNAPSHOT-MOD","SNAPSHOT-DEL"):
            continue

        row = {
            "File":    e.get("file", e.get("name", e.get("details",""))),
            "Time":    str(e.get("time",""))[:19],
            "Size":    e.get("size",""),
            "Hash":    (str(e.get("hash",""))[:20] + "…") if e.get("hash") else "",
            "Process": proc,
        }

        if tag == "SNAPSHOT-ADD":
            row["Entropy"] = round(float(e.get("entropy", 0) or 0), 3)
            adds.append(row)
        elif tag == "SNAPSHOT-MOD":
            row["Entropy Before"] = round(float(e.get("entropy_before", 0) or 0), 3)
            row["Entropy After"]  = round(float(e.get("entropy",        0) or 0), 3)
            row["Entropy Δ"]      = round(float(e.get("entropy_change",
                                    row["Entropy After"] - row["Entropy Before"])), 3)
            mods.append(row)
        elif tag == "SNAPSHOT-DEL":
            dels.append(row)

# ── Summary metrics ───────────────────────────────────────────────────────────
high_entropy = sum(1 for r in mods if r.get("Entropy After", 0) > 7.5)

c1, c2, c3, c4 = st.columns(4)
c1.metric("Files Added",       len(adds))
c2.metric("Files Modified",    len(mods))
c3.metric("Files Deleted",     len(dels))
c4.metric("🔴 High Entropy",   high_entropy,
          help="Entropy > 7.5 on modified files — typical of encrypted/ransomed content")

if high_entropy > 0:
    st.error(
        f"🚨 {high_entropy} modified file(s) show HIGH entropy (>7.5). "
        "This is a strong indicator that files have been encrypted by ransomware."
    )
elif mods:
    st.warning(f"⚠️ {len(mods)} file(s) modified. Entropy levels appear normal.")

if adds:
    st.warning(f"⚠️ {len(adds)} new file(s) appeared after the incident snapshot was taken.")

if dels:
    st.error(f"🚨 {len(dels)} file(s) were deleted — common in ransomware and data destruction attacks.")

if not (adds or mods or dels):
    st.success("✅ No snapshot changes detected in the correlation data.")
    st.stop()

st.divider()

# ── ADDED FILES ───────────────────────────────────────────────────────────────
st.markdown("### ➕ Added Files")
if adds:
    df_add = pd.DataFrame(adds)
    st.dataframe(df_add, use_container_width=True, hide_index=True, height=280)
else:
    st.success("No new files detected.")

st.divider()

# ── MODIFIED FILES ────────────────────────────────────────────────────────────
st.markdown("### ✏️ Modified Files")
if mods:
    df_mod = pd.DataFrame(mods)
    st.dataframe(df_mod, use_container_width=True, hide_index=True, height=300)

    # ── FIX: entropy was computed but never displayed — now shown ─────────────
    st.markdown("#### 🌡️ Entropy Before vs After (Modified Files)")
    st.caption(
        "Entropy measures how random the data in a file is. "
        "Normal files score 3–6. Encrypted files score 7.5–8.0. "
        "A big jump means the file content was scrambled — a ransomware sign."
    )

    # Shorten long paths for chart labels
    ent_df = df_mod[["File","Entropy Before","Entropy After"]].copy()
    ent_df["File"] = ent_df["File"].apply(
        lambda x: ("…" + str(x)[-35:]) if len(str(x)) > 35 else str(x)
    )
    st.bar_chart(ent_df.set_index("File"), use_container_width=True, height=320)

    st.markdown("#### 📈 Entropy Change (Δ) per File")
    st.caption("Positive delta means the file became MORE random — likely encrypted.")
    delta_df = df_mod[["File","Entropy Δ"]].copy()
    delta_df["File"] = delta_df["File"].apply(
        lambda x: ("…" + str(x)[-35:]) if len(str(x)) > 35 else str(x)
    )
    st.bar_chart(delta_df.set_index("File"), use_container_width=True, height=280)
else:
    st.success("No modified files detected.")

st.divider()

# ── DELETED FILES ─────────────────────────────────────────────────────────────
st.markdown("### ❌ Deleted Files")
if dels:
    df_del = pd.DataFrame(dels)
    st.dataframe(df_del, use_container_width=True, hide_index=True, height=250)
else:
    st.success("No deleted files detected.")

st.divider()

# ── Export ────────────────────────────────────────────────────────────────────
st.markdown("### 💾 Export")
col1, col2, col3 = st.columns(3)
with col1:
    if adds:
        st.download_button("📥 Added Files CSV",
                           pd.DataFrame(adds).to_csv(index=False),
                           "snapshot_added.csv","text/csv", use_container_width=True)
with col2:
    if mods:
        st.download_button("📥 Modified Files CSV",
                           pd.DataFrame(mods).to_csv(index=False),
                           "snapshot_modified.csv","text/csv", use_container_width=True)
with col3:
    if dels:
        st.download_button("📥 Deleted Files CSV",
                           pd.DataFrame(dels).to_csv(index=False),
                           "snapshot_deleted.csv","text/csv", use_container_width=True)