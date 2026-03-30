#!/usr/bin/env python3
"""
compare.py
Filesystem Snapshot Comparison Utility

Compares two snapshot JSON files (before/after) and reports:
- Added files
- Removed files
- Modified files (with entropy flagging for ransomware detection)

FIX: Corrected self-comparison bug on line 18 where after_files[f] was
     compared to itself instead of before_files[f], causing modified
     files to never be detected.

Usage:
    python compare.py <before.json> <after.json>
"""

import json
import sys


def compare_snapshots(before_path, after_path):
    """
    Compare two snapshot files and print a diff report.

    Args:
        before_path: Path to the before-snapshot JSON file
        after_path:  Path to the after-snapshot JSON file
    """
    try:
        with open(before_path, "r", encoding="utf-8") as f:
            before = json.load(f)
    except Exception as e:
        print(f"[ERROR] Could not load before snapshot: {e}")
        sys.exit(1)

    try:
        with open(after_path, "r", encoding="utf-8") as f:
            after = json.load(f)
    except Exception as e:
        print(f"[ERROR] Could not load after snapshot: {e}")
        sys.exit(1)

    before_files = {item["path"]: item for item in before.get("files", [])}
    after_files  = {item["path"]: item for item in after.get("files",  [])}

    # ── Added files ──────────────────────────────────────────────────────────
    print("== Added files ==")
    added = [f for f in after_files if f not in before_files]
    if added:
        for f in added:
            ent = after_files[f].get("entropy", 0)
            flag = " [high entropy]" if ent > 7.5 else ""
            print(f"  [added]{flag} {f} (entropy {ent:.2f})")
    else:
        print("  (none)")

    # ── Removed files ────────────────────────────────────────────────────────
    print("\n== Removed files ==")
    removed = [f for f in before_files if f not in after_files]
    if removed:
        for f in removed:
            print(f"  [removed] {f}")
    else:
        print("  (none)")

    # ── Modified files ───────────────────────────────────────────────────────
    # FIX: was `after_files[f]["hash"] != after_files[f]["hash"]`
    #      (always False — comparing a value to itself).
    #      Corrected to compare before_files[f] vs after_files[f].
    print("\n== Modified files ==")
    modified = [
        f for f in after_files
        if f in before_files and before_files[f]["hash"] != after_files[f]["hash"]
    ]
    if modified:
        for f in modified:
            ent_before = before_files[f].get("entropy", 0)
            ent_after  = after_files[f].get("entropy", 0)
            delta      = ent_after - ent_before
            flag = " [high entropy]" if ent_after > 7.5 else ""
            print(
                f"  [modified]{flag} {f} "
                f"(entropy {ent_before:.2f} → {ent_after:.2f}, Δ{delta:+.2f})"
            )
    else:
        print("  (none)")

    # ── Summary ──────────────────────────────────────────────────────────────
    print(f"\n== Summary ==")
    print(f"  Added:    {len(added)}")
    print(f"  Removed:  {len(removed)}")
    print(f"  Modified: {len(modified)}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python compare.py <before.json> <after.json>")
        sys.exit(1)

    compare_snapshots(sys.argv[1], sys.argv[2])