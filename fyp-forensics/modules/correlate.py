#!/usr/bin/env python3
"""
correlate.py
Unified Forensic Correlation Engine

Responsibilities:
- Correlate endpoint + cloud events
- Group by process (name|pid)
- Sort events by time
- Output correlation results

FIX: parse_time was splitting on "-" which destroyed ISO date strings
     e.g. "2024-01-15T10:30:00" → "2024" before fromisoformat() was called,
     causing all timestamp sorting to silently return datetime.min.
     Now only the timezone offset (+HH:MM) is stripped, never the date.
"""

import json
import os
import sys
from datetime import datetime
from collections import defaultdict


# ============================================================
# TIME PARSER (FIXED)
# ============================================================
def parse_time(t):
    """
    Convert timestamp to datetime (safe).

    Supported formats:
      - datetime object          → returned as-is (tz stripped if needed)
      - int / float              → Unix timestamp (ms auto-detected)
      - ISO 8601 string          → fromisoformat after sanitising Z / tz offset

    FIX: Previous version called .split("-")[0] on the raw string which
         truncated "2024-01-15T…" to "2024", breaking fromisoformat.
         Now only the +HH:MM timezone suffix is removed, leaving the
         date portion intact.

    Returns:
        datetime object, or datetime.min on failure.
    """
    if not t:
        return datetime.min

    # Already a datetime
    if isinstance(t, datetime):
        # Strip timezone so comparisons stay naive
        return t.replace(tzinfo=None) if t.tzinfo else t

    # Numeric Unix timestamp
    if isinstance(t, (int, float)):
        try:
            # Handle milliseconds
            if t > 10**10:
                return datetime.fromtimestamp(t / 1000)
            return datetime.fromtimestamp(t)
        except Exception:
            return datetime.min

    # String timestamp
    if isinstance(t, str):
        try:
            s = t.strip()

            # Remove trailing Z (UTC marker)
            if s.endswith("Z"):
                s = s[:-1]

            # Replace T separator for fromisoformat compatibility
            s = s.replace("T", " ")

            # FIX: Strip ONLY the timezone offset (+HH:MM or +HHMM).
            # Do NOT split on "-" as that would destroy the date portion.
            if "+" in s:
                s = s.split("+")[0]

            return datetime.fromisoformat(s.strip())
        except Exception:
            return datetime.min

    return datetime.min


# ============================================================
# CORE CORRELATION ENGINE
# ============================================================
def correlate(events):
    """
    Correlate events by process name + PID.

    Args:
        events (list): List of event dictionaries.

    Returns:
        dict: { "process_name|pid": [events…] }
    """
    if not events:
        return {}

    process_map = defaultdict(list)

    for e in events:
        # Extract process name (try multiple field names)
        process_name = (
            e.get("name") or
            e.get("Image") or
            e.get("process_name") or
            e.get("ProcessName") or
            "unknown_process"
        )

        # Strip full path — keep only the binary name
        if "\\" in process_name or "/" in process_name:
            process_name = process_name.replace("\\", "/").split("/")[-1]

        # Extract PID (try multiple field names)
        pid = (
            e.get("pid") or
            e.get("ProcessId") or
            e.get("process_id") or
            e.get("PID") or
            "unknown_pid"
        )

        pid = str(pid)
        key = f"{process_name}|{pid}"
        process_map[key].append(e)

    # Sort events per process by timestamp
    for key in process_map:
        process_map[key].sort(key=lambda ev: parse_time(ev.get("time")))

    return dict(process_map)


# ============================================================
# OUTPUT HELPERS
# ============================================================
def save_correlation_json(correlation, out_path):
    """
    Save correlation result as JSON.

    Args:
        correlation: Correlation dictionary.
        out_path:    Output file path.
    """
    try:
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(correlation, f, indent=2, default=str)
        print(f"[INFO] Saved correlation to {out_path}")
    except Exception as e:
        print(f"[ERROR] Failed to save correlation JSON: {e}")


def save_correlation_text(correlation, out_path, limit=25):
    """
    Save human-readable correlation report.

    Args:
        correlation: Correlation dictionary.
        out_path:    Output file path.
        limit:       Maximum events shown per process.
    """
    try:
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write("FORENSIC CORRELATION REPORT\n")
            f.write("=" * 50 + "\n\n")

            for proc, events in correlation.items():
                f.write(f"[{proc}]\n")
                f.write("-" * 50 + "\n")

                for ev in events[:limit]:
                    t       = ev.get("time", "NoTime")
                    src     = ev.get("source", "unknown")
                    details = ev.get("details", "No details")
                    f.write(f"[{src}] {t} - {details}\n")

                if len(events) > limit:
                    f.write(f"... {len(events) - limit} more events\n")

                f.write("\n")

        print(f"[INFO] Saved correlation report to {out_path}")
    except Exception as e:
        print(f"[ERROR] Failed to save correlation text: {e}")


# ============================================================
# CLI ENTRYPOINT
# ============================================================
def main():
    """
    CLI usage:
        python correlate.py input1.json [input2.json …] -o report/
    """
    import argparse

    parser = argparse.ArgumentParser(description="Unified Forensic Correlation Engine")
    parser.add_argument("inputs", nargs="+", help="Input JSON files containing event lists")
    parser.add_argument("-o", "--outdir", default="report", help="Output directory")
    args = parser.parse_args()

    all_events = []

    for path in args.inputs:
        if not os.path.exists(path):
            print(f"[WARN] Missing file: {path}")
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                all_events.extend(data)
            else:
                print(f"[WARN] {path} does not contain a list")
        except Exception as e:
            print(f"[ERROR] Failed to load {path}: {e}")

    if not all_events:
        print("No events loaded. Exiting.")
        return

    os.makedirs(args.outdir, exist_ok=True)

    print(f"Correlating {len(all_events)} events...")
    correlation = correlate(all_events)
    print(f"Found {len(correlation)} unique processes")

    json_out = os.path.join(args.outdir, "correlation.json")
    txt_out  = os.path.join(args.outdir, "correlation.txt")

    save_correlation_json(correlation, json_out)
    save_correlation_text(correlation, txt_out)

    print("Correlation complete:")
    print(f"  - {json_out}")
    print(f"  - {txt_out}")


if __name__ == "__main__":
    main()