#!/usr/bin/env python3
"""
behavior.py
Endpoint Behavior Analysis Module

Scores forensic events per-process and classifies overall risk level.

FIX: YARA rules were never loading because the search paths did not
     include the actual project location of ransomware_rules.yar
     (rules/ransomware_rules.yar relative to project root).
     Added an absolute path resolved from this file's location so
     YARA rules are found regardless of the working directory.
"""

import math
import os
from datetime import datetime, timedelta
import logging

LOG = logging.getLogger("behavior")
LOG.setLevel(logging.INFO)

# ── Risk weights (tunable) ───────────────────────────────────────────────────
WEIGHTS = {
    "entropy_high":      30,
    "snapshot_add":      10,
    "snapshot_mod":      10,
    "yara_hit":          40,
    "ioc_hash":          50,
    "ioc_ip":            20,
    "ioc_domain":        20,
    "many_file_ops":     30,
    "suspicious_network": 15,
    "suspicious_parent": 25,
}

# ── Risk level cutoffs ───────────────────────────────────────────────────────
LEVELS = [
    (0,   "LOW"),
    (40,  "MEDIUM"),
    (80,  "HIGH"),
    (140, "CRITICAL"),
]

# ── YARA initialisation ──────────────────────────────────────────────────────
# This file lives at:  <project_root>/modules/detection/behavior.py
# Project root is therefore two levels up.
_MODULE_DIR  = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_MODULE_DIR, "../.."))

YARA_RULES = None
try:
    import yara

    # FIX: Added the absolute project-root-relative path as the first candidate.
    # Previous version only searched relative to CWD and this file, missing
    # the actual location at <project_root>/rules/ransomware_rules.yar.
    yara_paths = [
        os.path.join(_PROJECT_ROOT, "rules", "ransomware_rules.yar"),   # ← FIX (added)
        os.path.join(_MODULE_DIR,   "../../rules/ransomware_rules.yar"),
        os.path.join(_MODULE_DIR,   "ransomware_rules.yar"),
        os.path.join(_MODULE_DIR,   "../ransomware_rules.yar"),
        "rules/ransomware_rules.yar",
        "ransomware_rules.yar",
    ]

    for yara_path in yara_paths:
        resolved = os.path.abspath(yara_path)
        if os.path.exists(resolved):
            try:
                YARA_RULES = yara.compile(filepath=resolved)
                LOG.info(f"YARA rules loaded from: {resolved}")
                break
            except Exception as e:
                LOG.debug(f"Failed to compile YARA from {resolved}: {e}")

    if not YARA_RULES:
        LOG.warning("YARA module available but no rules file found.")
        LOG.warning("Checked paths: " + ", ".join(os.path.abspath(p) for p in yara_paths))
        LOG.warning("YARA scanning disabled.")

except ImportError:
    LOG.warning("YARA module not installed — YARA scanning disabled.")
except Exception as e:
    LOG.warning(f"YARA initialisation failed: {e}")


# ── Helpers ──────────────────────────────────────────────────────────────────
def parse_time_safe(t):
    """Safe time parser with fallback to None."""
    if not t:
        return None
    if isinstance(t, datetime):
        return t
    if isinstance(t, (int, float)):
        try:
            return datetime.fromtimestamp(t / 1000 if t > 10**10 else t)
        except Exception:
            return None
    if isinstance(t, str):
        try:
            s = t.replace("Z", "").replace("T", " ").split("+")[0]
            return datetime.fromisoformat(s.strip())
        except Exception:
            return None
    return None


def score_event(e):
    """
    Return risk score for a single event.

    Args:
        e (dict): Event dictionary.

    Returns:
        int: Risk score contribution.
    """
    score   = 0
    tags    = e.get("tag", "").upper()
    details = (e.get("details") or "").lower()

    # Snapshot indicators
    if tags == "SNAPSHOT-ADD":
        score += WEIGHTS["snapshot_add"]
    if tags == "SNAPSHOT-MOD":
        score += WEIGHTS["snapshot_mod"]

    # High entropy in details string
    if "entropy=" in details:
        try:
            ent_str = details.split("entropy=")[1].split(")")[0].split()[0].strip()
            if float(ent_str) > 7.5:
                score += WEIGHTS["entropy_high"]
        except Exception:
            pass

    # YARA markers embedded in details
    if "[yara]" in details or e.get("yara_hit"):
        score += WEIGHTS["yara_hit"]

    # IOC hits
    if e.get("ioc_hit"):
        if "hash" in details:
            score += WEIGHTS["ioc_hash"]
        elif "ip" in details or "domain" in details:
            score += WEIGHTS["ioc_ip"]

    # Network indicators
    if tags == "NETWORK":
        dst = e.get("dst_ip") or ""
        # Non-private external IP
        if dst and not dst.startswith(("10.", "172.", "192.168.")):
            score += WEIGHTS["suspicious_network"]
        # Suspicious ports
        if any(p in details for p in [":445", ":3389", ":8080", ":4444"]):
            score += WEIGHTS["suspicious_network"] // 2

    # Suspicious parent/child relationships
    name          = (e.get("name") or "").lower()
    parent_detail = details
    suspicious_parents  = ["powershell", "cmd.exe", "wscript", "cscript"]
    suspicious_children = ["word", "excel", "outlook", "winword"]

    if any(p in parent_detail for p in suspicious_parents) and \
       any(c in name for c in suspicious_children):
        score += WEIGHTS["suspicious_parent"]

    # Live YARA file scan
    if YARA_RULES and tags in ("SNAPSHOT-ADD", "SNAPSHOT-MOD"):
        file_path = e.get("file")
        if file_path and os.path.exists(file_path):
            try:
                matches = YARA_RULES.match(filepath=file_path)
                if matches:
                    score += WEIGHTS["yara_hit"]
                    e["yara_matches"] = [str(m) for m in matches]
                    LOG.info(f"YARA hit: {file_path} matched {len(matches)} rule(s)")
            except Exception as ex:
                LOG.debug(f"YARA scan failed for {file_path}: {ex}")

    return score


# ── Main aggregation ─────────────────────────────────────────────────────────
def aggregate_process_scores(events, window_minutes=5):
    """
    Aggregate risk scores for all processes found in the event list.

    Args:
        events (list):       List of event dictionaries.
        window_minutes (int): Sliding window for burst detection.

    Returns:
        dict: { "process_name|pid": { score, events, risk_level, … } }
    """
    proc_map = {}

    # ── Base scoring ─────────────────────────────────────────────────────────
    for e in events:
        pid  = e.get("pid") or "unknown"
        name = e.get("name") or "unknown"

        # Strip full path
        if "\\" in name or "/" in name:
            name = name.replace("\\", "/").split("/")[-1]

        key = f"{name}|{pid}"

        if key not in proc_map:
            proc_map[key] = {"score": 0, "events": [], "file_ops_times": []}

        pts = score_event(e)
        proc_map[key]["score"]  += pts
        proc_map[key]["events"].append(e)

        # Track file-operation timestamps for burst detection
        if e.get("tag") in ("SNAPSHOT-ADD", "SNAPSHOT-MOD", "FILEMOD", "FILE-CREATE"):
            t = parse_time_safe(e.get("time"))
            if t:
                proc_map[key]["file_ops_times"].append(t)

        e.setdefault("behavior", {})["score"] = pts

    # ── Burst detection ──────────────────────────────────────────────────────
    window         = timedelta(minutes=window_minutes)
    threshold_ops  = 10

    for key, v in proc_map.items():
        times = sorted(v["file_ops_times"])
        for i in range(len(times)):
            j = i
            while j < len(times) and (times[j] - times[i]) <= window:
                j += 1
            if (j - i) >= threshold_ops:
                v["score"] += WEIGHTS["many_file_ops"]
                LOG.info(f"Burst detected for {key}: {j - i} file ops in {window_minutes} min")
                break

    # ── Risk level classification ─────────────────────────────────────────────
    for key, v in proc_map.items():
        s     = v["score"]
        level = "LOW"
        for cutoff, label in LEVELS:
            if s >= cutoff:
                level = label

        v["risk_score"] = s
        v["risk_level"] = level

        for e in v["events"]:
            e.setdefault("behavior", {})["proc_score"] = s
            e.setdefault("behavior", {})["proc_level"] = level

    return proc_map


# ── Self-test ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("Behavior Analysis Module — Self-test")
    print("=" * 60)

    test_events = [
        {
            "source":  "snapshot",
            "tag":     "SNAPSHOT-MOD",
            "name":    "test.exe",
            "pid":     "1234",
            "file":    "/tmp/test.txt",
            "details": "File modified: /tmp/test.txt (entropy: 7.8)",
            "time":    "2026-02-09T14:30:00",
        },
        {
            "source":  "sysmon",
            "tag":     "NETWORK",
            "name":    "test.exe",
            "pid":     "1234",
            "dst_ip":  "8.8.8.8",
            "details": "Network connection to 8.8.8.8:443",
            "time":    "2026-02-09T14:30:05",
        },
    ]

    result = aggregate_process_scores(test_events)

    print(f"\nProcessed {len(result)} processes:")
    for key, data in result.items():
        print(f"  {key}:")
        print(f"    Risk Score : {data['risk_score']}")
        print(f"    Risk Level : {data['risk_level']}")
        print(f"    Events     : {len(data['events'])}")

    print("\n" + "=" * 60)
    print("YARA rules loaded:", YARA_RULES is not None)
    print("=" * 60)