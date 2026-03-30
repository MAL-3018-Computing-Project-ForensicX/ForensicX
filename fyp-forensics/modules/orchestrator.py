#!/usr/bin/env python3
"""
orchestrator.py - FINAL VERSION with absolute paths
Unified Digital Forensic Framework - Pipeline Orchestrator

- All external modules are imported lazily.
- Uses absolute paths for all outputs (project root based).
- Cloud collection reads config from config/config.json.
- Pipeline continues even if cloud modules fail.
"""

import os
import json
import logging
import sys
import traceback
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Any, Tuple

# ----------------------------------------------------------------------
# Project root determination (absolute path)
# orchestrator.py is in modules/, so project root = parent of modules/
# ----------------------------------------------------------------------
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REPORT_DIR = os.path.join(PROJECT_ROOT, "report")
CLOUD_DATA_DIR = os.path.join(PROJECT_ROOT, "data", "cloud")

# Ensure directories exist
os.makedirs(REPORT_DIR, exist_ok=True)
os.makedirs(CLOUD_DATA_DIR, exist_ok=True)

# ----------------------------------------------------------------------
# Logging setup (log file goes to report/)
# ----------------------------------------------------------------------
log_file = os.path.join(REPORT_DIR, "pipeline.log")
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file, mode='a')
    ]
)
logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------
# Built‑in fallback functions (unchanged)
# ----------------------------------------------------------------------
def parse_time(t):
    if not t:
        return datetime.min
    if isinstance(t, datetime):
        return t
    if isinstance(t, (int, float)):
        try:
            if t > 10**10:
                return datetime.fromtimestamp(t / 1000)
            return datetime.fromtimestamp(t)
        except:
            return datetime.min
    if isinstance(t, str):
        try:
            t = t.replace("Z", "").replace("T", " ").split("+")[0]
            return datetime.fromisoformat(t.strip())
        except:
            return datetime.min
    return datetime.min

def correlate_builtin(events):
    if not events:
        return {}
    process_map = defaultdict(list)
    for e in events:
        process_name = (
            e.get("name") or
            e.get("Image") or
            e.get("process_name") or
            "unknown_process"
        )
        if "\\" in process_name or "/" in process_name:
            process_name = process_name.replace("\\", "/").split("/")[-1]
        pid = str(e.get("pid") or e.get("ProcessId") or "unknown_pid")
        key = f"{process_name}|{pid}"
        process_map[key].append(e)
    for key in process_map:
        process_map[key].sort(key=lambda ev: parse_time(ev.get("time")))
    return dict(process_map)

def save_correlation_json_builtin(correlation, out_path):
    try:
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(correlation, f, indent=2, default=str)
        logger.info(f"Saved correlation to {out_path}")
    except Exception as e:
        logger.error(f"Failed to save correlation: {e}")

def save_correlation_text_builtin(correlation, out_path, limit=25):
    try:
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write("FORENSIC CORRELATION REPORT\n")
            f.write("=" * 50 + "\n\n")
            for proc, events in correlation.items():
                f.write(f"[{proc}]\n")
                f.write("-" * 50 + "\n")
                for ev in events[:limit]:
                    t = ev.get("time", "NoTime")
                    src = ev.get("source", "unknown")
                    details = ev.get("details", "No details")
                    f.write(f"[{src}] {t} - {details}\n")
                if len(events) > limit:
                    f.write(f"... {len(events) - limit} more events\n")
                f.write("\n")
        logger.info(f"Saved correlation report to {out_path}")
    except Exception as e:
        logger.error(f"Failed to save correlation text: {e}")

# ----------------------------------------------------------------------
# Lazy module loader (unchanged except cloud_behavior import)
# ----------------------------------------------------------------------
class LazyLoader:
    def __init__(self):
        self._correlate = None
        self._save_correlation_json = None
        self._save_correlation_text = None
        self._aggregate_process_scores = None
        self._analyze_cloud_behavior = None
        self._add_artifact = None
        self._add_audit = None
        self._build_all_reports = None
        self._normalize_cloud_events = None
        self._correlate_cloud_endpoint = None

    @property
    def correlate(self):
        if self._correlate is None:
            try:
                from modules.correlate import correlate
                self._correlate = correlate
                logger.debug("Lazy-loaded correlate")
            except ImportError:
                logger.warning("correlate module not found, using built-in")
                self._correlate = correlate_builtin
        return self._correlate

    @property
    def save_correlation_json(self):
        if self._save_correlation_json is None:
            try:
                from modules.correlate import save_correlation_json
                self._save_correlation_json = save_correlation_json
                logger.debug("Lazy-loaded save_correlation_json")
            except ImportError:
                logger.warning("save_correlation_json not found, using built-in")
                self._save_correlation_json = save_correlation_json_builtin
        return self._save_correlation_json

    @property
    def save_correlation_text(self):
        if self._save_correlation_text is None:
            try:
                from modules.correlate import save_correlation_text
                self._save_correlation_text = save_correlation_text
                logger.debug("Lazy-loaded save_correlation_text")
            except ImportError:
                logger.warning("save_correlation_text not found, using built-in")
                self._save_correlation_text = save_correlation_text_builtin
        return self._save_correlation_text

    @property
    def aggregate_process_scores(self):
        if self._aggregate_process_scores is None:
            try:
                from modules.detection.behavior import aggregate_process_scores
                self._aggregate_process_scores = aggregate_process_scores
                logger.debug("Lazy-loaded aggregate_process_scores")
            except ImportError:
                logger.warning("behavior module not found")
                self._aggregate_process_scores = None
        return self._aggregate_process_scores

    @property
    def analyze_cloud_behavior(self):
        if self._analyze_cloud_behavior is None:
            try:
                # FIXED: correct import path
                from modules.cloud.cloud_behavior import analyze_cloud_behavior
                self._analyze_cloud_behavior = analyze_cloud_behavior
                logger.debug("Lazy-loaded analyze_cloud_behavior")
            except ImportError:
                logger.warning("cloud_behavior module not found")
                self._analyze_cloud_behavior = None
        return self._analyze_cloud_behavior

    @property
    def add_artifact(self):
        if self._add_artifact is None:
            try:
                from modules.forensics.evidence import add_artifact
                self._add_artifact = add_artifact
                logger.debug("Lazy-loaded add_artifact")
            except ImportError:
                logger.warning("evidence module not found")
                self._add_artifact = None
        return self._add_artifact

    @property
    def add_audit(self):
        if self._add_audit is None:
            try:
                from modules.forensics.evidence import add_audit
                self._add_audit = add_audit
                logger.debug("Lazy-loaded add_audit")
            except ImportError:
                logger.warning("evidence module not found")
                self._add_audit = None
        return self._add_audit

    @property
    def build_all_reports(self):
        if self._build_all_reports is None:
            try:
                from report.report_builder import build_all_reports
                self._build_all_reports = build_all_reports
                logger.debug("Lazy-loaded build_all_reports")
            except ImportError:
                logger.warning("report_builder module not found")
                self._build_all_reports = None
        return self._build_all_reports

    @property
    def normalize_cloud_events(self):
        if self._normalize_cloud_events is None:
            try:
                from modules.cloud.cloud_normalize import normalize_cloud_events
                self._normalize_cloud_events = normalize_cloud_events
                logger.debug("Lazy-loaded normalize_cloud_events")
            except ImportError:
                logger.warning("cloud_normalize not available")
                self._normalize_cloud_events = None
        return self._normalize_cloud_events

    @property
    def correlate_cloud_endpoint(self):
        if self._correlate_cloud_endpoint is None:
            try:
                from modules.cloud.cloud_endpoint_correlate import correlate_cloud_endpoint
                self._correlate_cloud_endpoint = correlate_cloud_endpoint
                logger.debug("Lazy-loaded correlate_cloud_endpoint")
            except ImportError:
                logger.warning("cloud_endpoint_correlate not available")
                self._correlate_cloud_endpoint = None
        return self._correlate_cloud_endpoint

_lazy = LazyLoader()

# ----------------------------------------------------------------------
# Cloud collection – safe version with absolute paths
# ----------------------------------------------------------------------
def collect_cloud_safe():
    logger.info("  Attempting cloud collection...")
    config_path = os.path.join(PROJECT_ROOT, "config", "config.json")
    output_path = os.path.join(CLOUD_DATA_DIR, "cloud_events.json")

    if not os.path.exists(config_path):
        logger.warning(f"Cloud config not found at {config_path}. Skipping cloud collection.")
        return False

    try:
        with open(config_path, "r") as f:
            cfg = json.load(f)
    except Exception as e:
        logger.error(f"Failed to load cloud config: {e}")
        return False

    all_events = []
    collected_any = False

    # Google Drive
    if cfg.get("google_drive", {}).get("enabled"):
        logger.info("    Trying Google Drive...")
        try:
            from modules.cloud.google_drive import collect_drive_metadata
            cred_file = cfg["google_drive"].get("credentials_file")
            if cred_file:
                if not os.path.isabs(cred_file):
                    cred_file = os.path.join(PROJECT_ROOT, cred_file)
                events = collect_drive_metadata(cred_file)
                if events:
                    all_events.extend(events)
                    logger.info(f"    ✓ Google Drive: {len(events)} items")
                    collected_any = True
            else:
                logger.warning("    No credentials_file for Google Drive")
        except Exception as e:
            logger.warning(f"    Google Drive failed: {e}")

    # OneDrive
    if cfg.get("onedrive", {}).get("enabled"):
        logger.info("    Trying OneDrive...")
        try:
            from modules.cloud.onedrive import collect_onedrive_metadata
            client_id = cfg["onedrive"].get("client_id")
            if client_id:
                events = collect_onedrive_metadata(client_id)
                if events:
                    all_events.extend(events)
                    logger.info(f"    ✓ OneDrive: {len(events)} items")
                    collected_any = True
            else:
                logger.warning("    No client_id for OneDrive")
        except Exception as e:
            logger.warning(f"    OneDrive failed: {e}")

    if all_events:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(all_events, f, indent=2, default=str)
        logger.info(f"  ✓ Saved {len(all_events)} events to {output_path}")
        return True
    else:
        if not collected_any:
            logger.warning("  No cloud credentials found or all collections failed")
        return False

# ----------------------------------------------------------------------
# Validation (paths are absolute, so os.path.exists works)
# ----------------------------------------------------------------------
def validate_config(config: Dict) -> Tuple[bool, List[str]]:
    errors = []
    paths  = config.get("paths", {})
    if config.get("sysmon", False):
        sysmon_all = paths.get("sysmon_all")
        if not sysmon_all:
            errors.append("Sysmon enabled but sysmon_all path not configured")
        elif not os.path.exists(sysmon_all):
            errors.append(f"Sysmon file not found: {sysmon_all}")
    if config.get("snapshots", False):
        before = paths.get("before_snapshot")
        after  = paths.get("after_snapshot")
        if not before or not after:
            errors.append("Snapshots enabled but snapshot paths not configured")
        elif not os.path.exists(before):
            errors.append(f"Before snapshot not found: {before}")
        elif not os.path.exists(after):
            errors.append(f"After snapshot not found: {after}")
    if config.get("memory", False):
        pslist = (
            paths.get("pslist")
            or paths.get("pslist_path")
            or os.path.join(PROJECT_ROOT, "report", "pslist.txt")
        )
        if not os.path.exists(pslist):
            logger.warning(
                f"Memory analysis enabled but pslist not found: {pslist}. "
                f"Generate via Memory Analysis page or: vol -f memory.raw windows.pslist > report/pslist.txt"
            )
    if not any([config.get("sysmon"), config.get("snapshots"), config.get("memory"), config.get("cloud")]):
        errors.append("At least one data source must be enabled")
    return (len(errors) == 0, errors)

# ----------------------------------------------------------------------
# Event loaders (unchanged – they accept absolute paths)
# ----------------------------------------------------------------------
def get_sysmon_tag(event_id: str) -> str:
    mapping = {
        "1": "PROCESS-CREATE", "3": "NETWORK", "5": "PROCESS-TERMINATE",
        "7": "IMAGE-LOAD", "8": "CREATE-REMOTE-THREAD", "10": "PROCESS-ACCESS",
        "11": "FILE-CREATE", "12": "REGISTRY-CREATE", "13": "REGISTRY-SET",
        "15": "FILE-STREAM-CREATE", "22": "DNS-QUERY", "23": "FILE-DELETE"
    }
    return mapping.get(str(event_id), f"SYSMON-{event_id}")

def format_sysmon_details(ev: Dict) -> str:
    eid = str(ev.get("event_id", "unknown"))
    data = ev.get("data", {})
    if eid == "1":
        image = data.get("Image", "unknown")
        pid = data.get("ProcessId", "?")
        parent = data.get("ParentImage", "unknown")
        cmdline = data.get("CommandLine", "")
        details = f"Process created: {image} (PID:{pid}) | Parent: {parent}"
        if cmdline:
            details += f" | CMD: {cmdline[:100]}"
        return details
    elif eid == "3":
        image = data.get("Image", "unknown")
        dst_ip = data.get("DestinationIp", "unknown")
        dst_port = data.get("DestinationPort", "?")
        return f"Network: {image} → {dst_ip}:{dst_port}"
    elif eid == "11":
        target = data.get("TargetFilename", "unknown")
        image = data.get("Image", "")
        details = f"File created: {target}"
        if image:
            details += f" by {image}"
        return details
    else:
        image = data.get("Image", data.get("ProcessName", "unknown"))
        return f"Sysmon EID {eid}: {image}"

def load_sysmon(path: str) -> List[Dict]:
    if not os.path.exists(path):
        logger.warning(f"Sysmon file not found: {path}")
        return []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            raw_events = json.load(f)
        if not isinstance(raw_events, list):
            logger.error("Sysmon file must contain a JSON array")
            return []
        normalized = []
        for ev in raw_events:
            try:
                event_id = str(ev.get("event_id", "unknown"))
                data = ev.get("data", {})
                normalized.append({
                    "source": "sysmon",
                    "time": ev.get("time"),
                    "event_id": event_id,
                    "tag": get_sysmon_tag(event_id),
                    "name": data.get("Image", "unknown"),
                    "pid": data.get("ProcessId"),
                    "ppid": data.get("ParentProcessId"),
                    "src_ip": data.get("SourceIp"),
                    "dst_ip": data.get("DestinationIp"),
                    "details": format_sysmon_details(ev),
                    "raw": ev
                })
            except:
                continue
        return normalized
    except Exception as e:
        logger.error(f"Error loading Sysmon: {e}")
        return []

def load_snapshots(before_path: str, after_path: str) -> List[Dict]:
    if not os.path.exists(before_path) or not os.path.exists(after_path):
        return []
    try:
        with open(before_path, 'r') as f:
            before = json.load(f)
        with open(after_path, 'r') as f:
            after = json.load(f)
        before_files = {f["path"]: f for f in before.get("files", [])}
        after_files = {f["path"]: f for f in after.get("files", [])}
        events = []
        # Added files
        for path, file_data in after_files.items():
            if path not in before_files:
                events.append({
                    "source": "snapshot",
                    "time": datetime.fromtimestamp(file_data["mtime"]).isoformat(),
                    "tag": "SNAPSHOT-ADD",
                    "name": os.path.basename(path),
                    "file": path,
                    "hash": file_data["hash"],
                    "entropy": file_data["entropy"],
                    "size": file_data["size"],
                    "details": f"File added: {path} (entropy: {file_data['entropy']:.2f})"
                })
        # Modified files
        for path, after_file in after_files.items():
            if path in before_files:
                before_file = before_files[path]
                if after_file["hash"] != before_file["hash"]:
                    entropy_change = after_file["entropy"] - before_file["entropy"]
                    events.append({
                        "source": "snapshot",
                        "time": datetime.fromtimestamp(after_file["mtime"]).isoformat(),
                        "tag": "SNAPSHOT-MOD",
                        "name": os.path.basename(path),
                        "file": path,
                        "hash": after_file["hash"],
                        "entropy": after_file["entropy"],
                        "entropy_change": entropy_change,
                        "details": f"File modified: {path} | entropy: {before_file['entropy']:.2f} → {after_file['entropy']:.2f}"
                    })
        return events
    except Exception as e:
        logger.error(f"Error comparing snapshots: {e}")
        return []

def load_volatility(pslist_path: str) -> List[Dict]:
    """
    Parse a Volatility 3 windows.pslist (or psscan/cmdline) text output file
    into a list of normalised event dicts.

    Handles both Volatility 3 format (tab-separated with 2+ space gaps)
    and legacy Volatility 2 format (fixed-width columns).
    """
    if not os.path.exists(pslist_path):
        logger.warning(f"Volatility file not found: {pslist_path}")
        return []
    try:
        import re
        events = []
        with open(pslist_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        # Find the header row (contains PID and PPID or ImageFileName)
        header_idx = 0
        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped:
                continue
            # Skip Volatility 3 progress/stacking lines
            if stripped.startswith("*") or "Progress" in stripped or "Stacking" in stripped:
                continue
            upper = stripped.upper()
            if ("PID" in upper and "PPID" in upper) or "IMAGEFILENAME" in upper or "NAME" in upper:
                header_idx = i
                break

        header_line = lines[header_idx].strip() if header_idx < len(lines) else ""
        headers = re.split(r'\s{2,}|\t', header_line) if header_line else []
        headers = [h.strip() for h in headers if h.strip()]

        # Data starts after the header (skip any separator line like "---")
        data_start = header_idx + 1
        if data_start < len(lines) and lines[data_start].strip().startswith("---"):
            data_start += 1

        for line in lines[data_start:]:
            line = line.strip()
            if not line or line.startswith("*") or "Progress" in line:
                continue
            try:
                # Split on 2+ spaces or tabs, matching column count
                parts = re.split(r'\s{2,}|\t', line, maxsplit=max(len(headers) - 1, 5))
                parts = [p.strip() for p in parts]

                if len(parts) < 2:
                    continue

                # Try to extract named columns, fall back to positional
                def col(names, pos):
                    for n in names:
                        for h, v in zip(headers, parts):
                            if n.lower() in h.lower():
                                return v
                    return parts[pos] if pos < len(parts) else "unknown"

                proc_name = col(["ImageFileName", "Name", "Image"], 1)
                pid       = col(["PID"],  2)
                ppid      = col(["PPID"], 3)

                # Try to get create time (column 8-9 in Vol2, varies in Vol3)
                time_val = "unknown"
                time_cols = [h for h in headers if "time" in h.lower() or "create" in h.lower()]
                if time_cols:
                    for h, v in zip(headers, parts):
                        if "time" in h.lower() or "create" in h.lower():
                            time_val = v
                            break
                elif len(parts) >= 9:
                    time_val = " ".join(parts[7:9])

                events.append({
                    "source":  "volatility",
                    "time":    time_val if time_val != "unknown" else None,
                    "tag":     "MEMORY-PROCESS",
                    "name":    proc_name,
                    "pid":     pid,
                    "ppid":    ppid,
                    "details": f"Memory process: {proc_name} (PID:{pid}, PPID:{ppid})"
                })
            except Exception:
                continue

        logger.info(f"  Parsed {len(events)} processes from {os.path.basename(pslist_path)}")
        return events
    except Exception as e:
        logger.error(f"Error loading Volatility output: {e}")
        return []


def load_all_events(config: Dict) -> List[Dict]:
    """
    Load all configured event sources and return a combined list.

    Sources used (when enabled in config):
      - Sysmon All JSON     → config["paths"]["sysmon_all"]
      - Sysmon Network JSON → config["paths"]["sysmon_network"]  (optional)
      - Snapshots           → config["paths"]["before_snapshot"] + after_snapshot
      - Volatility pslist   → config["paths"]["pslist"]  (NEW — from dashboard input)
                              Falls back to config["paths"]["pslist_path"] and
                              report/pslist.txt for backward compatibility
    """
    all_events = []
    paths      = config.get("paths", {})

    # ── Sysmon ───────────────────────────────────────────────────────────────
    if config.get("sysmon", False):
        logger.info("Loading Sysmon events...")

        sysmon_all = paths.get("sysmon_all")
        if sysmon_all and os.path.exists(sysmon_all):
            events = load_sysmon(sysmon_all)
            all_events.extend(events)
            logger.info(f"  ✓ Loaded {len(events)} events from {os.path.basename(sysmon_all)}")
        elif sysmon_all:
            logger.warning(f"  Sysmon All not found: {sysmon_all}")

        # Sysmon Network is optional — only load if a non-empty path is given
        # and it's a different file from sysmon_all (avoids double-counting)
        sysmon_network = paths.get("sysmon_network", "").strip()
        if (sysmon_network
                and os.path.exists(sysmon_network)
                and sysmon_network != sysmon_all):
            events = load_sysmon(sysmon_network)
            all_events.extend(events)
            logger.info(f"  ✓ Loaded {len(events)} events from {os.path.basename(sysmon_network)}")

    # ── Snapshots ─────────────────────────────────────────────────────────────
    if config.get("snapshots", False):
        logger.info("Loading snapshot events...")
        before = paths.get("before_snapshot")
        after  = paths.get("after_snapshot")
        if before and after:
            events = load_snapshots(before, after)
            all_events.extend(events)
            logger.info(f"  ✓ Loaded {len(events)} snapshot changes")
        else:
            logger.warning("  Snapshot paths not configured — skipping")

    # ── Volatility / Memory ───────────────────────────────────────────────────
    if config.get("memory", False):
        logger.info("Loading Volatility memory analysis...")

        # Priority order for finding the pslist file:
        #   1. config["paths"]["pslist"]       ← set by new dashboard input
        #   2. config["paths"]["pslist_path"]  ← legacy key name
        #   3. <project_root>/report/pslist.txt ← fallback default
        volatility_path = (
            paths.get("pslist")
            or paths.get("pslist_path")
            or os.path.join(PROJECT_ROOT, "report", "pslist.txt")
        )

        if volatility_path and os.path.exists(volatility_path):
            events = load_volatility(volatility_path)
            all_events.extend(events)
            logger.info(f"  ✓ Loaded {len(events)} memory processes from {os.path.basename(volatility_path)}")
        else:
            logger.warning(
                f"  Volatility pslist not found: {volatility_path}\n"
                f"  Generate it first: vol -f memory.raw windows.pslist > report/pslist.txt\n"
                f"  Or use the Memory Analysis page in the dashboard."
            )

    return all_events

# ----------------------------------------------------------------------
# Risk summary (unchanged)
# ----------------------------------------------------------------------
def calculate_endpoint_summary(behavior_result: Dict) -> Dict:
    if not behavior_result:
        return {
            "endpoint_risk_level": "LOW",
            "total_processes": 0,
            "high_risk_processes": 0,
            "critical_risk_processes": 0,
            "medium_risk_processes": 0,
            "low_risk_processes": 0,
            "max_risk_score": 0,
            "decision_reason": ["No processes analyzed"],
            "generated_at": datetime.now().isoformat()
        }
    high_risk = sum(1 for v in behavior_result.values() if v.get("risk_level") == "HIGH")
    critical_risk = sum(1 for v in behavior_result.values() if v.get("risk_level") == "CRITICAL")
    medium_risk = sum(1 for v in behavior_result.values() if v.get("risk_level") == "MEDIUM")
    low_risk = sum(1 for v in behavior_result.values() if v.get("risk_level") == "LOW")
    max_score = max((v.get("risk_score", 0) for v in behavior_result.values()), default=0)
    decision_reasons = []
    if critical_risk > 0:
        endpoint_risk = "CRITICAL"
        decision_reasons.append(f"{critical_risk} CRITICAL risk process(es) detected")
    elif high_risk >= 3:
        endpoint_risk = "HIGH"
        decision_reasons.append(f"{high_risk} HIGH risk processes detected")
    elif high_risk >= 1:
        endpoint_risk = "HIGH"
        decision_reasons.append(f"{high_risk} HIGH risk process(es) detected")
    elif medium_risk >= 5:
        endpoint_risk = "MEDIUM"
        decision_reasons.append(f"{medium_risk} MEDIUM risk processes detected")
    elif medium_risk >= 1:
        endpoint_risk = "MEDIUM"
        decision_reasons.append(f"{medium_risk} MEDIUM risk process(es) detected")
    else:
        endpoint_risk = "LOW"
        decision_reasons.append("No significant risk indicators detected")
    if max_score >= 140:
        decision_reasons.append(f"Maximum process risk score: {max_score} (CRITICAL)")
    elif max_score >= 80:
        decision_reasons.append(f"Maximum process risk score: {max_score} (HIGH)")
    json_safe_processes = {}
    for proc_key, proc_data in behavior_result.items():
        json_safe_processes[proc_key] = {
            "risk_score": proc_data.get("risk_score", 0),
            "risk_level": proc_data.get("risk_level", "UNKNOWN"),
            "events_count": len(proc_data.get("events", []))
        }
    return {
        "endpoint_risk_level": endpoint_risk,
        "total_processes": len(behavior_result),
        "high_risk_processes": high_risk,
        "critical_risk_processes": critical_risk,
        "medium_risk_processes": medium_risk,
        "low_risk_processes": low_risk,
        "max_risk_score": max_score,
        "decision_reason": decision_reasons,
        "generated_at": datetime.now().isoformat(),
        "process_details": json_safe_processes
    }

# ----------------------------------------------------------------------
# Main pipeline – now using absolute paths for all outputs
# ----------------------------------------------------------------------
def run_pipeline(config: Dict) -> Dict[str, Any]:
    started_at = datetime.now().isoformat()
    logger.info("=" * 60)
    logger.info("FORENSIC PIPELINE START")
    logger.info("=" * 60)
    logger.info(f"Loading Sysmon from: {sysmon_all}")
    logger.info(f"Loading snapshot from: {before} and {after}")
    logger.info(f"Loading Volatility from: {volatility_path}")
    execution_log = []

    # STAGE 0: Validation
    logger.info("\n[STAGE 0] Validating configuration...")
    is_valid, validation_errors = validate_config(config)
    if not is_valid:
        logger.error("❌ Configuration validation failed:")
        for error in validation_errors:
            logger.error(f"  - {error}")
        return {
            "success": False,
            "status": "FAILED",
            "message": "Configuration validation failed",
            "errors": validation_errors,
            "started_at": started_at,
            "finished_at": datetime.now().isoformat(),
            "stats": {},
            "output_files": [],
            "execution_log": execution_log
        }
    logger.info("✓ Configuration validated")
    execution_log.append("Configuration validation passed")

    all_events = []
    behavior_result = {}
    cloud_risk = {}
    correlation_result = {}

    # STAGE 1: Load Events
    logger.info("\n[STAGE 1] Loading endpoint events...")
    try:
        all_events = load_all_events(config)
        logger.info(f"✓ Total: {len(all_events)} events")
        execution_log.append(f"Loaded {len(all_events)} endpoint events")
    except Exception as e:
        logger.error(f"❌ Error: {e}")
        execution_log.append(f"Endpoint loading failed: {e}")

    # STAGE 2: Cloud Collection
    if config.get("cloud", False):
        logger.info("\n[STAGE 2] Collecting cloud metadata...")
        try:
            success = collect_cloud_safe()
            if success:
                logger.info("✓ Cloud metadata collected")
                execution_log.append("Cloud metadata collected")
            else:
                logger.warning("⚠ Cloud collection returned no data or failed")
                execution_log.append("Cloud collection skipped (no data)")
        except Exception as e:
            logger.error(f"❌ Unexpected error in cloud collection: {e}")
            execution_log.append(f"Cloud collection error: {e}")
    else:
        logger.info("\n[STAGE 2] Cloud collection skipped")
        execution_log.append("Cloud collection skipped")

    # STAGE 3: Cloud Behavior
    if config.get("cloud", False) and _lazy.analyze_cloud_behavior:
        logger.info("\n[STAGE 3] Analyzing cloud behavior...")
        cloud_events_path = os.path.join(CLOUD_DATA_DIR, "cloud_events.json")
        try:
            if os.path.exists(cloud_events_path):
                with open(cloud_events_path, "r", encoding="utf-8") as f:
                    cloud_events = json.load(f)
                cloud_risk = _lazy.analyze_cloud_behavior(cloud_events)
                out_path = os.path.join(REPORT_DIR, "cloud_risk_summary.json")
                with open(out_path, "w", encoding="utf-8") as f:
                    json.dump(cloud_risk, f, indent=2)
                logger.info(f"✓ Analyzed {len(cloud_risk)} accounts")
                execution_log.append(f"Cloud behavior analyzed: {len(cloud_risk)} accounts")
            else:
                logger.warning(f"Cloud events file not found: {cloud_events_path}")
                execution_log.append("Cloud behavior skipped - no events file")
        except Exception as e:
            logger.error(f"❌ Cloud behavior error: {e}")
            execution_log.append(f"Cloud behavior failed: {e}")
    else:
        logger.info("\n[STAGE 3] Cloud analysis skipped")
        execution_log.append("Cloud analysis skipped")

    # STAGE 4: Endpoint Behavior
    if config.get("behavior", False) and all_events and _lazy.aggregate_process_scores:
        logger.info("\n[STAGE 4] Analyzing endpoint behavior...")
        try:
            behavior_result = _lazy.aggregate_process_scores(all_events)
            endpoint_summary = calculate_endpoint_summary(behavior_result)
            out_path = os.path.join(REPORT_DIR, "endpoint_risk_summary.json")
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(endpoint_summary, f, indent=2)
            logger.info(f"✓ Analyzed {len(behavior_result)} processes")
            logger.info(f"  Risk level: {endpoint_summary['endpoint_risk_level']}")
            execution_log.append(f"Endpoint behavior: {len(behavior_result)} processes")
        except Exception as e:
            logger.error(f"❌ Error: {e}")
            execution_log.append(f"Endpoint analysis failed: {e}")
    else:
        logger.info("\n[STAGE 4] Endpoint analysis skipped")
        execution_log.append("Endpoint analysis skipped")

    # STAGE 5: Unified Correlation
    logger.info("\n[STAGE 5] Running correlation engine...")
    try:
        events_to_correlate = all_events.copy()
        # Add cloud events if they exist
        cloud_events_path = os.path.join(CLOUD_DATA_DIR, "cloud_events.json")
        if os.path.exists(cloud_events_path) and _lazy.normalize_cloud_events:
            try:
                with open(cloud_events_path, "r", encoding="utf-8") as f:
                    cloud_events = json.load(f)
                normalized_cloud = _lazy.normalize_cloud_events(cloud_events)
                events_to_correlate.extend(normalized_cloud)
                logger.info(f"  + Added {len(normalized_cloud)} cloud events")
            except Exception as e:
                logger.warning(f"  ⚠ Could not add cloud events: {e}")

        if events_to_correlate:
            logger.info(f"  Correlating {len(events_to_correlate)} events...")
            correlation_result = _lazy.correlate(events_to_correlate)
            json_path = os.path.join(REPORT_DIR, "correlation.json")
            txt_path = os.path.join(REPORT_DIR, "correlation.txt")
            _lazy.save_correlation_json(correlation_result, json_path)
            _lazy.save_correlation_text(correlation_result, txt_path)
            logger.info(f"✓ Correlated {len(correlation_result)} processes")
            execution_log.append(f"Correlation: {len(correlation_result)} processes")
        else:
            logger.warning("⚠ No events to correlate")
            with open(os.path.join(REPORT_DIR, "correlation.json"), "w") as f:
                json.dump({}, f, indent=2)
            correlation_result = {}
    except Exception as e:
        logger.error(f"❌ Correlation error: {e}")
        logger.error(traceback.format_exc())
        execution_log.append(f"Correlation failed: {e}")
        try:
            with open(os.path.join(REPORT_DIR, "correlation.json"), "w") as f:
                json.dump({}, f, indent=2)
        except:
            pass
        correlation_result = {}

    # STAGE 6: Cloud-Endpoint Correlation
    if config.get("cloud_endpoint", False) and _lazy.correlate_cloud_endpoint:
        logger.info("\n[STAGE 6] Correlating cloud ↔ endpoint...")
        try:
            # The correlate_cloud_endpoint function now uses absolute paths internally
            correlations = _lazy.correlate_cloud_endpoint()
            out_path = os.path.join(REPORT_DIR, "cloud_endpoint_correlations.json")
            with open(out_path, "w") as f:
                json.dump(correlations, f, indent=2, default=str)
            logger.info(f"✓ Found {len(correlations)} correlations")
            execution_log.append(f"Cloud-endpoint: {len(correlations)} links")
        except Exception as e:
            logger.error(f"❌ Error: {e}")
            execution_log.append(f"Cloud-endpoint correlation failed: {e}")
    else:
        logger.info("\n[STAGE 6] Cloud-endpoint correlation skipped")
        execution_log.append("Cloud-endpoint correlation skipped")

    # STAGE 7: Evidence Manifest
    logger.info("\n[STAGE 7] Building evidence manifest...")
    try:
        manifest_path = os.path.join(REPORT_DIR, "manifest.json")
        if not os.path.exists(manifest_path):
            manifest = {
                "generated": datetime.utcnow().isoformat() + "Z",
                "artifacts": [],
                "audit": []
            }
            with open(manifest_path, "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=2)
        if _lazy.add_artifact:
            report_files = [
                (os.path.join(REPORT_DIR, "correlation.json"), "correlation_output"),
                (os.path.join(REPORT_DIR, "correlation.txt"), "correlation_report"),
                (os.path.join(REPORT_DIR, "endpoint_risk_summary.json"), "endpoint_behavior"),
                (os.path.join(REPORT_DIR, "cloud_risk_summary.json"), "cloud_behavior")
            ]
            for filepath, role in report_files:
                if os.path.exists(filepath):
                    try:
                        _lazy.add_artifact(manifest_path, filepath, role=role)
                    except:
                        pass
        if _lazy.add_audit:
            _lazy.add_audit(
                manifest_path,
                actor="forensic_pipeline",
                action="analysis_complete",
                note=f"Completed at {datetime.now().isoformat()}"
            )
        logger.info("✓ Manifest created")
        execution_log.append("Evidence manifest created")
    except Exception as e:
        logger.error(f"❌ Error: {e}")
        execution_log.append(f"Manifest failed: {e}")

    # STAGE 8: Reports
    if config.get("reports", False):
        logger.info("\n[STAGE 8] Generating reports...")
        try:
            if correlation_result and _lazy.build_all_reports:
                _lazy.build_all_reports(correlation_result, REPORT_DIR)
                logger.info("✓ Reports generated")
                execution_log.append("Reports generated")
            else:
                logger.warning("⚠ No data for reports or report_builder not available")
                execution_log.append("Reports skipped: no data or missing module")
        except Exception as e:
            logger.error(f"❌ Error: {e}")
            execution_log.append(f"Reports failed: {e}")
    else:
        logger.info("\n[STAGE 8] Reports skipped")
        execution_log.append("Reports skipped")

    # Completion
    finished_at = datetime.now().isoformat()
    logger.info("\n" + "=" * 60)
    logger.info("PIPELINE COMPLETE")
    logger.info("=" * 60)

    high_risk_count = 0
    if behavior_result:
        high_risk_count = sum(
            1 for v in behavior_result.values()
            if v.get("risk_level") in ("HIGH", "CRITICAL")
        )

    output_files = []
    if os.path.exists(REPORT_DIR):
        for file in os.listdir(REPORT_DIR):
            file_path = os.path.join(REPORT_DIR, file)
            if os.path.isfile(file_path):
                output_files.append(file_path)

    return {
        "success": True,
        "status": "SUCCESS",
        "message": "Analysis completed successfully",
        "started_at": started_at,
        "finished_at": finished_at,
        "execution_log": execution_log,
        "steps": execution_log,
        "stats": {
            "endpoint_events": len(all_events),
            "cloud_risk_entries": len(cloud_risk),
            "behavior_processes": len(behavior_result),
            "high_risk_processes": high_risk_count,
            "correlation_processes": len(correlation_result)
        },
        "output_files": output_files
    }

# ----------------------------------------------------------------------
# CLI entrypoint (unchanged)
# ----------------------------------------------------------------------
def main():
    import argparse
    parser = argparse.ArgumentParser(description="ForensicX - Unified Digital Forensic Framework")
    parser.add_argument("--sysmon", help="Path to Sysmon JSON file")
    parser.add_argument("--before", help="Path to before snapshot")
    parser.add_argument("--after", help="Path to after snapshot")
    parser.add_argument("--skip-cloud", action="store_true", help="Skip cloud collection")
    args = parser.parse_args()
    config = {
        "snapshots": bool(args.before and args.after),
        "sysmon": bool(args.sysmon),
        "memory": False,
        "behavior": True,
        "cloud": not args.skip_cloud,
        "cloud_endpoint": not args.skip_cloud,
        "reports": True,
        "paths": {
            "sysmon_all": args.sysmon or "data/logs/sysmon_all.json",
            "sysmon_network": "",
            "before_snapshot": args.before or "snapshots/before.json",
            "after_snapshot": args.after or "snapshots/after.json",
        }
    }
    result = run_pipeline(config)
    print("\n" + "=" * 60)
    print("PIPELINE EXECUTION SUMMARY")
    print("=" * 60)
    print(f"Status: {result['status']}")
    print(f"Started: {result['started_at']}")
    print(f"Finished: {result['finished_at']}")
    print(f"\nStatistics:")
    for key, value in result.get('stats', {}).items():
        print(f"  {key}: {value}")
    print(f"\nOutput files: {len(result.get('output_files', []))}")
    print("=" * 60)
    return 0 if result['success'] else 1

if __name__ == "__main__":
    sys.exit(main())