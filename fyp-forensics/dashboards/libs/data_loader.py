"""
libs/data_loader.py
Centralised data loader for all ForensicX dashboard pages.

All paths resolved absolutely from this file's location so pages work
regardless of which directory Streamlit was launched from.
"""

import json
import os

# dashboards/libs/ → dashboards/ → project root
_LIBS_DIR  = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR   = os.path.abspath(os.path.join(_LIBS_DIR, "../.."))
REPORT_DIR = os.path.join(ROOT_DIR, "report")
DATA_DIR   = os.path.join(ROOT_DIR, "data")

# ── File paths ───────────────────────────────────────────────────────────────
CORRELATION_PATH         = os.path.join(REPORT_DIR, "correlation.json")
ENDPOINT_RISK_PATH       = os.path.join(REPORT_DIR, "endpoint_risk_summary.json")
CLOUD_RISK_PATH          = os.path.join(REPORT_DIR, "cloud_risk_summary.json")
CLOUD_ENDPOINT_CORR_PATH = os.path.join(REPORT_DIR, "cloud_endpoint_correlations.json")
MANIFEST_PATH            = os.path.join(REPORT_DIR, "manifest.json")
IOC_PATH                 = os.path.join(ROOT_DIR, "data", "ioc.json")
CLOUD_EVENTS_PATH        = os.path.join(ROOT_DIR, "data", "cloud", "cloud_events.json")
SNAPSHOTS_BEFORE_PATH    = os.path.join(ROOT_DIR, "snapshots", "before.json")
SNAPSHOTS_AFTER_PATH     = os.path.join(ROOT_DIR, "snapshots", "after.json")


def _safe_load(path: str, default=None):
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def load_correlation():
    """Load process correlation data. Returns flat dict {proc: [events]}."""
    data = _safe_load(CORRELATION_PATH, {})
    # report_builder wraps data under "process_timeline" key — unwrap if needed
    if isinstance(data, dict) and "process_timeline" in data:
        return data["process_timeline"]
    return data if isinstance(data, dict) else {}


def load_iocs():
    data = _safe_load(IOC_PATH, [])
    return data if isinstance(data, list) else []


def load_endpoint_risk():
    return _safe_load(ENDPOINT_RISK_PATH, None)


def load_cloud_risk():
    return _safe_load(CLOUD_RISK_PATH, None)


def load_cloud_endpoint_correlations():
    data = _safe_load(CLOUD_ENDPOINT_CORR_PATH, [])
    return data if isinstance(data, list) else []


def load_manifest():
    return _safe_load(MANIFEST_PATH, None)


def load_cloud_events():
    data = _safe_load(CLOUD_EVENTS_PATH, [])
    return data if isinstance(data, list) else []


def load_snapshots():
    before = _safe_load(SNAPSHOTS_BEFORE_PATH, None)
    after  = _safe_load(SNAPSHOTS_AFTER_PATH,  None)
    return before, after