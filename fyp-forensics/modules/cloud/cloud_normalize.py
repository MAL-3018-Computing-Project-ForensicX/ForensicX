#!/usr/bin/env python3
"""
cloud_normalize.py
Cloud Event Normalizer

Converts raw cloud provider events (Google Drive, OneDrive) into
the standard forensic timeline event format used by the correlation engine.

FIX: provider field could be None when normalizing some events, causing
     `ev.get("provider").upper()` to raise AttributeError: 'NoneType'
     has no attribute 'upper'.
     Now safely falls back to "UNKNOWN" before calling .upper().
"""

from datetime import datetime


def normalize_cloud_events(cloud_events):
    """
    Normalize cloud events into standard forensic timeline format.

    Each output event has the same structure as Sysmon/snapshot events so
    the correlation engine can process all sources uniformly.

    Args:
        cloud_events (list): Raw events from google_drive.py / onedrive.py.

    Returns:
        list: Normalized event dictionaries.
    """
    normalized = []

    for ev in cloud_events:
        # FIX: was ev.get("provider").upper() — crashes if provider is None.
        # Now safely coerces to "UNKNOWN" before calling .upper().
        provider_raw   = ev.get("provider") or "unknown"
        provider_upper = provider_raw.upper()

        file_name = ev.get("file_name") or ev.get("name") or "unknown_file"
        owner     = ev.get("owner") or "unknown"
        shared    = ev.get("shared", False)

        # Prefer modified_time → created_time → collected_at
        time = (
            ev.get("modified_time") or
            ev.get("created_time") or
            ev.get("collected_at")
        )

        details = (
            f"[CLOUD-{provider_upper}] "
            f"File='{file_name}', "
            f"Shared={shared}, "
            f"Owner={owner}"
        )

        normalized.append({
            "source":   "cloud",
            "provider": provider_raw,
            "event_id": "cloud_file_metadata",
            "tag":      "CLOUD",
            "time":     time,
            "name":     file_name,
            "file":     file_name,
            "pid":      f"{provider_raw}_cloud",   # virtual PID for grouping
            "details":  details,
            "raw":      ev
        })

    return normalized