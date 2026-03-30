#!/usr/bin/env python3
"""
cloud_collect.py
Cloud Metadata Collection Module

Collects file metadata from Google Drive and OneDrive using configured credentials,
then saves all events to data/cloud/cloud_events.json.

FIX: CONFIG_PATH was pointing to <project_root>/config.json but the
     actual config lives at <project_root>/config/config.json.
     This caused cloud collection to silently skip on every run.
     Now matches the path used by orchestrator.py.
"""

import json
import os
import sys

# ── Project-root resolution ──────────────────────────────────────────────────
# This file lives at:  <project_root>/modules/cloud/cloud_collect.py
# So project root is two levels up.
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))

# FIX: was os.path.join(PROJECT_ROOT, "config.json")
#      Corrected to match actual location: config/config.json
CONFIG_PATH = os.path.join(PROJECT_ROOT, "config", "config.json")
OUTPUT_PATH = os.path.join(PROJECT_ROOT, "data", "cloud", "cloud_events.json")


def main():
    """Run cloud collection for all enabled providers."""

    # Guard: config must exist
    if not os.path.exists(CONFIG_PATH):
        print(f"[WARN] Cloud config not found at {CONFIG_PATH}. Skipping cloud collection.")
        return

    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
            cfg = json.load(fh)
    except Exception as e:
        print(f"[ERROR] Failed to load config: {e}")
        return

    all_events = []

    # ── Google Drive ─────────────────────────────────────────────────────────
    if cfg.get("google_drive", {}).get("enabled"):
        print("[+] Collecting Google Drive metadata...")
        try:
            from modules.cloud.google_drive import collect_drive_metadata

            cred_file = cfg["google_drive"].get("credentials_file")
            if not cred_file:
                print("    ⚠ No credentials_file specified for Google Drive")
            else:
                # Resolve relative paths against project root
                if not os.path.isabs(cred_file):
                    cred_file = os.path.join(PROJECT_ROOT, cred_file)

                if not os.path.exists(cred_file):
                    print(f"    ⚠ Credentials file not found: {cred_file}")
                else:
                    gd_events = collect_drive_metadata(cred_file)
                    all_events.extend(gd_events)
                    print(f"    ✓ Google Drive: {len(gd_events)} items")
        except Exception as e:
            print(f"    ⚠ Google Drive collection failed: {e}")

    # ── OneDrive ─────────────────────────────────────────────────────────────
    if cfg.get("onedrive", {}).get("enabled"):
        print("[+] Collecting OneDrive metadata...")
        try:
            from modules.cloud.onedrive import collect_onedrive_metadata

            client_id = cfg["onedrive"].get("client_id")
            if not client_id:
                print("    ⚠ No client_id specified for OneDrive")
            else:
                od_events = collect_onedrive_metadata(client_id)
                all_events.extend(od_events)
                print(f"    ✓ OneDrive: {len(od_events)} items")
        except Exception as e:
            print(f"    ⚠ OneDrive collection failed: {e}")

    # ── Save results ─────────────────────────────────────────────────────────
    if all_events:
        os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
        with open(OUTPUT_PATH, "w", encoding="utf-8") as fh:
            json.dump(all_events, fh, indent=2, default=str)
        print(f"[+] Cloud metadata collected: {len(all_events)} events")
        print(f"[+] Saved to {OUTPUT_PATH}")
    else:
        print("[+] No cloud events collected (no providers enabled or credentials missing).")


if __name__ == "__main__":
    main()