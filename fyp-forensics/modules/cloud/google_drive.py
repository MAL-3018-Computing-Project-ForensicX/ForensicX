"""
google_drive.py
Google Drive Metadata Collector — NO TOKEN CACHING (enforced)

SECURITY: This module NEVER saves or loads any token file.
On every call it:
  1. Actively deletes any leftover token file (drive_token.pickle) if found
  2. Runs a fresh OAuth browser flow with prompt=consent so Google always
     shows the account picker — even if the browser has an active session
  3. Uses access_type="online" so no refresh token is issued
  4. Does NOT write the new credentials anywhere on disk

This guarantees the user must authenticate every single time.
"""

import os
import datetime
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow

SCOPES = ['https://www.googleapis.com/auth/drive.metadata.readonly']

# Determine project root (three levels up: modules/cloud/google_drive.py → root)
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))

# All known locations where old token files might exist
_STALE_TOKEN_PATHS = [
    os.path.join(PROJECT_ROOT, "config", "drive_token.pickle"),
    os.path.join(PROJECT_ROOT, "drive_token.pickle"),
    os.path.join(os.path.dirname(__file__), "drive_token.pickle"),
    "drive_token.pickle",
    "config/drive_token.pickle",
]


def _purge_stale_tokens():
    """Delete any cached token files left over from previous versions."""
    for path in _STALE_TOKEN_PATHS:
        try:
            abs_path = path if os.path.isabs(path) else os.path.abspath(path)
            if os.path.exists(abs_path):
                os.remove(abs_path)
                print(f"[SECURITY] Removed stale Google Drive token: {abs_path}")
        except Exception as e:
            print(f"[WARN] Could not remove token file {path}: {e}")


def collect_drive_metadata(credentials_file):
    """
    Collect file metadata from Google Drive.

    Always performs a fresh OAuth login — no token is ever cached or saved.
    The user must authorise in their browser on every run.

    Args:
        credentials_file: Path to the OAuth client secrets JSON file.

    Returns:
        List of event dicts, one per file.
    """
    # Step 1: Purge any stale cached tokens from previous versions
    _purge_stale_tokens()

    # Step 2: Run a completely fresh OAuth flow
    flow = InstalledAppFlow.from_client_secrets_file(credentials_file, SCOPES)

    # prompt="consent"  → Google always shows the account picker
    # access_type="online" → no refresh token issued, session is one-time only
    os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = "1"
    creds = flow.run_local_server(
        port=0,
        prompt="consent",
        access_type="online",
    )

    # Step 3: Use credentials immediately — DO NOT save them anywhere
    service = build('drive', 'v3', credentials=creds)

    results = service.files().list(
        pageSize=100,
        fields="files(id,name,modifiedTime,createdTime,owners(displayName,emailAddress),shared,size)"
    ).execute()

    events = []
    for f in results.get('files', []):
        events.append({
            "source":        "cloud",
            "provider":      "google_drive",
            "event_type":    "file_metadata",
            "file_name":     f.get("name"),
            "file_id":       f.get("id"),
            "shared":        f.get("shared"),
            "owner":         f.get("owners", [{}])[0].get("emailAddress"),
            "created_time":  f.get("createdTime"),
            "modified_time": f.get("modifiedTime"),
            "collected_at":  datetime.datetime.utcnow().isoformat() + "Z"
        })

    return events