"""
onedrive.py
OneDrive Metadata Collector — NO TOKEN CACHING (enforced)
OneDrive Metadata Collector — with automatic browser login

SECURITY: This module NEVER saves or loads any token file.
On every call it:
  1. Actively deletes any leftover token file (onedrive_token.json) if found
  2. Creates a fresh MSAL app with an empty in-memory-only token cache
  3. Never calls acquire_token_silent() — always forces device-code flow
  4. Does NOT write the token/cache anywhere on disk

This guarantees the user must authenticate every single time.
"""
"""
onedrive.py
OneDrive Metadata Collector — with automatic browser login
"""

import os
import json
import datetime
import webbrowser
import logging
from msal import PublicClientApplication, SerializableTokenCache
import requests

GRAPH_API_ENDPOINT = "https://graph.microsoft.com/v1.0"

# Get logger for consistent formatting
logger = logging.getLogger(__name__)

# Determine project root
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))

# Stale token paths
_STALE_TOKEN_PATHS = [
    os.path.join(PROJECT_ROOT, "config", "onedrive_token.json"),
    os.path.join(PROJECT_ROOT, "onedrive_token.json"),
    os.path.join(os.path.dirname(__file__), "onedrive_token.json"),
    "onedrive_token.json",
    "config/onedrive_token.json",
]


def _purge_stale_tokens():
    """Delete any cached token files."""
    for path in _STALE_TOKEN_PATHS:
        try:
            abs_path = path if os.path.isabs(path) else os.path.abspath(path)
            if os.path.exists(abs_path):
                os.remove(abs_path)
                logger.info(f"[SECURITY] Removed stale OneDrive token: {abs_path}")
        except Exception as e:
            logger.warning(f"Could not remove token file {path}: {e}")


def collect_onedrive_metadata(client_id, redirect_uri="http://localhost:8080"):
    """
    Collect file metadata from OneDrive using interactive browser flow.
    
    Automatically opens the login page in your default browser.
    
    Args:
        client_id: Azure App Registration client ID.
        redirect_uri: Redirect URI (must match Azure App registration)
        
    Returns:
        List of event dicts, one per file.
    """
    # Purge stale tokens
    _purge_stale_tokens()
    
    # Create MSAL app with empty cache
    empty_cache = SerializableTokenCache()
    app = PublicClientApplication(
        client_id,
        authority="https://login.microsoftonline.com/common",
        token_cache=empty_cache,
    )
    
    # Use ONLY the basic scope - no reserved scopes
    scopes = ["Files.Read.All"]
    
    logger.info("Opening browser for Microsoft login...")
    
    try:
        # Use interactive flow which opens browser automatically
        result = app.acquire_token_interactive(
            scopes=scopes,
            prompt="select_account",  # Always show account picker
            timeout=120  # 2 minute timeout for authentication
        )
        
        if "access_token" in result:
            logger.info("✓ OneDrive authentication successful")
        else:
            logger.warning(f"Authentication failed: {result.get('error_description', 'Unknown error')}")
            return []
            
    except Exception as e:
        logger.warning(f"Interactive auth failed: {e}")
        logger.info("Falling back to device code flow...")
        
        # Fallback to device code flow if interactive fails
        flow = app.initiate_device_flow(scopes=scopes)
        if "user_code" not in flow:
            logger.error("Device code flow failed to initiate")
            return []
        
        # Try to auto-open the device code URL
        if "verification_uri" in flow:
            try:
                webbrowser.open(flow["verification_uri"])
                logger.info("Opened browser for device code authentication")
            except:
                pass
        
        # Display device code message (this is the fallback only)
        logger.info(flow["message"])
        result = app.acquire_token_by_device_flow(flow)
        
        if "access_token" not in result:
            logger.error(f"Device code flow failed: {result.get('error_description', 'unknown error')}")
            return []
        
        logger.info("✓ OneDrive authentication successful")
    
    # Fetch files from OneDrive
    logger.info("Fetching OneDrive files...")
    headers = {"Authorization": f"Bearer {result['access_token']}"}
    
    # Get root files
    response = requests.get(
        f"{GRAPH_API_ENDPOINT}/me/drive/root/children",
        headers=headers
    )
    
    if response.status_code != 200:
        logger.error(f"Failed to fetch files: {response.status_code}")
        return []
    
    events = []
    for item in response.json().get("value", []):
        events.append({
            "source":        "cloud",
            "provider":      "onedrive",
            "event_type":    "file_metadata",
            "file_name":     item.get("name"),
            "file_id":       item.get("id"),
            "created_time":  item.get("createdDateTime"),
            "modified_time": item.get("lastModifiedDateTime"),
            "shared":        "shared" in item,
            "size":          item.get("size"),
            "collected_at":  datetime.datetime.utcnow().isoformat() + "Z"
        })
    
    logger.info(f"✓ Retrieved {len(events)} files")
    return events