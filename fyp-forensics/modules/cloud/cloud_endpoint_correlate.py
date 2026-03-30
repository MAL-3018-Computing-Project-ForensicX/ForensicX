#!/usr/bin/env python3
"""
cloud_endpoint_correlate.py
Cloud-Endpoint Correlation Module

Correlates cloud storage activity (Google Drive, OneDrive) with endpoint events
to detect data exfiltration and ransomware attack chains.

FIXED: Now uses absolute paths (PROJECT_ROOT) to locate data files.
"""

import json
import os
from datetime import datetime, timedelta

# Determine project root (three levels up from this file: modules/cloud/cloud_endpoint_correlate.py -> project root)
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
CLOUD_PATH = os.path.join(PROJECT_ROOT, "data/cloud/cloud_events.json")
CORRELATION_PATH = os.path.join(PROJECT_ROOT, "report/correlation.json")
OUTPUT_PATH = os.path.join(PROJECT_ROOT, "report/cloud_endpoint_correlations.json")
CORRELATION_WINDOW_MINUTES = 10


def parse_time(t):
    """
    Parse various timestamp formats to timezone-naive datetime object.
    
    CRITICAL FIX: Always returns timezone-naive datetime to avoid
    "can't subtract offset-naive and offset-aware datetimes" error.
    """
    if not t:
        return None
    if isinstance(t, datetime):
        # Convert to timezone-naive if needed
        if t.tzinfo is not None:
            return t.replace(tzinfo=None)
        return t
    try:
        if isinstance(t, (int, float)):
            # Unix timestamp - creates naive datetime
            return datetime.fromtimestamp(t)
        if isinstance(t, str):
            # Remove 'Z' suffix if present
            if t.endswith("Z"):
                t = t[:-1]
            # Parse ISO format
            dt = datetime.fromisoformat(t)
            # Convert to timezone-naive
            if dt.tzinfo is not None:
                return dt.replace(tzinfo=None)
            return dt
    except:
        return None
    return None


def extract_filename(path_or_name):
    """Extract clean filename for matching."""
    if not path_or_name:
        return ""
    # Remove path separators
    name = path_or_name.replace("\\", "/").split("/")[-1]
    # Remove common ransomware extensions for matching
    name = name.replace(".locked", "").replace(".encrypted", "").replace(".crypt", "")
    return name.lower()


def calculate_confidence(time_diff_seconds, filename_match_score):
    """
    Calculate correlation confidence level.
    
    Args:
        time_diff_seconds: Absolute time difference between events
        filename_match_score: 0.0-1.0 (1.0 = exact match)
    
    Returns:
        "HIGH", "MEDIUM", or "LOW"
    """
    if time_diff_seconds <= 10 and filename_match_score >= 0.8:
        return "HIGH"
    elif time_diff_seconds <= 60 and filename_match_score >= 0.5:
        return "MEDIUM"
    elif time_diff_seconds <= 300 and filename_match_score >= 0.3:
        return "MEDIUM"
    else:
        return "LOW"


def correlate_cloud_endpoint():
    """
    Correlate cloud activity with endpoint activity.
    
    Returns:
        List of correlation findings with confidence scores
    """
    correlations = []
    
    # Load cloud events
    if not os.path.exists(CLOUD_PATH):
        print(f"[WARN] Cloud events not found: {CLOUD_PATH}")
        # Save empty result
        os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
        with open(OUTPUT_PATH, 'w', encoding='utf-8') as f:
            json.dump([], f, indent=2)
        return correlations
    
    try:
        with open(CLOUD_PATH, 'r', encoding='utf-8') as f:
            cloud_events = json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to load cloud events: {e}")
        # Save empty result
        os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
        with open(OUTPUT_PATH, 'w', encoding='utf-8') as f:
            json.dump([], f, indent=2)
        return correlations
    
    print(f"Loaded {len(cloud_events)} cloud events")
    
    # Load endpoint correlation data
    if not os.path.exists(CORRELATION_PATH):
        print(f"[WARN] Endpoint correlation not found: {CORRELATION_PATH}")
        print(f"[INFO] Creating correlations based on cloud data only")
        
        # Create basic correlations from cloud data
        for ce in cloud_events:
            cloud_time = parse_time(
                ce.get("modified_time") or ce.get("created_time") or ce.get("collected_at")
            )
            
            if not cloud_time:
                continue
            
            correlations.append({
                "type": "cloud_only",
                "cloud_provider": ce.get("provider"),
                "cloud_owner": ce.get("owner", "unknown"),
                "file_name": ce.get("file_name"),
                "cloud_time": cloud_time.isoformat(),
                "endpoint_process": "N/A (no endpoint data)",
                "endpoint_time": "N/A",
                "pid": "N/A",
                "timestamp_diff_seconds": 0,
                "confidence": "LOW",
                "description": (
                    f"Cloud file '{ce.get('file_name')}' "
                    f"modified on {ce.get('provider')} by {ce.get('owner', 'unknown')} "
                    f"(no endpoint correlation available)"
                ),
                "reason": "Cloud activity detected but no endpoint data available for correlation"
            })
        
        # Save and return
        os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
        with open(OUTPUT_PATH, 'w', encoding='utf-8') as f:
            json.dump(correlations, f, indent=2)
        
        print(f"[INFO] Saved {len(correlations)} cloud-only events to {OUTPUT_PATH}")
        return correlations
    
    # Load endpoint events
    try:
        with open(CORRELATION_PATH, 'r', encoding='utf-8') as f:
            endpoint_correlation = json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to load endpoint correlation: {e}")
        # Save empty result
        os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
        with open(OUTPUT_PATH, 'w', encoding='utf-8') as f:
            json.dump([], f, indent=2)
        return correlations
    
    print(f"Loaded endpoint correlation data")
    
    # Flatten endpoint events from process groups
    endpoint_events = []
    for process_key, events in endpoint_correlation.items():
        if isinstance(events, list):
            for event in events:
                event['process_key'] = process_key
                endpoint_events.append(event)
    
    print(f"Correlating {len(cloud_events)} cloud events with {len(endpoint_events)} endpoint events")
    
    # Correlation logic
    window = timedelta(minutes=CORRELATION_WINDOW_MINUTES)
    
    for ce in cloud_events:
        cloud_time = parse_time(
            ce.get("modified_time") or ce.get("created_time") or ce.get("collected_at")
        )
        
        if not cloud_time:
            continue
        
        cloud_filename = extract_filename(ce.get("file_name", ""))
        best_match = None
        best_score = 0
        
        # Find matching endpoint events
        for ee in endpoint_events:
            endpoint_time = parse_time(ee.get("time"))
            
            if not endpoint_time:
                continue
            
            # Check temporal proximity
            try:
                time_diff = abs((cloud_time - endpoint_time).total_seconds())
            except Exception as e:
                print(f"[WARN] Time diff calculation failed: {e}")
                continue
            
            if time_diff > (CORRELATION_WINDOW_MINUTES * 60):
                continue  # Outside correlation window
            
            # Check filename match
            endpoint_file = extract_filename(
                ee.get("file") or ee.get("name") or ee.get("details", "")
            )
            
            # Calculate filename match score
            filename_match_score = 0.0
            if cloud_filename and endpoint_file:
                if cloud_filename == endpoint_file:
                    filename_match_score = 1.0
                elif cloud_filename in endpoint_file or endpoint_file in cloud_filename:
                    filename_match_score = 0.7
                elif any(word in endpoint_file for word in cloud_filename.split() if len(word) > 3):
                    filename_match_score = 0.4
            
            # Calculate overall match score
            match_score = filename_match_score * (1.0 - (time_diff / (CORRELATION_WINDOW_MINUTES * 60)))
            
            if match_score > best_score:
                best_score = match_score
                best_match = {
                    "event": ee,
                    "time_diff": time_diff,
                    "filename_score": filename_match_score
                }
        
        # Create correlation entry
        if best_match and best_score > 0.1:  # Minimum threshold
            ee = best_match["event"]
            time_diff = best_match["time_diff"]
            filename_score = best_match["filename_score"]
            confidence = calculate_confidence(time_diff, filename_score)
            
            correlations.append({
                "type": "cloud_endpoint_correlation",
                "confidence": confidence,
                "match_score": round(best_score, 3),
                "timestamp_diff_seconds": round(time_diff, 2),
                
                # Cloud side
                "cloud_provider": ce.get("provider"),
                "cloud_owner": ce.get("owner", "unknown"),
                "cloud_time": cloud_time.isoformat(),
                "file_name": ce.get("file_name"),
                
                # Endpoint side
                "endpoint_process": ee.get("process_key", "unknown"),
                "endpoint_time": parse_time(ee.get("time")).isoformat() if ee.get("time") else "unknown",
                "endpoint_source": ee.get("source"),
                "pid": ee.get("pid", "unknown"),
                
                # Analysis
                "description": (
                    f"Cloud file '{ce.get('file_name')}' modified on {ce.get('provider')} "
                    f"correlates with endpoint activity by {ee.get('process_key')} "
                    f"(time delta: {time_diff:.1f}s, filename match: {filename_score:.0%})"
                ),
                "filename_match_score": round(filename_score, 3),
                "reason": get_correlation_reason(confidence, time_diff, filename_score)
            })
        else:
            # No endpoint match found - record cloud event only
            correlations.append({
                "type": "cloud_no_endpoint_match",
                "cloud_provider": ce.get("provider"),
                "cloud_owner": ce.get("owner", "unknown"),
                "file_name": ce.get("file_name"),
                "cloud_time": cloud_time.isoformat(),
                "endpoint_process": "N/A (no match found)",
                "endpoint_time": "N/A",
                "pid": "N/A",
                "timestamp_diff_seconds": 0,
                "confidence": "LOW",
                "description": (
                    f"Cloud file '{ce.get('file_name')}' modified on {ce.get('provider')} "
                    f"by {ce.get('owner', 'unknown')} (no matching endpoint activity)"
                ),
                "reason": "Cloud activity detected but no matching endpoint events within time window"
            })
    
    # Save results
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, 'w', encoding='utf-8') as f:
        json.dump(correlations, f, indent=2)
    
    # Print summary
    high_conf = sum(1 for c in correlations if c.get("confidence") == "HIGH")
    medium_conf = sum(1 for c in correlations if c.get("confidence") == "MEDIUM")
    low_conf = sum(1 for c in correlations if c.get("confidence") == "LOW")
    
    print(f"✓ Found {len(correlations)} correlations")
    print(f"Confidence breakdown:")
    print(f"  - HIGH: {high_conf}")
    print(f"  - MEDIUM: {medium_conf}")
    print(f"  - LOW: {low_conf}")
    
    return correlations


def get_correlation_reason(confidence, time_diff, filename_score):
    """Generate human-readable reason for correlation."""
    reasons = []
    
    if time_diff <= 10:
        reasons.append("Very close temporal proximity (≤10s)")
    elif time_diff <= 60:
        reasons.append("Close temporal proximity (≤1min)")
    elif time_diff <= 300:
        reasons.append("Moderate temporal proximity (≤5min)")
    
    if filename_score >= 0.8:
        reasons.append("Strong filename match")
    elif filename_score >= 0.5:
        reasons.append("Moderate filename match")
    elif filename_score >= 0.3:
        reasons.append("Weak filename match")
    
    if confidence == "HIGH":
        reasons.append("High likelihood of causation")
    elif confidence == "MEDIUM":
        reasons.append("Possible correlation")
    else:
        reasons.append("Weak correlation")
    
    return "; ".join(reasons)


if __name__ == "__main__":
    """
    Test the correlation function.
    """
    print("=" * 60)
    print("Cloud-Endpoint Correlation Module")
    print("=" * 60)
    
    correlations = correlate_cloud_endpoint()
    
    print("\n" + "=" * 60)
    print(f"Correlation complete: {len(correlations)} findings")
    print("=" * 60)
    
    if correlations:
        print("\nSample correlation:")
        print(json.dumps(correlations[0], indent=2))