from collections import defaultdict
from datetime import datetime, timedelta

# ----------------------------------------------------------------------
# Local parse_time (no external dependency)
# ----------------------------------------------------------------------
def parse_time(t):
    """
    Parse various timestamp formats to datetime object
    
    Args:
        t: timestamp string, int, float, or datetime
    
    Returns:
        datetime object or None if parsing fails
    """
    if not t:
        return None
    
    # If already a datetime object
    if isinstance(t, datetime):
        return t
    
    # If it's a timestamp (int/float)
    if isinstance(t, (int, float)):
        try:
            return datetime.fromtimestamp(t)
        except:
            return None
    
    # If it's a string
    if isinstance(t, str):
        try:
            # Remove Z suffix if present
            if t.endswith("Z"):
                t = t[:-1]
            
            # Try ISO format first
            try:
                return datetime.fromisoformat(t)
            except:
                pass
            
            # Try common timestamp formats
            formats = [
                "%Y-%m-%d %H:%M:%S.%f",
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d %H:%M",
                "%Y-%m-%dT%H:%M:%S.%f",
                "%Y-%m-%dT%H:%M:%S"
            ]
            
            for fmt in formats:
                try:
                    return datetime.strptime(t, fmt)
                except:
                    continue
            
            return None
        except Exception:
            return None
    
    return None


def group_cloud_events(events):
    """
    Group cloud events by provider and owner
    
    Args:
        events: List of event dictionaries
    
    Returns:
        dict: Dictionary with keys like "google_drive|user@email.com" containing lists of events
    """
    grouped = defaultdict(list)

    for e in events:
        # Check if it's a cloud event
        if e.get("source") != "cloud" and e.get("provider") not in ["google_drive", "onedrive"]:
            continue

        # Extract provider (fallback to source if provider not present)
        provider = e.get("provider", "unknown")
        if provider == "unknown" and "source" in e:
            provider = e["source"]
        
        # Extract owner/email
        owner = e.get("owner", e.get("owner_email", e.get("user_email", "unknown")))
        if owner == "unknown":
            owner = e.get("email", "unknown")
        
        key = f"{provider}|{owner}"
        grouped[key].append(e)

    return grouped


def detect_rename_burst(events, window_minutes=5, threshold=8):
    """
    Detect rapid rename activity typical of ransomware
    
    Returns:
        dict with rename_count and suspicious flag
    """
    rename_times = []

    for e in events:
        # Look for rename-related metadata
        if e.get("event_type") in ["file_rename", "file_metadata"]:
            name = e.get("file_name", "").lower()
            if "." in name:
                rename_times.append(parse_time(
                    e.get("modified_time") or e.get("time")
                ))

    rename_times = [t for t in rename_times if t]
    rename_times.sort()

    max_rename_burst = 0
    for i in range(len(rename_times)):
        start = rename_times[i]
        end = start + timedelta(minutes=window_minutes)
        count = sum(1 for t in rename_times if start <= t <= end)
        max_rename_burst = max(max_rename_burst, count)

    return {
        "rename_burst": max_rename_burst,
        "suspicious": max_rename_burst >= threshold
    }


def detect_cloud_wide_impact(events, unique_files, max_burst, threshold=10):
    """
    Detect cloud-wide ransomware impact
    
    Returns:
        tuple: (is_cloud_wide, reason)
    """
    # Rule 1: High file count with burst activity
    if unique_files >= 20 and max_burst >= threshold:
        return True, f"Cloud-wide modification pattern: {unique_files} files affected with {max_burst} modifications in short time"
    
    # Rule 2: Multiple file types affected
    file_extensions = set()
    for e in events:
        filename = e.get("file_name", e.get("name", ""))
        if "." in filename:
            ext = filename.split(".")[-1].lower()
            if len(ext) <= 5:  # Reasonable extension length
                file_extensions.add(ext)
    
    if len(file_extensions) >= 5 and max_burst >= threshold:
        return True, f"Multiple file types affected ({len(file_extensions)} types): ransomware typically targets diverse files"
    
    # Rule 3: Temporal spread across different times
    if len(events) >= 30:
        times = []
        for e in events:
            t = parse_time(e.get("modified_time") or e.get("created_time") or e.get("time"))
            if t:
                times.append(t)
        
        if times:
            times.sort()
            time_span = (max(times) - min(times)).total_seconds() / 3600  # hours
            if time_span > 0.5 and time_span < 4:  # Between 30 mins and 4 hours
                return True, f"Systematic encryption over {time_span:.1f} hours: consistent with ransomware operation"
    
    return False, ""


def analyze_cloud_behavior(events, window_minutes=10, threshold=10):
    """
    Detect ransomware-like behavior in cloud metadata
    
    Args:
        events: List of event dictionaries
        window_minutes: Time window in minutes to check for bursts
        threshold: Number of events within window to consider as suspicious
    
    Returns:
        dict: Risk summary for each provider and owner combination
    """
    # First, group events by provider and owner
    grouped_events = group_cloud_events(events)
    
    risk_summary = {}

    for key, evs in grouped_events.items():
        if not evs:
            continue
            
        # Split key back into provider and owner
        provider, owner = key.split("|") if "|" in key else (key, "unknown")
        
        # Extract timestamps
        times = []
        for e in evs:
            # Try multiple possible timestamp fields
            timestamp_fields = ["modified_time", "created_time", "collected_at", "timestamp", "time"]
            
            for field in timestamp_fields:
                t = e.get(field)
                if t:
                    dt = parse_time(t)
                    if dt:
                        times.append(dt)
                        break
        
        if not times:
            risk_summary[key] = {
                "provider": provider,
                "owner": owner,
                "total_events": len(evs),
                "max_burst": 0,
                "risk_level": "LOW",
                "reason": "No valid timestamps found"
            }
            continue
        
        times.sort()
        
        # Analyze temporal patterns
        max_burst = 0
        burst_windows = []
        
        for i in range(len(times)):
            window_start = times[i]
            window_end = window_start + timedelta(minutes=window_minutes)
            
            # Count events within window
            count = sum(1 for t in times if window_start <= t <= window_end)
            
            if count > max_burst:
                max_burst = count
                burst_windows = [(window_start, window_end, count)]
            elif count == max_burst and max_burst > 0:
                burst_windows.append((window_start, window_end, count))
        
        # Calculate risk level
        risk_level = "LOW"
        risk_reasons = []
        
        if max_burst >= threshold:
            risk_level = "HIGH"
            risk_reasons.append(f"High burst activity: {max_burst} events within {window_minutes} minutes")
        elif max_burst >= threshold // 2:
            risk_level = "MEDIUM"
            risk_reasons.append(f"Medium burst activity: {max_burst} events within {window_minutes} minutes")
        
        # Additional risk indicators
        unique_files = len(set(e.get("file_name", e.get("name", "")) for e in evs))
        if unique_files > threshold * 2:
            risk_level = max(risk_level, "MEDIUM")
            risk_reasons.append(f"High file count: {unique_files} unique files")
        
        # Check for suspicious file extensions
        ransom_extensions = ['.locky', '.crypt', '.encrypted', '.locked', '.wncry', '.wcry', 
                            '.ransom', '.lockbit', '.lock', '.encrypt', '.enc']
        ransom_files = []
        for e in evs:
            filename = e.get("file_name", e.get("name", "")).lower()
            if any(filename.endswith(ext) for ext in ransom_extensions):
                ransom_files.append(filename)
        
        if ransom_files:
            risk_level = "HIGH"
            risk_reasons.append(f"Ransomware-like file extensions detected: {ransom_files[:3]}")  # Show first 3
        
        # Detect rename burst activity
        rename_analysis = detect_rename_burst(evs)
        if rename_analysis["suspicious"]:
            risk_level = "HIGH"
            risk_reasons.append(
                f"Rapid rename activity detected: {rename_analysis['rename_burst']} renames within 5 minutes"
            )
        
        # Detect cloud-wide impact (STEP 5.2.3 - ADDED)
        cloud_wide_impact, cloud_wide_reason = detect_cloud_wide_impact(evs, unique_files, max_burst, threshold)
        if cloud_wide_impact:
            risk_level = "HIGH"
            risk_reasons.append(cloud_wide_reason)
        
        # Automated pattern detection (non-human behavior)
        if max_burst >= 15 and unique_files >= 15:
            # Very consistent, rapid modification pattern
            time_intervals = []
            for i in range(1, len(times)):
                interval = (times[i] - times[i-1]).total_seconds()
                if interval > 0:
                    time_intervals.append(interval)
            
            if time_intervals:
                avg_interval = sum(time_intervals) / len(time_intervals)
                if 1 <= avg_interval <= 10:  # Between 1-10 seconds between events
                    risk_level = max(risk_level, "HIGH")
                    risk_reasons.append(f"Automated pattern detected: average {avg_interval:.1f}s between events (non-human behavior)")
        
        risk_summary[key] = {
            "provider": provider,
            "owner": owner,
            "total_events": len(evs),
            "unique_files": unique_files,
            "max_burst": max_burst,
            "rename_burst": rename_analysis["rename_burst"],
            "risk_level": risk_level,
            "risk_reasons": risk_reasons if risk_reasons else ["No significant indicators"],
            "time_range": {
                "first": min(times).isoformat() if times else None,
                "last": max(times).isoformat() if times else None
            },
            "burst_windows": [
                {
                    "start": start.isoformat(),
                    "end": end.isoformat(),
                    "count": count
                }
                for start, end, count in burst_windows[:3]  # Limit to top 3 windows
            ]
        }
    
    return risk_summary


def get_high_risk_cloud_activities(risk_summary, min_risk="MEDIUM"):
    """
    Filter and return only high/medium risk activities
    
    Args:
        risk_summary: Output from analyze_cloud_behavior
        min_risk: Minimum risk level to include ("LOW", "MEDIUM", "HIGH")
    
    Returns:
        dict: Filtered risk summary
    """
    risk_levels = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
    min_level = risk_levels.get(min_risk.upper(), 1)
    
    filtered = {}
    for key, data in risk_summary.items():
        if risk_levels.get(data["risk_level"], 0) >= min_level:
            filtered[key] = data
    
    return filtered


# Enhanced testing with ransomware-like patterns
if __name__ == "__main__":
    print("Testing enhanced cloud behavior analysis...")
    print("=" * 60)
    
    # Create ransomware-like test data
    test_time = datetime(2024, 1, 15, 10, 0, 0)
    ransomware_events = []
    
    # Simulate ransomware burst
    for i in range(25):
        event_time = test_time + timedelta(seconds=i*5)  # Every 5 seconds
        ransomware_events.append({
            "source": "cloud",
            "provider": "google_drive",
            "owner": "victim@company.com",
            "file_name": f"document{i}.docx.encrypted",
            "modified_time": event_time.isoformat() + "Z",
            "event_type": "file_metadata"
        })
    
    # Add some normal events
    normal_events = [
        {
            "source": "cloud",
            "provider": "google_drive",
            "owner": "user@example.com",
            "file_name": "report.pdf",
            "modified_time": "2024-01-15T09:00:00Z",
            "event_type": "file_metadata"
        }
    ]
    
    all_test_events = ransomware_events + normal_events
    
    # Test analysis
    risk = analyze_cloud_behavior(all_test_events, window_minutes=10, threshold=8)
    
    print("Risk Analysis Results:")
    print("=" * 60)
    
    for key, data in risk.items():
        print(f"\n🔍 {key}:")
        print(f"   Provider: {data['provider']}")
        print(f"   Owner: {data['owner']}")
        print(f"   Risk Level: {data['risk_level']}")
        print(f"   Total Events: {data['total_events']}")
        print(f"   Unique Files: {data['unique_files']}")
        print(f"   Max Burst: {data['max_burst']}")
        print(f"   Rename Burst: {data['rename_burst']}")
        
        if data['risk_reasons']:
            print(f"   Risk Reasons:")
            for reason in data['risk_reasons']:
                print(f"     • {reason}")
    
    print("\n" + "=" * 60)
    
    # Test filtering
    high_risk = get_high_risk_cloud_activities(risk, "HIGH")
    print(f"HIGH Risk Activities: {len(high_risk)}")
    
    if high_risk:
        print("\nHigh Risk Details:")
        for key, data in high_risk.items():
            print(f"  {key}: {data['risk_level']} - {', '.join(data['risk_reasons'][:2])}")
    
    print("\n" + "=" * 60)
    print("Enhanced cloud ransomware behavior detection complete!")