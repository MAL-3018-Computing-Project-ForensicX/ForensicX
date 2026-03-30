from datetime import datetime

def normalize_cloud_events(events):
    normalized = []

    for e in events:
        provider = e.get("provider", "unknown")
        fname = e.get("file_name", "unknown")
        fid = e.get("file_id", "unknown")

        # Prefer modified_time → created_time → collected_at
        time = (
            e.get("modified_time")
            or e.get("created_time")
            or e.get("collected_at")
        )

        details = (
            f"[CLOUD] {provider} file '{fname}' "
            f"(id={fid}) shared={e.get('shared', False)}"
        )

        normalized.append({
            "source": "cloud",
            "event_id": "cloud_file",
            "tag": "CLOUD",
            "time": time,
            "pid": f"{provider}_cloud",   # virtual PID
            "name": f"{provider}_cloud",  # virtual process
            "file": fname,
            "details": details,
            "raw": e
        })

    return normalized
