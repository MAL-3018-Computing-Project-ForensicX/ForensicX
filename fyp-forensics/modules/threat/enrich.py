# modules/threat/enrich.py
import requests, logging, time, json, os
LOG = logging.getLogger("enrich")
LOG.setLevel(logging.INFO)

def load_config(conf_path="config/config.json"):
    if not os.path.exists(conf_path):
        return {}
    return json.load(open(conf_path, "r", encoding="utf-8"))

def vt_lookup_hash(api_key, h):
    """VirusTotal file/hash report - simple v3 example (replace as needed)"""
    if not api_key:
        return {"vt": "no_key"}
    url = f"https://www.virustotal.com/api/v3/files/{h}"
    headers = {"x-apikey": api_key}
    try:
        r = requests.get(url, headers=headers, timeout=15)
        return r.json()
    except Exception as e:
        LOG.warning("VT lookup failed: %s", e)
        return {"error": str(e)}

def abuseipdb_check(api_key, ip):
    if not api_key:
        return {"abuseipdb": "no_key"}
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    headers = {"Key": api_key, "Accept": "application/json"}
    try:
        r = requests.get(url, headers=headers, params=params, timeout=10)
        return r.json()
    except Exception as e:
        LOG.warning("AbuseIPDB lookup failed: %s", e)
        return {"error": str(e)}

def enrich_events(events, config=None):
    """
    events: list of event dicts (as from correlate)
    Returns: enrichment summary & events modified (adds e['enrich'] entries)
    """
    if config is None:
        config = load_config()
    vt_key = config.get("virus_total_api_key", "")
    abuse_key = config.get("abuseipdb_api_key", "")
    stats = {"vt_hashes":0,"abuse_ips":0}
    for e in events:
        try:
            # hash enrichment for snapshot artifacts
            if e.get("hash"):
                # simple local check: compare to ioc.json later; here do external if key present
                if vt_key:
                    res = vt_lookup_hash(vt_key, e["hash"])
                    e.setdefault("enrich", {})["virustotal"] = res
                    stats["vt_hashes"] += 1
            # IP enrichment for network events
            if e.get("tag") == "NETWORK":
                # extract IPs from details (structured fields preferred: src_ip/dst_ip)
                src = e.get("src_ip") or ""
                dst = e.get("dst_ip") or ""
                for ip in (src, dst):
                    if ip:
                        if abuse_key:
                            res = abuseipdb_check(abuse_key, ip)
                            e.setdefault("enrich", {}).setdefault("abuseipdb", {})[ip] = res
                            stats["abuse_ips"] += 1
                        else:
                            e.setdefault("enrich", {}).setdefault("abuseipdb", {})[ip] = {"note":"no_key"}
        except Exception as ex:
            LOG.warning("enrich error for event: %s", ex)
    return stats
