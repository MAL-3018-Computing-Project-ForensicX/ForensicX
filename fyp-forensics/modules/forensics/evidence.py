# modules/forensics/evidence.py
import os, hashlib, json, time, logging
from datetime import datetime

LOG = logging.getLogger("evidence")
logging.basicConfig(level=logging.INFO)

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def add_artifact(manifest_path, artifact_path, role="unknown", extra=None):
    """
    Add artifact record to manifest.json and return record dict.
    manifest schema: {"generated": ts, "artifacts": [ {path, sha256, size, mtime, role, note} ], "audit": []}
    """
    manifest = {}
    if os.path.exists(manifest_path):
        with open(manifest_path, "r", encoding="utf-8") as fh:
            try:
                manifest = json.load(fh)
            except:
                manifest = {}
    if not manifest:
        manifest = {"generated": datetime.utcnow().isoformat() + "Z", "artifacts": [], "audit": []}

    rec = {}
    p = os.path.abspath(artifact_path)
    rec["path"] = p
    rec["role"] = role
    rec["sha256"] = sha256_file(p) if os.path.exists(p) else None
    stat = os.stat(p) if os.path.exists(p) else None
    rec["size"] = stat.st_size if stat else None
    rec["mtime"] = datetime.utcfromtimestamp(stat.st_mtime).isoformat() + "Z" if stat else None
    rec["added"] = datetime.utcnow().isoformat() + "Z"
    rec["extra"] = extra or {}
    manifest["artifacts"].append(rec)
    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, ensure_ascii=False)
    LOG.info("Added artifact to manifest: %s", p)
    return rec

def add_audit(manifest_path, actor, action, note=""):
    manifest = {}
    if os.path.exists(manifest_path):
        with open(manifest_path, "r", encoding="utf-8") as fh:
            try:
                manifest = json.load(fh)
            except:
                manifest = {}
    if not manifest:
        manifest = {"generated": datetime.utcnow().isoformat() + "Z", "artifacts": [], "audit": []}
    entry = {"time": datetime.utcnow().isoformat() + "Z", "actor": actor, "action": action, "note": note}
    manifest.setdefault("audit", []).append(entry)
    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, ensure_ascii=False)
    LOG.info("Audit logged: %s - %s", actor, action)
    return entry
