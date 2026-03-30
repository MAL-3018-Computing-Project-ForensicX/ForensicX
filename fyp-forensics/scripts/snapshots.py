import os, hashlib, json, time, sys, math

def shannon_entropy(data):
    if not data:
        return 0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    for c in freq.values():
        p = c / len(data)
        entropy -= p * math.log2(p)
    return entropy

def hash_file(path):
    h = hashlib.sha256()
    first_chunk_entropy = 0

    with open(path, 'rb') as f:
        chunk = f.read(1024*1024)  # Read first 1MB
        if chunk:
            h.update(chunk)
            first_chunk_entropy = shannon_entropy(chunk)

        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    
    return h.hexdigest(), first_chunk_entropy

def snapshot(dir_path, out_file):
    data = {"timestamp": time.time(), "files": []}
    for root, dirs, files in os.walk(dir_path):
        for name in files:
            fpath = os.path.join(root, name)
            try:
                fhash, entropy = hash_file(fpath)
                data["files"].append({
                    "path": fpath,
                    "hash": fhash,
                    "entropy": entropy,
                    "size": os.path.getsize(fpath),
                    "mtime": os.path.getmtime(fpath)
                })
            except Exception as e:
                print(f"skipping {fpath}: {e}")
    with open(out_file, 'w') as out:
        json.dump(data, out, indent=2)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python snapshot.py <directory> <out_json>")
        sys.exit(1)
    snapshot(sys.argv[1], sys.argv[2])
