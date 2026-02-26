#!/usr/bin/env python3
import argparse
import hashlib
import os
import re
from datetime import datetime

HASH_RE = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")

def compute_hash(path, algo):
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def load_iocs(ioc_file):
    iocs = set()
    with open(ioc_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if HASH_RE.match(line):
                iocs.add(line.lower())
    return iocs

def main():
    ap = argparse.ArgumentParser(description="Offline IOC checker (hash compare + simple indicator scan).")
    ap.add_argument("--ioc-file", required=True, help="Path to IOC list (hashes)")
    ap.add_argument("--hash-file", required=True, help="File to hash and compare")
    args = ap.parse_args()

    if not os.path.exists(args.hash_file):
        raise SystemExit(f"File not found: {args.hash_file}")

    iocs = load_iocs(args.ioc_file)
    sha256 = compute_hash(args.hash_file, "sha256")
    md5 = compute_hash(args.hash_file, "md5")

    print(f"[{datetime.now().isoformat()}] IOC Check")
    print(f"File: {os.path.abspath(args.hash_file)}")
    print(f"MD5: {md5}")
    print(f"SHA256: {sha256}")
    print("-" * 60)

    hit = False
    if md5.lower() in iocs:
        print("[MATCH] MD5 hash is in IOC list")
        hit = True
    if sha256.lower() in iocs:
        print("[MATCH] SHA256 hash is in IOC list")
        hit = True

    if not hit:
        print("[OK] No hash match found in IOC list (offline).")

    print("\nNote: For production, combine with approved AV/EDR tooling and vendor threat intel.")
if __name__ == "__main__":
    main()
