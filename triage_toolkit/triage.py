#!/usr/bin/env python3
import argparse
import json
import os
import platform
import socket
import subprocess
import sys
from datetime import datetime

import psutil

def run_cmd(cmd):
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, shell=isinstance(cmd, str))
        return out.strip()
    except Exception as e:
        return f"ERROR running {cmd}: {e}"

def best_effort_dns():
    system = platform.system().lower()
    if system == "windows":
        return run_cmd("ipconfig /all")
    # linux/mac
    resolv = ""
    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8", errors="ignore") as f:
            resolv = f.read()
    except Exception as e:
        resolv = f"ERROR reading /etc/resolv.conf: {e}"
    return resolv.strip()

def best_effort_routes():
    system = platform.system().lower()
    if system == "windows":
        return run_cmd("route print")
    return run_cmd("ip route || route -n")

def list_ips():
    ips = []
    for iface, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            if a.family.name in ("AF_INET", "AddressFamily.AF_INET"):
                ips.append({"interface": iface, "ip": a.address, "netmask": a.netmask})
    return ips

def connections_snapshot(limit=200):
    conns = []
    try:
        for c in psutil.net_connections(kind="inet")[:limit]:
            laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
            raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
            conns.append({
                "laddr": laddr,
                "raddr": raddr,
                "status": c.status,
                "pid": c.pid
            })
    except Exception as e:
        conns.append({"error": str(e)})
    return conns

def top_processes(limit=30):
    procs = []
    for p in psutil.process_iter(attrs=["pid", "name", "username"]):
        try:
            info = p.info
            # CPU percent needs a prior call; keep it simple
            mem = p.memory_info().rss if p.is_running() else 0
            procs.append({
                "pid": info.get("pid"),
                "name": info.get("name"),
                "username": info.get("username"),
                "rss_bytes": mem
            })
        except Exception:
            continue
    procs.sort(key=lambda x: x.get("rss_bytes", 0), reverse=True)
    return procs[:limit]

def file_hash(path, algo="sha256"):
    import hashlib
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def security_notes():
    return [
        "Red flags: unknown admin tools, repeated MFA prompts, browser proxy changes, unknown startup items.",
        "If compromise suspected: isolate device from network and escalate with collected report.",
        "Do not delete suspicious files before hashing/capturing paths and timestamps."
    ]

def main():
    ap = argparse.ArgumentParser(description="IT Security Triage Toolkit - Endpoint diagnostics collector")
    ap.add_argument("--outdir", default="reports", help="Output directory (default: reports)")
    ap.add_argument("--hash-file", default=None, help="Optional file path to hash (safe offline)")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    hostname = socket.gethostname()

    report = {
        "timestamp": datetime.now().isoformat(),
        "host": {
            "hostname": hostname,
            "platform": platform.platform(),
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "python": sys.version,
            "boot_time": datetime.fromtimestamp(psutil.boot_time()).isoformat(),
            "users": [u._asdict() for u in psutil.users()],
        },
        "network": {
            "ips": list_ips(),
            "routes": best_effort_routes(),
            "dns_config": best_effort_dns(),
            "connections": connections_snapshot(),
        },
        "processes": {
            "top_by_memory": top_processes()
        },
        "security_notes": security_notes(),
        "hashes": {}
    }

    if args.hash_file:
        try:
            report["hashes"]["sha256"] = file_hash(args.hash_file, "sha256")
            report["hashes"]["md5"] = file_hash(args.hash_file, "md5")
            report["hashes"]["file"] = os.path.abspath(args.hash_file)
        except Exception as e:
            report["hashes"]["error"] = str(e)

    json_path = os.path.join(args.outdir, f"triage_{hostname}_{ts}.json")
    txt_path = os.path.join(args.outdir, f"triage_{hostname}_{ts}.txt")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    # Human-friendly text summary
    lines = []
    lines.append(f"IT Security Triage Report - {hostname} - {report['timestamp']}")
    lines.append("=" * 72)
    lines.append(f"OS: {report['host']['platform']}")
    lines.append(f"Boot time: {report['host']['boot_time']}")
    lines.append("")
    lines.append("IP Addresses:")
    for ip in report["network"]["ips"]:
        lines.append(f"  - {ip['interface']}: {ip['ip']} ({ip.get('netmask','')})")
    lines.append("")
    lines.append("Top Processes (by memory):")
    for p in report["processes"]["top_by_memory"]:
        lines.append(f"  - {p['name']} (PID {p['pid']}) user={p.get('username')} rss={p['rss_bytes']}")
    lines.append("")
    if report["hashes"]:
        lines.append("File Hashes:")
        for k, v in report["hashes"].items():
            lines.append(f"  {k}: {v}")
        lines.append("")
    lines.append("Security Notes:")
    for n in report["security_notes"]:
        lines.append(f"  - {n}")
    lines.append("")
    lines.append(f"Saved JSON: {json_path}")
    lines.append(f"Saved TXT : {txt_path}")

    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print("\n".join(lines))

if __name__ == "__main__":
    main()
