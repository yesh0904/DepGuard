#!/usr/bin/env python3
"""depguard: small CLI that scans Python and npm dependencies for known
vulnerabilities and exposes the results as Prometheus metrics.

Setup:  pip install pip-audit prometheus-client
Usage:  python depguard.py scan --requirements requirements.txt --npm-dir ./my-node-app
        python depguard.py scan --requirements requirements.txt --serve 8000
Metrics: http://localhost:8000/metrics  (scrape with Prometheus, chart in Grafana)
"""
import argparse
import json
import subprocess
import sys
import time

from prometheus_client import Gauge, start_http_server

VULNS = Gauge("depguard_vulnerabilities", "Known vulnerabilities found",
              ["ecosystem", "severity"])
PKGS = Gauge("depguard_vulnerable_packages", "Packages with known vulnerabilities",
             ["ecosystem"])
LAST_SCAN = Gauge("depguard_last_scan_timestamp", "Unix time of the last scan")


def run(cmd, cwd=None):
    # pip-audit and npm audit exit non-zero when vulnerabilities are found,
    # so do not use check=True.
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True).stdout


def scan_pip(requirements):
    out = run(["pip-audit", "-r", requirements, "-f", "json"])
    data = json.loads(out)
    deps = data.get("dependencies", data) if isinstance(data, dict) else data
    bad = [d for d in deps if d.get("vulns")]
    total = sum(len(d["vulns"]) for d in bad)
    VULNS.labels("pip", "unknown").set(total)
    PKGS.labels("pip").set(len(bad))
    for d in bad:
        fixes = sorted({v for x in d["vulns"] for v in x.get("fix_versions", [])})
        print(f"[pip] {d['name']} {d['version']}: {len(d['vulns'])} vuln(s); fix: {', '.join(fixes) or 'none'}")
    print(f"[pip] {len(bad)} vulnerable package(s), {total} vulnerabilities")
    return total


def scan_npm(path):
    out = run(["npm", "audit", "--json"], cwd=path)
    data = json.loads(out)
    counts = data.get("metadata", {}).get("vulnerabilities", {})
    for sev in ("info", "low", "moderate", "high", "critical"):
        VULNS.labels("npm", sev).set(counts.get(sev, 0))
    PKGS.labels("npm").set(len(data.get("vulnerabilities", {})))
    print(f"[npm] {counts}")
    return counts.get("total", 0)


def main():
    p = argparse.ArgumentParser(prog="depguard")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan dependencies")
    s.add_argument("--requirements", help="path to requirements.txt")
    s.add_argument("--npm-dir", help="folder containing package.json")
    s.add_argument("--serve", type=int, metavar="PORT", help="serve Prometheus metrics on PORT")
    s.add_argument("--fail-on-vulns", action="store_true", help="exit 1 if any found (for CI)")
    a = p.parse_args()

    total = 0
    if a.requirements:
        total += scan_pip(a.requirements)
    if a.npm_dir:
        total += scan_npm(a.npm_dir)
    LAST_SCAN.set(time.time())

    if a.serve:
        start_http_server(a.serve)
        print(f"Serving metrics on :{a.serve}/metrics (Ctrl+C to stop)")
        while True:
            time.sleep(3600)
    if a.fail_on_vulns and total:
        sys.exit(1)


if __name__ == "__main__":
    main()
