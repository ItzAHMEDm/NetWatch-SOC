"""NetWatch-SOC: Auth log & network flow anomaly detector with MITRE ATT&CK alert mapping."""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

FAILED_LOGIN_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2}).*?"
    r"Failed password.*?from\s+(?P<ip>(?:\d{1,3}\.){3}\d{1,3})",
    re.IGNORECASE,
)

HIGH_RISK_PORTS = {23: "Telnet", 3389: "RDP", 4444: "Metasploit/Reverse Shell", 1337: "C2/Backdoor", 6667: "IRC Botnet"}


def _parse_syslog_ts(month: str, day: str, time_str: str, year: int = 2026) -> float:
    dt = datetime.strptime(f"{year} {month} {int(day):02d} {time_str}", "%Y %b %d %H:%M:%S")
    return dt.timestamp()


def analyze_auth_log(
    log_path: Path, threshold: int = 5, window_seconds: int = 300
) -> list[dict[str, Any]]:
    """Detect SSH brute-force / credential stuffing bursts in auth logs."""
    attempts_by_ip: dict[str, list[float]] = defaultdict(list)
    for line in log_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        m = FAILED_LOGIN_RE.search(line)
        if m:
            ts = _parse_syslog_ts(m.group("month"), m.group("day"), m.group("time"))
            attempts_by_ip[m.group("ip")].append(ts)

    alerts: list[dict[str, Any]] = []
    for ip, times in sorted(attempts_by_ip.items()):
        times.sort()
        max_burst = 0
        left = 0
        for right, t in enumerate(times):
            while t - times[left] > window_seconds:
                left += 1
            max_burst = max(max_burst, right - left + 1)
        if max_burst >= threshold:
            alerts.append(
                {
                    "severity": "HIGH",
                    "rule": "SSH Brute-Force Burst",
                    "mitre_attack": "T1110 (Brute Force)",
                    "source_ip": ip,
                    "count": max_burst,
                    "detail": f"{max_burst} failed logins within {window_seconds}s window.",
                }
            )
    return alerts


def analyze_network_flows(
    csv_path: Path,
    port_scan_threshold: int = 8,
    exfil_bytes_threshold: int = 10_000_000,
) -> list[dict[str, Any]]:
    """Analyze CSV network flow / Wireshark exports for scans, C2 ports, and data spikes."""
    ports_by_src: dict[str, set[int]] = defaultdict(set)
    c2_hits: dict[tuple[str, int], int] = defaultdict(int)
    exfil_hits: list[dict[str, Any]] = []

    with csv_path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            src = (row.get("src_ip") or "").strip()
            dst = (row.get("dst_ip") or "").strip()
            if not src:
                continue
            try:
                dport = int(row.get("dst_port") or 0)
            except ValueError:
                dport = 0
            try:
                byte_cnt = int(row.get("bytes") or 0)
            except ValueError:
                byte_cnt = 0

            if dport > 0:
                ports_by_src[src].add(dport)
            if dport in HIGH_RISK_PORTS:
                c2_hits[(src, dport)] += 1
            if byte_cnt >= exfil_bytes_threshold:
                exfil_hits.append(
                    {
                        "severity": "MEDIUM",
                        "rule": "Large Outbound Data Spike",
                        "mitre_attack": "T1048 (Exfiltration Over Alternative Protocol)",
                        "source_ip": src,
                        "destination_ip": dst,
                        "bytes": byte_cnt,
                        "detail": f"{byte_cnt:,} bytes transferred to {dst}:{dport}.",
                    }
                )

    alerts: list[dict[str, Any]] = []
    for src, ports in sorted(ports_by_src.items()):
        if len(ports) >= port_scan_threshold:
            alerts.append(
                {
                    "severity": "HIGH",
                    "rule": "Port Scan / Reconnaissance",
                    "mitre_attack": "T1046 (Network Service Discovery)",
                    "source_ip": src,
                    "distinct_ports": len(ports),
                    "detail": f"Probed {len(ports)} distinct destination ports.",
                }
            )
    for (src, dport), cnt in sorted(c2_hits.items()):
        alerts.append(
            {
                "severity": "HIGH",
                "rule": f"High-Risk Port Traffic ({HIGH_RISK_PORTS[dport]})",
                "mitre_attack": "T1571 (Non-Standard Port)",
                "source_ip": src,
                "dst_port": dport,
                "count": cnt,
                "detail": f"{cnt} connection(s) observed on port {dport} ({HIGH_RISK_PORTS[dport]}).",
            }
        )
    alerts.extend(exfil_hits)
    return alerts


def main() -> None:
    parser = argparse.ArgumentParser(description="SOC log and network flow anomaly analyzer")
    parser.add_argument("--auth-log", type=Path)
    parser.add_argument("--flows", type=Path)
    parser.add_argument("--out", type=Path, default=Path("soc_alerts.json"))
    args = parser.parse_args()

    alerts: list[dict[str, Any]] = []
    if args.auth_log:
        alerts.extend(analyze_auth_log(args.auth_log))
    if args.flows:
        alerts.extend(analyze_network_flows(args.flows))

    args.out.write_text(json.dumps({"alert_count": len(alerts), "alerts": alerts}, indent=2), encoding="utf-8")
    print(f"Generated {len(alerts)} SOC alerts -> {args.out}")


if __name__ == "__main__":
    main()
