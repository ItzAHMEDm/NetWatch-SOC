# NetWatch-SOC

A SOC log and network-flow anomaly triage CLI with **MITRE ATT&CK** alert mapping.

## Detections
- **SSH Brute-Force Bursts (`T1110`):** Sliding-window detection of repeated authentication failures per IP.
- **Port Scanning (`T1046`):** Flags sources probing multiple distinct destination ports.
- **High-Risk Port / C2 Indicators (`T1571`):** Alerts on Telnet (`23`), RDP (`3389`), Metasploit (`4444`), and common backdoor ports.
- **Large Outbound Exfiltration (`T1048`):** Flags abnormal outbound byte-volume spikes.

## Quick Start
```bash
python netwatch.py --auth-log sample_logs/auth_sample.log --flows sample_logs/flows_sample.csv --out soc_alerts.json
pytest -v
```

*Built by Ahmed Muhammad (`BSc Cyber Security & Digital Forensics`).*
