"""Unit tests for NetWatch-SOC anomaly detection."""

from pathlib import Path

from netwatch import analyze_auth_log, analyze_network_flows


def test_brute_force_and_flow_detection(tmp_path: Path) -> None:
    auth = tmp_path / "auth.log"
    auth.write_text(
        "\n".join(
            f"Nov 26 12:00:0{i} srv sshd[1]: Failed password for root from 203.0.113.10 port 500{i} ssh2"
            for i in range(6)
        ),
        encoding="utf-8",
    )
    auth_alerts = analyze_auth_log(auth, threshold=5)
    assert len(auth_alerts) == 1
    assert auth_alerts[0]["source_ip"] == "203.0.113.10"
    assert "T1110" in auth_alerts[0]["mitre_attack"]

    flows = tmp_path / "flows.csv"
    rows = ["timestamp,src_ip,dst_ip,dst_port,protocol,bytes"]
    for p in range(100, 110):
        rows.append(f"2026-11-26T12:00:00Z,10.1.1.5,10.1.1.2,{p},TCP,512")
    rows.append("2026-11-26T12:01:00Z,10.1.1.8,198.51.100.2,4444,TCP,1000")
    flows.write_text("\n".join(rows), encoding="utf-8")

    flow_alerts = analyze_network_flows(flows)
    rules = {a["rule"] for a in flow_alerts}
    assert "Port Scan / Reconnaissance" in rules
    assert any("4444" in str(a.get("detail", "")) for a in flow_alerts)
