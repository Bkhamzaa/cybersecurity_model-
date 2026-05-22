from __future__ import annotations

import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

MODEL_DIR = Path("results/wazuh_family")

NUMERIC_COLS = [
    "timestamp_hour", "timestamp_weekday", "agent_id", "rule_id",
    "rule_level", "rule_firedtimes", "rule_mail", "data_src_port",
    "data_dest_port", "data_alert_signature_id", "data_alert_severity",
    "data_flow_pkts_toserver", "data_flow_pkts_toclient",
    "data_flow_bytes_toserver", "data_flow_bytes_toclient",
]
CATEGORICAL_COLS = [
    "scenario", "location", "input_type", "agent_name",
    "predecoder_hostname", "predecoder_program_name",
    "decoder_name", "decoder_parent", "rule_description", "rule_groups",
    "data_event_type", "data_app_proto", "data_proto",
    "data_srcip", "data_dstip", "data_alert_category", "data_alert_action",
]
ALL_COLS = NUMERIC_COLS + CATEGORICAL_COLS


def make_row(**kwargs) -> dict:
    row = {col: np.nan for col in ALL_COLS}
    row.update(kwargs)
    return row


ALERTS = [
    {
        "label": "Port Scan (iptables)",
        "expected": "Scanning",
        "row": make_row(
            timestamp_hour=10,
            timestamp_weekday=4,          # Friday
            agent_id=1,
            rule_id=100200,
            rule_level=8,
            rule_firedtimes=1,
            rule_mail=0,
            data_src_port=33444,
            data_dest_port=9999,
            scenario="live",
            location="/var/log/iptables.log",
            agent_name="ubuntu",
            predecoder_program_name="kernel",
            decoder_name="kernel",
            decoder_parent="kernel",
            rule_description="iptables: Port scan detected",
            rule_groups="iptables|portscan|recon",
            data_proto="TCP",
            data_srcip="192.168.1.50",
            data_dstip="192.168.1.212",
        ),
    },
    {
        "label": "Unauthorized Sudo (privilege escalation)",
        "expected": "CredentialAccess",
        "row": make_row(
            timestamp_hour=10,
            timestamp_weekday=4,
            agent_id=1,
            rule_id=5405,
            rule_level=10,
            rule_firedtimes=1,
            rule_mail=0,
            scenario="live",
            location="/var/log/auth.log",
            agent_name="ubuntu",
            predecoder_program_name="sudo",
            decoder_name="sudo",
            decoder_parent="sudo",
            rule_description="Unauthorized user attempted to use sudo.",
            rule_groups="sudo|syslog|authentication_failed|privileged",
            data_srcip="192.168.1.50",
            data_dstip="192.168.1.212",
        ),
    },
    {
        "label": "SQL Injection (web attack 200 OK)",
        "expected": "WebAttack",
        "row": make_row(
            timestamp_hour=10,
            timestamp_weekday=4,
            agent_id=1,
            rule_id=31106,
            rule_level=6,
            rule_firedtimes=1,
            rule_mail=0,
            scenario="live",
            location="/var/log/apache2/other_vhosts_access.log",
            agent_name="ubuntu",
            decoder_name="web-accesslog",
            decoder_parent="web-accesslog",
            rule_description="A web attack returned code 200 (success).",
            rule_groups="web|accesslog|attack",
            data_srcip="192.168.1.50",
            data_dstip="192.168.1.212",
        ),
    },
    {
        "label": "Nikto Web Scanner (multiple 400 errors)",
        "expected": "WebAttack",
        "row": make_row(
            timestamp_hour=10,
            timestamp_weekday=4,
            agent_id=1,
            rule_id=31151,
            rule_level=10,
            rule_firedtimes=15,
            rule_mail=0,
            scenario="live",
            location="/var/log/apache2/other_vhosts_access.log",
            agent_name="ubuntu",
            decoder_name="web-accesslog",
            decoder_parent="web-accesslog",
            rule_description="Multiple web server 400 error codes from same source ip.",
            rule_groups="web|accesslog|recon|web_scan",
            data_srcip="192.168.1.50",
            data_dstip="192.168.1.212",
        ),
    },
    {
        "label": "PAM: User login failed (SSH auth failure)",
        "expected": "CredentialAccess",
        "row": make_row(
            timestamp_hour=11,
            timestamp_weekday=4,
            agent_id=1,
            rule_id=5503,
            rule_level=5,
            rule_firedtimes=1,
            rule_mail=0,
            scenario="live",
            location="/var/log/auth.log",
            agent_name="ubuntu",
            predecoder_program_name="sshd",
            decoder_name="pam",
            rule_description="PAM: User login failed.",
            rule_groups="pam|authentication_failed|syslog",
            data_srcip="192.168.1.50",
            data_dstip="192.168.1.212",
        ),
    },
    {
        "label": "SSH Brute Force (multiple failed passwords)",
        "expected": "CredentialAccess",
        "row": make_row(
            timestamp_hour=11,
            timestamp_weekday=4,
            agent_id=1,
            rule_id=5763,
            rule_level=10,
            rule_firedtimes=8,
            rule_mail=0,
            scenario="live",
            location="/var/log/auth.log",
            agent_name="ubuntu",
            predecoder_program_name="sshd",
            decoder_name="sshd",
            decoder_parent="sshd",
            rule_description="sshd: brute force trying to get access to the system. Authentication failed.",
            rule_groups="sshd|authentication_failed|brute_force|syslog",
            data_srcip="192.168.1.50",
            data_src_port=60524,
            data_dstip="192.168.1.212",
        ),
    },
]


def main() -> None:
    pipeline = joblib.load(MODEL_DIR / "model.joblib")
    label_encoder = joblib.load(MODEL_DIR / "label_encoder.joblib")

    df = pd.DataFrame([a["row"] for a in ALERTS])

    probas = pipeline.predict_proba(df)
    preds = pipeline.predict(df)

    print("=" * 65)
    print(f"  MODEL: family classifier  |  classes: {list(label_encoder.classes_)}")
    print("=" * 65)

    for i, alert in enumerate(ALERTS):
        predicted_class = label_encoder.inverse_transform([preds[i]])[0]
        confidence = probas[i].max() * 100
        correct = predicted_class == alert["expected"]
        verdict = "CORRECT" if correct else "WRONG"

        print(f"\n[{i+1}] {alert['label']}")
        print(f"    Expected  : {alert['expected']}")
        print(f"    Predicted : {predicted_class}  ({confidence:.1f}% confidence)  [{verdict}]")
        print("    All class probabilities:")
        for cls, prob in zip(label_encoder.classes_, probas[i]):
            bar = "#" * int(prob * 40)
            print(f"      {cls:<20} {prob*100:5.1f}%  {bar}")

    print("\n" + "=" * 65)
    correct_count = sum(
        label_encoder.inverse_transform([preds[i]])[0] == a["expected"]
        for i, a in enumerate(ALERTS)
    )
    print(f"  Result: {correct_count}/{len(ALERTS)} correct")
    print("=" * 65)


if __name__ == "__main__":
    main()
