"""
Simulates live network traffic hitting AEGIS AI, by replaying rows from the
test dataset to the Node.js API. Designed for LIVE COLLEGE PRESENTATIONS & VIVA.

Usage:
    python simulate_traffic.py --continuous          # Continuous live attacks & normal stream
    python simulate_traffic.py --continuous --auto-block  # Auto-detect AND automatically block repeat attackers
    python simulate_traffic.py --demo-attack         # Targeted 8-packet attack burst from Moscow (203.0.113.7)
    python simulate_traffic.py --count 50 --delay 0.8     # Send 50 packets with 0.8s interval
"""

import pandas as pd
import requests
import time
import argparse
import random
import sys
import os

# Fix Windows console UTF-8 output encoding
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

FEATURE_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
    "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
]

IP_LOCATIONS = {
    "203.0.113.7":  ("Moscow", "Russia"),
    "198.51.100.4": ("Beijing", "China"),
    "192.0.2.15":   ("Lagos", "Nigeria"),
    "198.51.100.22": ("Sao Paulo", "Brazil"),
    "203.0.113.44": ("Bucharest", "Romania"),
    "192.0.2.88":   ("Jakarta", "Indonesia"),
    "198.51.100.99": ("Frankfurt", "Germany"),
    "203.0.113.111": ("Tokyo", "Japan"),
}
IP_POOL = list(IP_LOCATIONS.keys())
DEMO_ATTACK_IP = "203.0.113.7"

API_URL = "http://localhost:4000/api/detect"
BLOCK_URL = "http://localhost:4000/api/block"


def load_dataset():
    paths = [
        "data/test_processed.csv",
        os.path.join(os.path.dirname(__file__), "data", "test_processed.csv"),
        r"C:\Users\SAMSUNG\Downloads\nids-project (1)\nids-project\data\test_processed.csv",
    ]
    for p in paths:
        if os.path.exists(p):
            try:
                print(f"[+] Loaded test dataset from: {p}")
                return pd.read_csv(p)
            except Exception as e:
                print(f"[!] Warning reading {p}: {e}")
    print("[-] ERROR: test_processed.csv not found in any standard path.")
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="AEGIS AI Live Attack Simulator for College Demo")
    parser.add_argument("--count", type=int, default=40, help="Number of connections to simulate (if not continuous)")
    parser.add_argument("--delay", type=float, default=1.0, help="Seconds between each connection (default: 1.0s)")
    parser.add_argument("--continuous", action="store_true", help="Run continuously in infinite loop until stopped (Ctrl+C)")
    parser.add_argument("--auto-block", action="store_true", help="Automatically trigger firewall block upon detecting an attack")
    parser.add_argument("--attacks-only", action="store_true", help="Only simulate attack traffic")
    parser.add_argument("--demo-attack", action="store_true", help="Send repeated attacks from ONE fixed IP (Moscow) for block demo")
    args = parser.parse_args()

    df = load_dataset()

    attack_df = df[df["binary_label"] == 1]
    normal_df = df[df["binary_label"] == 0]

    print("\n" + "=" * 70)
    print("   AEGIS AI — LIVE ATTACK INTRUSION & ACTIVE DEFENSE SIMULATOR")
    print("=" * 70)
    print(f"Target Gateway : {API_URL}")
    print(f"Attack Ratio   : {'100% Attacks' if args.attacks_only else 'Mixed (60% Attack / 40% Normal)'}")
    print(f"Auto-Defense   : {'[ENABLED] Auto-blocks malicious IPs' if args.auto_block else '[MANUAL] Use Dashboard to block'}")
    print(f"Mode           : {'CONTINUOUS LIVE STREAM' if args.continuous else f'{args.count} Connections'}")
    print("=" * 70 + "\n")

    packet_count = 0
    attack_count = 0
    blocked_count = 0
    normal_count = 0

    try:
        while True:
            packet_count += 1

            if args.demo_attack:
                row = attack_df.sample(n=1).iloc[0]
                chosen_ip = DEMO_ATTACK_IP
            else:
                # 60% attack, 40% normal for exciting college demo
                if args.attacks_only or random.random() < 0.60:
                    row = attack_df.sample(n=1).iloc[0]
                else:
                    row = normal_df.sample(n=1).iloc[0]
                chosen_ip = random.choice(IP_POOL)

            payload = {col: float(row[col]) for col in FEATURE_COLUMNS}
            payload["source_ip"] = chosen_ip
            city, country = IP_LOCATIONS.get(chosen_ip, ("Unknown", "Unknown"))
            payload["location"] = f"{city}, {country}"
            true_label = "Attack" if row["binary_label"] == 1 else "Normal"

            try:
                t0 = time.time()
                response = requests.post(API_URL, json=payload, timeout=8)
                latency = int((time.time() - t0) * 1000)
                result = response.json()
                predicted = result.get("prediction", "ERROR")
                confidence = result.get("confidence", 0)

                status_tag = f"[{predicted.upper()}]"
                if predicted == "Attack":
                    attack_count += 1
                    symbol = "[!]"
                    # If auto-block is on, automatically tell gateway to block this IP
                    if args.auto_block:
                        try:
                            requests.post(BLOCK_URL, json={"source_ip": chosen_ip}, timeout=3)
                            status_tag += " -> [AUTO-BLOCKED]"
                        except Exception:
                            pass
                elif predicted == "Blocked":
                    blocked_count += 1
                    symbol = "[X]"
                else:
                    normal_count += 1
                    symbol = "[+]"

                print(f"{symbol} #{packet_count:03d} | IP: {chosen_ip:15s} ({payload['location']:20s}) | "
                      f"Class: {status_tag:22s} ({confidence*100:4.1f}% conf) | {latency}ms")

            except requests.exceptions.ConnectionError:
                print("\n[!] ERROR: Could not connect to API Gateway at http://localhost:4000. Is server running?")
                time.sleep(3)
                continue
            except Exception as e:
                print(f"[!] Request error: {e}")

            if not args.continuous and packet_count >= (8 if args.demo_attack else args.count):
                break

            time.sleep(args.delay)

    except KeyboardInterrupt:
        print("\n\n[+] Stream interrupted by user (Ctrl+C).")

    print("\n" + "-" * 50)
    print("SESSION SUMMARY:")
    print(f"  Total Packets Sent   : {packet_count}")
    print(f"  Attacks Detected     : {attack_count}")
    print(f"  Rejections (Blocked) : {blocked_count}")
    print(f"  Normal Traffic       : {normal_count}")
    print("-" * 50 + "\n")


if __name__ == "__main__":
    main()
