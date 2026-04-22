"""
Send test attack predictions directly to the dashboard API
to demonstrate the notification + sound alert system.
"""
import requests
import time

dashboard_url = "http://localhost:3000/api/predictions"

attacks = [
    {
        "timestamp": "2026-04-22T19:32:00.000000",
        "src_ip": "192.168.1.105",
        "dst_ip": "10.0.0.1",
        "src_port": 44821,
        "dst_port": 80,
        "protocol": "TCP",
        "total_packets": 1500,
        "total_bytes": 450000,
        "duration": 2.5,
        "connection_state": "SYN",
        "prediction": 1,
        "attack_probability": 0.92,
    },
    {
        "timestamp": "2026-04-22T19:32:02.000000",
        "src_ip": "10.45.23.8",
        "dst_ip": "10.0.0.1",
        "src_port": 38291,
        "dst_port": 443,
        "protocol": "TCP",
        "total_packets": 890,
        "total_bytes": 230000,
        "duration": 1.8,
        "connection_state": "RST",
        "prediction": 1,
        "attack_probability": 0.87,
    },
    {
        "timestamp": "2026-04-22T19:32:04.000000",
        "src_ip": "172.16.5.22",
        "dst_ip": "10.0.0.1",
        "src_port": 52100,
        "dst_port": 3306,
        "protocol": "TCP",
        "total_packets": 45,
        "total_bytes": 12000,
        "duration": 0.3,
        "connection_state": "CON",
        "prediction": 1,
        "attack_probability": 0.95,
    },
    {
        "timestamp": "2026-04-22T19:32:06.000000",
        "src_ip": "192.168.1.105",
        "dst_ip": "10.0.0.1",
        "src_port": 44830,
        "dst_port": 22,
        "protocol": "TCP",
        "total_packets": 200,
        "total_bytes": 8500,
        "duration": 0.1,
        "connection_state": "SYN",
        "prediction": 1,
        "attack_probability": 0.78,
    },
    {
        "timestamp": "2026-04-22T19:32:08.000000",
        "src_ip": "10.99.12.4",
        "dst_ip": "10.0.0.1",
        "src_port": 60100,
        "dst_port": 80,
        "protocol": "TCP",
        "total_packets": 3200,
        "total_bytes": 980000,
        "duration": 5.2,
        "connection_state": "CON",
        "prediction": 1,
        "attack_probability": 0.98,
    },
    {
        "timestamp": "2026-04-22T19:32:10.000000",
        "src_ip": "192.168.2.50",
        "dst_ip": "10.0.0.1",
        "src_port": 39200,
        "dst_port": 8080,
        "protocol": "TCP",
        "total_packets": 60,
        "total_bytes": 15000,
        "duration": 0.5,
        "connection_state": "CON",
        "prediction": 1,
        "attack_probability": 0.55,
    },
]

print("=" * 50)
print("  SENDING TEST ATTACK PREDICTIONS TO DASHBOARD")
print("=" * 50)
print()

for i, atk in enumerate(attacks):
    prob = atk["attack_probability"]
    if prob > 0.8:
        severity = "CRITICAL"
    elif prob > 0.5:
        severity = "HIGH"
    else:
        severity = "MEDIUM"

    src = atk["src_ip"]
    resp = requests.post(dashboard_url, json=atk, timeout=5)
    print(f"  [{i+1}/6] {severity} attack ({prob*100:.0f}%) from {src} -> Status: {resp.status_code}")
    time.sleep(2.5)

print()
print("Done! Check the dashboard for notifications and sound alerts.")
print("  - Toast notifications should appear in the top-right corner")
print("  - Sound alerts should play for each detection")
print("  - Click the bell icon to see alert history")
