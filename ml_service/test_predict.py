
import requests
import json

payload = {
    "duration": 0.01,
    "total_packets": 10,
    "forward_packets": 5,
    "reverse_packets": 5,
    "total_bytes": 1000,
    "forward_bytes": 500,
    "reverse_bytes": 500,
    "min_packet_size": 60,
    "max_packet_size": 1500,
    "avg_packet_size": 100,
    "forward_avg_packet_size": 100,
    "reverse_avg_packet_size": 100,
    "packets_per_second": 1000,
    "bytes_per_second": 100000,
    "forward_packets_per_second": 500,
    "reverse_packets_per_second": 500,
    "tcp_flags_count": 2,
    "syn_count": 1,
    "fin_count": 0,
    "rst_count": 0,
    "ack_count": 1,
    "forward_tcp_flags": 1,
    "reverse_tcp_flags": 1,
    "src_port": 12345,
    "dst_port": 80,
    "protocol": 6,
    "forward_ttl": 64,
    "reverse_ttl": 64,
    "tcp_window_size_forward": 1024,
    "tcp_window_size_reverse": 1024,
    "is_bidirectional": 1,
    "connection_state": "CON"
}

try:
    response = requests.post("http://localhost:8080/predict", json=payload)
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.text}")
except Exception as e:
    print(f"Error: {e}")
