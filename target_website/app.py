"""
Target Demo Website — Local HTTP Server
========================================

This is a simple Flask website running on port 5000.
The network agent captures traffic to/from this site and sends it
to the ML backend for intrusion prediction.

Browse http://localhost:5000 to generate network traffic that gets analyzed.
"""

from flask import Flask, render_template_string, jsonify, request
import random
import time
import os

app = Flask(__name__)

# Simple HTML template for the target website
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Demo Web Application</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            color: #e0e0e0;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
        }
        .container { max-width: 900px; width: 100%; padding: 40px 20px; }
        header {
            text-align: center;
            padding: 40px 0;
            border-bottom: 1px solid rgba(255,255,255,0.1);
            margin-bottom: 40px;
        }
        h1 {
            font-size: 2.5rem;
            background: linear-gradient(135deg, #e94560, #0f3460);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
        }
        .subtitle { color: #888; font-size: 0.95rem; }
        .card-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 30px 0; }
        .card {
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 12px;
            padding: 24px;
            transition: all 0.3s ease;
            cursor: pointer;
        }
        .card:hover {
            transform: translateY(-4px);
            border-color: #e94560;
            box-shadow: 0 8px 25px rgba(233,69,96,0.15);
        }
        .card h3 { color: #e94560; margin-bottom: 10px; font-size: 1.1rem; }
        .card p { color: #aaa; font-size: 0.9rem; line-height: 1.5; }
        .btn {
            display: inline-block;
            padding: 12px 28px;
            background: linear-gradient(135deg, #e94560, #c23152);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            cursor: pointer;
            transition: all 0.3s;
            text-decoration: none;
            margin: 5px;
        }
        .btn:hover { transform: scale(1.05); box-shadow: 0 4px 15px rgba(233,69,96,0.4); }
        .btn.secondary { background: linear-gradient(135deg, #0f3460, #16213e); border: 1px solid rgba(255,255,255,0.2); }
        .actions { text-align: center; margin: 30px 0; }
        .status { text-align: center; margin: 20px 0; padding: 16px; background: rgba(16,185,129,0.1); border: 1px solid rgba(16,185,129,0.2); border-radius: 8px; }
        .status.warning { background: rgba(245,158,11,0.1); border-color: rgba(245,158,11,0.2); }
        #response-area { margin: 20px 0; padding: 16px; background: rgba(0,0,0,0.3); border-radius: 8px; font-family: monospace; font-size: 0.85rem; min-height: 60px; }
        .data-table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .data-table th, .data-table td { padding: 12px 16px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.08); }
        .data-table th { color: #e94560; font-size: 0.85rem; text-transform: uppercase; }
        .data-table tr:hover { background: rgba(255,255,255,0.03); }
        footer { text-align: center; padding: 30px; color: #555; font-size: 0.8rem; margin-top: 40px; border-top: 1px solid rgba(255,255,255,0.05); }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🌐 Demo Web Application</h1>
            <p class="subtitle">This is the target website being monitored by CyberGuard AI</p>
        </header>

        <div class="status">
            ✅ This website is running on <strong>localhost:5000</strong> — All traffic to/from this site is being captured and analyzed by the ML intrusion detection system.
        </div>

        <div class="card-grid">
            <div class="card" onclick="fetchData('/api/users')">
                <h3>👥 Users API</h3>
                <p>Fetch user data from the server. Each request generates network packets that are analyzed.</p>
            </div>
            <div class="card" onclick="fetchData('/api/products')">
                <h3>📦 Products API</h3>
                <p>Browse product catalog. Generates HTTP traffic for the packet sniffer to capture.</p>
            </div>
            <div class="card" onclick="fetchData('/api/transactions')">
                <h3>💳 Transactions</h3>
                <p>View recent transactions. Each API call creates network flows analyzed by the ML model.</p>
            </div>
            <div class="card" onclick="fetchData('/api/health')">
                <h3>🏥 Health Check</h3>
                <p>Server health status. Simple ping that generates minimal traffic for baseline analysis.</p>
            </div>
        </div>

        <div class="actions">
            <button class="btn" onclick="generateTraffic()">🚀 Generate Burst Traffic</button>
            <button class="btn secondary" onclick="fetchData('/api/search?q=test')">🔍 Search Query</button>
            <button class="btn secondary" onclick="fetchData('/api/login')">🔐 Login Attempt</button>
        </div>

        <div id="response-area">Click any card or button above to generate traffic...</div>

        <h2 style="margin: 30px 0 15px; color: #e94560;">📊 Server Activity Log</h2>
        <table class="data-table">
            <thead>
                <tr>
                    <th>Time</th>
                    <th>Endpoint</th>
                    <th>Method</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody id="activity-log">
                <tr><td colspan="4" style="text-align:center; color:#666;">No requests yet — click above to start</td></tr>
            </tbody>
        </table>

        <footer>
            Demo Web Application — Target site for CyberGuard AI network monitoring
        </footer>
    </div>

    <script>
        const logArea = document.getElementById('activity-log');
        const respArea = document.getElementById('response-area');
        let firstRequest = true;

        async function fetchData(endpoint) {
            const start = Date.now();
            try {
                const res = await fetch(endpoint);
                const data = await res.json();
                const elapsed = Date.now() - start;
                respArea.textContent = JSON.stringify(data, null, 2);
                addLog(endpoint, 'GET', res.status, elapsed);
            } catch (err) {
                respArea.textContent = 'Error: ' + err.message;
                addLog(endpoint, 'GET', 'ERR', 0);
            }
        }

        async function generateTraffic() {
            respArea.textContent = '🚀 Generating burst traffic...';
            const endpoints = ['/api/users', '/api/products', '/api/transactions', '/api/health', '/api/search?q=test'];
            for (let i = 0; i < 10; i++) {
                const ep = endpoints[Math.floor(Math.random() * endpoints.length)];
                await fetchData(ep);
                await new Promise(r => setTimeout(r, 200));
            }
            respArea.textContent = '✅ Burst complete — 10 requests sent. Check the CyberGuard dashboard!';
        }

        function addLog(endpoint, method, status, ms) {
            if (firstRequest) { logArea.innerHTML = ''; firstRequest = false; }
            const row = document.createElement('tr');
            const time = new Date().toLocaleTimeString('en-US', {hour12:false});
            row.innerHTML = '<td>' + time + '</td><td>' + endpoint + '</td><td>' + method + '</td><td>' + status + ' (' + ms + 'ms)</td>';
            logArea.prepend(row);
            if (logArea.children.length > 20) logArea.lastChild.remove();
        }
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/users')
def api_users():
    users = [
        {"id": i, "name": f"User_{i}", "email": f"user{i}@example.com", "role": random.choice(["admin", "user", "editor"])}
        for i in range(1, random.randint(3, 8))
    ]
    return jsonify({"users": users, "count": len(users), "timestamp": time.time()})

@app.route('/api/products')
def api_products():
    products = [
        {"id": i, "name": f"Product_{i}", "price": round(random.uniform(9.99, 499.99), 2), "stock": random.randint(0, 100)}
        for i in range(1, random.randint(4, 10))
    ]
    return jsonify({"products": products, "count": len(products)})

@app.route('/api/transactions')
def api_transactions():
    txns = [
        {"id": f"TXN-{random.randint(10000,99999)}", "amount": round(random.uniform(5, 500), 2), "status": random.choice(["completed", "pending", "failed"])}
        for _ in range(random.randint(3, 7))
    ]
    return jsonify({"transactions": txns, "total": sum(t["amount"] for t in txns)})

@app.route('/api/health')
def api_health():
    return jsonify({"status": "healthy", "uptime": time.time(), "version": "1.0.0"})

@app.route('/api/search')
def api_search():
    query = request.args.get('q', '')
    results = [{"title": f"Result for '{query}' #{i}", "score": round(random.uniform(0.5, 1.0), 3)} for i in range(random.randint(2, 6))]
    return jsonify({"query": query, "results": results, "count": len(results)})

@app.route('/api/login')
def api_login():
    return jsonify({"status": "auth_required", "message": "Please provide credentials", "session": None})

if __name__ == '__main__':
    print("🌐 Target Website starting on http://localhost:5000")
    print("📡 Traffic to this site will be captured by the network agent")
    print("🛡️ Predictions will appear on the CyberGuard dashboard at http://localhost:3000")
    app.run(host='0.0.0.0', port=5000, debug=False)
