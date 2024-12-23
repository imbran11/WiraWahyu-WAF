from flask import Flask, request, render_template, send_file, session, redirect, url_for, jsonify
import re
import requests
import pandas as pd
import random
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Required for session management

# Simulated database of known malicious IP addresses
malicious_ips = {"192.168.1.1", "10.0.0.1", "20.213.156.164", "217.160.145.62", "194.38.20.161", "65.108.195.44"}

# Define attack patterns using regex
attack_patterns = {
    'sql_injection': re.compile(r'(union|select|insert|delete|update|drop).*', re.IGNORECASE),
    'xss_attack': re.compile(r'(<script>|<iframe>).*', re.IGNORECASE),
}

# Load configuration from config.py
import config

import os

# Global variable to store previous logs for download
previous_logs = []

@app.route('/reset', methods=['POST'])
def reset():
    global logs, blocked_ips, previous_logs

    # Store current logs as previous logs
    previous_logs = logs.copy()

    # Clear current logs and blocked IPs
    logs.clear()
    blocked_ips.clear()

    # Reset CSV file
    if os.path.exists("log.csv"):
        os.remove("log.csv")

    return redirect(url_for('monitor'))

@app.route('/download-previous-report', methods=['GET'])
def download_previous_report():
    if not previous_logs:  # Check if there are previous logs to download
        return "No previous logs available to download.", 400

    df = pd.DataFrame(previous_logs)
    
    df['Blocked IP'] = df['action'].apply(lambda x: 'Yes' if x == 'Blocked' else 'No')

    csv_file_path = "previous_log.csv"
    
    df.to_csv(csv_file_path, index=False)

    with open(csv_file_path, 'r', encoding='utf-8') as file:
        content = file.readlines()

    with open(csv_file_path, 'w', encoding='utf-8') as file:
        file.write('IP Address,Action,Reason,Timestamp,Blocked IP\n')
        file.writelines(content[1:])

    return send_file(csv_file_path, as_attachment=True)


# List to store logs of activities
logs = []
blocked_ips = []  # List to store blocked IPs

def send_telegram_alert(message):
    url = f"https://api.telegram.org/bot{config.TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {'chat_id': config.TELEGRAM_CHAT_ID, 'text': message}
    requests.post(url, data=payload)

@app.route('/log-request', methods=['POST'])
def log_request():
    data = request.json
    
    # Log incoming data from e-commerce app
    ip_address = data.get("ip")
    action = data.get("action")
    reason = data.get("reason")
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    logs.append({"ip": ip_address, "action": action, "reason": reason, "timestamp": timestamp})
    
    return jsonify({"status": "success", "message": "Log recorded."}), 201

@app.route('/fetch-logs', methods=['GET'])
def fetch_logs():
    return jsonify({'logs': logs})

@app.before_request
def check_request():
    ip_address = request.remote_addr
    
    # Log every access attempt for testing purposes
    log_activity(ip_address, "Accessed", "Normal Traffic")

    if ip_address in malicious_ips:
        log_activity(ip_address, "Blocked", "Malicious IP")
        blocked_ips.append(ip_address)  # Add to blocked IPs list
        send_telegram_alert(f"Blocked request from malicious IP: {ip_address}")
        return "403 Forbidden", 403
    
    for attack_type, pattern in attack_patterns.items():
        if pattern.search(request.path) or pattern.search(request.query_string.decode()):
            log_activity(ip_address, "Blocked", f"{attack_type} attempt")
            blocked_ips.append(ip_address)  # Add to blocked IPs list
            send_telegram_alert(f"Blocked {attack_type} attempt from IP: {ip_address}")
            return "403 Forbidden", 403

def log_activity(ip, action, reason):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    logs.append({"ip": ip, "action": action, "reason": reason, "timestamp": timestamp})

import random

# Global variable to count normal traffic accesses
normal_traffic_count = 0

# List of possible attack reasons
attack_reasons = [
    "SQL Injection Attempt",
    "Cross-Site Scripting (XSS) Attempt",
    "Malicious Bot Activity",
    "Brute Force Attack",
    "Unusual Traffic Patterns"
]

@app.before_request
def check_request():
    global normal_traffic_count  # Use global variable to track normal traffic count
    ip_address = request.remote_addr
    
    # Log every access attempt for testing purposes
    log_activity(ip_address, "Accessed", "Normal Traffic")
    
    normal_traffic_count += 1  # Increment count for normal traffic

    if ip_address in malicious_ips:
        log_activity(ip_address, "Blocked", "Malicious IP")
        blocked_ips.append(ip_address)  # Add to blocked IPs list
        send_telegram_alert(f"Blocked request from malicious IP: {ip_address}")
        return "403 Forbidden", 403
    
    for attack_type, pattern in attack_patterns.items():
        if pattern.search(request.path) or pattern.search(request.query_string.decode()):
            log_activity(ip_address, "Blocked", f"{attack_type} attempt")
            blocked_ips.append(ip_address)  # Add to blocked IPs list
            send_telegram_alert(f"Blocked {attack_type} attempt from IP: {ip_address}")
            return "403 Forbidden", 403

    # Randomly decide whether to block an IP (e.g., with a 20% chance)
    if random.random() < 0.2:  # Adjust probability as needed
        simulated_blocked_ip = f"192.0.2.{random.randint(100, 200)}"  # Simulate a blocked IP
        malicious_ips.add(simulated_blocked_ip)  # Add to malicious IPs for blocking
        
        # Randomly select a reason for blocking
        reason = random.choice(attack_reasons)
        
        log_activity(simulated_blocked_ip, "Blocked", reason)
        blocked_ips.append(simulated_blocked_ip)  # Add to blocked IPs list
        send_telegram_alert(f"Simulated Blocked request from IP: {simulated_blocked_ip} due to {reason}")

def log_activity(ip, action, reason):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    logs.append({"ip": ip, "action": action, "reason": reason, "timestamp": timestamp})


@app.route('/')
def home():
    # Sample data for dashboard trends
    protection_trend = [random.randint(50, 100) for _ in range(7)]  # Last 7 days
    detection_trend = [random.randint(20, 80) for _ in range(7)]
    
    # Sample vulnerability status counts
    vulnerability_status = {
        "Critical": random.randint(0, 5),
        "High": random.randint(0, 10),
        "Medium": random.randint(0, 15),
        "Low": random.randint(0, 20)
    }
    
    # Sample vulnerability trend data
    vulnerability_trend = [random.randint(0, 10) for _ in range(7)]

    # Example statistics (replace with real logic)
    total_requests = random.randint(1000, 2000)
    blocked_requests = random.randint(100, 300)
    detected_attacks = random.randint(10, 50)

    return render_template(
        'dashboard.html',
        protection_trend=protection_trend,
        detection_trend=detection_trend,
        vulnerability_status=vulnerability_status,
        vulnerability_trend=vulnerability_trend,
        total_requests=total_requests,
        blocked_requests=blocked_requests,
        detected_attacks=detected_attacks
    )


@app.route('/scan', methods=['GET', 'POST'])
def scan():
    scan_result = None
    if request.method == 'POST':
        url = request.form.get('url')
        
        try:
            response = requests.get(url)
            status_code = response.status_code
            content_length = len(response.content)
            scan_result = {
                "url": url,
                "status_code": status_code,
                "content_length": content_length,
                "action": "Accessed",
                "reason": "Normal Traffic"
            }
            log_activity(request.remote_addr, scan_result["action"], scan_result["reason"])
        except Exception as e:
            scan_result = {
                "url": url,
                "error": str(e)
            }
    
    return render_template('scan.html', scan_result=scan_result)

@app.route('/overview', methods=['GET', 'POST'])
def overview():
    app_name = None
    stats = None

    if request.method == 'POST':
        app_name = request.form.get('app_name')
        stats = {
            "total_requests": random.randint(1000, 5000),
            "blocked_requests": random.randint(100, 500),
            "detected_attacks": random.randint(10, 100)
        }

    return render_template('overview.html', app_name=app_name, stats=stats)

@app.route('/detect', methods=['GET', 'POST'])
def detect():
    scan_result = None
    if request.method == 'POST':
        domain = request.form.get('domain')
        
        ip_address = "192.0.2.1"  # Simulated IP address for the given domain
        scan_result = {
            "domain": domain,
            "ip_address": ip_address,
            "status": "Success",
            "vulnerabilities": random.randint(0, 5)  # Simulated number of vulnerabilities
        }
    
    return render_template('detect.html', scan_result=scan_result)

@app.route('/auto_scan', methods=['POST'])
def auto_scan():
    predefined_domain = "example.com"  # Replace with your predefined domain or logic to get the last entered domain
    
    scan_result = {
        "domain": predefined_domain,
        "ip_address": "192.0.2.1",
        "status": "Success",
        "vulnerabilities": random.randint(0, 5)  # Simulated number of vulnerabilities
    }
    
    return render_template('detect.html', scan_result=scan_result)

@app.route('/protect')
def protect():
    return render_template('protect.html')

@app.route('/monitor', methods=['GET', 'POST'])
def monitor():
    scan_result = None
    
    if request.method == 'POST':
        url = request.form.get('url')

        # Reset previous results before processing new URL
        global logs  # Ensure we're using the global logs list
        logs.clear()  # Clear previous logs if needed; adjust based on your requirements
        
        try:
            response = requests.get(url)
            status_code = response.status_code
            content_length = len(response.content)
            scan_result = {
                "url": url,
                "status_code": status_code,
                "content_length": content_length,
                "action": "Accessed",
                "reason": "Normal Traffic"
            }
            log_activity(request.remote_addr, scan_result["action"], scan_result["reason"])
            
            # Store the last scanned URL in session for persistence
            session['last_url'] = url
            
            return redirect(url_for('monitor'))  # Redirect to avoid resubmission

        except Exception as e:
            scan_result = {
                "url": url,
                "error": str(e)
            }

    # Check if there's a URL stored in the session to perform scanning on page load
    if 'last_url' in session:
        last_url = session['last_url']
        
        try:
            response = requests.get(last_url)
            status_code = response.status_code
            content_length = len(response.content)
            scan_result = {
                "url": last_url,
                "status_code": status_code,
                "content_length": content_length,
                "action": "Accessed",
                "reason": "Normal Traffic"
            }
            log_activity(request.remote_addr, scan_result["action"], scan_result["reason"])
            
        except Exception as e:
            scan_result = {
                "url": last_url,
                "error": str(e)
            }

    return render_template('monitor.html', logs=logs, scan_result=scan_result, blocked_ips=blocked_ips)

@app.route('/analysis')
def analysis():
    return render_template('analysis.html')

@app.route('/settings')
def settings():
    return render_template('settings.html')

@app.route('/manage')
def manage():
    return render_template('manage.html')

@app.route('/download-log')
def download_log():
    if not logs:  # Check if there are logs to download
        return "No logs available to download.", 400

    df = pd.DataFrame(logs)
    
    df['Blocked IP'] = df['action'].apply(lambda x: 'Yes' if x == 'Blocked' else 'No')

    csv_file_path = "log.csv"
    
    df.to_csv(csv_file_path, index=False)

    with open(csv_file_path, 'r', encoding='utf-8') as file:
        content = file.readlines()

    with open(csv_file_path, 'w', encoding='utf-8') as file:
        file.write('IP Address,Action,Reason,Timestamp,Blocked IP\n')
        file.writelines(content[1:])

    return send_file(csv_file_path, as_attachment=True)

@app.route('/fetch-overview-data', methods=['GET'])
def fetch_overview_data():
    total_requests = len(logs) # Count total requests from logs
    blocked_ips_count = len(blocked_ips) # Count blocked IPs

    # Prepare attack trend data by type
    attack_types = ['SQL Injection', 'XSS', 'CSRF', 'DDoS', 'Malware']
    attack_counts = {attack_type: 0 for attack_type in attack_types}

    # Count attacks based on their reasons logged in the logs
    for log in logs:
        if log['action'] == 'Blocked':
            reason = log['reason']
            for attack_type in attack_types:
                if attack_type in reason:
                    attack_counts[attack_type] += 1

    # Prepare labels and counts for the chart
    return jsonify({
        'total_requests': total_requests,
        'blocked_ips_count': blocked_ips_count,
        'attack_types': list(attack_counts.keys()),
        'attack_counts': list(attack_counts.values()),
    })


if __name__ == '__main__':
    app.run(port=5000)
