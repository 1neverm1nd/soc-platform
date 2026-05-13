"""Seed database with realistic incident data using the ML model."""
import sys, os, pickle, json, random
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(__file__))

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(SCRIPT_DIR, "model.pkl")

import mysql.connector

SAMPLE_LOGS = [
    ("brute-force", "SSH brute force: {n} failed attempts from {ip} within 60 seconds"),
    ("brute-force", "Authentication failure: invalid password for account admin [{ip}]"),
    ("brute-force", "RDP brute force: {ip} attempting remote desktop login to DC-01"),
    ("sql-injection", "SQLi detected: ' OR 1=1-- payload from {ip} on /api/users"),
    ("sql-injection", "Web application firewall blocked UNION SELECT from {ip}"),
    ("sql-injection", "Blind SQL injection: boolean-based enumeration from {ip}"),
    ("phishing", "Phishing email from spoofed domain targeting analyst@corp.local"),
    ("phishing", "Credential harvesting page detected: fake login mimicking Office365"),
    ("malware", "Malware Emotet.B detected on host webserver-{n}"),
    ("malware", "Ransomware encryption activity on host fileserver - files being modified"),
    ("malware", "C2 callback: webserver-{n} connecting to known malicious server {ip}"),
    ("ddos", "SYN flood: {n} packets/sec from {ip} targeting 10.0.0.1"),
    ("ddos", "HTTP flood: {n} requests/sec from botnet targeting /api/login"),
    ("privilege-escalation", "Privilege escalation via CVE-2021-{n}: user gained root on db-primary"),
    ("privilege-escalation", "Sudo abuse: service_acct executed restricted command on prod-server"),
    ("data-exfiltration", "Large data transfer: {n}MB from fileserver to external {ip}:443"),
    ("data-exfiltration", "DLP alert: PII data leaving network via HTTPS to {ip}"),
    ("unauthorized-access", "Unauthorized access to restricted /admin from {ip}"),
    ("unauthorized-access", "Impossible travel: user logged from two countries within 1 hour"),
    ("port-scanning", "Nmap scan from {ip}: {n} ports probed on 10.0.0.0/24 in 5s"),
    ("port-scanning", "Masscan detected: {ip} scanning entire subnet 192.168.0.0/16"),
    ("vulnerability-exploit", "Log4Shell exploit: CVE-2021-44228 payload from {ip}"),
    ("vulnerability-exploit", "EternalBlue exploit (MS17-010) detected from {ip} targeting fileserver"),
]

COUNTRIES = [
    ("China", 22), ("Russia", 14), ("United States", 10), ("Germany", 7),
    ("Netherlands", 6), ("Brazil", 5), ("South Korea", 5), ("India", 5),
    ("Ukraine", 4), ("France", 4), ("Japan", 3), ("Romania", 3),
    ("Nigeria", 3), ("Iran", 2), ("Poland", 2),
]

MITRE_MAP = {
    "brute-force": ("T1110", "Brute Force", "Credential Access"),
    "sql-injection": ("T1190", "Exploit Public-Facing Application", "Initial Access"),
    "phishing": ("T1566", "Phishing", "Initial Access"),
    "malware": ("T1204", "User Execution", "Execution"),
    "ddos": ("T1498", "Network Denial of Service", "Impact"),
    "data-exfiltration": ("T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
    "privilege-escalation": ("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation"),
    "unauthorized-access": ("T1078", "Valid Accounts", "Defense Evasion"),
    "port-scanning": ("T1046", "Network Service Discovery", "Discovery"),
    "vulnerability-exploit": ("T1203", "Exploitation for Client Execution", "Execution"),
}

def weighted_country():
    total = sum(w for _, w in COUNTRIES)
    r = random.random() * total
    for country, w in COUNTRIES:
        r -= w
        if r <= 0:
            return country
    return COUNTRIES[0][0]

def rand_ip():
    return f"{random.randint(1,223)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"

def fill(tmpl):
    return tmpl.replace("{n}", str(random.randint(10, 9999))).replace("{ip}", rand_ip())

def calc_severity(ml_type, confidence, abuse_score=0):
    critical_types = {"malware", "data-exfiltration", "privilege-escalation", "vulnerability-exploit"}
    high_types = {"sql-injection", "phishing", "brute-force", "ddos"}
    if ml_type in critical_types and confidence > 0.8:
        return "critical"
    if ml_type in critical_types or (ml_type in high_types and confidence > 0.75) or abuse_score > 80:
        return "high"
    if ml_type in high_types or abuse_score > 50:
        return "medium"
    return "low"

def main():
    print("Loading ML model...")
    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)

    conn = mysql.connector.connect(host="127.0.0.1", user="root", password="1234", database="soc_db")
    cur = conn.cursor()

    # Generate incidents spread over last 30 days
    N = 80
    now = datetime.now()
    inserted = 0

    for i in range(N):
        type_hint, tmpl = random.choice(SAMPLE_LOGS)
        log = fill(tmpl)
        country = weighted_country()
        source_ip = rand_ip()
        dest_ip = f"10.0.{random.randint(0,5)}.{random.randint(1,254)}"

        # Predict with ML
        try:
            classes = model.classes_
            import numpy as np
            proba = model.predict_proba([log])[0]
            top_idx = int(np.argmax(proba))
            ml_type = str(classes[top_idx])
            confidence = float(proba[top_idx])
        except Exception:
            ml_type = type_hint
            confidence = round(random.uniform(0.7, 0.98), 4)

        mitre = MITRE_MAP.get(ml_type, ("T1059", "Command Scripting Interpreter", "Execution"))
        severity = calc_severity(ml_type, confidence)

        # Random timestamp in last 30 days
        days_ago = random.randint(0, 29)
        hours_ago = random.randint(0, 23)
        ts = now - timedelta(days=days_ago, hours=hours_ago, minutes=random.randint(0, 59))

        cur.execute("""
            INSERT INTO incidents (raw_log, source_ip, destination_ip, ml_type, ml_confidence,
                severity, status, threat_country, mitre_id, mitre_technique, mitre_tactic, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (log, source_ip, dest_ip, ml_type, confidence, severity,
              random.choice(["open", "open", "investigating", "resolved"]),
              country, mitre[0], mitre[1], mitre[2], ts, ts))
        inserted += 1

    conn.commit()
    cur.close()
    conn.close()
    print(f"[OK] Inserted {inserted} incidents into soc_db.incidents")

if __name__ == "__main__":
    main()
