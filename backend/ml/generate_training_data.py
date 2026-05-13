"""Generate synthetic training data for SOC ML model."""
import random
import json

CLASSES = [
    "brute-force", "sql-injection", "phishing", "malware", "ddos",
    "privilege-escalation", "data-exfiltration", "unauthorized-access",
    "port-scanning", "vulnerability-exploit"
]

TEMPLATES = {
    "brute-force": [
        "Failed login attempt for user {user} from {ip} - attempt {n} of {max}",
        "Authentication failure: invalid password for account {user} [{ip}]",
        "SSH brute force detected: {n} failed attempts from {ip} within 60 seconds",
        "Multiple authentication failures user={user} src={ip} attempts={n}",
        "ALERT: Account lockout triggered for {user} after {n} failed logins from {ip}",
        "Login brute force attack: {ip} tried {n} passwords against {user}",
        "Excessive auth failures: user {user} locked out, attacker IP {ip}",
        "Credential stuffing detected: {n} accounts attempted from {ip}",
        "RDP brute force: {ip} attempting remote desktop login to {target}",
        "Hydra/Medusa tool signature: rapid sequential auth attempts from {ip}",
    ],
    "sql-injection": [
        "SQLi attempt detected in request: {param}=1' OR '1'='1",
        "Web application firewall blocked SQL injection: UNION SELECT from {ip}",
        "Attack detected: payload contains DROP TABLE in field {param}",
        "XSS/SQLi combo: {ip} sent ' AND 1=1-- in search query",
        "Database error triggered by malformed input from {ip}: {param}='; SELECT * FROM users--",
        "SQL injection in login form: username=' OR 1=1# from {ip}",
        "Blind SQL injection detected: boolean-based enumeration from {ip}",
        "Time-based SQL injection: SLEEP(5) payload from {ip} on endpoint {endpoint}",
        "xp_cmdshell execution attempt via SQL injection from {ip}",
        "INFORMATION_SCHEMA enumeration detected from {ip} on {target}",
    ],
    "phishing": [
        "Suspicious email from spoofed domain {domain} targeting {user}",
        "Phishing link clicked: user {user} visited malicious URL from email",
        "Credential harvesting page detected: fake login mimicking {target}",
        "Spear phishing email with malicious attachment opened by {user}",
        "Email gateway blocked phishing: sender {email} impersonating IT support",
        "Business email compromise attempt targeting {user} finance department",
        "Homograph attack detected: fake domain {domain} used in phishing campaign",
        "Anti-phishing training failure: {user} submitted credentials to test site",
        "Malicious OAuth app consent phishing targeting {user}",
        "Callback phishing: voicemail lure sent to {user} requesting callback",
    ],
    "malware": [
        "Malware signature detected: {malware} on host {host}",
        "Ransomware encryption activity detected on {host} - files being modified",
        "C2 callback detected: {host} connecting to known malicious server {ip}",
        "Trojan dropper executed: {process} spawned suspicious child process",
        "Endpoint protection quarantined {malware} on {host}",
        "Fileless malware: PowerShell download cradle detected on {host}",
        "Cryptominer detected: high CPU usage + pool connection from {host}",
        "Backdoor communication: {host} sending beaconing traffic to {ip}",
        "Rootkit detected: kernel module tampering on {host}",
        "Worm propagation: {malware} attempting lateral movement from {host}",
    ],
    "ddos": [
        "DDoS attack: {n} requests/second from {n2} IPs targeting {target}",
        "SYN flood detected: {ip} sending {n} SYN packets without completing handshake",
        "UDP amplification attack: {n} Gbps traffic spike targeting {target}",
        "HTTP flood: {n} requests/sec from botnet to {endpoint}",
        "DNS amplification DDoS: reflectors sending {n} Mbps to {target}",
        "Application layer DDoS: {n} concurrent connections exhausting {target}",
        "Slowloris attack: {ip} holding {n} connections open to {target}",
        "NTP amplification: {n}x traffic amplification targeting {target}",
        "ICMP ping flood from {ip}: {n} packets/sec",
        "Carpet bombing DDoS: attack spread across {n} destination IPs",
    ],
    "privilege-escalation": [
        "Privilege escalation detected: {user} gained root via {exploit}",
        "Sudo abuse: {user} executed restricted command on {host}",
        "Token impersonation: {process} attempted privilege escalation on {host}",
        "Kernel exploit attempt: {exploit} executed by {user} on {host}",
        "UAC bypass detected: {process} elevated without prompt on {host}",
        "Setuid binary exploitation: {user} escalated via {binary} on {host}",
        "DLL injection into privileged process by {user} on {host}",
        "Access token manipulation: {user} duplicated admin token on {host}",
        "Scheduled task abuse for persistence and privilege by {user}",
        "Service account compromise: {user} gained SYSTEM via service {service}",
    ],
    "data-exfiltration": [
        "Large data transfer detected: {n} MB sent from {host} to external {ip}",
        "Data exfiltration via DNS: {host} sending encoded queries to {domain}",
        "Sensitive file access and upload: {user} sent {file} to {ip}",
        "DLP alert: PII data leaving network via {protocol} to {ip}",
        "C2 exfiltration: {host} uploading compressed archive to {ip}",
        "Clipboard exfiltration: {process} capturing and sending clipboard data",
        "Email exfiltration: {user} forwarded {n} emails to external {email}",
        "Cloud storage abuse: {user} uploaded {n} files to unauthorized bucket",
        "Steganography suspected: image files with embedded data sent to {ip}",
        "FTP exfiltration: {n} MB of database dump transferred to {ip}",
    ],
    "unauthorized-access": [
        "Unauthorized access to restricted resource by {user} from {ip}",
        "Account sharing detected: {user} credentials used from {n} different IPs",
        "After-hours access: {user} logged in at {time} outside business hours",
        "Impossible travel: {user} authenticated from {country1} and {country2} within 1 hour",
        "Stale account reactivation: dormant account {user} accessed from {ip}",
        "Service account interactive login detected for {user} on {host}",
        "Unauthorized API access: {user} called restricted endpoint {endpoint}",
        "Shared credentials detected: {n} users logged in with same account",
        "Unauthorized database access: {user} queried sensitive tables without permission",
        "VPN split tunneling abuse: {user} bypassing security controls",
    ],
    "port-scanning": [
        "Port scan detected from {ip}: {n} ports probed on {target} in {time}s",
        "Nmap scan signature: OS fingerprinting from {ip} against {target}",
        "Masscan detected: {ip} scanning entire subnet {subnet}",
        "SYN scan: {ip} performed stealth scan on {n} ports of {target}",
        "UDP port scan: {ip} probing common service ports on {target}",
        "Vulnerability scanner activity from {ip}: {n} probes in {time} seconds",
        "Network discovery scan: {ip} enumerated {n} live hosts in {subnet}",
        "Shodan bot detected scanning {target} from {ip}",
        "Service version enumeration: {ip} grabbing banners from {target}",
        "Firewall evasion port scan: fragmented packets from {ip} to {target}",
    ],
    "vulnerability-exploit": [
        "Exploit attempt: CVE-{cve} payload sent from {ip} to {target}",
        "Buffer overflow attack detected on {service} from {ip}",
        "Remote code execution: {ip} exploited {vuln} on {target}",
        "Log4Shell exploitation attempt from {ip}: JNDI lookup payload detected",
        "EternalBlue exploit (MS17-010) detected from {ip} targeting {target}",
        "Apache Struts RCE exploit from {ip} - CVE-{cve}",
        "ProxyLogon exploit attempt: {ip} targeting Exchange server {target}",
        "Shellshock exploit: {ip} sent malicious User-Agent to {target}",
        "SQL Server xp_cmdshell exploitation from {ip} via SQLi on {target}",
        "Heartbleed memory disclosure: {ip} sent malformed TLS heartbeat to {target}",
    ],
}

FILL = {
    "user": ["admin", "john.doe", "system", "service_acct", "root", "guest", "backup_user", "db_admin", "api_user", "test"],
    "ip": [f"192.168.{random.randint(1,254)}.{random.randint(1,254)}" for _ in range(10)] +
           [f"{random.randint(1,223)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}" for _ in range(20)],
    "host": ["webserver-01", "db-primary", "fileserver", "dc-01", "workstation-42", "api-gateway", "mail-server", "vpn-gateway"],
    "target": ["10.0.0.1", "prod-db", "web-app", "internal-api", "192.168.1.100", "fileserver.corp"],
    "domain": ["secure-login.net", "corp-verify.com", "update-now.io", "paypal-secure.xyz", "microsoft-support.net"],
    "email": ["it-support@fake.com", "noreply@corp-update.net", "billing@suspicious.xyz"],
    "param": ["id", "search", "username", "query", "filter", "page", "sort"],
    "endpoint": ["/api/users", "/login", "/admin", "/search", "/api/data", "/reports"],
    "malware": ["Emotet.B", "Ryuk.Ransomware", "Cobalt.Strike", "Mimikatz", "TrickBot", "AgentTesla", "RedLine"],
    "process": ["powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe", "regsvr32.exe"],
    "exploit": ["CVE-2021-44228", "MS17-010", "CVE-2020-1472", "PrintNightmare", "DirtyPipe"],
    "binary": ["sudo", "find", "python", "perl", "bash"],
    "service": ["spooler", "BITS", "WSearch", "Schedule"],
    "subnet": ["192.168.1.0/24", "10.0.0.0/16", "172.16.0.0/12"],
    "file": ["passwords.xlsx", "customer_data.csv", "financial_report.pdf", "source_code.zip"],
    "protocol": ["HTTP", "FTP", "DNS", "ICMP", "SMTP"],
    "country1": ["Kazakhstan", "Germany", "France"],
    "country2": ["China", "Russia", "Nigeria"],
    "time": ["02:47", "23:15", "03:30", "01:22"],
    "vuln": ["Log4Shell", "Heartbleed", "ShellShock", "EternalBlue", "ProxyLogon"],
    "service2": ["Apache", "Nginx", "IIS", "OpenSSH", "SMB"],
}

def fill(template):
    import re
    def replace(m):
        key = m.group(1)
        if key == "n": return str(random.randint(10, 10000))
        if key == "n2": return str(random.randint(50, 5000))
        if key == "max": return str(random.randint(5, 20))
        if key == "cve": return f"{random.randint(2018,2024)}-{random.randint(1000,50000)}"
        if key in FILL: return random.choice(FILL[key])
        return m.group(0)
    return re.sub(r'\{(\w+)\}', replace, template)


def generate(n_per_class=200):
    data = []
    for cls in CLASSES:
        templates = TEMPLATES[cls]
        for _ in range(n_per_class):
            tmpl = random.choice(templates)
            log = fill(tmpl)
            data.append({"text": log, "label": cls})
    random.shuffle(data)
    return data


if __name__ == "__main__":
    import csv, os
    data = generate(300)
    out_path = os.path.join(os.path.dirname(__file__), "training_data.csv")
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["text", "label"])
        writer.writeheader()
        writer.writerows(data)
    print(f"Generated {len(data)} training samples -> {out_path}")
    label_counts = {}
    for row in data:
        label_counts[row["label"]] = label_counts.get(row["label"], 0) + 1
    for label, cnt in sorted(label_counts.items()):
        print(f"  {label}: {cnt}")
