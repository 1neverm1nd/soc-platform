"""
Generate synthetic training data for SOC text classifier.
v2: 15 classes (added normal, lateral-movement, command-and-control,
    ransomware, cryptomining), 600 samples per class = 9 000 total.
"""
import random, re, csv, os

CLASSES = [
    "normal",
    "brute-force",
    "sql-injection",
    "phishing",
    "malware",
    "ransomware",
    "ddos",
    "privilege-escalation",
    "data-exfiltration",
    "unauthorized-access",
    "port-scanning",
    "vulnerability-exploit",
    "lateral-movement",
    "command-and-control",
    "cryptomining",
]

TEMPLATES = {
    # ── NORMAL / BENIGN ────────────────────────────────────────────────────────
    "normal": [
        "INFO: User {user} logged in successfully from {ip}",
        "DEBUG: API request GET /api/health 200 OK in {n}ms",
        "INFO: Scheduled backup completed successfully for {host}",
        "INFO: Certificate renewed for *.corp.local, valid 365 days",
        "DEBUG: Database connection pool {n}/20 used on {host}",
        "INFO: Software update v{n}.{n2} installed on {host}",
        "DEBUG: DNS query for {domain} resolved in {n}ms",
        "INFO: User {user} logged out, session duration {n} minutes",
        "INFO: Routine health check passed on {host} - all services up",
        "DEBUG: Cache hit rate {n}% on {endpoint} endpoint",
        "INFO: File {file} backed up successfully to archive",
        "DEBUG: Email delivered to {user}, queue empty",
        "INFO: Network scan by monitoring agent {host} completed",
        "DEBUG: Heartbeat received from {host} at {time}",
        "INFO: Config sync successful between {host} and primary node",
        "INFO: SSL handshake completed with {ip} in {n}ms",
        "DEBUG: Load balancer redistributed traffic, {n} active nodes",
        "INFO: Patch {exploit} applied successfully on {host}",
        "DEBUG: Metrics collected from {host}: CPU {n}%, RAM {n}%",
        "INFO: User {user} changed password successfully",
    ],

    # ── BRUTE FORCE ────────────────────────────────────────────────────────────
    "brute-force": [
        "Failed login attempt for user {user} from {ip} — attempt {n} of {max}",
        "Authentication failure: invalid password for account {user} [{ip}]",
        "SSH brute force detected: {n} failed attempts from {ip} within 60 seconds",
        "Multiple authentication failures user={user} src={ip} attempts={n}",
        "ALERT: Account lockout triggered for {user} after {n} failed logins from {ip}",
        "Login brute force attack: {ip} tried {n} passwords against {user}",
        "Credential stuffing: {n} accounts attempted from {ip}",
        "RDP brute force: {ip} attempting remote desktop login to {host}",
        "Hydra/Medusa tool signature: rapid sequential auth attempts from {ip}",
        "Password spray attack: single password tried against {n} accounts from {ip}",
        "LDAP brute force: {n} bind failures for {user} from {ip}",
        "Kerberos pre-auth failure storm: {n} AS-REQ failures from {ip}",
        "FTP brute force: {ip} attempting {n} username/password combinations",
        "API key brute force: {n} invalid tokens from {ip} to {endpoint}",
        "WPA2 handshake captured and offline dictionary attack in progress from {ip}",
    ],

    # ── SQL INJECTION ──────────────────────────────────────────────────────────
    "sql-injection": [
        "SQLi attempt detected in request: {param}=1' OR '1'='1",
        "WAF blocked SQL injection: UNION SELECT from {ip}",
        "Attack detected: payload contains DROP TABLE in field {param}",
        "Blind SQL injection: boolean-based enumeration from {ip}",
        "Time-based SQL injection: SLEEP(5) payload from {ip} on {endpoint}",
        "xp_cmdshell execution attempt via SQL injection from {ip}",
        "INFORMATION_SCHEMA enumeration detected from {ip}",
        "Stacked query injection: multiple statements in {param} from {ip}",
        "Out-of-band SQLi: DNS exfiltration via SQL injection from {ip}",
        "Error-based SQLi: extractvalue() function abuse from {ip}",
        "NoSQL injection detected: MongoDB operator injection from {ip}",
        "Second-order SQL injection in stored procedure triggered by {user}",
        "SQL truncation attack: username field overflow from {ip}",
        "Stored XSS via SQL injection: script payload in {param} from {ip}",
        "SQLMap tool signature detected from {ip} targeting {endpoint}",
    ],

    # ── PHISHING ───────────────────────────────────────────────────────────────
    "phishing": [
        "Phishing email from spoofed domain {domain} targeting {user}",
        "Phishing link clicked: {user} visited malicious URL from email",
        "Credential harvesting page: fake login mimicking {host}",
        "Spear phishing email with malicious attachment opened by {user}",
        "Email gateway blocked phishing: {email} impersonating IT support",
        "Business email compromise attempt targeting {user} finance",
        "Homograph attack: fake domain {domain} in phishing campaign",
        "Malicious OAuth app consent phishing targeting {user}",
        "Callback phishing: voicemail lure sent to {user}",
        "Whaling attack: executive impersonation targeting CFO {user}",
        "SMiShing: malicious SMS link sent to {user} mobile",
        "Vishing call: social engineering targeting {user} for credentials",
        "Clone phishing: legitimate email re-sent with malicious link to {user}",
        "Quishing: QR code phishing targeting {user} mobile device",
        "Adversary-in-the-middle phishing: {user} credentials captured via proxy {ip}",
    ],

    # ── MALWARE ────────────────────────────────────────────────────────────────
    "malware": [
        "Malware signature detected: {malware} on {host}",
        "Trojan dropper executed: {process} spawned suspicious child",
        "Endpoint protection quarantined {malware} on {host}",
        "Fileless malware: PowerShell download cradle on {host}",
        "Backdoor communication: {host} beaconing to {ip}",
        "Rootkit: kernel module tampering on {host}",
        "Keylogger detected: {process} hooking keyboard on {host}",
        "Spyware capturing screenshots on {host} and sending to {ip}",
        "Banker trojan intercepting credentials from browser on {host}",
        "Worm propagation: {malware} lateral movement from {host}",
        "Adware injecting ads into browser process on {host}",
        "Remote access trojan {malware} establishing persistence on {host}",
        "Polymorphic malware evading AV on {host}: hash changed {n} times",
        "Macro malware in Office document executed by {user} on {host}",
        "Living-off-the-land: {process} abused for malware execution on {host}",
    ],

    # ── RANSOMWARE ─────────────────────────────────────────────────────────────
    "ransomware": [
        "Ransomware detected: {malware} encrypting files on {host}",
        "Mass file encryption: {n} files modified in 60s on {host}",
        "Ransom note created: README_DECRYPT.txt dropped on {host}",
        "Shadow copies deleted: vssadmin delete shadows on {host} by {process}",
        "Ransomware C2: {host} connected to payment server {ip}",
        "File extension changed to .encrypted/.locked on {n} files on {host}",
        "Backup files targeted: {malware} deleting .bak and .vhd on {host}",
        "Ryuk/LockBit ransomware signature detected on {host}",
        "Ransomware propagation: {malware} spreading via SMB from {host}",
        "WBADMIN delete catalog executed before encryption on {host}",
        "Ransomware key exchange: {host} connecting to {ip} for public key",
        "Double extortion: {malware} exfiltrating before encrypting on {host}",
        "Ransomware dropper via phishing macro executed by {user} on {host}",
        "Scheduled task created by ransomware for persistence on {host}",
        "Registry modification: {malware} adding startup entry on {host}",
    ],

    # ── DDOS ───────────────────────────────────────────────────────────────────
    "ddos": [
        "DDoS: {n} req/sec from {n2} IPs targeting {host}",
        "SYN flood: {ip} sending {n} SYN packets, no handshake",
        "UDP amplification: {n} Gbps spike targeting {host}",
        "HTTP flood: {n} req/sec from botnet to {endpoint}",
        "DNS amplification DDoS: {n} Mbps reflector traffic to {host}",
        "Application DDoS: {n} concurrent connections exhausting {host}",
        "Slowloris: {ip} holding {n} connections open to {host}",
        "NTP amplification: {n}x traffic amplification to {host}",
        "ICMP ping flood from {ip}: {n} packets/sec",
        "Carpet bombing DDoS across {n} destination IPs",
        "Memcached amplification: {n} Gbps reflected at {host}",
        "QUIC flood: {n} UDP/443 packets/sec targeting {host}",
        "BGP hijack causing traffic rerouting affecting {host}",
        "SSL/TLS exhaustion attack: {n} handshakes/sec to {host}",
        "Botnets {n} bots coordinating layer-7 attack on {endpoint}",
    ],

    # ── PRIVILEGE ESCALATION ───────────────────────────────────────────────────
    "privilege-escalation": [
        "Privilege escalation: {user} gained root via {exploit}",
        "Sudo abuse: {user} executed restricted command on {host}",
        "Token impersonation: {process} escalated privilege on {host}",
        "Kernel exploit: {exploit} by {user} on {host}",
        "UAC bypass: {process} elevated without prompt on {host}",
        "Setuid binary exploitation by {user} via {binary} on {host}",
        "DLL injection into privileged process by {user} on {host}",
        "Access token manipulation: {user} duplicated admin token on {host}",
        "Scheduled task abuse for privilege escalation by {user}",
        "Service account compromise: {user} gained SYSTEM via {service}",
        "PrintNightmare exploit: {user} gained SYSTEM via print spooler on {host}",
        "Dirty COW exploit: {user} wrote to read-only memory on {host}",
        "Named pipe impersonation: {process} captured SYSTEM token on {host}",
        "Unquoted service path exploitation by {user} on {host}",
        "AlwaysInstallElevated registry abuse by {user} on {host}",
    ],

    # ── DATA EXFILTRATION ──────────────────────────────────────────────────────
    "data-exfiltration": [
        "Large transfer: {n} MB from {host} to external {ip}",
        "DNS exfiltration: {host} sending encoded TXT queries to {domain}",
        "Sensitive file {file} uploaded to {ip} by {user}",
        "DLP alert: PII leaving network via {protocol} to {ip}",
        "C2 exfiltration: compressed archive uploaded to {ip}",
        "Clipboard exfiltration: {process} capturing clipboard on {host}",
        "Email exfiltration: {user} forwarded {n} emails to {email}",
        "Cloud abuse: {user} uploaded {n} files to unauthorized bucket",
        "Steganography: image files with embedded data sent to {ip}",
        "FTP exfiltration: {n} MB database dump to {ip}",
        "HTTPS upload of {n} MB to unknown {ip} by {host}",
        "USB exfiltration: {file} copied to removable device by {user}",
        "ICMP covert channel: {host} exfiltrating data via ping to {ip}",
        "Slack/Teams exfiltration: {user} sending files to external workspace",
        "Git repo exfiltration: {user} cloning sensitive repo to {ip}",
    ],

    # ── UNAUTHORIZED ACCESS ────────────────────────────────────────────────────
    "unauthorized-access": [
        "Unauthorized access to restricted resource by {user} from {ip}",
        "Account sharing: {user} credentials from {n} different IPs",
        "After-hours access: {user} logged in at {time}",
        "Impossible travel: {user} authenticated from {country1} and {country2} in 1 hour",
        "Stale account reactivation: dormant {user} accessed from {ip}",
        "Service account interactive login for {user} on {host}",
        "Unauthorized API access: {user} called restricted {endpoint}",
        "Shared credentials: {n} users with same account",
        "Unauthorized database query by {user} on sensitive tables",
        "VPN split tunneling abuse by {user}",
        "IDOR vulnerability exploited: {user} accessing other users data via {endpoint}",
        "Broken access control: {user} escalated to admin role via {endpoint}",
        "Path traversal: {ip} accessed ../../../../etc/passwd via {endpoint}",
        "Directory listing exposed: {ip} browsing {endpoint} without auth",
        "JWT token forgery: {ip} crafted invalid token accepted by {host}",
    ],

    # ── PORT SCANNING ──────────────────────────────────────────────────────────
    "port-scanning": [
        "Port scan: {ip} probed {n} ports on {host} in {n2}s",
        "Nmap scan: OS fingerprinting from {ip} against {host}",
        "Masscan: {ip} scanning subnet {subnet}",
        "SYN stealth scan: {ip} on {n} ports of {host}",
        "UDP port scan: {ip} probing service ports on {host}",
        "Vulnerability scanner from {ip}: {n} probes in {n2}s",
        "Network discovery: {ip} enumerated {n} live hosts in {subnet}",
        "Shodan bot scanning {host} from {ip}",
        "Service version enumeration: {ip} grabbing banners from {host}",
        "Firewall evasion scan: fragmented packets from {ip} to {host}",
        "Xmas scan: {ip} sending FIN+URG+PSH to {host}",
        "SCTP INIT scan from {ip} to {host}",
        "IPv6 scan: {ip} probing link-local on {subnet}",
        "Zombie/idle scan: {ip} using {host} as zombie for blind scan",
        "ACK scan for firewall mapping from {ip} to {host}",
    ],

    # ── VULNERABILITY EXPLOIT ──────────────────────────────────────────────────
    "vulnerability-exploit": [
        "Exploit attempt: CVE-{cve} payload from {ip} to {host}",
        "Buffer overflow on {service} from {ip}",
        "RCE: {ip} exploited {vuln} on {host}",
        "Log4Shell exploitation: JNDI lookup payload from {ip}",
        "EternalBlue (MS17-010) from {ip} targeting {host}",
        "Apache Struts RCE from {ip} — CVE-{cve}",
        "ProxyLogon: {ip} targeting Exchange {host}",
        "Shellshock: malicious User-Agent from {ip}",
        "Heartbleed: {ip} sent malformed TLS heartbeat to {host}",
        "Spring4Shell RCE: {ip} exploiting CVE-2022-22965 on {host}",
        "Citrix ADC exploit CVE-{cve}: directory traversal from {ip}",
        "F5 BIG-IP TMUI RCE: {ip} exploiting CVE-2020-5902 on {host}",
        "Atlassian Confluence exploit CVE-{cve} from {ip}",
        "VMware vCenter exploit: {ip} RCE via SSRF on {host}",
        "OpenSSL memory corruption CVE-{cve} triggered from {ip}",
    ],

    # ── LATERAL MOVEMENT ───────────────────────────────────────────────────────
    "lateral-movement": [
        "Lateral movement: {user} accessing {host} from compromised {host}",
        "Pass-the-hash: {ip} authenticating with NTLM hash to {host}",
        "Pass-the-ticket: Kerberos ticket reused from {ip} to {host}",
        "SMB lateral movement: {malware} copying itself to \\\\{host}\\admin$",
        "WMI lateral movement: {ip} executing command on {host} remotely",
        "PsExec lateral movement: remote shell from {ip} to {host}",
        "RDP lateral movement: {user} connecting from {ip} to {host}",
        "Remote scheduled task created by {ip} on {host}",
        "SSH lateral movement: {user} hopping from {ip} to {host}",
        "Overpass-the-hash: {user} converting NTLM to Kerberos TGT",
        "DCSync: {ip} replicating domain credentials from DC {host}",
        "Token impersonation for lateral: {process} using {user} token on {host}",
        "Cobalt Strike beacon lateral movement: {ip} → {host}",
        "DCOM lateral movement: {ip} executing {process} on {host}",
        "SPN scanning: {ip} enumerating Kerberoastable accounts on {host}",
    ],

    # ── COMMAND AND CONTROL ────────────────────────────────────────────────────
    "command-and-control": [
        "C2 beacon: {host} connecting to {ip} every {n} seconds",
        "DNS C2: {host} resolving unusual TXT records from {domain}",
        "HTTPS C2: encrypted beaconing from {host} to {ip}:443",
        "Domain fronting C2: {host} using CDN to reach {ip}",
        "Cobalt Strike C2 profile detected: {host} → {ip}",
        "Metasploit Meterpreter session: {host} → {ip}:{n}",
        "Empire PowerShell C2: {host} checking in with {ip}",
        "Sliver/Havoc C2 beacon from {host} to {ip}",
        "IRC botnet: {host} joining channel on {ip}:{n}",
        "C2 over social media API: {host} polling {domain} for commands",
        "Icmpsh C2: ICMP-based command channel {host} → {ip}",
        "C2 over Telegram/Discord: {host} connecting to {domain}",
        "HTTP long-polling C2: {host} keeping connection to {ip} for {n}s",
        "Named pipe C2: local {process} relaying commands to {ip}",
        "Fast-flux DNS: {host} resolving {domain} to {n} different IPs",
    ],

    # ── CRYPTOMINING ───────────────────────────────────────────────────────────
    "cryptomining": [
        "Cryptominer detected: {process} connecting to pool {ip}:{n}",
        "High CPU {n}% sustained on {host}: Monero mining suspected",
        "XMRig miner process {process} running on {host}",
        "Browser cryptojacking: coin-hive script on {domain}",
        "Stratum mining protocol detected: {host} → {ip}:3333",
        "GPU utilization {n}% continuous: ETH mining on {host}",
        "Kubernetes pod running crypto miner: {host}",
        "Cloud instance {host} CPU pegged at {n}% — cryptomining",
        "Nicehash connection from {host} to {ip}",
        "Unauthorized crypto wallet: {host} sending {n} Monero",
        "Mining pool traffic: {host} sending shares to {domain}",
        "Coinhive JavaScript miner injected into {endpoint} via XSS",
        "Container escape → host {host} running cryptominer {process}",
        "Crontab modified on {host}: miner scheduled every {n} minutes",
        "Powershell download: XMRig binary pulled from {ip} to {host}",
    ],
}

FILL = {
    "user":     ["admin", "john.doe", "system", "service_acct", "root", "guest",
                 "backup_user", "db_admin", "api_user", "test", "developer", "analyst"],
    "ip":       ([f"192.168.{random.randint(1,254)}.{random.randint(1,254)}" for _ in range(8)] +
                 [f"{random.randint(1,223)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}" for _ in range(20)]),
    "host":     ["webserver-01", "db-primary", "fileserver", "dc-01", "workstation-42",
                 "api-gateway", "mail-server", "vpn-gateway", "k8s-node-1", "devops-host"],
    "target":   ["10.0.0.1", "prod-db", "web-app", "internal-api", "192.168.1.100", "fileserver.corp"],
    "domain":   ["secure-login.net", "corp-verify.com", "update-now.io", "paypal-secure.xyz",
                 "xmrpool.eu", "c2.evil.xyz", "fastflux.ru"],
    "email":    ["it-support@fake.com", "noreply@corp-update.net", "billing@suspicious.xyz"],
    "param":    ["id", "search", "username", "query", "filter", "page", "sort"],
    "endpoint": ["/api/users", "/login", "/admin", "/search", "/api/data", "/reports"],
    "malware":  ["Emotet.B", "Ryuk.Ransomware", "LockBit.3", "Cobalt.Strike", "Mimikatz",
                 "TrickBot", "AgentTesla", "RedLine", "BlackCat", "Conti"],
    "process":  ["powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe", "regsvr32.exe",
                 "xmrig", "python3", "bash", "cscript.exe"],
    "exploit":  ["CVE-2021-44228", "MS17-010", "CVE-2020-1472", "PrintNightmare",
                 "DirtyPipe", "CVE-2022-22965"],
    "binary":   ["sudo", "find", "python", "perl", "bash"],
    "service":  ["spooler", "BITS", "WSearch", "Schedule"],
    "subnet":   ["192.168.1.0/24", "10.0.0.0/16", "172.16.0.0/12"],
    "file":     ["passwords.xlsx", "customer_data.csv", "financial_report.pdf",
                 "source_code.zip", "backup.sql", "private_key.pem"],
    "protocol": ["HTTP", "FTP", "DNS", "ICMP", "SMTP", "HTTPS"],
    "country1": ["Kazakhstan", "Germany", "France", "USA"],
    "country2": ["China", "Russia", "Nigeria", "North Korea"],
    "time":     ["02:47", "23:15", "03:30", "01:22", "04:55"],
    "vuln":     ["Log4Shell", "Heartbleed", "ShellShock", "EternalBlue", "ProxyLogon",
                 "Spring4Shell"],
    "service2": ["Apache", "Nginx", "IIS", "OpenSSH", "SMB"],
}


def fill(template: str) -> str:
    def replace(m):
        key = m.group(1)
        if key == "n":    return str(random.randint(10, 9999))
        if key == "n2":   return str(random.randint(5, 500))
        if key == "max":  return str(random.randint(5, 20))
        if key == "cve":  return f"{random.randint(2018,2024)}-{random.randint(1000,50000)}"
        if key in FILL:   return random.choice(FILL[key])
        return m.group(0)
    return re.sub(r'\{(\w+)\}', replace, template)


def generate(n_per_class: int = 600) -> list[dict]:
    data = []
    for cls in CLASSES:
        templates = TEMPLATES[cls]
        for _ in range(n_per_class):
            tmpl = random.choice(templates)
            data.append({"text": fill(tmpl), "label": cls})
    random.shuffle(data)
    return data


if __name__ == "__main__":
    data = generate(600)
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "training_data.csv")
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["text", "label"])
        writer.writeheader()
        writer.writerows(data)
    counts = {}
    for row in data:
        counts[row["label"]] = counts.get(row["label"], 0) + 1
    print(f"Generated {len(data)} samples -> {out_path}")
    for label in CLASSES:
        print(f"  {label}: {counts.get(label, 0)}")
