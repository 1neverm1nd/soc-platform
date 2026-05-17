import { spawn } from "child_process";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ML_SCRIPT = path.join(__dirname, "../../ml/predict.py");

const MITRE_MAP: Record<string, { mitreId: string; mitreTechnique: string; mitreTactic: string }> = {
  "brute-force":           { mitreId: "T1110", mitreTechnique: "Brute Force",                          mitreTactic: "Credential Access" },
  "sql-injection":         { mitreId: "T1190", mitreTechnique: "Exploit Public-Facing Application",    mitreTactic: "Initial Access" },
  "phishing":              { mitreId: "T1566", mitreTechnique: "Phishing",                             mitreTactic: "Initial Access" },
  "malware":               { mitreId: "T1204", mitreTechnique: "User Execution",                       mitreTactic: "Execution" },
  "ddos":                  { mitreId: "T1498", mitreTechnique: "Network Denial of Service",            mitreTactic: "Impact" },
  "data-exfiltration":     { mitreId: "T1041", mitreTechnique: "Exfiltration Over C2 Channel",        mitreTactic: "Exfiltration" },
  "privilege-escalation":  { mitreId: "T1068", mitreTechnique: "Exploitation for Privilege Escalation", mitreTactic: "Privilege Escalation" },
  "unauthorized-access":   { mitreId: "T1078", mitreTechnique: "Valid Accounts",                      mitreTactic: "Defense Evasion" },
  "port-scanning":         { mitreId: "T1046", mitreTechnique: "Network Service Discovery",            mitreTactic: "Discovery" },
  "vulnerability-exploit": { mitreId: "T1203", mitreTechnique: "Exploitation for Client Execution",   mitreTactic: "Execution" },
  // Expanded classes
  "ransomware":            { mitreId: "T1486", mitreTechnique: "Data Encrypted for Impact",            mitreTactic: "Impact" },
  "lateral-movement":      { mitreId: "T1021", mitreTechnique: "Remote Services",                     mitreTactic: "Lateral Movement" },
  "command-and-control":   { mitreId: "T1071", mitreTechnique: "Application Layer Protocol",           mitreTactic: "Command and Control" },
  "cryptomining":          { mitreId: "T1496", mitreTechnique: "Resource Hijacking",                   mitreTactic: "Impact" },
  "backdoor":              { mitreId: "T1543", mitreTechnique: "Create or Modify System Process",      mitreTactic: "Persistence" },
  "shellcode":             { mitreId: "T1055", mitreTechnique: "Process Injection",                    mitreTactic: "Defense Evasion" },
  "worm":                  { mitreId: "T1080", mitreTechnique: "Taint Shared Content",                 mitreTactic: "Lateral Movement" },
  "fuzzing":               { mitreId: "T1110", mitreTechnique: "Brute Force / Fuzzing",                mitreTactic: "Credential Access" },
  "network-analysis":      { mitreId: "T1040", mitreTechnique: "Network Sniffing",                     mitreTactic: "Discovery" },
  "normal":                { mitreId: "T0000", mitreTechnique: "Benign Activity",                      mitreTactic: "None" },
};

const REGEX_FALLBACK: Array<{ pattern: RegExp; type: string }> = [
  // Normal / benign — check FIRST to avoid false positives
  { pattern: /INFO:|DEBUG:|heartbeat|health.?check|backup.?complet|keepalive|ping.?ok|system.?start/i, type: "normal" },
  // Specific threats
  { pattern: /ransomware|encrypt.?file|ransom.?note|shadow.?cop|vssadmin.?delete/i, type: "ransomware" },
  { pattern: /c2.?beacon|command.?control|cobalt.?strike|beacon.?check.?in|cnc.?server/i, type: "command-and-control" },
  { pattern: /lateral.?move|pass.?hash|pass.?ticket|psexec|wmi.?exec|smb.?spread/i, type: "lateral-movement" },
  { pattern: /cryptomin|xmrig|mining.?pool|stratum\+tcp|monero|coin.?hive/i, type: "cryptomining" },
  { pattern: /shellcode|heap.?spray|rop.?chain|nop.?sled|meterpreter/i, type: "shellcode" },
  { pattern: /worm.?spread|self.?replicate|infect.?host|blaster|conficker/i, type: "worm" },
  { pattern: /fuzz.?input|afl\+\+|boofuzz|mutation.?test|invalid.?input.+crash/i, type: "fuzzing" },
  { pattern: /packet.?capture|tcpdump|wireshark|network.?sniff|promiscuous.?mode/i, type: "network-analysis" },
  { pattern: /backdoor|reverse.?shell|persist.?service|crontab.?inject/i, type: "backdoor" },
  { pattern: /brute.?force|password.?attempt|failed.?login|auth.?fail/i, type: "brute-force" },
  { pattern: /sql.?inject|union.?select|1=1|drop.?table|xp_cmd/i, type: "sql-injection" },
  { pattern: /phish|spear|credential.?harvest|fake.?login/i, type: "phishing" },
  { pattern: /malware|trojan/i, type: "malware" },
  { pattern: /ddos|flood|syn.?flood|amplif|botnet/i, type: "ddos" },
  { pattern: /exfil|data.?leak|loot|exporting.?data/i, type: "data-exfiltration" },
  { pattern: /priv.?esc|sudo.?exploit|privilege|escalat/i, type: "privilege-escalation" },
  { pattern: /unauthorized|invalid.?cred|access.?denied.+attempt/i, type: "unauthorized-access" },
  { pattern: /port.?scan|nmap|masscan|service.?discovery/i, type: "port-scanning" },
  { pattern: /cve-|exploit|vuln|remote.?code.?exec|rce/i, type: "vulnerability-exploit" },
];

export interface MLResult {
  type: string;
  confidence: number;
  alternatives: Array<{ type: string; confidence: number }>;
  mitreId: string;
  mitreTechnique: string;
  mitreTactic: string;
  usedFallback: boolean;
  explanation?: Array<{ feature: string; value: number; impact: number; description: string }>;
  anomalyScore?: number | null;
  isAnomaly?: boolean;
  mode?: string;
}

function regexFallback(log: string): MLResult {
  for (const { pattern, type } of REGEX_FALLBACK) {
    if (pattern.test(log)) {
      const mitre = MITRE_MAP[type] ?? { mitreId: "T1059", mitreTechnique: "Command and Scripting Interpreter", mitreTactic: "Execution" };
      return { type, confidence: 0.65, alternatives: [], ...mitre, usedFallback: true };
    }
  }
  const mitre = MITRE_MAP["normal"]!;
  return { type: "normal", confidence: 0.6, alternatives: [], ...mitre, usedFallback: true };
}

function runPredict(input: string): Promise<MLResult> {
  return new Promise((resolve) => {
    try {
      const proc = spawn("python", [ML_SCRIPT], { timeout: 15000 });
      let stdout = "";
      let stderr = "";

      proc.stdout.on("data", (d: Buffer) => { stdout += d.toString(); });
      proc.stderr.on("data", (d: Buffer) => { stderr += d.toString(); });

      proc.on("close", (code) => {
        if (code !== 0 || !stdout.trim()) {
          console.warn("[ML] Python failed, using regex fallback:", stderr.slice(0, 200));
          resolve(regexFallback(input));
          return;
        }
        try {
          const result = JSON.parse(stdout.trim()) as {
            type: string;
            confidence: number;
            alternatives?: Array<{ type: string; confidence: number }>;
            explanation?: Array<{ feature: string; value: number; impact: number; description: string }>;
            anomalyScore?: number | null;
            isAnomaly?: boolean;
            mode?: string;
          };
          const mitre = MITRE_MAP[result.type] ?? { mitreId: "T1059", mitreTechnique: "Command and Scripting Interpreter", mitreTactic: "Execution" };
          resolve({
            ...result,
            alternatives: result.alternatives ?? [],
            ...mitre,
            usedFallback: false,
            explanation:  result.explanation  ?? [],
            anomalyScore: result.anomalyScore ?? null,
            isAnomaly:    result.isAnomaly    ?? false,
            mode:         result.mode         ?? "text",
          } as MLResult);
        } catch {
          resolve(regexFallback(input));
        }
      });

      proc.on("error", () => resolve(regexFallback(input)));
      proc.stdin.write(input);
      proc.stdin.end();
    } catch {
      resolve(regexFallback(input));
    }
  });
}

export async function classifyLog(rawLog: string): Promise<MLResult> {
  return runPredict(rawLog);
}

export async function classifyWithFeatures(rawLog: string, features: Record<string, unknown> | null): Promise<MLResult> {
  if (!features) return runPredict(rawLog);
  const payload = JSON.stringify({ text: rawLog, features });
  return runPredict(payload);
}

export { MITRE_MAP };
