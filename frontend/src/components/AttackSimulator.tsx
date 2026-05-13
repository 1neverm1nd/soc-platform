import { useState, useRef, useCallback } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { trpc } from "@/lib/trpc";
import { useQueryClient } from "@tanstack/react-query";
import { cn } from "@/lib/utils";
import { Zap, X, Play, Square, Terminal } from "lucide-react";
import { toast } from "sonner";

const ATTACKS = [
  { type: "brute-force",          label: "Brute Force",      log: "SSH brute force: {n} failed attempts from {ip}" },
  { type: "sql-injection",        label: "SQL Injection",     log: "SQLi detected: ' OR 1=1-- from {ip} on /api/users" },
  { type: "phishing",             label: "Phishing",          log: "Phishing email from spoofed domain targeting {user}@corp.local" },
  { type: "malware",              label: "Malware",           log: "Malware Emotet.B detected on host webserver-{n}" },
  { type: "ddos",                 label: "DDoS",              log: "SYN flood: {n} packets/sec from {ip} targeting 10.0.0.1" },
  { type: "privilege-escalation", label: "Priv. Escalation",  log: "Privilege escalation via CVE-2021-{n} on host db-primary" },
  { type: "data-exfiltration",    label: "Data Exfil",        log: "Large data transfer: {n}MB from fileserver to {ip}:443" },
  { type: "unauthorized-access",  label: "Unauth. Access",    log: "Unauthorized access from {ip} to restricted /admin endpoint" },
  { type: "port-scanning",        label: "Port Scan",         log: "Nmap scan from {ip}: {n} ports probed in 5 seconds" },
  { type: "vulnerability-exploit",label: "Vuln Exploit",      log: "Log4Shell exploit attempt CVE-2021-44228 from {ip}" },
];

const COUNTRY_POOL = [
  { code: "CN", country: "China",         w: 22 },
  { code: "RU", country: "Russia",        w: 14 },
  { code: "US", country: "United States", w: 10 },
  { code: "DE", country: "Germany",       w: 7  },
  { code: "NL", country: "Netherlands",   w: 6  },
  { code: "BR", country: "Brazil",        w: 5  },
  { code: "KR", country: "South Korea",   w: 5  },
  { code: "IN", country: "India",         w: 5  },
  { code: "UA", country: "Ukraine",       w: 4  },
  { code: "FR", country: "France",        w: 4  },
  { code: "JP", country: "Japan",         w: 3  },
  { code: "RO", country: "Romania",       w: 3  },
  { code: "PL", country: "Poland",        w: 3  },
  { code: "NG", country: "Nigeria",       w: 3  },
  { code: "IR", country: "Iran",          w: 2  },
];

const BENIGN_LOGS = [
  "INFO: User john.doe logged in from 192.168.1.45",
  "INFO: Scheduled backup completed successfully",
  "DEBUG: API request GET /api/health 200 OK in 12ms",
  "INFO: Certificate renewal successful for *.corp.local",
  "DEBUG: Database connection pool: 8/20 used",
  "INFO: Routine port scan by monitoring agent completed",
  "INFO: Software update installed on workstation-12",
  "DEBUG: DNS query for mail.google.com resolved",
];

function rnd(min: number, max: number) { return Math.floor(Math.random() * (max - min + 1)) + min; }
function randIp() { return `${rnd(1,223)}.${rnd(1,254)}.${rnd(1,254)}.${rnd(1,254)}`; }

function weightedCountry(): { country: string; code: string } {
  const total = COUNTRY_POOL.reduce((s, c) => s + c.w, 0);
  let r = Math.random() * total;
  for (const c of COUNTRY_POOL) { r -= c.w; if (r <= 0) return c; }
  return COUNTRY_POOL[0]!;
}

function fillTemplate(tmpl: string) {
  return tmpl
    .replace("{n}", String(rnd(10, 9999)))
    .replace("{ip}", randIp())
    .replace("{user}", ["admin", "john", "service"][rnd(0, 2)]!);
}

export function AttackSimulator() {
  const [open,          setOpen]          = useState(false);
  const [mode,          setMode]          = useState<"quick" | "storm" | "realistic">("quick");
  const [stormRunning,  setStormRunning]  = useState(false);
  const [stormCount,    setStormCount]    = useState(0);
  const [stormTarget,   setStormTarget]   = useState(20);
  const [logs,          setLogs]          = useState<{ text: string; tag: string; ts: string }[]>([]);
  const stormRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const qc = useQueryClient();

  const ingest = trpc.incident.ingest.useMutation({ onSuccess: () => qc.invalidateQueries() });

  const addLog = useCallback((text: string, tag: string) => {
    const ts = new Date().toLocaleTimeString();
    setLogs((prev) => [{ text, tag, ts }, ...prev].slice(0, 30));
  }, []);

  const fire = useCallback(async (attack?: typeof ATTACKS[0]) => {
    const chosen  = attack ?? ATTACKS[rnd(0, ATTACKS.length - 1)]!;
    const country = weightedCountry();
    const log     = fillTemplate(chosen.log);
    const sourceIp = randIp();
    await ingest.mutateAsync({
      rawLog: log, sourceIp,
      destinationIp: `10.0.${rnd(0,5)}.${rnd(1,254)}`,
      threatCountry: country.country,
    });
    addLog(`[THREAT] ${chosen.label} from ${country.code} (${sourceIp})`, "threat");
  }, [ingest, addLog]);

  const fireRealistic = useCallback(async () => {
    if (Math.random() < 0.65) {
      const log = BENIGN_LOGS[rnd(0, BENIGN_LOGS.length - 1)]!;
      addLog(`[OK] ${log.slice(0, 60)}`, "benign");
    } else {
      const attack = ATTACKS[rnd(0, ATTACKS.length - 1)]!;
      const country = weightedCountry();
      addLog(`[${country.code}] Threat detected: ${attack.label}`, "threat");
      await fire(attack);
    }
  }, [fire, addLog]);

  function startStorm() {
    setStormRunning(true); setStormCount(0);
    let count = 0;
    stormRef.current = setInterval(async () => {
      await fire(); count++; setStormCount(count);
      if (count >= stormTarget) stopStorm();
    }, 500);
  }

  function stopStorm() {
    setStormRunning(false);
    if (stormRef.current) { clearInterval(stormRef.current); stormRef.current = null; }
  }

  function startRealistic() {
    setStormRunning(true); setStormCount(0);
    let count = 0;
    stormRef.current = setInterval(async () => {
      await fireRealistic(); count++; setStormCount(count);
      if (count >= stormTarget) stopStorm();
    }, 300);
  }

  const inputStyle = {
    background: "rgba(255,255,255,0.05)",
    border: "1px solid rgba(255,255,255,0.1)",
    borderRadius: 8,
    color: "var(--text-primary)",
  };

  return (
    <div className="fixed bottom-6 right-6 z-50">
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: 12, scale: 0.97 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 8, scale: 0.97 }}
            transition={{ duration: 0.18, ease: [0.23, 1, 0.32, 1] }}
            className="mb-3 w-[420px] overflow-hidden shadow-2xl"
            style={{
              background: "rgba(8,12,22,0.97)",
              border: "1px solid rgba(249,115,22,0.2)",
              borderRadius: 12,
            }}
          >
            {/* Header */}
            <div className="flex items-center justify-between px-4 py-3" style={{ borderBottom: "1px solid rgba(255,255,255,0.06)", background: "rgba(249,115,22,0.07)" }}>
              <div className="flex items-center gap-2">
                <Zap className="w-3.5 h-3.5 text-orange-400" />
                <span className="text-[var(--text-primary)] font-semibold text-xs">Attack Simulator</span>
              </div>
              <button onClick={() => setOpen(false)} className="text-[var(--text-tertiary)]"
                style={{ transition: "color 120ms" }}
                onMouseEnter={(e) => e.currentTarget.style.color = "var(--text-primary)"}
                onMouseLeave={(e) => e.currentTarget.style.color = "var(--text-tertiary)"}>
                <X className="w-3.5 h-3.5" />
              </button>
            </div>

            {/* Mode tabs */}
            <div className="flex" style={{ borderBottom: "1px solid rgba(255,255,255,0.06)" }}>
              {(["quick", "storm", "realistic"] as const).map((m) => (
                <button key={m}
                  onClick={() => { setMode(m); stopStorm(); }}
                  className="flex-1 py-2 text-[11px] font-medium capitalize"
                  style={{
                    color: mode === m ? "#fb923c" : "var(--text-tertiary)",
                    borderBottom: mode === m ? "2px solid #f97316" : "2px solid transparent",
                    transition: "color 120ms",
                  }}>
                  {m === "quick" ? "Quick Fire" : m === "storm" ? "Storm Mode" : "Realistic"}
                </button>
              ))}
            </div>

            <div className="p-4">
              {mode === "quick" && (
                <div className="grid grid-cols-2 gap-1.5">
                  {ATTACKS.map((a) => (
                    <button key={a.type} onClick={() => fire(a)} disabled={ingest.isPending}
                      className="text-left px-3 py-2 rounded-lg text-[11px] disabled:opacity-40 select-none"
                      style={{
                        background: "rgba(255,255,255,0.04)",
                        border: "1px solid rgba(255,255,255,0.06)",
                        color: "var(--text-secondary)",
                        transition: "background-color 120ms, border-color 120ms, color 120ms",
                      }}
                      onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(249,115,22,0.1)"; e.currentTarget.style.borderColor = "rgba(249,115,22,0.25)"; e.currentTarget.style.color = "var(--text-primary)"; }}
                      onMouseLeave={(e) => { e.currentTarget.style.background = "rgba(255,255,255,0.04)"; e.currentTarget.style.borderColor = "rgba(255,255,255,0.06)"; e.currentTarget.style.color = "var(--text-secondary)"; }}
                      onMouseDown={(e) => e.currentTarget.style.transform = "scale(0.97)"}
                      onMouseUp={(e) => e.currentTarget.style.transform = "scale(1)"}>
                      {a.label}
                    </button>
                  ))}
                </div>
              )}

              {mode === "storm" && (
                <div className="space-y-3">
                  <div className="flex items-center gap-3">
                    <label className="text-[var(--text-tertiary)] text-xs">Count:</label>
                    <input type="number" min={1} max={200} value={stormTarget}
                      onChange={(e) => setStormTarget(Number(e.target.value))}
                      className="flex-1 px-3 py-1.5 text-sm text-center focus:outline-none"
                      style={inputStyle} />
                  </div>
                  {stormRunning && (
                    <div>
                      <div className="flex justify-between text-[10px] text-[var(--text-tertiary)] mb-1">
                        <span>Progress</span><span className="tabular">{stormCount}/{stormTarget}</span>
                      </div>
                      <div className="h-1.5 rounded-full overflow-hidden" style={{ background: "rgba(255,255,255,0.05)" }}>
                        <div className="h-full bg-orange-500 rounded-full" style={{ width: `${(stormCount / stormTarget) * 100}%`, transition: "width 400ms" }} />
                      </div>
                    </div>
                  )}
                  <button
                    onClick={stormRunning ? stopStorm : startStorm}
                    className="w-full py-2 rounded-lg text-xs font-medium text-white flex items-center justify-center gap-2 select-none"
                    style={{
                      background: stormRunning ? "rgba(239,68,68,0.7)" : "rgba(249,115,22,0.7)",
                      border: stormRunning ? "1px solid rgba(239,68,68,0.3)" : "1px solid rgba(249,115,22,0.3)",
                      transition: "background-color 150ms, transform 100ms",
                    }}
                    onMouseDown={(e) => e.currentTarget.style.transform = "scale(0.98)"}
                    onMouseUp={(e) => e.currentTarget.style.transform = "scale(1)"}
                    onMouseLeave={(e) => e.currentTarget.style.transform = "scale(1)"}>
                    {stormRunning ? <><Square className="w-3 h-3" /> Stop Storm</> : <><Play className="w-3 h-3" /> Start Storm</>}
                  </button>
                </div>
              )}

              {mode === "realistic" && (
                <div className="space-y-3">
                  <p className="text-[var(--text-tertiary)] text-[11px]">65% benign + 35% threats. Watch ML filter traffic.</p>
                  <div className="flex items-center gap-3">
                    <label className="text-[var(--text-tertiary)] text-xs">Events:</label>
                    <input type="number" min={5} max={200} value={stormTarget}
                      onChange={(e) => setStormTarget(Number(e.target.value))}
                      className="flex-1 px-3 py-1.5 text-sm text-center focus:outline-none"
                      style={inputStyle} />
                  </div>
                  {stormRunning && (
                    <div className="h-1.5 rounded-full overflow-hidden" style={{ background: "rgba(255,255,255,0.05)" }}>
                      <div className="h-full bg-blue-500 rounded-full" style={{ width: `${(stormCount / stormTarget) * 100}%`, transition: "width 400ms" }} />
                    </div>
                  )}
                  <button
                    onClick={stormRunning ? stopStorm : startRealistic}
                    className="w-full py-2 rounded-lg text-xs font-medium text-white flex items-center justify-center gap-2 select-none"
                    style={{
                      background: stormRunning ? "rgba(239,68,68,0.7)" : "rgba(37,99,235,0.7)",
                      border: stormRunning ? "1px solid rgba(239,68,68,0.3)" : "1px solid rgba(59,130,246,0.3)",
                      transition: "background-color 150ms, transform 100ms",
                    }}
                    onMouseDown={(e) => e.currentTarget.style.transform = "scale(0.98)"}
                    onMouseUp={(e) => e.currentTarget.style.transform = "scale(1)"}
                    onMouseLeave={(e) => e.currentTarget.style.transform = "scale(1)"}>
                    {stormRunning ? <><Square className="w-3 h-3" /> Stop</> : <><Play className="w-3 h-3" /> Run Simulation</>}
                  </button>
                </div>
              )}
            </div>

            {/* Terminal log */}
            {logs.length > 0 && (
              <div style={{ borderTop: "1px solid rgba(255,255,255,0.05)", background: "rgba(0,0,0,0.25)" }}>
                <div className="flex items-center gap-2 px-3 py-1.5" style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                  <Terminal className="w-2.5 h-2.5 text-[var(--text-tertiary)]" />
                  <span className="text-[var(--text-tertiary)] text-[10px]">Log Feed</span>
                </div>
                <div className="max-h-28 overflow-y-auto px-3 py-2 space-y-0.5 font-mono">
                  {logs.map((l, i) => (
                    <div key={i} className={cn("text-[10px]",
                      l.tag === "threat" ? "text-red-400" : l.tag === "benign" ? "text-green-400/70" : "text-[var(--text-tertiary)]")}>
                      <span className="text-[var(--text-tertiary)] opacity-50">{l.ts}</span> {l.text}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>

      {/* FAB */}
      <button
        onClick={() => setOpen(!open)}
        className="w-12 h-12 rounded-full flex items-center justify-center text-white select-none"
        style={{
          background: open ? "#ea580c" : "#c2410c",
          boxShadow: "0 0 24px rgba(249,115,22,0.4)",
          transition: "background-color 150ms, transform 100ms, box-shadow 150ms",
        }}
        onMouseEnter={(e) => e.currentTarget.style.background = "#ea580c"}
        onMouseLeave={(e) => e.currentTarget.style.background = open ? "#ea580c" : "#c2410c"}
        onMouseDown={(e) => e.currentTarget.style.transform = "scale(0.95)"}
        onMouseUp={(e) => e.currentTarget.style.transform = "scale(1)"}
      >
        <Zap className="w-5 h-5" />
      </button>
    </div>
  );
}
