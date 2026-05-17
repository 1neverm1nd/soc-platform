import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardHeader, CardTitle } from "@/components/ui/Card";
import { ATTACK_COLORS } from "@/lib/utils";
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
} from "recharts";
import { Brain, Target } from "lucide-react";

const MITRE_MAP: Record<string, { id: string; technique: string; tactic: string }> = {
  "brute-force":           { id: "T1110", technique: "Brute Force",            tactic: "Credential Access" },
  "sql-injection":         { id: "T1190", technique: "Exploit Public-Facing",  tactic: "Initial Access" },
  "phishing":              { id: "T1566", technique: "Phishing",               tactic: "Initial Access" },
  "malware":               { id: "T1204", technique: "User Execution",         tactic: "Execution" },
  "ransomware":            { id: "T1486", technique: "Data Encrypted",         tactic: "Impact" },
  "ddos":                  { id: "T1498", technique: "Network DoS",            tactic: "Impact" },
  "data-exfiltration":     { id: "T1041", technique: "Exfil Over C2",         tactic: "Exfiltration" },
  "privilege-escalation":  { id: "T1068", technique: "Exploit for PE",         tactic: "Privilege Escalation" },
  "unauthorized-access":   { id: "T1078", technique: "Valid Accounts",         tactic: "Defense Evasion" },
  "port-scanning":         { id: "T1046", technique: "Network Service Scan",   tactic: "Discovery" },
  "network-analysis":      { id: "T1040", technique: "Network Sniffing",       tactic: "Discovery" },
  "vulnerability-exploit": { id: "T1203", technique: "Exploit for Execution",  tactic: "Execution" },
  "lateral-movement":      { id: "T1021", technique: "Remote Services",        tactic: "Lateral Movement" },
  "command-and-control":   { id: "T1071", technique: "App Layer Protocol",     tactic: "Command & Control" },
  "cryptomining":          { id: "T1496", technique: "Resource Hijacking",     tactic: "Impact" },
  "backdoor":              { id: "T1543", technique: "Create/Modify Svc",      tactic: "Persistence" },
  "shellcode":             { id: "T1055", technique: "Process Injection",       tactic: "Defense Evasion" },
  "worm":                  { id: "T1080", technique: "Taint Shared Content",   tactic: "Lateral Movement" },
  "fuzzing":               { id: "T1110", technique: "Brute Force / Fuzzing",  tactic: "Credential Access" },
};

const TT = {
  background: "rgba(6,9,18,0.98)",
  border: "1px solid rgba(255,255,255,0.08)",
  borderRadius: "8px",
  color: "var(--text-primary)",
  fontSize: "12px",
  boxShadow: "0 8px 32px rgba(0,0,0,0.4)",
};

export function AnalyticsPage() {
  const [days, setDays] = useState(30);

  const timeSeries = trpc.incident.timeSeries.useQuery({ days });
  const stats      = trpc.incident.stats.useQuery();
  const heatmap    = trpc.incident.heatmap.useQuery();

  const areaData = (timeSeries.data ?? []).map((r) => ({
    date: r.date?.slice(5),
    incidents: Number(r.count),
  }));

  const typeData = (stats.data?.byType ?? []).map((r) => ({
    name: r.mlType ?? "unknown",
    value: Number(r.count),
    color: ATTACK_COLORS[r.mlType ?? ""] ?? "#475569",
  }));

  const heatmapData = Array.from({ length: 24 }, (_, h) => {
    const found = heatmap.data?.find((r) => Number(r.hour) === h);
    return { hour: h, label: `${String(h).padStart(2, "0")}:00`, count: found ? Number(found.count) : 0 };
  });
  const maxHeat = Math.max(...heatmapData.map((d) => d.count), 1);

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-[var(--text-primary)]">Analytics</h1>
          <p className="text-[var(--text-tertiary)] text-xs mt-0.5">Patterns and trends</p>
        </div>
        <div className="flex gap-1">
          {[7, 14, 30, 90].map((d) => (
            <button
              key={d}
              onClick={() => setDays(d)}
              className="px-3 py-1.5 rounded-md text-xs font-medium select-none"
              style={{
                background: days === d ? "#2563eb" : "rgba(255,255,255,0.04)",
                color: days === d ? "#fff" : "var(--text-tertiary)",
                border: days === d ? "1px solid rgba(59,130,246,0.3)" : "1px solid var(--border)",
                transition: "background-color 120ms, color 120ms, border-color 120ms",
              }}
              onMouseDown={(e) => { e.currentTarget.style.transform = "scale(0.96)"; }}
              onMouseUp={(e) => { e.currentTarget.style.transform = "scale(1)"; }}
              onMouseLeave={(e) => { e.currentTarget.style.transform = "scale(1)"; }}
            >
              {d}d
            </button>
          ))}
        </div>
      </div>

      {/* Timeline */}
      <Card>
        <CardHeader><CardTitle>Incident Volume — {days} days</CardTitle></CardHeader>
        <ResponsiveContainer width="100%" height={210}>
          <AreaChart data={areaData} margin={{ top: 4, right: 0, left: -20, bottom: 0 }}>
            <defs>
              <linearGradient id="aG" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#2563eb" stopOpacity={0.2} />
                <stop offset="100%" stopColor="#2563eb" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false} />
            <XAxis dataKey="date" tick={{ fill: "var(--text-tertiary)", fontSize: 10 }} tickLine={false} axisLine={false} interval="preserveStartEnd" />
            <YAxis tick={{ fill: "var(--text-tertiary)", fontSize: 10 }} tickLine={false} axisLine={false} />
            <Tooltip contentStyle={TT} cursor={{ stroke: "rgba(255,255,255,0.06)" }} />
            <Area type="monotone" dataKey="incidents" stroke="#2563eb" strokeWidth={1.5} fill="url(#aG)" dot={false} />
          </AreaChart>
        </ResponsiveContainer>
      </Card>

      <div className="grid grid-cols-2 gap-4">
        {/* Attack types */}
        <Card>
          <CardHeader><CardTitle>Attack Distribution</CardTitle></CardHeader>
          <div className="flex gap-3">
            <ResponsiveContainer width="45%" height={190}>
              <PieChart>
                <Pie data={typeData} cx="50%" cy="50%" outerRadius={72} innerRadius={28} dataKey="value" paddingAngle={2} strokeWidth={0}>
                  {typeData.map((e, i) => <Cell key={i} fill={e.color} />)}
                </Pie>
                <Tooltip contentStyle={TT} />
              </PieChart>
            </ResponsiveContainer>
            <div className="flex-1 space-y-1.5 py-1 overflow-y-auto">
              {typeData.map((d) => (
                <div key={d.name} className="flex items-center gap-2">
                  <div className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: d.color }} />
                  <span className="text-[var(--text-secondary)] text-[11px] flex-1 truncate">{d.name}</span>
                  <span className="text-[var(--text-primary)] text-[11px] font-mono tabular">{d.value}</span>
                </div>
              ))}
            </div>
          </div>
        </Card>

        {/* Heatmap */}
        <Card>
          <CardHeader><CardTitle>Activity by Hour</CardTitle></CardHeader>
          <div className="grid grid-cols-12 gap-1 mt-1">
            {heatmapData.map((d) => {
              const intensity = d.count / maxHeat;
              return (
                <div
                  key={d.hour}
                  title={`${d.label}: ${d.count}`}
                  className="h-7 rounded cursor-default"
                  style={{
                    background: `rgba(37,99,235,${0.04 + intensity * 0.85})`,
                    border: "1px solid rgba(37,99,235,0.1)",
                  }}
                />
              );
            })}
          </div>
          <div className="flex justify-between mt-1.5 text-[10px] text-[var(--text-tertiary)]">
            <span>00:00</span><span>06:00</span><span>12:00</span><span>18:00</span><span>23:00</span>
          </div>
          <div className="flex items-center gap-2 mt-2">
            <span className="text-[10px] text-[var(--text-tertiary)]">Low</span>
            <div className="flex gap-0.5">
              {[0.08, 0.25, 0.45, 0.65, 0.9].map((v) => (
                <div key={v} className="w-5 h-2.5 rounded-sm" style={{ background: `rgba(37,99,235,${v})` }} />
              ))}
            </div>
            <span className="text-[10px] text-[var(--text-tertiary)]">High</span>
          </div>
        </Card>
      </div>

      {/* MITRE coverage */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-1.5">
            <Target className="w-3.5 h-3.5" /> MITRE ATT&CK Coverage
          </CardTitle>
        </CardHeader>
        <div className="grid grid-cols-5 gap-2">
          {(stats.data?.byType ?? []).map((r) => {
            const mitre = MITRE_MAP[r.mlType ?? ""];
            if (!mitre) return null;
            return (
              <a
                key={r.mlType}
                href={`https://attack.mitre.org/techniques/${mitre.id}`}
                target="_blank"
                rel="noopener noreferrer"
                className="p-3 rounded-lg block"
                style={{
                  background: "rgba(255,255,255,0.02)",
                  border: "1px solid var(--border)",
                  transition: "border-color 120ms, background-color 120ms",
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.borderColor = "rgba(37,99,235,0.3)";
                  e.currentTarget.style.background = "rgba(37,99,235,0.04)";
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.borderColor = "var(--border)";
                  e.currentTarget.style.background = "rgba(255,255,255,0.02)";
                }}
              >
                <div className="text-blue-400 font-mono text-xs mb-1">{mitre.id}</div>
                <div className="text-[var(--text-primary)] text-xs font-medium truncate">{mitre.technique}</div>
                <div className="text-[var(--text-tertiary)] text-[10px] mt-0.5">{mitre.tactic}</div>
                <div className="mt-2 text-orange-400 font-bold text-sm tabular">{r.count}×</div>
              </a>
            );
          })}
        </div>
      </Card>

      {/* ML Model Card */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-1.5">
            <Brain className="w-3.5 h-3.5" /> ML Model
          </CardTitle>
        </CardHeader>
        <div className="grid grid-cols-3 gap-3">
          {[
            { label: "Architecture", main: "XGB + RF + ExtraTrees", sub: "Soft-voting ensemble (x2+x3+x1)" },
            { label: "Accuracy", main: "75.8%", sub: "UNSW-NB15 test set, 10 classes", green: true },
            { label: "Features", main: "46", sub: "network flow + 4 engineered" },
          ].map(({ label, main, sub, green }) => (
            <div key={label} className="p-3 rounded-lg" style={{ background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)" }}>
              <div className="text-[10px] text-[var(--text-tertiary)] uppercase tracking-wider mb-1">{label}</div>
              <div className={`text-sm font-semibold ${green ? "text-green-400" : "text-[var(--text-primary)]"}`}>{main}</div>
              <div className="text-[var(--text-tertiary)] text-[11px] mt-0.5">{sub}</div>
            </div>
          ))}
        </div>
        <div className="mt-3 flex flex-wrap gap-1">
          {Object.keys(MITRE_MAP).map((cls) => (
            <span
              key={cls}
              className="px-2 py-0.5 rounded text-[11px]"
              style={{ background: "rgba(37,99,235,0.08)", border: "1px solid rgba(37,99,235,0.15)", color: "rgba(96,165,250,0.8)" }}
            >
              {cls}
            </span>
          ))}
        </div>
      </Card>
    </div>
  );
}
