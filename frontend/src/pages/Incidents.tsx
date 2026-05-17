import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { useQueryClient } from "@tanstack/react-query";
import { Card } from "@/components/ui/Card";
import { SeverityBadge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Spinner } from "@/components/ui/Spinner";
import { fmtDate, confidenceColor, typeIcon } from "@/lib/utils";
import { IncidentDrawer } from "@/components/IncidentDrawer";
import {
  Search, CheckSquare, Square,
  ExternalLink, Download, FileText, Check, PanelRight
} from "lucide-react";
import { toast } from "sonner";

const STATUSES = ["", "open", "investigating", "resolved", "false_positive"] as const;
const SEVERITIES = ["", "critical", "high", "medium", "low"] as const;
const TYPES = [
  "", "normal",
  "brute-force", "sql-injection", "phishing", "malware", "ransomware",
  "ddos", "data-exfiltration", "privilege-escalation", "unauthorized-access",
  "port-scanning", "vulnerability-exploit", "lateral-movement",
  "command-and-control", "cryptomining", "backdoor", "shellcode",
  "worm", "fuzzing", "network-analysis",
];

interface Incident {
  id: number;
  rawLog: string;
  sourceIp: string | null;
  destinationIp: string | null;
  mlType: string | null;
  mlConfidence: number | null;
  severity: string;
  status: string;
  threatCountry: string | null;
  abuseScore: number | null;
  mitreId: string | null;
  mitreTechnique: string | null;
  mitreTactic: string | null;
  aiAnalysis: unknown;
  analystNotes: string | null;
  analystLabel: string | null;
  createdAt: Date;
}

function exportPdf(incident: Incident) {
  const html = `<!DOCTYPE html><html><head><title>Incident #${incident.id}</title><style>
    body{font-family:sans-serif;max-width:800px;margin:auto;padding:20px;color:#1a1a1a}
    h1{color:#1e40af;border-bottom:2px solid #1e40af;padding-bottom:10px}
    .badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:bold}
    .critical{background:#fee2e2;color:#dc2626}.high{background:#ffedd5;color:#ea580c}
    .medium{background:#fef9c3;color:#ca8a04}.low{background:#dcfce7;color:#16a34a}
    .grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:15px 0}
    .box{background:#f8fafc;padding:10px;border-radius:6px;border:1px solid #e2e8f0}
    pre{background:#1e293b;color:#e2e8f0;padding:12px;border-radius:6px;white-space:pre-wrap;font-size:12px}
    .mitre{background:#eff6ff;border:1px solid #bfdbfe;padding:8px 12px;border-radius:6px;color:#1e40af}
  </style></head><body>
  <h1>Incident Report #${incident.id}</h1>
  <span class="badge ${incident.severity}">${incident.severity.toUpperCase()}</span>
  <span style="margin-left:8px;color:#6b7280;font-size:14px">${fmtDate(incident.createdAt)}</span>
  <div class="grid">
    <div class="box"><strong>Type</strong><br>${incident.mlType ?? "unknown"}</div>
    <div class="box"><strong>Confidence</strong><br>${incident.mlConfidence ? Math.round(incident.mlConfidence * 100) + "%" : "N/A"}</div>
    <div class="box"><strong>Source IP</strong><br>${incident.sourceIp ?? "N/A"}</div>
    <div class="box"><strong>Country</strong><br>${incident.threatCountry ?? "N/A"}</div>
    <div class="box"><strong>Status</strong><br>${incident.status}</div>
    <div class="box"><strong>Analyst Label</strong><br>${incident.analystLabel ?? "Not set"}</div>
  </div>
  ${incident.mitreId ? `<div class="mitre"><strong>MITRE ATT&CK</strong>: ${incident.mitreId} — ${incident.mitreTechnique}</div>` : ""}
  <h3>Raw Log</h3><pre>${incident.rawLog}</pre>
  ${incident.aiAnalysis ? `<h3>AI Analysis</h3><pre>${JSON.stringify(incident.aiAnalysis, null, 2)}</pre>` : ""}
  ${incident.analystNotes ? `<h3>Analyst Notes</h3><p>${incident.analystNotes}</p>` : ""}
  </body></html>`;
  const w = window.open("", "_blank");
  if (w) { w.document.write(html); w.document.close(); w.print(); }
}

export function IncidentsPage() {
  const qc = useQueryClient();
  const [page, setPage] = useState(1);
  const [status, setStatus] = useState<string>("");
  const [severity, setSeverity] = useState<string>("");
  const [mlType, setMlType] = useState<string>("");
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [drawerIncident, setDrawerIncident] = useState<Incident | null>(null);

  const query = trpc.incident.list.useQuery({
    page, limit: 20,
    status: status as "open" | "investigating" | "resolved" | "false_positive" | undefined || undefined,
    severity: severity as "low" | "medium" | "high" | "critical" | undefined || undefined,
    mlType: mlType || undefined,
    search: search || undefined,
  });

  const updateStatus = trpc.incident.updateStatus.useMutation({ onSuccess: () => qc.invalidateQueries() });
  const bulkResolve = trpc.incident.bulkResolve.useMutation({ onSuccess: () => { qc.invalidateQueries(); setSelected(new Set()); toast.success("Incidents resolved"); } });
  const exportData = trpc.incident.exportTrainingData.useQuery(undefined, { enabled: false });

  const incidents = query.data?.incidents ?? [];
  const total = query.data?.total ?? 0;
  const totalPages = Math.ceil(total / 20);

  function toggleSelect(id: number) {
    setSelected((prev) => { const s = new Set(prev); s.has(id) ? s.delete(id) : s.add(id); return s; });
  }

  async function handleExportCsv() {
    const data = await exportData.refetch();
    if (!data.data) return;
    const csv = ["text,label", ...data.data.map((r) => `"${r.rawLog?.replace(/"/g, '""')}","${r.analystLabel ?? r.mlType}"`)].join("\n");
    const a = document.createElement("a");
    a.href = "data:text/csv;charset=utf-8," + encodeURIComponent(csv);
    a.download = "training_data.csv";
    a.click();
    toast.success(`Exported ${data.data.length} labeled samples`);
  }

  return (
    <div className="p-6 space-y-4">
      <IncidentDrawer incident={drawerIncident} onClose={() => setDrawerIncident(null)} />
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-[var(--text-primary)]">Incidents</h1>
          <p className="text-[var(--text-tertiary)] text-xs mt-0.5">{total} total incidents</p>
        </div>
        <div className="flex gap-2">
          {selected.size > 0 && (
            <Button variant="danger" size="sm" onClick={() => bulkResolve.mutate({ ids: [...selected] })}>
              <Check className="w-3.5 h-3.5" /> Resolve {selected.size}
            </Button>
          )}
          <Button variant="outline" size="sm" onClick={handleExportCsv}>
            <Download className="w-3.5 h-3.5" /> Export CSV
          </Button>
        </div>
      </div>

      {/* Filters */}
      <Card className="p-3">
        <div className="flex gap-3 flex-wrap">
          <div className="relative flex-1 min-w-48">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[var(--text-tertiary)]" />
            <input
              value={search} onChange={(e) => { setSearch(e.target.value); setPage(1); }}
              placeholder="Search logs..."
              style={{
                background: "rgba(255,255,255,0.04)", border: "1px solid var(--border)",
                borderRadius: "6px", paddingLeft: "32px", paddingRight: "12px", paddingTop: "7px", paddingBottom: "7px",
                color: "var(--text-primary)", fontSize: "12px", outline: "none", width: "100%",
              }}
              onFocus={(e) => { e.currentTarget.style.borderColor = "rgba(37,99,235,0.5)"; }}
              onBlur={(e) => { e.currentTarget.style.borderColor = "var(--border)"; }}
            />
          </div>
          {[
            { label: "Status", value: status, setter: setStatus, options: STATUSES },
            { label: "Severity", value: severity, setter: setSeverity, options: SEVERITIES },
            { label: "Type", value: mlType, setter: setMlType, options: TYPES },
          ].map(({ label, value, setter, options }) => (
            <select key={label} value={value} onChange={(e) => { setter(e.target.value); setPage(1); }}
              style={{
                background: "rgba(255,255,255,0.04)", border: "1px solid var(--border)",
                borderRadius: "6px", padding: "7px 10px", color: "var(--text-primary)", fontSize: "12px", outline: "none",
              }}>
              <option value="" style={{ background: "#0d1117" }}>{label}</option>
              {options.filter(Boolean).map((o) => <option key={o} value={o} style={{ background: "#0d1117" }}>{o}</option>)}
            </select>
          ))}
        </div>
      </Card>

      {/* Table */}
      <div className="overflow-hidden rounded-lg" style={{ background: "var(--bg-card)", border: "1px solid var(--border)" }}>
        <table className="w-full text-sm">
          <thead>
            <tr style={{ borderBottom: "1px solid var(--border)" }}>
              <th className="w-10 p-3"><input type="checkbox" className="accent-blue-500" onChange={(e) => setSelected(e.target.checked ? new Set(incidents.map((i) => i.id)) : new Set())} /></th>
              {["ID", "Type", "Severity", "Source IP", "Country", "Confidence", "MITRE", "Status", "Time", "Actions"].map((h) => (
                <th key={h} className="p-3 text-left text-[var(--text-tertiary)] text-xs font-medium">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {query.isLoading && (
              <tr><td colSpan={11} className="p-8 text-center"><Spinner className="mx-auto" /></td></tr>
            )}
            {incidents.map((inc) => (
                <tr
                  key={inc.id}
                  style={{ borderBottom: "1px solid rgba(255,255,255,0.03)", transition: "background-color 100ms" }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(255,255,255,0.015)"; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                >
                  <td className="p-3">
                    <button onClick={() => toggleSelect(inc.id)}>
                      {selected.has(inc.id)
                        ? <CheckSquare className="w-4 h-4 text-blue-400" />
                        : <Square className="w-4 h-4 text-[var(--text-tertiary)]" />}
                    </button>
                  </td>
                  <td className="p-3 text-[var(--text-tertiary)] font-mono text-xs">#{inc.id}</td>
                  <td className="p-3">
                    <div className="flex items-center gap-2">
                      <span className="text-sm">{typeIcon(inc.mlType ?? "")}</span>
                      <span className="text-[var(--text-secondary)] text-xs">{inc.mlType ?? "unknown"}</span>
                    </div>
                  </td>
                  <td className="p-3"><SeverityBadge severity={inc.severity} /></td>
                  <td className="p-3 text-[var(--text-secondary)] font-mono text-xs">{inc.sourceIp ?? "—"}</td>
                  <td className="p-3 text-[var(--text-secondary)] text-xs">{inc.threatCountry ?? "—"}</td>
                  <td className="p-3">
                    <span className={`text-xs font-mono ${confidenceColor(inc.mlConfidence ?? 0)}`}>
                      {inc.mlConfidence ? Math.round(inc.mlConfidence * 100) + "%" : "—"}
                    </span>
                  </td>
                  <td className="p-3">
                    {inc.mitreId && (
                      <a href={`https://attack.mitre.org/techniques/${inc.mitreId}`} target="_blank" rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs transition-colors duration-100"
                        style={{ background: "rgba(37,99,235,0.1)", color: "#60a5fa", border: "1px solid rgba(37,99,235,0.2)" }}
                        onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(37,99,235,0.18)"; }}
                        onMouseLeave={(e) => { e.currentTarget.style.background = "rgba(37,99,235,0.1)"; }}
                      >
                        {inc.mitreId} <ExternalLink className="w-2.5 h-2.5" />
                      </a>
                    )}
                  </td>
                  <td className="p-3">
                    <select value={inc.status} onChange={(e) => updateStatus.mutate({ id: inc.id, status: e.target.value as "open" | "investigating" | "resolved" | "false_positive" })}
                      style={{
                        background: "rgba(255,255,255,0.04)", border: "1px solid var(--border)",
                        borderRadius: "4px", padding: "3px 8px", color: "var(--text-primary)", fontSize: "11px", outline: "none",
                      }}>
                      {["open", "investigating", "resolved", "false_positive"].map((s) => <option key={s} value={s} style={{ background: "#0d1117" }}>{s}</option>)}
                    </select>
                  </td>
                  <td className="p-3 text-[var(--text-tertiary)] text-xs">{fmtDate(inc.createdAt)}</td>
                  <td className="p-3">
                    <div className="flex gap-1">
                      <button
                        onClick={() => setDrawerIncident(inc as Incident)}
                        className="p-1.5 rounded text-[var(--text-tertiary)]"
                        style={{ transition: "background-color 100ms, color 100ms" }}
                        onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(255,255,255,0.06)"; e.currentTarget.style.color = "var(--text-primary)"; }}
                        onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; e.currentTarget.style.color = "var(--text-tertiary)"; }}
                        title="Open details"
                      >
                        <PanelRight className="w-3.5 h-3.5" />
                      </button>
                      <button onClick={() => exportPdf(inc as Incident)}
                        className="p-1.5 rounded text-[var(--text-tertiary)]"
                        style={{ transition: "background-color 100ms, color 100ms" }}
                        onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(255,255,255,0.06)"; e.currentTarget.style.color = "var(--text-primary)"; }}
                        onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; e.currentTarget.style.color = "var(--text-tertiary)"; }}
                        title="Export PDF"
                      >
                        <FileText className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-2">
          <Button size="sm" variant="ghost" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>← Prev</Button>
          <span className="text-[var(--text-tertiary)] text-sm">{page} / {totalPages}</span>
          <Button size="sm" variant="ghost" disabled={page >= totalPages} onClick={() => setPage(p => p + 1)}>Next →</Button>
        </div>
      )}
    </div>
  );
}
