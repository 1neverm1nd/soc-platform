import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { useQueryClient } from "@tanstack/react-query";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Spinner } from "@/components/ui/Spinner";
import { BookOpen, Plus, Play, Trash2, ChevronDown, ChevronRight, CheckCircle, Clock } from "lucide-react";
import { toast } from "sonner";

const ACTION_TYPES = ["isolate_host", "collect_forensics", "notify_team", "block_ip", "reset_credentials", "scan_network", "patch_vulnerability", "quarantine_file"];
const ATTACK_TYPES = ["brute-force", "sql-injection", "phishing", "malware", "ddos", "privilege-escalation", "data-exfiltration", "unauthorized-access", "port-scanning", "vulnerability-exploit"];

const INPUT = "w-full rounded-lg px-3 py-2 text-[var(--text-primary)] text-xs focus:outline-none";
const INPUT_STYLE = { background: "rgba(255,255,255,0.04)", border: "1px solid var(--border)", transition: "border-color 150ms" };

export function PlaybooksPage() {
  const qc = useQueryClient();
  const [creating, setCreating] = useState(false);
  const [expanded, setExpanded] = useState<number | null>(null);
  const [executing, setExecuting] = useState<number | null>(null);
  const [newName, setNewName] = useState("");
  const [newDesc, setNewDesc] = useState("");
  const [newType, setNewType] = useState("");
  const [newSteps, setNewSteps] = useState<Array<{ actionType: string; description: string }>>([
    { actionType: "notify_team", description: "" },
  ]);

  const playbooks = trpc.playbooks.list.useQuery();
  const stats     = trpc.playbooks.stats.useQuery();
  const create    = trpc.playbooks.create.useMutation({
    onSuccess: () => {
      qc.invalidateQueries(); setCreating(false);
      setNewName(""); setNewDesc(""); setNewType("");
      setNewSteps([{ actionType: "notify_team", description: "" }]);
      toast.success("Playbook created");
    },
  });
  const exec = trpc.playbooks.execute.useMutation({
    onSuccess: (data) => {
      setExecuting(null);
      toast.success(`Executed: ${data.stepsExecuted} steps in ${data.totalTime}ms`);
      qc.invalidateQueries();
    },
    onError: () => setExecuting(null),
  });
  const del = trpc.playbooks.delete.useMutation({
    onSuccess: () => { qc.invalidateQueries(); toast.success("Deleted"); },
  });

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-[var(--text-primary)]">Response Playbooks</h1>
          <p className="text-[var(--text-tertiary)] text-xs mt-0.5">Automated response procedures</p>
        </div>
        <Button variant="primary" size="sm" onClick={() => setCreating(true)}>
          <Plus className="w-3.5 h-3.5" /> New Playbook
        </Button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-3">
        {[
          { label: "Total",    value: stats.data?.total    ?? 0, icon: BookOpen,   color: "#3b82f6" },
          { label: "Active",   value: stats.data?.active   ?? 0, icon: CheckCircle, color: "#22c55e" },
          { label: "Executed", value: stats.data?.executed ?? 0, icon: Clock,       color: "#f97316" },
        ].map(({ label, value, icon: Icon, color }) => (
          <Card key={label}>
            <div className="flex items-center gap-3">
              <div className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0"
                style={{ background: `${color}18`, border: `1px solid ${color}28` }}>
                <Icon className="w-3.5 h-3.5" style={{ color }} />
              </div>
              <div>
                <div className="text-[var(--text-tertiary)] text-[11px] uppercase tracking-wider">{label}</div>
                <div className="text-xl font-semibold tabular" style={{ color }}>{value}</div>
              </div>
            </div>
          </Card>
        ))}
      </div>

      {/* Create form */}
      {creating && (
        <Card>
          <div className="text-[var(--text-primary)] text-xs font-semibold uppercase tracking-wider mb-3">Create Playbook</div>
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-[var(--text-tertiary)] text-[10px] uppercase tracking-wider mb-1 block">Name *</label>
                <input value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="Playbook name" className={INPUT} style={INPUT_STYLE}
                  onFocus={(e) => e.currentTarget.style.borderColor = "rgba(37,99,235,0.4)"}
                  onBlur={(e) => e.currentTarget.style.borderColor = "var(--border)"} />
              </div>
              <div>
                <label className="text-[var(--text-tertiary)] text-[10px] uppercase tracking-wider mb-1 block">Incident Type</label>
                <select value={newType} onChange={(e) => setNewType(e.target.value)} className={INPUT} style={INPUT_STYLE}>
                  <option value="" style={{ background: "#0d1526" }}>Any type</option>
                  {ATTACK_TYPES.map((t) => <option key={t} value={t} style={{ background: "#0d1526" }}>{t}</option>)}
                </select>
              </div>
            </div>
            <div>
              <label className="text-[var(--text-tertiary)] text-[10px] uppercase tracking-wider mb-1 block">Description</label>
              <input value={newDesc} onChange={(e) => setNewDesc(e.target.value)} placeholder="Optional description" className={INPUT} style={INPUT_STYLE}
                onFocus={(e) => e.currentTarget.style.borderColor = "rgba(37,99,235,0.4)"}
                onBlur={(e) => e.currentTarget.style.borderColor = "var(--border)"} />
            </div>
            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="text-[var(--text-tertiary)] text-[10px] uppercase tracking-wider">Steps</label>
                <button
                  onClick={() => setNewSteps([...newSteps, { actionType: "notify_team", description: "" }])}
                  className="text-blue-400 text-xs"
                  style={{ transition: "opacity 120ms" }}
                  onMouseEnter={(e) => e.currentTarget.style.opacity = "0.7"}
                  onMouseLeave={(e) => e.currentTarget.style.opacity = "1"}
                >
                  + Add step
                </button>
              </div>
              {newSteps.map((step, i) => (
                <div key={i} className="flex gap-2 mb-2">
                  <div className="w-5 flex items-center justify-center text-[var(--text-tertiary)] text-[10px] font-mono">{i + 1}</div>
                  <select value={step.actionType}
                    onChange={(e) => setNewSteps(newSteps.map((s, j) => j === i ? { ...s, actionType: e.target.value } : s))}
                    className={`${INPUT} flex-1`} style={INPUT_STYLE}>
                    {ACTION_TYPES.map((a) => <option key={a} value={a} style={{ background: "#0d1526" }}>{a}</option>)}
                  </select>
                  <input value={step.description}
                    onChange={(e) => setNewSteps(newSteps.map((s, j) => j === i ? { ...s, description: e.target.value } : s))}
                    placeholder="Description (optional)" className={`${INPUT} flex-1`} style={INPUT_STYLE}
                    onFocus={(e) => e.currentTarget.style.borderColor = "rgba(37,99,235,0.4)"}
                    onBlur={(e) => e.currentTarget.style.borderColor = "var(--border)"} />
                  {newSteps.length > 1 && (
                    <button onClick={() => setNewSteps(newSteps.filter((_, j) => j !== i))}
                      className="text-[var(--text-tertiary)] px-2 text-sm"
                      style={{ transition: "color 120ms" }}
                      onMouseEnter={(e) => e.currentTarget.style.color = "#ef4444"}
                      onMouseLeave={(e) => e.currentTarget.style.color = "var(--text-tertiary)"}>
                      ×
                    </button>
                  )}
                </div>
              ))}
            </div>
            <div className="flex gap-2">
              <Button variant="primary" size="sm"
                onClick={() => create.mutate({
                  name: newName, description: newDesc || undefined,
                  incidentType: newType || undefined,
                  actions: newSteps.map((s, i) => ({ sequence: i + 1, actionType: s.actionType, description: s.description || undefined })),
                })}
                disabled={!newName || create.isPending}>
                {create.isPending ? <Spinner className="w-3 h-3" /> : null} Create
              </Button>
              <Button variant="ghost" size="sm" onClick={() => setCreating(false)}>Cancel</Button>
            </div>
          </div>
        </Card>
      )}

      {/* Playbook list */}
      <div className="space-y-2">
        {playbooks.isLoading && <div className="flex justify-center py-8"><Spinner /></div>}
        {(playbooks.data ?? []).map((pb) => (
          <div key={pb.id} className="rounded-lg overflow-hidden" style={{ background: "var(--bg-card)", border: "1px solid var(--border)" }}>
            <div className="flex items-center gap-3 px-4 py-3">
              <div className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: pb.isActive ? "#22c55e" : "rgba(255,255,255,0.15)" }} />
              <div className="flex-1 min-w-0">
                <div className="text-[var(--text-primary)] text-sm font-medium">{pb.name}</div>
                <div className="flex gap-3 mt-0.5">
                  {pb.incidentType && <span className="text-orange-400/70 text-[11px]">{pb.incidentType}</span>}
                  <span className="text-[var(--text-tertiary)] text-[11px]">
                    {(pb as typeof pb & { actions?: unknown[] }).actions?.length ?? 0} steps
                  </span>
                  <span className="text-[var(--text-tertiary)] text-[11px]">{pb.executionCount} runs</span>
                  {pb.avgExecutionTime && (
                    <span className="text-[var(--text-tertiary)] text-[11px]">~{Math.round(pb.avgExecutionTime)}ms</span>
                  )}
                </div>
              </div>
              <div className="flex gap-1.5">
                <Button size="sm" variant="outline"
                  onClick={() => { setExecuting(pb.id); exec.mutate({ playbookId: pb.id, incidentId: 1 }); }}
                  disabled={executing === pb.id}>
                  {executing === pb.id ? <Spinner className="w-3 h-3" /> : <Play className="w-3 h-3" />} Run
                </Button>
                <button
                  onClick={() => setExpanded(expanded === pb.id ? null : pb.id)}
                  className="p-1.5 rounded"
                  style={{ color: "var(--text-tertiary)", transition: "background-color 120ms, color 120ms" }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(255,255,255,0.06)"; e.currentTarget.style.color = "var(--text-primary)"; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; e.currentTarget.style.color = "var(--text-tertiary)"; }}
                >
                  {expanded === pb.id ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                </button>
                <button
                  onClick={() => del.mutate({ id: pb.id })}
                  className="p-1.5 rounded"
                  style={{ color: "var(--text-tertiary)", transition: "background-color 120ms, color 120ms" }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(239,68,68,0.08)"; e.currentTarget.style.color = "#ef4444"; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; e.currentTarget.style.color = "var(--text-tertiary)"; }}
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
            {expanded === pb.id && (
              <div className="px-4 pb-4 pt-3" style={{ borderTop: "1px solid var(--border)" }}>
                {pb.description && <p className="text-[var(--text-secondary)] text-xs mb-3">{pb.description}</p>}
                <div className="space-y-1.5">
                  {((pb as typeof pb & { actions?: Array<{ id: number; sequence: number; actionType: string; description?: string }> }).actions ?? []).map((action) => (
                    <div key={action.id} className="flex items-center gap-3">
                      <span className="text-[var(--text-tertiary)] font-mono text-[10px] w-4">{action.sequence}</span>
                      <span className="px-2 py-0.5 rounded text-[11px]" style={{ background: "rgba(59,130,246,0.1)", color: "#93c5fd", border: "1px solid rgba(59,130,246,0.2)" }}>
                        {action.actionType}
                      </span>
                      {action.description && <span className="text-[var(--text-tertiary)] text-[11px]">{action.description}</span>}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
