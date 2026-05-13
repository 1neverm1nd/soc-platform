import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { useQueryClient } from "@tanstack/react-query";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Spinner } from "@/components/ui/Spinner";
import { Zap, Plus, Pencil, Trash2, ToggleLeft, ToggleRight, ChevronDown, ChevronRight } from "lucide-react";
import { toast } from "sonner";

const ATTACK_TYPES = ["brute-force", "sql-injection", "phishing", "malware", "ddos", "privilege-escalation", "data-exfiltration", "unauthorized-access", "port-scanning", "vulnerability-exploit"];
const SEVERITIES   = ["low", "medium", "high", "critical"];
const ACTION_TYPES = ["block_ip", "notify", "escalate", "update_status", "create_ticket"];

interface Rule {
  id: number; name: string; description: string | null; isEnabled: boolean; priority: number;
  conditionType: string | null; conditionMinSeverity: string | null; conditionMinConfidence: number | null;
  conditionIpPattern: string | null; actions: unknown; triggerCount: number;
}

const INPUT_CLS = "w-full rounded-lg px-3 py-2 text-[var(--text-primary)] text-xs focus:outline-none";
const INPUT_STYLE = { background: "rgba(255,255,255,0.04)", border: "1px solid var(--border)", transition: "border-color 150ms" };

function focusBlue(e: React.FocusEvent<HTMLInputElement | HTMLSelectElement>) {
  e.currentTarget.style.borderColor = "rgba(37,99,235,0.4)";
}
function blurBorder(e: React.FocusEvent<HTMLInputElement | HTMLSelectElement>) {
  e.currentTarget.style.borderColor = "var(--border)";
}

function RuleForm({ initial, onSave, onCancel }: {
  initial?: Partial<Rule>;
  onSave: (data: Record<string, unknown>) => void;
  onCancel: () => void;
}) {
  const [name,     setName]     = useState(initial?.name ?? "");
  const [desc,     setDesc]     = useState(initial?.description ?? "");
  const [priority, setPriority] = useState(initial?.priority ?? 50);
  const [condType, setCondType] = useState(initial?.conditionType ?? "");
  const [condSev,  setCondSev]  = useState(initial?.conditionMinSeverity ?? "");
  const [condConf, setCondConf] = useState(initial?.conditionMinConfidence ? String(Math.round(initial.conditionMinConfidence * 100)) : "");
  const [condIp,   setCondIp]   = useState(initial?.conditionIpPattern ?? "");
  const [actions,  setActions]  = useState<string[]>(
    Array.isArray(initial?.actions)
      ? (initial.actions as Array<{ type: string }>).map((a) => a.type)
      : ["notify"]
  );

  return (
    <div className="space-y-3 p-4 rounded-lg" style={{ background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)" }}>
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="text-[var(--text-tertiary)] text-[10px] uppercase tracking-wider mb-1 block">Rule Name *</label>
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Block malware IPs" className={INPUT_CLS} style={{ ...INPUT_STYLE }} onFocus={focusBlue} onBlur={blurBorder} />
        </div>
        <div>
          <label className="text-[var(--text-tertiary)] text-[10px] uppercase tracking-wider mb-1 block">Priority (lower = higher)</label>
          <input type="number" value={priority} onChange={(e) => setPriority(Number(e.target.value))} min={1} max={100} className={INPUT_CLS} style={{ ...INPUT_STYLE }} onFocus={focusBlue} onBlur={blurBorder} />
        </div>
      </div>
      <div>
        <label className="text-[var(--text-tertiary)] text-[10px] uppercase tracking-wider mb-1 block">Description</label>
        <input value={desc} onChange={(e) => setDesc(e.target.value)} placeholder="Optional description" className={INPUT_CLS} style={{ ...INPUT_STYLE }} onFocus={focusBlue} onBlur={blurBorder} />
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="text-[var(--text-tertiary)] text-[10px] uppercase tracking-wider mb-1 block">Attack Type</label>
          <select value={condType} onChange={(e) => setCondType(e.target.value)} className={INPUT_CLS} style={{ ...INPUT_STYLE }} onFocus={focusBlue} onBlur={blurBorder}>
            <option value="" style={{ background: "#0d1526" }}>Any type</option>
            {ATTACK_TYPES.map((t) => <option key={t} value={t} style={{ background: "#0d1526" }}>{t}</option>)}
          </select>
        </div>
        <div>
          <label className="text-[var(--text-tertiary)] text-[10px] uppercase tracking-wider mb-1 block">Min Severity</label>
          <select value={condSev} onChange={(e) => setCondSev(e.target.value)} className={INPUT_CLS} style={{ ...INPUT_STYLE }} onFocus={focusBlue} onBlur={blurBorder}>
            <option value="" style={{ background: "#0d1526" }}>Any severity</option>
            {SEVERITIES.map((s) => <option key={s} value={s} style={{ background: "#0d1526" }}>{s}</option>)}
          </select>
        </div>
        <div>
          <label className="text-[var(--text-tertiary)] text-[10px] uppercase tracking-wider mb-1 block">Min Confidence (%)</label>
          <input type="number" value={condConf} onChange={(e) => setCondConf(e.target.value)} placeholder="e.g. 80" min={0} max={100} className={INPUT_CLS} style={{ ...INPUT_STYLE }} onFocus={focusBlue} onBlur={blurBorder} />
        </div>
        <div>
          <label className="text-[var(--text-tertiary)] text-[10px] uppercase tracking-wider mb-1 block">IP Pattern (regex)</label>
          <input value={condIp} onChange={(e) => setCondIp(e.target.value)} placeholder="e.g. ^192\.168\." className={INPUT_CLS} style={{ ...INPUT_STYLE }} onFocus={focusBlue} onBlur={blurBorder} />
        </div>
      </div>
      <div>
        <label className="text-[var(--text-tertiary)] text-[10px] uppercase tracking-wider mb-2 block">Actions</label>
        <div className="flex flex-wrap gap-2">
          {ACTION_TYPES.map((a) => (
            <button key={a} type="button"
              onClick={() => setActions((prev) => prev.includes(a) ? prev.filter((x) => x !== a) : [...prev, a])}
              className="px-3 py-1 rounded text-[11px] select-none"
              style={{
                background: actions.includes(a) ? "rgba(37,99,235,0.2)" : "rgba(255,255,255,0.04)",
                color: actions.includes(a) ? "#93c5fd" : "var(--text-tertiary)",
                border: actions.includes(a) ? "1px solid rgba(59,130,246,0.35)" : "1px solid var(--border)",
                transition: "background-color 120ms, color 120ms, border-color 120ms",
              }}>
              {a}
            </button>
          ))}
        </div>
      </div>
      <div className="flex gap-2 pt-1">
        <Button variant="primary" size="sm"
          onClick={() => onSave({ name, description: desc, priority, conditionType: condType || undefined, conditionMinSeverity: condSev || undefined, conditionMinConfidence: condConf ? Number(condConf) / 100 : undefined, conditionIpPattern: condIp || undefined, actions: actions.map((t) => ({ type: t })) })}
          disabled={!name || !actions.length}>
          Save Rule
        </Button>
        <Button variant="ghost" size="sm" onClick={onCancel}>Cancel</Button>
      </div>
    </div>
  );
}

export function RulesPage() {
  const qc = useQueryClient();
  const [creating,  setCreating]  = useState(false);
  const [editing,   setEditing]   = useState<number | null>(null);
  const [expanded,  setExpanded]  = useState<number | null>(null);

  const rules  = trpc.rules.list.useQuery();
  const create = trpc.rules.create.useMutation({ onSuccess: () => { qc.invalidateQueries(); setCreating(false); toast.success("Rule created"); } });
  const update = trpc.rules.update.useMutation({ onSuccess: () => { qc.invalidateQueries(); setEditing(null); toast.success("Updated"); } });
  const toggle = trpc.rules.toggle.useMutation({ onSuccess: () => qc.invalidateQueries() });
  const del    = trpc.rules.delete.useMutation({ onSuccess: () => { qc.invalidateQueries(); toast.success("Deleted"); } });

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-[var(--text-primary)]">Response Rules</h1>
          <p className="text-[var(--text-tertiary)] text-xs mt-0.5">Automated incident response</p>
        </div>
        <Button variant="primary" size="sm" onClick={() => setCreating(true)}>
          <Plus className="w-3.5 h-3.5" /> New Rule
        </Button>
      </div>

      {creating && (
        <Card>
          <div className="text-[var(--text-primary)] text-xs font-semibold uppercase tracking-wider mb-3">Create New Rule</div>
          <RuleForm onSave={(data) => create.mutate(data as Parameters<typeof create.mutate>[0])} onCancel={() => setCreating(false)} />
        </Card>
      )}

      <div className="space-y-2">
        {rules.isLoading && <div className="flex justify-center py-8"><Spinner /></div>}
        {(rules.data ?? []).map((rule) => (
          <div key={rule.id} className="rounded-lg overflow-hidden" style={{ background: "var(--bg-card)", border: "1px solid var(--border)" }}>
            <div className="flex items-center gap-3 px-4 py-3">
              <div className="w-7 h-7 rounded-md flex items-center justify-center text-[var(--text-tertiary)] text-[10px] font-mono flex-shrink-0"
                style={{ background: "rgba(255,255,255,0.04)", border: "1px solid var(--border)" }}>
                {rule.priority}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-[var(--text-primary)] text-sm font-medium">{rule.name}</span>
                  {!rule.isEnabled && <span className="text-[var(--text-tertiary)] text-[10px]">(disabled)</span>}
                </div>
                <div className="flex gap-3 mt-0.5 flex-wrap">
                  {rule.conditionType && <span className="text-orange-400/70 text-[11px]">{rule.conditionType}</span>}
                  {rule.conditionMinSeverity && <span className="text-yellow-400/70 text-[11px]">≥{rule.conditionMinSeverity}</span>}
                  {rule.conditionMinConfidence && <span className="text-blue-400/70 text-[11px]">≥{Math.round(rule.conditionMinConfidence * 100)}% conf</span>}
                  <span className="text-[var(--text-tertiary)] text-[11px]">{rule.triggerCount} triggers</span>
                </div>
              </div>
              <div className="flex items-center gap-1.5">
                <div className="flex gap-1 flex-wrap">
                  {(Array.isArray(rule.actions) ? rule.actions as Array<{ type: string }> : []).map((a) => (
                    <span key={a.type} className="px-1.5 py-0.5 rounded text-[10px]"
                      style={{ background: "rgba(59,130,246,0.1)", color: "#93c5fd", border: "1px solid rgba(59,130,246,0.2)" }}>
                      {a.type}
                    </span>
                  ))}
                </div>
                <button onClick={() => toggle.mutate({ id: rule.id, enabled: !rule.isEnabled })} className="p-1.5 rounded"
                  style={{ transition: "background-color 120ms" }}
                  onMouseEnter={(e) => e.currentTarget.style.background = "rgba(255,255,255,0.06)"}
                  onMouseLeave={(e) => e.currentTarget.style.background = "transparent"}>
                  {rule.isEnabled
                    ? <ToggleRight className="w-5 h-5 text-green-400" />
                    : <ToggleLeft  className="w-5 h-5 text-[var(--text-tertiary)]" />}
                </button>
                <button onClick={() => setExpanded(expanded === rule.id ? null : rule.id)} className="p-1.5 rounded"
                  style={{ color: "var(--text-tertiary)", transition: "background-color 120ms" }}
                  onMouseEnter={(e) => e.currentTarget.style.background = "rgba(255,255,255,0.06)"}
                  onMouseLeave={(e) => e.currentTarget.style.background = "transparent"}>
                  {expanded === rule.id ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                </button>
                <button onClick={() => setEditing(rule.id)} className="p-1.5 rounded"
                  style={{ color: "var(--text-tertiary)", transition: "background-color 120ms, color 120ms" }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(255,255,255,0.06)"; e.currentTarget.style.color = "#93c5fd"; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; e.currentTarget.style.color = "var(--text-tertiary)"; }}>
                  <Pencil className="w-3.5 h-3.5" />
                </button>
                <button onClick={() => del.mutate({ id: rule.id })} className="p-1.5 rounded"
                  style={{ color: "var(--text-tertiary)", transition: "background-color 120ms, color 120ms" }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(239,68,68,0.08)"; e.currentTarget.style.color = "#ef4444"; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; e.currentTarget.style.color = "var(--text-tertiary)"; }}>
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>

            {editing === rule.id && (
              <div className="px-4 pb-4" style={{ borderTop: "1px solid var(--border)" }}>
                <div className="mt-3">
                  <RuleForm initial={rule}
                    onSave={(data) => { const { id: _id, ...rest } = data as Parameters<typeof update.mutate>[0]; update.mutate({ id: rule.id, ...rest }); }}
                    onCancel={() => setEditing(null)} />
                </div>
              </div>
            )}

            {expanded === rule.id && rule.description && (
              <div className="px-4 py-3" style={{ borderTop: "1px solid var(--border)" }}>
                <p className="text-[var(--text-secondary)] text-xs">{rule.description}</p>
              </div>
            )}
          </div>
        ))}
      </div>

      {!rules.isLoading && (rules.data ?? []).length === 0 && (
        <div className="text-center py-12" style={{ border: "1px dashed rgba(255,255,255,0.08)", borderRadius: 8 }}>
          <Zap className="w-6 h-6 mx-auto mb-2 text-[var(--text-tertiary)]" />
          <p className="text-[var(--text-tertiary)] text-xs">No rules yet — create one to automate responses</p>
        </div>
      )}
    </div>
  );
}
