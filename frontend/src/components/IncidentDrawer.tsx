import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { trpc } from "@/lib/trpc";
import { useQueryClient } from "@tanstack/react-query";
import { SeverityBadge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Spinner } from "@/components/ui/Spinner";
import { fmtDate, confidenceColor, typeIcon, ATTACK_COLORS } from "@/lib/utils";
import {
  X, ExternalLink, Bot, CheckCircle, XCircle, AlertCircle,
  FileText, Network, Activity, ChevronRight, Tag, Zap, Shield,
} from "lucide-react";
import { toast } from "sonner";

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

interface Props {
  incident: Incident | null;
  onClose: () => void;
}

const KILL_CHAIN = [
  "Recon", "Resource Dev", "Initial Access", "Execution",
  "Persistence", "Privilege Esc", "Defense Evasion", "Credential Access",
  "Discovery", "Lateral Movement", "Collection", "C2",
  "Exfiltration", "Impact",
];

const TACTIC_STAGE: Record<string, number> = {
  "reconnaissance": 0, "resource-development": 1, "initial-access": 2,
  "execution": 3, "persistence": 4, "privilege-escalation": 5,
  "defense-evasion": 6, "credential-access": 7, "discovery": 8,
  "lateral-movement": 9, "collection": 10, "command-and-control": 11,
  "exfiltration": 12, "impact": 13,
};

function KillChainViz({ tactic }: { tactic: string | null }) {
  if (!tactic) return null;
  const normalized = tactic.toLowerCase().replace(/\s+/g, "-");
  const active = TACTIC_STAGE[normalized] ?? -1;

  return (
    <div className="space-y-2">
      <div className="text-[11px] font-medium text-[var(--text-tertiary)] uppercase tracking-wider">Kill Chain Position</div>
      <div className="flex flex-wrap gap-1">
        {KILL_CHAIN.map((stage, i) => {
          const isActive = i === active;
          const isPast = i < active;
          return (
            <div key={stage} className="flex items-center">
              <div
                className="px-2 py-0.5 rounded text-[11px] font-medium"
                style={{
                  background: isActive
                    ? "rgba(239,68,68,0.15)"
                    : isPast
                    ? "rgba(249,115,22,0.08)"
                    : "rgba(255,255,255,0.03)",
                  border: isActive
                    ? "1px solid rgba(239,68,68,0.4)"
                    : isPast
                    ? "1px solid rgba(249,115,22,0.15)"
                    : "1px solid rgba(255,255,255,0.05)",
                  color: isActive
                    ? "#fca5a5"
                    : isPast
                    ? "rgba(249,115,22,0.6)"
                    : "var(--text-tertiary)",
                  // Emil: CSS box-shadow animation for the pulse, not JS
                  boxShadow: isActive ? "0 0 8px rgba(239,68,68,0.2)" : "none",
                  transition: "none",
                }}
              >
                {stage}
              </div>
              {i < KILL_CHAIN.length - 1 && (
                <ChevronRight
                  className="w-2 h-2 flex-shrink-0 mx-0.5"
                  style={{ color: isPast || isActive ? "rgba(255,255,255,0.15)" : "rgba(255,255,255,0.06)" }}
                />
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function AiAnalysisView({ analysis }: { analysis: unknown }) {
  if (!analysis || typeof analysis !== "object") return null;
  const a = analysis as Record<string, unknown>;

  return (
    <div className="space-y-3">
      {!!a.summary && (
        <div
          className="p-3 rounded-lg"
          style={{ background: "rgba(37,99,235,0.05)", border: "1px solid rgba(37,99,235,0.12)" }}
        >
          <div className="text-[10px] font-semibold text-blue-400/50 uppercase tracking-wider mb-1.5">Summary</div>
          <p className="text-[var(--text-secondary)] text-xs leading-relaxed">{String(a.summary)}</p>
        </div>
      )}

      {!!a.attackVector && (
        <div className="p-2.5 rounded-lg" style={{ background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)" }}>
          <div className="text-[10px] font-semibold text-[var(--text-tertiary)] uppercase tracking-wider mb-1">Attack Vector</div>
          <code className="text-orange-400/80 text-[11px] font-mono">{String(a.attackVector)}</code>
        </div>
      )}

      {Array.isArray(a.recommendedActions) && (a.recommendedActions as string[]).length > 0 && (
        <div>
          <div className="text-[10px] font-semibold text-[var(--text-tertiary)] uppercase tracking-wider mb-2">Recommended Actions</div>
          <div className="space-y-1">
            {(a.recommendedActions as string[]).map((action, i) => (
              <div
                key={i}
                className="flex items-start gap-2.5 p-2 rounded-lg stagger-item"
                style={{
                  background: "rgba(255,255,255,0.02)",
                  border: "1px solid var(--border)",
                  animationDelay: `${i * 35}ms`,
                }}
              >
                <span
                  className="text-[10px] font-semibold tabular mt-px flex-shrink-0 w-4 text-center"
                  style={{ color: "var(--text-tertiary)" }}
                >
                  {i + 1}
                </span>
                <span className="text-[var(--text-secondary)] text-xs">{action}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {Array.isArray(a.indicators) && (a.indicators as string[]).length > 0 && (
        <div>
          <div className="text-[10px] font-semibold text-[var(--text-tertiary)] uppercase tracking-wider mb-1.5">IOCs</div>
          <div className="flex flex-wrap gap-1">
            {(a.indicators as string[]).map((ioc, i) => (
              <span
                key={i}
                className="px-2 py-0.5 rounded text-[11px]"
                style={{
                  background: "rgba(234,179,8,0.08)",
                  border: "1px solid rgba(234,179,8,0.2)",
                  color: "rgba(234,179,8,0.8)",
                }}
              >
                {ioc}
              </span>
            ))}
          </div>
        </div>
      )}

      <div className="flex gap-2">
        {a.riskScore !== undefined && (
          <div className="flex-1 rounded-lg p-3 text-center" style={{ background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)" }}>
            <div className="text-[10px] text-[var(--text-tertiary)] uppercase tracking-wider">Risk Score</div>
            <div
              className="text-xl font-bold tabular mt-1"
              style={{
                color: Number(a.riskScore) >= 8 ? "#ef4444" : Number(a.riskScore) >= 6 ? "#f97316" : "#eab308",
              }}
            >
              {String(a.riskScore)}<span className="text-sm text-[var(--text-tertiary)]">/10</span>
            </div>
          </div>
        )}
        {!!a.falsePositiveRisk && (
          <div className="flex-1 rounded-lg p-3 text-center" style={{ background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)" }}>
            <div className="text-[10px] text-[var(--text-tertiary)] uppercase tracking-wider">FP Risk</div>
            <div
              className="text-lg font-bold mt-1 capitalize"
              style={{
                color: a.falsePositiveRisk === "low" ? "#22c55e" : a.falsePositiveRisk === "medium" ? "#eab308" : "#ef4444",
              }}
            >
              {String(a.falsePositiveRisk)}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// Verdict button — styled like a keyboard key
function VerdictButton({
  onClick, disabled, icon: Icon, label, color,
}: {
  onClick: () => void;
  disabled: boolean;
  icon: React.ElementType;
  label: string;
  color: string;
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium select-none"
      style={{
        background: `${color}10`,
        border: `1px solid ${color}25`,
        color: `${color}cc`,
        // Emil: transition-colors + scale on active
        transition: "background-color 120ms, border-color 120ms, transform 100ms",
      }}
      // Emil: inline active style via onMouseDown/onMouseUp for scale effect
      onMouseDown={(e) => { (e.currentTarget as HTMLButtonElement).style.transform = "scale(0.96)"; }}
      onMouseUp={(e) => { (e.currentTarget as HTMLButtonElement).style.transform = "scale(1)"; }}
      onMouseLeave={(e) => { (e.currentTarget as HTMLButtonElement).style.transform = "scale(1)"; }}
    >
      <Icon className="w-3.5 h-3.5" />
      {label}
    </button>
  );
}

export function IncidentDrawer({ incident, onClose }: Props) {
  const qc = useQueryClient();
  const [analyzing, setAnalyzing] = useState(false);
  const [activeTab, setActiveTab] = useState<"overview" | "ml" | "mitre" | "related">("overview");
  const [notes, setNotes] = useState<string>("");

  const analyzeInc = trpc.incident.analyze.useMutation({
    onSuccess: () => { qc.invalidateQueries(); toast.success("Analysis complete"); },
    onError: () => toast.error("Analysis failed"),
  });

  const updateStatus = trpc.incident.updateStatus.useMutation({
    onSuccess: () => { qc.invalidateQueries(); toast.success("Notes saved"); },
    onError: () => toast.error("Failed to save notes"),
  });

  const feedbackMut = trpc.incident.feedback.useMutation({
    onSuccess: (data) => { qc.invalidateQueries(); toast.success(`Verdict: ${data.analystLabel}`); },
    onError: () => toast.error("Failed to record verdict"),
  });

  const explainQuery = trpc.ml.explainIncident.useQuery(
    { id: incident?.id ?? 0 },
    { enabled: !!incident && activeTab === "ml" }
  );

  const relatedQuery = trpc.incident.relatedByIp.useQuery(
    { sourceIp: incident?.sourceIp ?? "", excludeId: incident?.id ?? 0, limit: 5 },
    { enabled: !!incident?.sourceIp && activeTab === "related" }
  );

  async function handleAnalyze() {
    if (!incident) return;
    setAnalyzing(true);
    try { await analyzeInc.mutateAsync({ id: incident.id }); }
    finally { setAnalyzing(false); }
  }

  const color = incident ? (ATTACK_COLORS[incident.mlType ?? ""] ?? "#6366f1") : "#6366f1";
  const hasAnalysis = incident?.aiAnalysis && typeof incident.aiAnalysis === "object";

  return (
    <AnimatePresence>
      {incident && (
        <>
          {/* Backdrop — fast fade */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            // Emil: specify transition duration, under 200ms
            transition={{ duration: 0.15 }}
            className="fixed inset-0 z-40"
            style={{ background: "rgba(0,0,0,0.5)", backdropFilter: "blur(4px)" }}
            onClick={onClose}
          />

          {/* Drawer — Emil: iOS drawer curve cubic-bezier(0.32, 0.72, 0, 1) */}
          <motion.div
            initial={{ x: "100%" }}
            animate={{ x: 0 }}
            exit={{ x: "100%" }}
            // Emil: duration 0.35 for drawers (200-500ms range), iOS-like easing
            transition={{ duration: 0.32, ease: [0.32, 0.72, 0, 1] }}
            className="fixed right-0 top-0 bottom-0 w-[580px] z-50 flex flex-col"
            style={{
              background: "rgba(6,9,18,0.98)",
              borderLeft: "1px solid var(--border)",
              boxShadow: "-24px 0 64px rgba(0,0,0,0.5)",
            }}
          >
            {/* Color accent line at top */}
            <div
              className="h-px w-full flex-shrink-0"
              style={{ background: `linear-gradient(90deg, transparent 0%, ${color} 50%, transparent 100%)` }}
            />

            {/* Header */}
            <div className="flex items-center gap-3 px-5 py-4 border-b border-[var(--border)]">
              <div
                className="w-9 h-9 rounded-xl flex items-center justify-center text-lg flex-shrink-0"
                style={{ background: `${color}15`, border: `1px solid ${color}30` }}
              >
                {typeIcon(incident.mlType ?? "")}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-[var(--text-primary)] font-semibold text-sm">
                    Incident #{incident.id}
                  </span>
                  <SeverityBadge severity={incident.severity} />
                  <span
                    className="text-[11px] px-1.5 py-0.5 rounded"
                    style={{ background: "rgba(255,255,255,0.05)", color: "var(--text-tertiary)", border: "1px solid var(--border)" }}
                  >
                    {incident.status}
                  </span>
                </div>
                <div className="text-[var(--text-tertiary)] text-xs mt-0.5 truncate">
                  {incident.mlType ?? "unknown"} · {fmtDate(incident.createdAt)}
                </div>
              </div>
              <button
                onClick={onClose}
                className="w-7 h-7 flex items-center justify-center rounded-md text-[var(--text-tertiary)] hover:text-[var(--text-primary)] hover:bg-white/6 transition-colors duration-100 active:scale-90 flex-shrink-0"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Verdict bar */}
            <div className="flex items-center gap-2 px-5 py-2.5 border-b border-[var(--border)]">
              <span className="text-[var(--text-tertiary)] text-[11px] mr-1 font-medium">Verdict:</span>
              <VerdictButton
                onClick={() => feedbackMut.mutate({ id: incident.id, verdict: "true_positive" })}
                disabled={feedbackMut.isPending}
                icon={CheckCircle}
                label="True Positive"
                color="#ef4444"
              />
              <VerdictButton
                onClick={() => feedbackMut.mutate({ id: incident.id, verdict: "false_positive" })}
                disabled={feedbackMut.isPending}
                icon={XCircle}
                label="False Positive"
                color="#22c55e"
              />
              <VerdictButton
                onClick={() => feedbackMut.mutate({ id: incident.id, verdict: "investigating" })}
                disabled={feedbackMut.isPending}
                icon={AlertCircle}
                label="Investigating"
                color="#eab308"
              />
              {incident.analystLabel && (
                <span className="ml-auto flex items-center gap-1 text-[11px] text-[var(--text-tertiary)]">
                  <Tag className="w-2.5 h-2.5" />
                  {incident.analystLabel}
                </span>
              )}
            </div>

            {/* Tabs — Emil: clip-path for active indicator, not just border-bottom */}
            <div className="flex border-b border-[var(--border)] px-5">
              {([
                { id: "overview", label: "Overview", icon: Shield },
                { id: "ml",       label: "ML",       icon: Zap },
                { id: "mitre",    label: "MITRE",    icon: Activity },
                { id: "related",  label: "Related",  icon: Network },
              ] as const).map(({ id, label, icon: Icon }) => (
                <button
                  key={id}
                  onClick={() => setActiveTab(id)}
                  className="flex items-center gap-1.5 px-3 py-2.5 text-xs font-medium border-b-2 transition-colors duration-100"
                  style={{
                    borderBottomColor: activeTab === id ? color : "transparent",
                    color: activeTab === id ? "var(--text-primary)" : "var(--text-tertiary)",
                  }}
                >
                  <Icon className="w-3 h-3" />
                  {label}
                </button>
              ))}
            </div>

            {/* Tab content */}
            <div className="flex-1 overflow-y-auto px-5 py-4 space-y-4">

              {/* ── OVERVIEW ─────────────────────────── */}
              {activeTab === "overview" && (
                <div className="space-y-3">
                  <div className="grid grid-cols-2 gap-2">
                    {[
                      { label: "Source IP", value: incident.sourceIp ?? "—", mono: true },
                      { label: "Destination", value: incident.destinationIp ?? "—", mono: true },
                      { label: "Country", value: incident.threatCountry ?? "—" },
                      { label: "Abuse Score", value: incident.abuseScore !== null ? `${incident.abuseScore}/100` : "—" },
                    ].map(({ label, value, mono }) => (
                      <div
                        key={label}
                        className="p-2.5 rounded-lg"
                        style={{ background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)" }}
                      >
                        <div className="text-[10px] text-[var(--text-tertiary)] font-medium uppercase tracking-wider mb-1">{label}</div>
                        <div className={`text-xs text-[var(--text-primary)] ${mono ? "font-mono" : ""}`}>{value}</div>
                      </div>
                    ))}
                  </div>

                  {/* Confidence bar */}
                  <div
                    className="p-3 rounded-lg"
                    style={{ background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)" }}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-[10px] text-[var(--text-tertiary)] font-medium uppercase tracking-wider">ML Confidence</span>
                      <span className={`text-sm font-semibold tabular ${confidenceColor(incident.mlConfidence ?? 0)}`}>
                        {incident.mlConfidence ? Math.round(incident.mlConfidence * 100) + "%" : "—"}
                      </span>
                    </div>
                    <div className="h-1 rounded-full overflow-hidden" style={{ background: "rgba(255,255,255,0.06)" }}>
                      <motion.div
                        initial={{ width: 0 }}
                        // Emil: animate exact transform/width. width is ok here (not in hot path)
                        animate={{ width: `${(incident.mlConfidence ?? 0) * 100}%` }}
                        transition={{ duration: 0.6, ease: [0.23, 1, 0.32, 1] }}
                        className="h-full rounded-full"
                        style={{ background: `linear-gradient(90deg, ${color}60, ${color})` }}
                      />
                    </div>
                  </div>

                  {/* Raw log */}
                  <div>
                    <div className="flex items-center gap-1.5 mb-1.5">
                      <FileText className="w-3 h-3 text-[var(--text-tertiary)]" />
                      <span className="text-[10px] font-semibold text-[var(--text-tertiary)] uppercase tracking-wider">Raw Log</span>
                    </div>
                    <pre
                      className="text-[11px] font-mono leading-relaxed p-3 rounded-lg max-h-36 overflow-y-auto"
                      style={{
                        background: "rgba(0,0,0,0.4)",
                        border: "1px solid rgba(255,255,255,0.06)",
                        color: "#86efac",
                        whiteSpace: "pre-wrap",
                        wordBreak: "break-all",
                      }}
                    >
                      {incident.rawLog}
                    </pre>
                  </div>

                  {/* Analyst Notes */}
                  <div>
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="text-[10px] font-semibold text-[var(--text-tertiary)] uppercase tracking-wider">Analyst Notes</span>
                      <button
                        onClick={() => updateStatus.mutate({ id: incident.id, status: incident.status as "open" | "investigating" | "resolved" | "false_positive", notes: notes || undefined })}
                        disabled={updateStatus.isPending}
                        className="text-[10px] px-2 py-1 rounded disabled:opacity-50"
                        style={{ background: "rgba(37,99,235,0.1)", border: "1px solid rgba(37,99,235,0.2)", color: "#60a5fa", transition: "background-color 120ms" }}
                        onMouseEnter={(e) => e.currentTarget.style.background = "rgba(37,99,235,0.18)"}
                        onMouseLeave={(e) => e.currentTarget.style.background = "rgba(37,99,235,0.1)"}
                      >
                        Save
                      </button>
                    </div>
                    <textarea
                      value={notes || incident.analystNotes || ""}
                      onChange={(e) => setNotes(e.target.value)}
                      placeholder="Add analyst notes, observations, or findings…"
                      rows={3}
                      className="w-full rounded-lg px-3 py-2 text-xs resize-none focus:outline-none"
                      style={{
                        background: "rgba(255,255,255,0.03)",
                        border: "1px solid var(--border)",
                        color: "var(--text-primary)",
                        transition: "border-color 150ms",
                      }}
                      onFocus={(e) => e.currentTarget.style.borderColor = "rgba(37,99,235,0.4)"}
                      onBlur={(e) => e.currentTarget.style.borderColor = "var(--border)"}
                    />
                  </div>

                  {/* AI Analysis */}
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-1.5">
                        <Bot className="w-3 h-3 text-[var(--text-tertiary)]" />
                        <span className="text-[10px] font-semibold text-[var(--text-tertiary)] uppercase tracking-wider">AI Analysis</span>
                      </div>
                      <Button size="sm" variant="outline" onClick={handleAnalyze} disabled={analyzing}>
                        {analyzing ? <Spinner className="w-3 h-3" /> : <Bot className="w-3 h-3" />}
                        {hasAnalysis ? "Re-analyze" : "Analyze"}
                      </Button>
                    </div>
                    {hasAnalysis ? (
                      <AiAnalysisView analysis={incident.aiAnalysis} />
                    ) : (
                      <div
                        className="py-8 text-center rounded-lg"
                        style={{ border: "1px dashed rgba(255,255,255,0.08)", background: "rgba(255,255,255,0.01)" }}
                      >
                        <div className="text-[var(--text-tertiary)] text-xs">No analysis yet</div>
                        <div className="text-[var(--text-tertiary)] text-[11px] mt-0.5 opacity-60">Click Analyze to generate</div>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* ── ML EXPLAIN ───────────────────────── */}
              {activeTab === "ml" && (
                <div className="space-y-4">
                  <div className="grid grid-cols-3 gap-2">
                    {[
                      { label: "Prediction", value: incident.mlType ?? "—" },
                      { label: "Confidence", value: incident.mlConfidence ? Math.round(incident.mlConfidence * 100) + "%" : "—", colored: true },
                      { label: "Analyst", value: incident.analystLabel ?? "—" },
                    ].map(({ label, value, colored }) => (
                      <div
                        key={label}
                        className="p-2.5 rounded-lg text-center"
                        style={{ background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)" }}
                      >
                        <div className="text-[10px] text-[var(--text-tertiary)] uppercase tracking-wider mb-1">{label}</div>
                        <div
                          className="text-xs font-semibold"
                          style={{ color: colored ? undefined : "var(--text-primary)" }}
                        >
                          {colored ? (
                            <span className={confidenceColor(incident.mlConfidence ?? 0)}>{value}</span>
                          ) : value}
                        </div>
                      </div>
                    ))}
                  </div>

                  {explainQuery.isLoading ? (
                    <div className="flex justify-center py-8"><Spinner /></div>
                  ) : (
                    <>
                      {(explainQuery.data?.topFeaturesForType?.length ?? 0) > 0 && (
                        <div>
                          <div className="text-[10px] font-semibold text-[var(--text-tertiary)] uppercase tracking-wider mb-2.5">
                            Top features for "{incident.mlType}"
                          </div>
                          <div className="space-y-2">
                            {explainQuery.data!.topFeaturesForType.map((f, i) => {
                              const max = explainQuery.data!.topFeaturesForType[0]?.importance ?? 1;
                              return (
                                <div key={f.feature} className="stagger-item" style={{ animationDelay: `${i * 30}ms` }}>
                                  <div className="flex items-center justify-between mb-1">
                                    <span className="text-xs font-mono text-[var(--text-secondary)]">{f.feature}</span>
                                    <span className="text-[11px] tabular" style={{ color }}>
                                      {f.importance.toFixed(4)}
                                    </span>
                                  </div>
                                  <div className="h-1 rounded-full overflow-hidden" style={{ background: "rgba(255,255,255,0.05)" }}>
                                    <div
                                      className="h-full rounded-full transition-[width] duration-500"
                                      style={{ width: `${(f.importance / max) * 100}%`, background: `${color}90` }}
                                    />
                                  </div>
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      )}

                      {(explainQuery.data?.topFeaturesGlobal?.length ?? 0) > 0 && (
                        <div>
                          <div className="text-[10px] font-semibold text-[var(--text-tertiary)] uppercase tracking-wider mb-2.5">
                            Global SHAP Importance
                          </div>
                          <div className="space-y-1.5">
                            {explainQuery.data!.topFeaturesGlobal.slice(0, 8).map((f, i) => {
                              const max = explainQuery.data!.topFeaturesGlobal[0]?.importance ?? 1;
                              return (
                                <div key={f.feature} className="flex items-center gap-3 stagger-item" style={{ animationDelay: `${i * 25}ms` }}>
                                  <span className="text-[10px] text-[var(--text-tertiary)] w-4 text-right tabular">{i + 1}</span>
                                  <span className="text-[11px] font-mono text-[var(--text-secondary)] w-28 truncate">{f.feature}</span>
                                  <div className="flex-1 h-1 rounded-full overflow-hidden" style={{ background: "rgba(255,255,255,0.05)" }}>
                                    <div
                                      className="h-full rounded-full"
                                      style={{ width: `${(f.importance / max) * 100}%`, background: "rgba(255,255,255,0.2)" }}
                                    />
                                  </div>
                                  <span className="text-[10px] tabular text-[var(--text-tertiary)] w-12 text-right">{f.importance.toFixed(4)}</span>
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      )}

                      <div
                        className="flex items-center gap-1.5 text-[11px] text-[var(--text-tertiary)] p-2 rounded"
                        style={{ background: "rgba(255,255,255,0.02)" }}
                      >
                        <Zap className="w-3 h-3" />
                        {explainQuery.data?.modelMode ?? "flow+text ensemble"}
                      </div>
                    </>
                  )}
                </div>
              )}

              {/* ── MITRE ───────────────────────────── */}
              {activeTab === "mitre" && (
                <div className="space-y-4">
                  {incident.mitreId ? (
                    <>
                      <div
                        className="p-4 rounded-lg"
                        style={{ background: "rgba(37,99,235,0.05)", border: "1px solid rgba(37,99,235,0.15)" }}
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div>
                            <div className="text-blue-400 font-mono font-bold">{incident.mitreId}</div>
                            <div className="text-[var(--text-primary)] font-medium text-sm mt-1">{incident.mitreTechnique}</div>
                            <div className="text-[var(--text-tertiary)] text-xs mt-0.5 capitalize">{incident.mitreTactic}</div>
                          </div>
                          <a
                            href={`https://attack.mitre.org/techniques/${incident.mitreId}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="flex items-center gap-1 px-2.5 py-1.5 rounded-md text-xs text-blue-400 transition-colors duration-100"
                            style={{ background: "rgba(37,99,235,0.1)", border: "1px solid rgba(37,99,235,0.2)" }}
                          >
                            ATT&CK <ExternalLink className="w-2.5 h-2.5" />
                          </a>
                        </div>
                      </div>
                      <KillChainViz tactic={incident.mitreTactic} />
                    </>
                  ) : (
                    <div
                      className="py-10 text-center rounded-lg"
                      style={{ border: "1px dashed rgba(255,255,255,0.08)" }}
                    >
                      <div className="text-[var(--text-tertiary)] text-xs">No MITRE mapping for this incident</div>
                    </div>
                  )}
                </div>
              )}

              {/* ── RELATED ─────────────────────────── */}
              {activeTab === "related" && (
                <div className="space-y-2">
                  {!incident.sourceIp ? (
                    <div
                      className="py-10 text-center rounded-lg"
                      style={{ border: "1px dashed rgba(255,255,255,0.08)" }}
                    >
                      <div className="text-[var(--text-tertiary)] text-xs">No source IP — can't find related incidents</div>
                    </div>
                  ) : relatedQuery.isLoading ? (
                    <div className="flex justify-center py-8"><Spinner /></div>
                  ) : (relatedQuery.data ?? []).length > 0 ? (
                    <>
                      <div className="text-[10px] font-semibold text-[var(--text-tertiary)] uppercase tracking-wider mb-2">
                        {relatedQuery.data!.length} from {incident.sourceIp}
                      </div>
                      {relatedQuery.data!.map((rel, i) => (
                        <div
                          key={rel.id}
                          className="p-3 rounded-lg stagger-item"
                          style={{
                            background: "rgba(255,255,255,0.02)",
                            border: "1px solid var(--border)",
                            animationDelay: `${i * 40}ms`,
                          }}
                        >
                          <div className="flex items-center justify-between mb-1">
                            <div className="flex items-center gap-2">
                              <span className="text-sm">{typeIcon(rel.mlType ?? "")}</span>
                              <span className="text-[var(--text-primary)] text-xs font-medium">{rel.mlType ?? "unknown"}</span>
                              <SeverityBadge severity={rel.severity} />
                            </div>
                            <span className="text-[var(--text-tertiary)] text-[11px] font-mono">#{rel.id}</span>
                          </div>
                          <div className="text-[var(--text-tertiary)] text-[11px]">{fmtDate(rel.createdAt)}</div>
                          <div className="text-[var(--text-tertiary)] text-[11px] font-mono truncate mt-0.5">{rel.rawLog?.slice(0, 70)}…</div>
                        </div>
                      ))}
                    </>
                  ) : (
                    <div
                      className="py-10 text-center rounded-lg"
                      style={{ border: "1px dashed rgba(255,255,255,0.08)" }}
                    >
                      <div className="text-[var(--text-tertiary)] text-xs">No other incidents from {incident.sourceIp}</div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}
