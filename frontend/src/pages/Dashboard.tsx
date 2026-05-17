import { useEffect, useRef, useState } from "react";
import { trpc } from "@/lib/trpc";
import { useQueryClient } from "@tanstack/react-query";
import { Card, CardHeader, CardTitle } from "@/components/ui/Card";
import { SeverityBadge } from "@/components/ui/Badge";
import { fmtDate, ATTACK_COLORS } from "@/lib/utils";
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid
} from "recharts";
import { AlertTriangle, ShieldAlert, Target, Ban, TrendingUp, Activity, Brain } from "lucide-react";
import { Link } from "wouter";
import { toast } from "sonner";

// Emil: spring-based counter — cubic-ease-out, 800ms feels natural
function AnimatedCounter({ target }: { target: number }) {
  const [val, setVal] = useState(0);
  const raf = useRef<number>(0);
  useEffect(() => {
    const start = performance.now();
    const from = 0;
    const duration = 700;
    const tick = (now: number) => {
      const p = Math.min((now - start) / duration, 1);
      // ease-out cubic
      const eased = 1 - Math.pow(1 - p, 3);
      setVal(Math.round(from + (target - from) * eased));
      if (p < 1) raf.current = requestAnimationFrame(tick);
    };
    raf.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf.current);
  }, [target]);
  return <span className="tabular">{val.toLocaleString()}</span>;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e",
};

const TOOLTIP_STYLE = {
  background: "rgba(8,12,22,0.97)",
  border: "1px solid rgba(255,255,255,0.08)",
  borderRadius: "8px",
  color: "var(--text-primary)",
  fontSize: "12px",
  boxShadow: "0 8px 32px rgba(0,0,0,0.4)",
};

export function DashboardPage() {
  const qc = useQueryClient();
  const sseRef = useRef<EventSource | null>(null);

  const stats = trpc.incident.stats.useQuery();
  const timeSeries = trpc.incident.timeSeries.useQuery({ days: 30 });
  const campaigns = trpc.campaigns.list.useQuery();
  const blockedCount = trpc.blocklist.count.useQuery();
  const mlStats = trpc.ml.stats.useQuery(undefined, { staleTime: 60000 });

  useEffect(() => {
    const es = new EventSource("/events");
    sseRef.current = es;
    es.addEventListener("new_incident", (e) => {
      const data = JSON.parse(e.data) as { mlType: string; severity: string };
      toast.info(`New ${data.severity} incident: ${data.mlType}`, { duration: 4000 });
      qc.invalidateQueries();
    });
    return () => es.close();
  }, [qc]);

  const kpiCards = [
    { label: "Total Incidents", value: stats.data?.total ?? 0, icon: AlertTriangle, color: "#e2e8f0", glow: undefined },
    { label: "Critical", value: stats.data?.critical ?? 0, icon: ShieldAlert, color: "#ef4444", glow: "red" as const },
    { label: "Active Campaigns", value: campaigns.data?.length ?? 0, icon: Target, color: "#f97316", glow: "yellow" as const },
    { label: "Blocked IPs", value: blockedCount.data?.count ?? 0, icon: Ban, color: "#22c55e", glow: "green" as const },
  ];

  const typeData = (stats.data?.byType ?? []).map((r) => ({
    name: r.mlType ?? "unknown",
    value: Number(r.count),
    color: ATTACK_COLORS[r.mlType ?? ""] ?? "#475569",
  }));

  const severityData = (stats.data?.bySeverity ?? []).map((r) => ({
    name: r.severity,
    value: Number(r.count),
    fill: SEVERITY_COLORS[r.severity] ?? "#475569",
  }));

  const areaData = (timeSeries.data ?? []).map((r) => ({
    date: r.date?.slice(5),
    incidents: Number(r.count),
  }));

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-[var(--text-primary)]">Security Dashboard</h1>
          <p className="text-[var(--text-tertiary)] text-xs mt-0.5">Real-time threat monitoring</p>
        </div>
        <div className="flex items-center gap-2">
          {/* Emil: CSS animation for frequently-seen element, not JS */}
          <span className="w-1.5 h-1.5 bg-green-400 rounded-full pulse-dot" />
          <span className="text-[var(--text-tertiary)] text-xs">Live</span>
        </div>
      </div>

      {/* KPI Cards — stagger via CSS, Emil prefers CSS over JS for this */}
      <div className="grid grid-cols-4 gap-3">
        {kpiCards.map(({ label, value, icon: Icon, color, glow }, i) => (
          <div key={label} className="stagger-item" style={{ animationDelay: `${i * 50}ms` }}>
            <Card glow={glow} className="relative">
              <div className="flex items-start justify-between">
                <div>
                  <p className="text-[var(--text-tertiary)] text-[11px] font-medium uppercase tracking-wider mb-2">
                    {label}
                  </p>
                  <p className="text-2xl font-semibold tabular" style={{ color }}>
                    <AnimatedCounter target={value} />
                  </p>
                </div>
                <div
                  className="w-8 h-8 rounded-lg flex items-center justify-center"
                  style={{ background: `${color}12`, border: `1px solid ${color}20` }}
                >
                  <Icon className="w-4 h-4" style={{ color }} />
                </div>
              </div>
            </Card>
          </div>
        ))}
      </div>

      {/* Charts */}
      <div className="grid grid-cols-3 gap-4">
        <Card className="col-span-2">
          <CardHeader>
            <CardTitle>Incident Timeline — 30 days</CardTitle>
            <TrendingUp className="w-3.5 h-3.5 text-[var(--text-tertiary)]" />
          </CardHeader>
          <ResponsiveContainer width="100%" height={190}>
            <AreaChart data={areaData} margin={{ top: 4, right: 0, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="incGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#2563eb" stopOpacity={0.25} />
                  <stop offset="100%" stopColor="#2563eb" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false} />
              <XAxis
                dataKey="date"
                tick={{ fill: "var(--text-tertiary)", fontSize: 10 }}
                tickLine={false} axisLine={false}
                interval="preserveStartEnd"
              />
              <YAxis
                tick={{ fill: "var(--text-tertiary)", fontSize: 10 }}
                tickLine={false} axisLine={false}
              />
              <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ stroke: "rgba(255,255,255,0.08)" }} />
              <Area type="monotone" dataKey="incidents" stroke="#2563eb" strokeWidth={1.5} fill="url(#incGrad)" dot={false} />
            </AreaChart>
          </ResponsiveContainer>
        </Card>

        <Card>
          <CardHeader><CardTitle>Attack Types</CardTitle></CardHeader>
          <ResponsiveContainer width="100%" height={190}>
            <PieChart>
              <Pie
                data={typeData}
                cx="50%" cy="50%"
                outerRadius={68} innerRadius={30}
                dataKey="value"
                paddingAngle={2}
                strokeWidth={0}
              >
                {typeData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
              </Pie>
              <Tooltip contentStyle={TOOLTIP_STYLE} />
            </PieChart>
          </ResponsiveContainer>
          {/* Legend */}
          <div className="mt-1 space-y-1">
            {typeData.slice(0, 4).map((d) => (
              <div key={d.name} className="flex items-center gap-2">
                <div className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: d.color }} />
                <span className="text-[var(--text-tertiary)] text-[11px] truncate">{d.name}</span>
                <span className="ml-auto text-[var(--text-secondary)] text-[11px] tabular">{d.value}</span>
              </div>
            ))}
          </div>
        </Card>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <Card>
          <CardHeader>
            <CardTitle>By Severity</CardTitle>
            <Activity className="w-3.5 h-3.5 text-[var(--text-tertiary)]" />
          </CardHeader>
          <ResponsiveContainer width="100%" height={160}>
            <BarChart data={severityData} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false} />
              <XAxis dataKey="name" tick={{ fill: "var(--text-tertiary)", fontSize: 11 }} tickLine={false} axisLine={false} />
              <YAxis tick={{ fill: "var(--text-tertiary)", fontSize: 11 }} tickLine={false} axisLine={false} />
              <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: "rgba(255,255,255,0.03)" }} />
              <Bar dataKey="value" radius={[3, 3, 0, 0]} maxBarSize={40}>
                {severityData.map((entry, i) => <Cell key={i} fill={entry.fill} fillOpacity={0.85} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Active Campaigns</CardTitle>
            <Link href="/incidents">
              <span className="text-blue-400/60 text-[11px] hover:text-blue-400 transition-colors duration-100 cursor-pointer">
                View all →
              </span>
            </Link>
          </CardHeader>
          <div className="space-y-1">
            {(campaigns.data ?? []).length === 0 ? (
              <div className="py-8 text-center">
                <div className="text-[var(--text-tertiary)] text-xs">No active campaigns</div>
                <div className="text-[var(--text-tertiary)] text-[11px] mt-1 opacity-60">All clear</div>
              </div>
            ) : (
              (campaigns.data ?? []).map((c, i) => (
                <div
                  key={c.id}
                  className="stagger-item flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-white/3 transition-colors duration-100"
                  style={{ animationDelay: `${i * 40}ms` }}
                >
                  <div
                    className="w-1.5 h-1.5 rounded-full flex-shrink-0"
                    style={{
                      background: c.severity === "critical" ? "#ef4444" : c.severity === "high" ? "#f97316" : "#eab308",
                    }}
                  />
                  <div className="flex-1 min-w-0">
                    <div className="text-[var(--text-primary)] text-xs font-mono truncate">{c.sourceIp}</div>
                    <div className="text-[var(--text-tertiary)] text-[11px]">{c.incidentCount} incidents</div>
                  </div>
                  <SeverityBadge severity={c.severity} />
                </div>
              ))
            )}
          </div>
        </Card>
      </div>

      {/* ML Status strip */}
      {mlStats.data && (() => {
        const fm = mlStats.data.flowModel as { accuracy?: number; classes?: string[]; version?: string } | null;
        const tm = mlStats.data.textModel as { accuracy?: number; training_samples?: number } | null;
        const avail = mlStats.data.modelsAvailable as { flow?: boolean; text?: boolean; anomaly?: boolean } | null;
        return (
          <div
            className="flex items-center gap-4 px-4 py-2.5 rounded-lg"
            style={{ background: "rgba(37,99,235,0.04)", border: "1px solid rgba(37,99,235,0.1)" }}
          >
            <Link href="/ml">
              <div className="flex items-center gap-1.5 cursor-pointer">
                <Brain className="w-3.5 h-3.5 text-blue-400" />
                <span className="text-blue-400 text-xs font-medium">ML Engine</span>
              </div>
            </Link>
            <div className="w-px h-3 bg-white/10" />
            {[
              { label: "Flow Model", value: fm?.accuracy ? `${(fm.accuracy * 100).toFixed(1)}%` : "—", ok: avail?.flow },
              { label: "Text Model", value: tm?.accuracy ? `${(tm.accuracy * 100).toFixed(1)}%` : "—", ok: avail?.text },
              { label: "Anomaly",    value: avail?.anomaly ? "Active" : "N/A",  ok: avail?.anomaly },
              { label: "Classes",    value: String(fm?.classes?.length ?? "—"),  ok: true },
            ].map(({ label, value, ok }) => (
              <div key={label} className="flex items-center gap-1.5">
                <div className="w-1.5 h-1.5 rounded-full" style={{ background: ok ? "#22c55e" : "#ef4444" }} />
                <span className="text-[var(--text-tertiary)] text-[11px]">{label}:</span>
                <span className="text-[var(--text-secondary)] text-[11px] font-medium tabular">{value}</span>
              </div>
            ))}
          </div>
        );
      })()}

      {/* Quick nav — Emil: subtle, functional, no gradient decorations */}
      <div className="grid grid-cols-4 gap-2">
        {[
          { href: "/incidents", label: "Incidents", icon: AlertTriangle },
          { href: "/analytics", label: "Analytics", icon: TrendingUp },
          { href: "/rules", label: "Rules", icon: ShieldAlert },
          { href: "/geo", label: "Geo Map", icon: Target },
        ].map(({ href, label, icon: Icon }) => (
          <Link key={href} href={href}>
            <div
              className={[
                "flex items-center gap-2.5 px-4 py-3 rounded-lg cursor-pointer",
                "border border-[var(--border)] hover:border-[var(--border-hover)]",
                "bg-white/2 hover:bg-white/4",
                // Emil: transition exact properties
                "transition-[border-color,background-color] duration-150",
                // Emil: scale on active
                "active:scale-[0.98] active:transition-transform active:duration-100",
              ].join(" ")}
            >
              <Icon className="w-4 h-4 text-[var(--text-tertiary)]" />
              <span className="text-[var(--text-secondary)] text-xs font-medium">{label}</span>
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}
