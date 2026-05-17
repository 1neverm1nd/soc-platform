import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { useQueryClient } from "@tanstack/react-query";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { fmtDate } from "@/lib/utils";
import { Bell, CheckCheck, AlertTriangle, ArrowUpCircle, RefreshCw, XCircle } from "lucide-react";
import { toast } from "sonner";

const TYPE_META: Record<string, { color: string; icon: typeof Bell; accent: string; label: string }> = {
  critical_incident: { color: "#ef4444", icon: AlertTriangle, accent: "rgba(239,68,68,0.08)",   label: "Critical" },
  escalation:        { color: "#f97316", icon: ArrowUpCircle, accent: "rgba(249,115,22,0.08)",   label: "Escalation" },
  status_change:     { color: "#3b82f6", icon: RefreshCw,     accent: "rgba(59,130,246,0.08)",   label: "Status" },
  false_positive:    { color: "#64748b", icon: XCircle,       accent: "rgba(100,116,139,0.08)", label: "False Positive" },
};

const TYPES = ["", "critical_incident", "escalation", "status_change", "false_positive"] as const;

export function NotificationsPage() {
  const qc = useQueryClient();
  const [filter, setFilter] = useState("");
  const [editingPrefs, setEditingPrefs] = useState(false);
  const [prefForm, setPrefForm] = useState({
    emailEnabled: true,
    inAppEnabled: true,
    minSeverity: "medium" as "low" | "medium" | "high" | "critical",
  });

  const notifs   = trpc.notifications.list.useQuery({ type: (filter || undefined) as "critical_incident" | "escalation" | "status_change" | "false_positive" | undefined });
  const stats    = trpc.notifications.stats.useQuery();
  const markRead = trpc.notifications.markRead.useMutation({ onSuccess: () => qc.invalidateQueries() });
  const markAll  = trpc.notifications.markAllRead.useMutation({ onSuccess: () => { qc.invalidateQueries(); toast.success("All marked as read"); } });
  const savePrefs = trpc.notifications.savePreferences.useMutation({
    onSuccess: () => { qc.invalidateQueries(); setEditingPrefs(false); toast.success("Preferences saved"); },
  });

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-[var(--text-primary)]">Notifications</h1>
          <p className="text-[var(--text-tertiary)] text-xs mt-0.5">{stats.data?.unread ?? 0} unread</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => setEditingPrefs(!editingPrefs)}>Preferences</Button>
          <Button variant="secondary" size="sm" onClick={() => markAll.mutate()}>
            <CheckCheck className="w-3.5 h-3.5" /> Mark All Read
          </Button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-3">
        {[
          { label: "Total",    value: stats.data?.total    ?? 0, color: "var(--text-primary)" },
          { label: "Critical", value: stats.data?.critical ?? 0, color: "#ef4444" },
          { label: "Unread",   value: stats.data?.unread   ?? 0, color: "#3b82f6" },
        ].map(({ label, value, color }) => (
          <Card key={label}>
            <div className="text-[var(--text-tertiary)] text-[11px] uppercase tracking-wider mb-1">{label}</div>
            <div className="text-2xl font-semibold tabular" style={{ color }}>{value}</div>
          </Card>
        ))}
      </div>

      {/* Prefs form */}
      {editingPrefs && (
        <Card>
          <div className="text-[var(--text-primary)] text-xs font-semibold uppercase tracking-wider mb-3">Notification Preferences</div>
          <div className="space-y-3">
            <div className="flex gap-6">
              {[
                { key: "emailEnabled" as const, label: "Email notifications" },
                { key: "inAppEnabled" as const, label: "In-app notifications" },
              ].map(({ key, label }) => (
                <label key={key} className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={prefForm[key]}
                    onChange={(e) => setPrefForm({ ...prefForm, [key]: e.target.checked })}
                    className="accent-blue-500"
                  />
                  <span className="text-[var(--text-secondary)] text-xs">{label}</span>
                </label>
              ))}
            </div>
            <div className="flex items-center gap-3">
              <label className="text-[var(--text-tertiary)] text-xs w-24">Min. Severity</label>
              <select
                value={prefForm.minSeverity}
                onChange={(e) => setPrefForm({ ...prefForm, minSeverity: e.target.value as typeof prefForm.minSeverity })}
                className="rounded-lg px-3 py-1.5 text-[var(--text-primary)] text-xs focus:outline-none"
                style={{ background: "rgba(255,255,255,0.04)", border: "1px solid var(--border)" }}
              >
                {["low", "medium", "high", "critical"].map((s) => (
                  <option key={s} value={s} style={{ background: "#0d1526" }}>{s}</option>
                ))}
              </select>
            </div>
            <div className="flex gap-2">
              <Button variant="primary" size="sm" onClick={() => savePrefs.mutate(prefForm)}>Save</Button>
              <Button variant="ghost" size="sm" onClick={() => setEditingPrefs(false)}>Cancel</Button>
            </div>
          </div>
        </Card>
      )}

      {/* Filter tabs */}
      <div className="flex gap-0" style={{ borderBottom: "1px solid var(--border)" }}>
        {TYPES.map((t) => {
          const meta = t ? TYPE_META[t] : null;
          const label = t ? (TYPE_META[t]?.label ?? t) : "All";
          return (
            <button
              key={t}
              onClick={() => setFilter(t)}
              className="px-4 py-2 text-xs font-medium select-none flex items-center gap-1.5"
              style={{
                color: filter === t ? "#3b82f6" : "var(--text-tertiary)",
                borderBottom: filter === t ? "2px solid #3b82f6" : "2px solid transparent",
                marginBottom: -1,
                transition: "color 120ms",
              }}
            >
              {meta && <meta.icon className="w-3 h-3" style={{ color: filter === t ? meta.color : "var(--text-tertiary)" }} />}
              {label}
            </button>
          );
        })}
      </div>

      {/* Notifications list */}
      <div className="space-y-2">
        {notifs.isLoading && (
          <div className="text-center py-12 text-[var(--text-tertiary)] text-xs">Loading…</div>
        )}
        {!notifs.isLoading && (notifs.data ?? []).length === 0 && (
          <div className="py-12 text-center rounded-lg" style={{ border: "1px dashed rgba(255,255,255,0.08)" }}>
            <Bell className="w-8 h-8 mx-auto mb-2 text-[var(--text-tertiary)] opacity-30" />
            <div className="text-[var(--text-tertiary)] text-sm">No notifications</div>
            <div className="text-[var(--text-tertiary)] text-[11px] mt-1 opacity-60">
              {filter ? "Try selecting a different filter" : "You're all caught up"}
            </div>
          </div>
        )}
        {(notifs.data ?? []).map((n) => {
          const meta = TYPE_META[n.type] ?? TYPE_META["status_change"]!;
          const Icon = meta.icon;
          return (
            <div
              key={n.id}
              onClick={() => !n.isRead && markRead.mutate({ id: n.id })}
              className="rounded-lg cursor-pointer"
              style={{
                background: !n.isRead ? meta.accent : "rgba(255,255,255,0.01)",
                border: "1px solid var(--border)",
                borderLeft: `3px solid ${meta.color}`,
                opacity: n.isRead ? 0.55 : 1,
                transition: "opacity 150ms",
                padding: "12px 16px",
              }}
            >
              <div className="flex items-start gap-3">
                <Icon className="w-3.5 h-3.5 mt-0.5 flex-shrink-0" style={{ color: meta.color }} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-start justify-between gap-2">
                    <span className="text-xs font-medium text-[var(--text-primary)]">{n.title}</span>
                    <span className="text-[var(--text-tertiary)] text-[10px] flex-shrink-0">{fmtDate(n.createdAt)}</span>
                  </div>
                  <p className="text-[var(--text-tertiary)] text-[11px] mt-0.5">{n.message}</p>
                  {n.incidentId && (
                    <span className="text-blue-400/60 text-[10px]">Incident #{n.incidentId}</span>
                  )}
                </div>
                {!n.isRead && (
                  <div className="w-1.5 h-1.5 rounded-full mt-1 flex-shrink-0" style={{ background: "#3b82f6" }} />
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
