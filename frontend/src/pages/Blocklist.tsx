import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardHeader, CardTitle } from "@/components/ui/Card";
import { ShieldOff, Plus, Trash2, Search, Download } from "lucide-react";
import { toast } from "sonner";
import { fmtDate } from "@/lib/utils";

const INPUT_STYLE: React.CSSProperties = {
  background: "rgba(255,255,255,0.04)",
  border: "1px solid var(--border)",
  borderRadius: "6px",
  color: "var(--text-primary)",
  fontSize: "12px",
  padding: "6px 10px",
  outline: "none",
  width: "100%",
};

export function BlocklistPage() {
  function handleExportCsv() {
    const rows = list.data ?? [];
    if (rows.length === 0) return;
    const csv = [
      "ip_address,reason,created_at",
      ...rows.map((r) => `"${r.ipAddress}","${(r.reason ?? "").replace(/"/g, "'")}","${r.createdAt ?? ""}"`),
    ].join("\n");
    const a = document.createElement("a");
    a.href = "data:text/csv;charset=utf-8," + encodeURIComponent(csv);
    a.download = `blocklist_${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    toast.success(`Exported ${rows.length} blocked IPs`);
  }

  const [ip, setIp] = useState("");
  const [reason, setReason] = useState("");
  const [search, setSearch] = useState("");

  const list    = trpc.blocklist.list.useQuery();
  const addMut  = trpc.blocklist.add.useMutation({
    onSuccess: () => {
      list.refetch();
      setIp("");
      setReason("");
      toast.success("IP blocked");
    },
    onError: (e) => toast.error(e.message),
  });
  const removeMut = trpc.blocklist.remove.useMutation({
    onSuccess: () => {
      list.refetch();
      toast.success("IP unblocked");
    },
    onError: (e) => toast.error(e.message),
  });

  const isValidIp = (v: string) =>
    /^(\d{1,3}\.){3}\d{1,3}$/.test(v) || /^[\da-fA-F:]+$/.test(v);

  function handleAdd(e: React.FormEvent) {
    e.preventDefault();
    if (!ip.trim() || !isValidIp(ip.trim())) {
      toast.error("Enter a valid IP address");
      return;
    }
    addMut.mutate({ ipAddress: ip.trim(), reason: reason.trim() || undefined });
  }

  const rows = (list.data ?? []).filter((r) =>
    search === "" || r.ipAddress.includes(search) || (r.reason ?? "").toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-[var(--text-primary)]">IP Blocklist</h1>
          <p className="text-[var(--text-tertiary)] text-xs mt-0.5">Manage blocked IP addresses</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleExportCsv}
            disabled={!list.data?.length}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium"
            style={{ background: "rgba(255,255,255,0.04)", border: "1px solid var(--border)", color: "var(--text-secondary)", transition: "background-color 120ms" }}
            onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(255,255,255,0.07)"; }}
            onMouseLeave={(e) => { e.currentTarget.style.background = "rgba(255,255,255,0.04)"; }}
            onMouseDown={(e) => { e.currentTarget.style.transform = "scale(0.97)"; }}
            onMouseUp={(e) => { e.currentTarget.style.transform = "scale(1)"; }}
          >
            <Download className="w-3 h-3" /> Export CSV
          </button>
          <div
            className="flex items-center gap-2 px-3 py-1.5 rounded-md"
            style={{ background: "rgba(239,68,68,0.08)", border: "1px solid rgba(239,68,68,0.2)" }}
          >
            <ShieldOff className="w-3.5 h-3.5 text-red-400" />
            <span className="text-red-400 text-xs font-semibold tabular">
              {list.data?.length ?? 0} blocked
            </span>
          </div>
        </div>
      </div>

      {/* Add form */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-1.5">
            <Plus className="w-3.5 h-3.5" /> Block IP Address
          </CardTitle>
        </CardHeader>
        <form onSubmit={handleAdd} className="flex gap-3 mt-1">
          <input
            style={INPUT_STYLE}
            placeholder="192.168.1.1"
            value={ip}
            onChange={(e) => setIp(e.target.value)}
            onFocus={(e) => { e.currentTarget.style.borderColor = "rgba(37,99,235,0.5)"; }}
            onBlur={(e) => { e.currentTarget.style.borderColor = "var(--border)"; }}
          />
          <input
            style={{ ...INPUT_STYLE, width: "auto", flex: 1 }}
            placeholder="Reason (optional)"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            onFocus={(e) => { e.currentTarget.style.borderColor = "rgba(37,99,235,0.5)"; }}
            onBlur={(e) => { e.currentTarget.style.borderColor = "var(--border)"; }}
          />
          <button
            type="submit"
            disabled={addMut.isPending || !ip.trim()}
            className="px-4 py-1.5 rounded-md text-xs font-medium text-white flex-shrink-0"
            style={{
              background: addMut.isPending || !ip.trim() ? "rgba(37,99,235,0.3)" : "#2563eb",
              border: "1px solid rgba(59,130,246,0.3)",
              cursor: addMut.isPending || !ip.trim() ? "not-allowed" : "pointer",
              transition: "background-color 120ms",
            }}
            onMouseDown={(e) => { if (!addMut.isPending) e.currentTarget.style.transform = "scale(0.97)"; }}
            onMouseUp={(e) => { e.currentTarget.style.transform = "scale(1)"; }}
            onMouseLeave={(e) => { e.currentTarget.style.transform = "scale(1)"; }}
          >
            {addMut.isPending ? "Blocking…" : "Block IP"}
          </button>
        </form>
      </Card>

      {/* Search + list */}
      <Card>
        <CardHeader>
          <CardTitle>Blocked IPs</CardTitle>
          <div className="relative mt-2">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[var(--text-tertiary)]" />
            <input
              style={{ ...INPUT_STYLE, paddingLeft: "28px" }}
              placeholder="Search IPs or reasons…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              onFocus={(e) => { e.currentTarget.style.borderColor = "rgba(37,99,235,0.5)"; }}
              onBlur={(e) => { e.currentTarget.style.borderColor = "var(--border)"; }}
            />
          </div>
        </CardHeader>

        {list.isLoading ? (
          <div className="py-8 text-center text-[var(--text-tertiary)] text-sm">Loading…</div>
        ) : rows.length === 0 ? (
          <div
            className="py-10 text-center rounded-lg mt-1"
            style={{ border: "1px dashed rgba(255,255,255,0.08)" }}
          >
            <ShieldOff className="w-8 h-8 mx-auto mb-2 text-[var(--text-tertiary)] opacity-40" />
            <div className="text-[var(--text-tertiary)] text-sm">
              {search ? "No results match your search" : "No IPs blocked yet"}
            </div>
          </div>
        ) : (
          <div className="space-y-1 mt-2">
            {rows.map((r) => (
              <div
                key={r.id}
                className="flex items-center gap-3 px-3 py-2.5 rounded-md group"
                style={{
                  background: "rgba(255,255,255,0.02)",
                  border: "1px solid var(--border)",
                  transition: "border-color 120ms",
                }}
                onMouseEnter={(e) => { e.currentTarget.style.borderColor = "rgba(255,255,255,0.08)"; }}
                onMouseLeave={(e) => { e.currentTarget.style.borderColor = "var(--border)"; }}
              >
                {/* Threat indicator */}
                <div
                  className="w-1.5 h-1.5 rounded-full flex-shrink-0"
                  style={{ background: "#ef4444", boxShadow: "0 0 6px rgba(239,68,68,0.5)" }}
                />

                {/* IP */}
                <span className="font-mono text-sm text-[var(--text-primary)] flex-shrink-0 min-w-[130px]">
                  {r.ipAddress}
                </span>

                {/* Reason */}
                <span className="text-[var(--text-secondary)] text-xs flex-1 truncate">
                  {r.reason ?? <span className="text-[var(--text-tertiary)] italic">No reason provided</span>}
                </span>

                {/* Date */}
                <span className="text-[var(--text-tertiary)] text-[11px] flex-shrink-0 tabular">
                  {r.createdAt ? fmtDate(r.createdAt) : "—"}
                </span>

                {/* Unblock button */}
                <button
                  onClick={() => removeMut.mutate({ id: r.id })}
                  disabled={removeMut.isPending}
                  className="p-1.5 rounded opacity-0 group-hover:opacity-100 text-[var(--text-tertiary)] hover:text-red-400"
                  style={{ transition: "opacity 120ms, color 120ms" }}
                  title="Unblock"
                  onMouseDown={(e) => { e.currentTarget.style.transform = "scale(0.9)"; }}
                  onMouseUp={(e) => { e.currentTarget.style.transform = "scale(1)"; }}
                  onMouseLeave={(e) => { e.currentTarget.style.transform = "scale(1)"; }}
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
