export function cn(...classes: (string | undefined | false | null)[]): string {
  return classes.filter(Boolean).join(" ");
}

export function severityColor(severity: string): string {
  const map: Record<string, string> = {
    critical: "text-red-400 bg-red-500/15 border-red-500/40",
    high: "text-orange-400 bg-orange-500/15 border-orange-500/40",
    medium: "text-yellow-400 bg-yellow-500/15 border-yellow-500/40",
    low: "text-green-400 bg-green-500/15 border-green-500/40",
  };
  return map[severity] ?? "text-gray-400 bg-gray-500/15 border-gray-500/40";
}

export function severityDot(severity: string): string {
  const map: Record<string, string> = {
    critical: "bg-red-500",
    high: "bg-orange-500",
    medium: "bg-yellow-500",
    low: "bg-green-500",
  };
  return map[severity] ?? "bg-gray-500";
}

export function typeIcon(type: string): string {
  const map: Record<string, string> = {
    "normal":                "✅",
    "brute-force":           "🔑",
    "sql-injection":         "💉",
    "phishing":              "🎣",
    "malware":               "🦠",
    "ransomware":            "🔒",
    "ddos":                  "🌊",
    "data-exfiltration":     "📤",
    "privilege-escalation":  "⬆️",
    "unauthorized-access":   "🚪",
    "port-scanning":         "🔍",
    "network-analysis":      "📡",
    "vulnerability-exploit": "💥",
    "lateral-movement":      "↔️",
    "command-and-control":   "📡",
    "cryptomining":          "⛏️",
    "backdoor":              "🚪",
    "shellcode":             "⚙️",
    "worm":                  "🪱",
    "fuzzing":               "🎲",
  };
  return map[type] ?? "⚠️";
}

export function fmtDate(date: string | Date): string {
  return new Date(date).toLocaleString("en-US", {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
  });
}

export function fmtDateShort(date: string | Date): string {
  return new Date(date).toLocaleDateString("en-US", { month: "short", day: "numeric" });
}

export function confidenceColor(v: number): string {
  if (v >= 0.9) return "text-green-400";
  if (v >= 0.7) return "text-yellow-400";
  return "text-orange-400";
}

export const ATTACK_COLORS: Record<string, string> = {
  // original
  "brute-force":           "#f97316",
  "sql-injection":         "#8b5cf6",
  "phishing":              "#ec4899",
  "malware":               "#ef4444",
  "ddos":                  "#3b82f6",
  "data-exfiltration":     "#f59e0b",
  "privilege-escalation":  "#10b981",
  "unauthorized-access":   "#6366f1",
  "port-scanning":         "#14b8a6",
  "vulnerability-exploit": "#e11d48",
  // new classes
  "normal":                "#22c55e",
  "ransomware":            "#dc2626",
  "lateral-movement":      "#0ea5e9",
  "command-and-control":   "#7c3aed",
  "cryptomining":          "#d97706",
  "backdoor":              "#9f1239",
  "shellcode":             "#7e22ce",
  "worm":                  "#b45309",
  "fuzzing":               "#0d9488",
  "network-analysis":      "#0891b2",
};
