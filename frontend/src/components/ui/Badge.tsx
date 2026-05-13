import { cn } from "@/lib/utils";

interface BadgeProps {
  children: React.ReactNode;
  variant?: "default" | "critical" | "high" | "medium" | "low" | "outline" | "blue";
  className?: string;
}

const variants: Record<string, string> = {
  default: "bg-white/10 text-white",
  critical: "bg-red-500/20 text-red-400 border border-red-500/40",
  high: "bg-orange-500/20 text-orange-400 border border-orange-500/40",
  medium: "bg-yellow-500/20 text-yellow-400 border border-yellow-500/40",
  low: "bg-green-500/20 text-green-400 border border-green-500/40",
  outline: "border border-white/20 text-white/70",
  blue: "bg-blue-500/20 text-blue-400 border border-blue-500/40",
};

export function Badge({ children, variant = "default", className }: BadgeProps) {
  return (
    <span className={cn("inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-medium", variants[variant], className)}>
      {children}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: string }) {
  return <Badge variant={severity as "critical" | "high" | "medium" | "low"}>{severity.toUpperCase()}</Badge>;
}
