import { cn } from "@/lib/utils";

interface CardProps {
  children: React.ReactNode;
  className?: string;
  onClick?: () => void;
  glow?: "red" | "blue" | "green" | "yellow";
}

export function Card({ children, className, onClick, glow }: CardProps) {
  const glowClass = glow ? `glow-${glow}` : "";
  return (
    <div
      onClick={onClick}
      className={cn(
        "card p-4",
        // Emil: specify exact properties on transition
        "transition-[border-color,box-shadow] duration-150",
        glow && glowClass,
        onClick && "cursor-pointer active:scale-[0.98] hover:border-[var(--border-hover)]",
        className
      )}
    >
      {children}
    </div>
  );
}

export function CardHeader({ children, className }: { children: React.ReactNode; className?: string }) {
  return <div className={cn("flex items-center justify-between mb-4", className)}>{children}</div>;
}

export function CardTitle({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <h3 className={cn("text-xs font-semibold text-[var(--text-secondary)] uppercase tracking-wider", className)}>
      {children}
    </h3>
  );
}
