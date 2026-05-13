import { cn } from "@/lib/utils";
import type { ButtonHTMLAttributes } from "react";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary" | "ghost" | "danger" | "outline";
  size?: "sm" | "md" | "lg";
}

const variants: Record<string, string> = {
  primary:   "bg-blue-600 hover:bg-blue-500 text-white border border-blue-500/30",
  secondary: "bg-white/8 hover:bg-white/12 text-white border border-white/10",
  ghost:     "text-[var(--text-secondary)] hover:text-white hover:bg-white/6",
  danger:    "bg-red-500/15 hover:bg-red-500/25 text-red-400 border border-red-500/25",
  outline:   "border border-[var(--border)] hover:border-[var(--border-hover)] hover:bg-white/4 text-[var(--text-primary)]",
};

const sizes: Record<string, string> = {
  sm: "px-2.5 py-1.5 text-xs gap-1.5 rounded-md",
  md: "px-3.5 py-2 text-sm gap-2 rounded-lg",
  lg: "px-5 py-2.5 text-sm gap-2 rounded-lg",
};

export function Button({ variant = "secondary", size = "md", className, children, disabled, ...props }: ButtonProps) {
  return (
    <button
      {...props}
      disabled={disabled}
      className={cn(
        // Emil: specify exact properties, never `transition: all`
        // Emil: scale(0.97) on active — buttons must feel responsive
        "inline-flex items-center font-medium",
        "transition-colors duration-150",
        "active:scale-[0.97] active:transition-transform active:duration-100",
        "disabled:opacity-40 disabled:cursor-not-allowed disabled:active:scale-100",
        "select-none",
        variants[variant],
        sizes[size],
        className
      )}
    >
      {children}
    </button>
  );
}
