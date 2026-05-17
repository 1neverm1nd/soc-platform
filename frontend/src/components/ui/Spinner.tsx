import { cn } from "@/lib/utils";

export function Spinner({ className }: { className?: string }) {
  return (
    <div className={cn("w-5 h-5 border-2 border-white/20 border-t-blue-400 rounded-full animate-spin", className)} />
  );
}

export function PageLoader() {
  return (
    <div className="flex items-center justify-center min-h-screen">
      <div className="flex flex-col items-center gap-3">
        <Spinner className="w-10 h-10" />
        <p className="text-[var(--text-tertiary)] text-sm">Loading...</p>
      </div>
    </div>
  );
}
