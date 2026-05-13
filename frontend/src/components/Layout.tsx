import { Link, useLocation } from "wouter";
import { trpc } from "@/lib/trpc";
import { clearAuth, getStoredUser } from "@/lib/auth";
import { cn } from "@/lib/utils";
import {
  Shield, LayoutDashboard, AlertTriangle, BarChart3, Globe,
  Network, Zap, BookOpen, Bell, LogOut, User, Brain
} from "lucide-react";

const NAV = [
  { href: "/", icon: LayoutDashboard, label: "Dashboard" },
  { href: "/incidents", icon: AlertTriangle, label: "Incidents" },
  { href: "/analytics", icon: BarChart3, label: "Analytics" },
  { href: "/ml", icon: Brain, label: "ML Dashboard" },
  { href: "/geo", icon: Globe, label: "Geo Map" },
  { href: "/network", icon: Network, label: "Network Graph" },
  { href: "/rules", icon: Zap, label: "Rules" },
  { href: "/playbooks", icon: BookOpen, label: "Playbooks" },
  { href: "/notifications", icon: Bell, label: "Notifications" },
];

export function Layout({ children }: { children: React.ReactNode }) {
  const [location, navigate] = useLocation();
  const user = getStoredUser();
  const unread = trpc.notifications.unreadCount.useQuery(undefined, { refetchInterval: 30000 });

  function handleLogout() {
    clearAuth();
    navigate("/login");
  }

  return (
    <div className="flex min-h-screen" style={{ background: "var(--bg)" }}>
      {/* Sidebar — clean, no heavy glassmorphism */}
      <aside
        className="w-56 flex-shrink-0 flex flex-col"
        style={{
          background: "rgba(8,12,22,0.95)",
          borderRight: "1px solid var(--border)",
        }}
      >
        {/* Logo */}
        <div className="flex items-center gap-3 px-4 h-14 border-b border-[var(--border)]">
          <div
            className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0"
            style={{
              background: "rgba(37,99,235,0.2)",
              border: "1px solid rgba(37,99,235,0.35)",
              boxShadow: "0 0 12px rgba(37,99,235,0.15)",
            }}
          >
            <Shield className="w-3.5 h-3.5 text-blue-400" />
          </div>
          <div>
            <div className="text-[var(--text-primary)] font-semibold text-sm leading-tight">SOC Platform</div>
            <div className="text-[var(--text-tertiary)] text-[10px]">Security Operations</div>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 px-2 py-3">
          {NAV.map(({ href, icon: Icon, label }) => {
            const active = location === href;
            return (
              <Link key={href} href={href}>
                <div
                  className={cn(
                    "flex items-center gap-2.5 px-3 py-2 rounded-md text-sm mb-0.5",
                    // Emil: transition-colors not transition-all
                    "transition-colors duration-100",
                    "cursor-pointer select-none",
                    active
                      ? "bg-blue-600/12 text-blue-400"
                      : "text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-white/4"
                  )}
                  style={active ? { border: "1px solid rgba(37,99,235,0.2)" } : { border: "1px solid transparent" }}
                >
                  <Icon
                    className={cn("w-3.5 h-3.5 flex-shrink-0", active ? "text-blue-400" : "text-[var(--text-tertiary)]")}
                    strokeWidth={active ? 2 : 1.75}
                  />
                  <span className="flex-1 text-xs font-medium">{label}</span>
                  {label === "Notifications" && (unread.data?.count ?? 0) > 0 && (
                    <span
                      className="text-white text-[10px] px-1.5 py-0.5 rounded-full min-w-[18px] text-center font-medium tabular"
                      style={{ background: "#ef4444", fontSize: "10px" }}
                    >
                      {unread.data?.count}
                    </span>
                  )}
                </div>
              </Link>
            );
          })}
        </nav>

        {/* User footer */}
        <div className="px-2 pb-3 border-t border-[var(--border)] pt-3">
          <div className="flex items-center gap-2.5 px-3 py-2 rounded-md">
            <div
              className="w-6 h-6 rounded-full flex items-center justify-center flex-shrink-0"
              style={{ background: "rgba(37,99,235,0.2)", border: "1px solid rgba(37,99,235,0.3)" }}
            >
              <User className="w-3 h-3 text-blue-400" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="text-[var(--text-primary)] text-xs font-medium truncate">{user?.username ?? "User"}</div>
              <div className="text-[var(--text-tertiary)] text-[10px] capitalize">{user?.role}</div>
            </div>
            <button
              onClick={handleLogout}
              // Emil: active:scale on interactive element
              className="p-1 rounded text-[var(--text-tertiary)] hover:text-red-400 transition-colors duration-100 active:scale-90"
              title="Sign out"
            >
              <LogOut className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </aside>

      {/* Main content — page-enter CSS animation (off main thread) */}
      <main className="flex-1 overflow-auto">
        {/* Emil: CSS animation for page transitions — faster & off main thread vs Framer Motion */}
        <div key={location} className="page-enter min-h-screen">
          {children}
        </div>
      </main>
    </div>
  );
}
