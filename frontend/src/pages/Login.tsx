import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { storeAuth } from "@/lib/auth";
import { useLocation } from "wouter";
import { Shield, Eye, EyeOff, Lock, User } from "lucide-react";
import { toast } from "sonner";

export function LoginPage() {
  const [, navigate] = useLocation();
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("admin123");
  const [showPw, setShowPw] = useState(false);

  const login = trpc.auth.login.useMutation({
    onSuccess: (data) => {
      storeAuth(data.token, data.user);
      toast.success(`Welcome back, ${data.user.username}!`);
      navigate("/");
    },
    onError: (err) => toast.error(err.message),
  });

  return (
    <div
      className="min-h-screen flex items-center justify-center relative overflow-hidden"
      style={{ background: "var(--bg)" }}
    >
      {/* Subtle ambient — single, restrained */}
      <div
        className="absolute pointer-events-none"
        style={{
          top: "20%", left: "50%", transform: "translateX(-50%)",
          width: "600px", height: "400px",
          background: "radial-gradient(ellipse at center, rgba(37,99,235,0.06) 0%, transparent 70%)",
        }}
      />

      {/* Card — Emil: from scale(0.97) not scale(0), ease-out, under 300ms */}
      <div
        className="w-full max-w-sm px-4 page-enter"
      >
        <div
          className="p-8 rounded-xl"
          style={{
            background: "rgba(10,16,30,0.95)",
            border: "1px solid var(--border)",
            boxShadow: "0 24px 64px rgba(0,0,0,0.5)",
          }}
        >
          {/* Logo */}
          <div className="flex flex-col items-center mb-8">
            <div
              className="w-12 h-12 rounded-xl flex items-center justify-center mb-4"
              style={{
                background: "rgba(37,99,235,0.15)",
                border: "1px solid rgba(37,99,235,0.3)",
                boxShadow: "0 0 20px rgba(37,99,235,0.12)",
              }}
            >
              <Shield className="w-6 h-6 text-blue-400" />
            </div>
            <h1 className="text-lg font-semibold text-[var(--text-primary)]">SOC Platform</h1>
            <p className="text-[var(--text-tertiary)] text-xs mt-0.5">Security Operations Center</p>
          </div>

          <form
            onSubmit={(e) => { e.preventDefault(); login.mutate({ username, password }); }}
            className="space-y-3"
          >
            <div className="relative">
              <User className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[var(--text-tertiary)]" />
              <input
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Username"
                className="w-full rounded-lg pl-9 pr-4 py-2.5 text-sm text-[var(--text-primary)] placeholder-[var(--text-tertiary)] focus:outline-none"
                style={{
                  background: "rgba(255,255,255,0.04)",
                  border: "1px solid var(--border)",
                  transition: "border-color 150ms",
                }}
                onFocus={(e) => e.currentTarget.style.borderColor = "rgba(37,99,235,0.4)"}
                onBlur={(e) => e.currentTarget.style.borderColor = "var(--border)"}
              />
            </div>
            <div className="relative">
              <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[var(--text-tertiary)]" />
              <input
                type={showPw ? "text" : "password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Password"
                className="w-full rounded-lg pl-9 pr-10 py-2.5 text-sm text-[var(--text-primary)] placeholder-[var(--text-tertiary)] focus:outline-none"
                style={{
                  background: "rgba(255,255,255,0.04)",
                  border: "1px solid var(--border)",
                  transition: "border-color 150ms",
                }}
                onFocus={(e) => e.currentTarget.style.borderColor = "rgba(37,99,235,0.4)"}
                onBlur={(e) => e.currentTarget.style.borderColor = "var(--border)"}
              />
              <button
                type="button"
                onClick={() => setShowPw(!showPw)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-[var(--text-tertiary)] hover:text-[var(--text-secondary)] transition-colors duration-100"
              >
                {showPw ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
              </button>
            </div>

            <button
              type="submit"
              disabled={login.isPending}
              className="w-full py-2.5 rounded-lg text-sm font-medium text-white disabled:opacity-50 select-none"
              style={{
                background: "#2563eb",
                border: "1px solid rgba(59,130,246,0.3)",
                transition: "background-color 150ms, transform 100ms",
              }}
              onMouseDown={(e) => { e.currentTarget.style.transform = "scale(0.98)"; }}
              onMouseUp={(e) => { e.currentTarget.style.transform = "scale(1)"; }}
              onMouseLeave={(e) => { e.currentTarget.style.transform = "scale(1)"; }}
            >
              {login.isPending ? "Signing in…" : "Sign In"}
            </button>
          </form>

          <div className="mt-5 pt-5 border-t border-[var(--border)]">
            <p className="text-[var(--text-tertiary)] text-[11px] text-center mb-2.5">Demo accounts</p>
            <div className="grid grid-cols-2 gap-2">
              {[
                { u: "admin", p: "admin123", r: "Admin" },
                { u: "analyst", p: "analyst123", r: "Analyst" },
              ].map((c) => (
                <button
                  key={c.u}
                  onClick={() => { setUsername(c.u); setPassword(c.p); }}
                  className="text-left px-3 py-2 rounded-lg transition-colors duration-100 active:scale-[0.97]"
                  style={{
                    background: "rgba(255,255,255,0.02)",
                    border: "1px solid var(--border)",
                  }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(255,255,255,0.05)"; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = "rgba(255,255,255,0.02)"; }}
                >
                  <div className="text-[var(--text-secondary)] text-xs font-medium">{c.u}</div>
                  <div className="text-[var(--text-tertiary)] text-[11px]">{c.r}</div>
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
