export interface AuthUser {
  id: number;
  username: string;
  email: string;
  role: "user" | "analyst" | "admin";
}

export function getStoredToken(): string | null {
  return localStorage.getItem("soc_token");
}

export function getStoredUser(): AuthUser | null {
  const raw = localStorage.getItem("soc_user");
  if (!raw) return null;
  try { return JSON.parse(raw) as AuthUser; } catch { return null; }
}

export function storeAuth(token: string, user: AuthUser): void {
  localStorage.setItem("soc_token", token);
  localStorage.setItem("soc_user", JSON.stringify(user));
}

export function clearAuth(): void {
  localStorage.removeItem("soc_token");
  localStorage.removeItem("soc_user");
}
