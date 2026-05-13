import { Route, Switch, Redirect, useLocation } from "wouter";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";
import { trpc, createTrpcClient } from "@/lib/trpc";
import { getStoredToken } from "@/lib/auth";
import { Layout } from "@/components/Layout";
import { AttackSimulator } from "@/components/AttackSimulator";
import { LoginPage } from "@/pages/Login";
import { DashboardPage } from "@/pages/Dashboard";
import { IncidentsPage } from "@/pages/Incidents";
import { AnalyticsPage } from "@/pages/Analytics";
import { GeoMapPage } from "@/pages/GeoMap";
import { NetworkGraphPage } from "@/pages/NetworkGraph";
import { RulesPage } from "@/pages/Rules";
import { PlaybooksPage } from "@/pages/Playbooks";
import { NotificationsPage } from "@/pages/Notifications";
import { MLDashboardPage } from "@/pages/MLDashboard";
import { Toaster } from "sonner";

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const [location] = useLocation();
  const token = getStoredToken();
  if (!token) return <Redirect to="/login" />;
  return <>{children}</>;
}

export default function App() {
  const [queryClient] = useState(() => new QueryClient({
    defaultOptions: { queries: { retry: 1, staleTime: 10000 } },
  }));
  const [trpcClient] = useState(() => createTrpcClient());

  return (
    <trpc.Provider client={trpcClient} queryClient={queryClient}>
      <QueryClientProvider client={queryClient}>
        <Switch>
          <Route path="/login" component={LoginPage} />

          <Route path="/">
            <ProtectedRoute>
              <Layout>
                <DashboardPage />
              </Layout>
              <AttackSimulator />
            </ProtectedRoute>
          </Route>

          <Route path="/incidents">
            <ProtectedRoute>
              <Layout><IncidentsPage /></Layout>
              <AttackSimulator />
            </ProtectedRoute>
          </Route>

          <Route path="/analytics">
            <ProtectedRoute>
              <Layout><AnalyticsPage /></Layout>
              <AttackSimulator />
            </ProtectedRoute>
          </Route>

          <Route path="/geo">
            <ProtectedRoute>
              <Layout><GeoMapPage /></Layout>
              <AttackSimulator />
            </ProtectedRoute>
          </Route>

          <Route path="/network">
            <ProtectedRoute>
              <Layout><NetworkGraphPage /></Layout>
              <AttackSimulator />
            </ProtectedRoute>
          </Route>

          <Route path="/rules">
            <ProtectedRoute>
              <Layout><RulesPage /></Layout>
              <AttackSimulator />
            </ProtectedRoute>
          </Route>

          <Route path="/playbooks">
            <ProtectedRoute>
              <Layout><PlaybooksPage /></Layout>
              <AttackSimulator />
            </ProtectedRoute>
          </Route>

          <Route path="/notifications">
            <ProtectedRoute>
              <Layout><NotificationsPage /></Layout>
              <AttackSimulator />
            </ProtectedRoute>
          </Route>

          <Route path="/ml">
            <ProtectedRoute>
              <Layout><MLDashboardPage /></Layout>
              <AttackSimulator />
            </ProtectedRoute>
          </Route>

          <Route><Redirect to="/" /></Route>
        </Switch>

        <Toaster
          position="top-right"
          theme="dark"
          toastOptions={{
            style: { background: "rgba(17,24,39,0.95)", border: "1px solid rgba(255,255,255,0.1)", color: "white" },
          }}
        />
      </QueryClientProvider>
    </trpc.Provider>
  );
}
