import { db } from "../db/index.js";
import { incidents, escalationPolicies, notifications } from "../db/schema.js";
import { eq, and, lte, inArray } from "drizzle-orm";

export async function runEscalationCheck(): Promise<void> {
  try {
    const policies = await db.select().from(escalationPolicies).where(eq(escalationPolicies.isActive, true));
    if (!policies.length) return;

    const severityRank: Record<string, number> = { low: 0, medium: 1, high: 2, critical: 3 };

    for (const policy of policies) {
      const cutoff = new Date(Date.now() - policy.timeoutMinutes * 60 * 1000);

      const staleIncidents = await db
        .select()
        .from(incidents)
        .where(
          and(
            inArray(incidents.status, ["open", "investigating"]),
            lte(incidents.createdAt, cutoff)
          )
        )
        .limit(20);

      const matching = staleIncidents.filter((i) => {
        const sevOk = (severityRank[i.severity] ?? 0) >= (severityRank[policy.minSeverity ?? "high"] ?? 2);
        const typeOk = !policy.incidentType || i.mlType === policy.incidentType;
        return sevOk && typeOk;
      });

      for (const incident of matching) {
        switch (policy.action) {
          case "notify_manager":
            await db.insert(notifications).values({
              userId: 1,
              type: "escalation",
              title: `Stale Incident #${incident.id} — Action Required`,
              message: `Incident open for >${policy.timeoutMinutes}min. Severity: ${incident.severity}`,
              incidentId: incident.id,
            });
            break;

          case "escalate_severity": {
            const ranks = ["low", "medium", "high", "critical"] as const;
            const idx = ranks.indexOf(incident.severity);
            if (idx < 3) {
              await db.update(incidents).set({ severity: ranks[idx + 1]! }).where(eq(incidents.id, incident.id));
            }
            break;
          }

          case "page_oncall":
            await db.insert(notifications).values({
              userId: 1,
              type: "escalation",
              title: `ON-CALL PAGE: Incident #${incident.id}`,
              message: `Critical escalation — incident unresolved for >${policy.timeoutMinutes}min`,
              incidentId: incident.id,
            });
            break;
        }
      }
    }
  } catch (err) {
    console.error("[EscalationManager] Error:", err);
  }
}
