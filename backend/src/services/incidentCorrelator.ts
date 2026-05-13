import { db } from "../db/index.js";
import { incidents, attackCampaigns } from "../db/schema.js";
import { eq, gte, and, count, sql } from "drizzle-orm";

const CORRELATION_WINDOW_MS = 30 * 60 * 1000; // 30 minutes
const MIN_INCIDENTS = 3;

export async function correlateIncident(incidentId: number, sourceIp: string | null): Promise<void> {
  if (!sourceIp) return;

  try {
    const windowStart = new Date(Date.now() - CORRELATION_WINDOW_MS);

    const recent = await db
      .select({ count: count() })
      .from(incidents)
      .where(and(eq(incidents.sourceIp, sourceIp), gte(incidents.createdAt, windowStart)));

    const incidentCount = Number(recent[0]?.count ?? 0);
    if (incidentCount < MIN_INCIDENTS) return;

    const typeRows = await db
      .select({ mlType: incidents.mlType })
      .from(incidents)
      .where(and(eq(incidents.sourceIp, sourceIp), gte(incidents.createdAt, windowStart)));

    const attackTypes = [...new Set(typeRows.map((r) => r.mlType).filter(Boolean))];

    const severities = await db
      .select({ severity: incidents.severity })
      .from(incidents)
      .where(and(eq(incidents.sourceIp, sourceIp), gte(incidents.createdAt, windowStart)));

    const severityRank = { low: 0, medium: 1, high: 2, critical: 3 };
    const maxSeverity = severities.reduce((max, r) => {
      return (severityRank[r.severity] ?? 0) > (severityRank[max] ?? 0) ? r.severity : max;
    }, "medium" as "low" | "medium" | "high" | "critical");

    await db
      .insert(attackCampaigns)
      .values({
        sourceIp,
        incidentCount,
        severity: maxSeverity,
        attackTypes: attackTypes as string[],
        lastSeen: new Date(),
        isActive: true,
      })
      .onDuplicateKeyUpdate({
        set: {
          incidentCount,
          severity: maxSeverity,
          attackTypes: attackTypes as string[],
          lastSeen: new Date(),
          isActive: true,
        },
      });

    console.log(`[Correlator] Campaign updated for ${sourceIp}: ${incidentCount} incidents`);
  } catch (err) {
    console.error("[Correlator] Error:", err);
  }
}
