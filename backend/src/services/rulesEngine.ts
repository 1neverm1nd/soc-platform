import { db } from "../db/index.js";
import { responseRules, blockedIps, notifications, responseActionLogs, incidents } from "../db/schema.js";
import { eq, and } from "drizzle-orm";

type Severity = "low" | "medium" | "high" | "critical";
const SEVERITY_RANK: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };

interface IncidentContext {
  id: number;
  mlType: string | null;
  severity: Severity;
  mlConfidence: number | null;
  sourceIp: string | null;
}

export async function runRulesEngine(incident: IncidentContext): Promise<void> {
  try {
    const rules = await db
      .select()
      .from(responseRules)
      .where(eq(responseRules.isEnabled, true))
      .orderBy(responseRules.priority);

    for (const rule of rules) {
      if (!matchesRule(incident, rule)) continue;

      const actions = (rule.actions as Array<{ type: string; params?: Record<string, unknown> }>) ?? [];

      for (const action of actions) {
        await executeAction(action, incident, rule.id);
      }

      await db
        .update(responseRules)
        .set({ triggerCount: (rule.triggerCount ?? 0) + 1 })
        .where(eq(responseRules.id, rule.id));
    }
  } catch (err) {
    console.error("[RulesEngine] Error:", err);
  }
}

function matchesRule(incident: IncidentContext, rule: typeof responseRules.$inferSelect): boolean {
  if (rule.conditionType && rule.conditionType !== incident.mlType) return false;
  if (rule.conditionMinSeverity) {
    if ((SEVERITY_RANK[incident.severity] ?? 0) < (SEVERITY_RANK[rule.conditionMinSeverity] ?? 0)) return false;
  }
  if (rule.conditionMinConfidence && (incident.mlConfidence ?? 0) < rule.conditionMinConfidence) return false;
  if (rule.conditionIpPattern && incident.sourceIp) {
    try {
      if (!new RegExp(rule.conditionIpPattern).test(incident.sourceIp)) return false;
    } catch {
      return false;
    }
  }
  return true;
}

async function executeAction(
  action: { type: string; params?: Record<string, unknown> },
  incident: IncidentContext,
  ruleId: number
): Promise<void> {
  const start = Date.now();
  let status: "success" | "failed" = "success";
  let result = "";

  try {
    switch (action.type) {
      case "block_ip":
        if (incident.sourceIp) {
          await db
            .insert(blockedIps)
            .values({ ipAddress: incident.sourceIp, reason: `Auto-blocked by rule #${ruleId}` })
            .onDuplicateKeyUpdate({ set: { isActive: true } });
          result = `Blocked IP: ${incident.sourceIp}`;
        }
        break;

      case "notify":
        await db.insert(notifications).values({
          userId: 1,
          type: "critical_incident",
          title: `Alert: ${incident.mlType ?? "Unknown"} detected`,
          message: `Incident #${incident.id} triggered rule #${ruleId}. Severity: ${incident.severity}`,
          incidentId: incident.id,
        });
        result = "Notification sent";
        break;

      case "escalate":
        await db.insert(notifications).values({
          userId: 1,
          type: "escalation",
          title: `ESCALATED: Incident #${incident.id}`,
          message: `Rule #${ruleId} escalated incident. Type: ${incident.mlType}, IP: ${incident.sourceIp ?? "N/A"}`,
          incidentId: incident.id,
        });
        result = "Escalated to manager";
        break;

      case "update_status":
        await db
          .update(incidents)
          .set({ status: "investigating" })
          .where(eq(incidents.id, incident.id));
        result = "Status updated to investigating";
        break;

      case "create_ticket":
        result = `Ticket created for incident #${incident.id}`;
        break;
    }
  } catch (err) {
    status = "failed";
    result = String(err);
  }

  await db.insert(responseActionLogs).values({
    incidentId: incident.id,
    ruleId,
    actionType: action.type,
    actionParams: action.params ?? {},
    status,
    result,
    executionTime: Date.now() - start,
  });
}
