import { db } from "../db/index.js";
import { responsePlaybooks, playbookActions, responseActionLogs } from "../db/schema.js";
import { eq, asc } from "drizzle-orm";

export async function executePlaybook(playbookId: number, incidentId: number): Promise<{ success: boolean; stepsExecuted: number; totalTime: number }> {
  const start = Date.now();
  let stepsExecuted = 0;

  try {
    const playbook = await db.query.responsePlaybooks.findFirst({ where: eq(responsePlaybooks.id, playbookId) });
    if (!playbook) throw new Error(`Playbook #${playbookId} not found`);

    const steps = await db
      .select()
      .from(playbookActions)
      .where(eq(playbookActions.playbookId, playbookId))
      .orderBy(asc(playbookActions.sequence));

    for (const step of steps) {
      const stepStart = Date.now();
      let status: "success" | "failed" = "success";
      let result = "";

      try {
        result = await simulateAction(step.actionType, step.actionParams as Record<string, unknown>);
        stepsExecuted++;
      } catch (err) {
        status = "failed";
        result = String(err);
      }

      await db.insert(responseActionLogs).values({
        incidentId,
        playbookId,
        actionType: step.actionType,
        actionParams: step.actionParams as Record<string, unknown>,
        status,
        result,
        executionTime: Date.now() - stepStart,
      });
    }

    const totalTime = Date.now() - start;
    const newAvg = playbook.avgExecutionTime
      ? Math.round((playbook.avgExecutionTime * playbook.executionCount + totalTime) / (playbook.executionCount + 1))
      : totalTime;

    await db
      .update(responsePlaybooks)
      .set({ executionCount: playbook.executionCount + 1, avgExecutionTime: newAvg })
      .where(eq(responsePlaybooks.id, playbookId));

    return { success: true, stepsExecuted, totalTime };
  } catch (err) {
    console.error("[PlaybookExecutor] Error:", err);
    return { success: false, stepsExecuted, totalTime: Date.now() - start };
  }
}

async function simulateAction(actionType: string, params: Record<string, unknown>): Promise<string> {
  await new Promise((r) => setTimeout(r, 50 + Math.random() * 200));
  const map: Record<string, string> = {
    isolate_host: `Host ${params.host ?? "target"} isolated from network`,
    collect_forensics: "Forensic snapshot collected",
    notify_team: `Team notified via ${params.channel ?? "in-app"}`,
    block_ip: `IP ${params.ip ?? "source"} added to blocklist`,
    reset_credentials: `Credentials reset for ${params.user ?? "affected user"}`,
    scan_network: "Network scan initiated",
    patch_vulnerability: `Patch applied: ${params.cve ?? "CVE-unknown"}`,
    quarantine_file: `File quarantined: ${params.file ?? "malicious file"}`,
  };
  return map[actionType] ?? `Action '${actionType}' executed`;
}
