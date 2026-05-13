import { z } from "zod";
import { router, protectedProcedure } from "./trpc.js";
import { db } from "../db/index.js";
import { responsePlaybooks, playbookActions, responseActionLogs } from "../db/schema.js";
import { eq, desc, count } from "drizzle-orm";
import { executePlaybook } from "../services/playbookExecutor.js";

export const playbooksRouter = router({
  list: protectedProcedure.query(async () => {
    const playbooks = await db.select().from(responsePlaybooks).orderBy(desc(responsePlaybooks.createdAt));
    const withActions = await Promise.all(
      playbooks.map(async (p) => {
        const actions = await db.select().from(playbookActions).where(eq(playbookActions.playbookId, p.id)).orderBy(playbookActions.sequence);
        return { ...p, actions };
      })
    );
    return withActions;
  }),

  create: protectedProcedure
    .input(z.object({
      name: z.string().min(1),
      description: z.string().optional(),
      incidentType: z.string().optional(),
      actions: z.array(z.object({
        sequence: z.number(),
        actionType: z.string(),
        actionParams: z.record(z.unknown()).optional(),
        description: z.string().optional(),
      })),
    }))
    .mutation(async ({ input }) => {
      const [result] = await db.insert(responsePlaybooks).values({ name: input.name, description: input.description, incidentType: input.incidentType });
      const playbookId = (result as { insertId: number }).insertId;
      if (input.actions.length > 0) {
        await db.insert(playbookActions).values(input.actions.map((a) => ({ ...a, playbookId, actionParams: a.actionParams ?? {} })));
      }
      return { id: playbookId };
    }),

  execute: protectedProcedure
    .input(z.object({ playbookId: z.number(), incidentId: z.number() }))
    .mutation(async ({ input }) => {
      return executePlaybook(input.playbookId, input.incidentId);
    }),

  stats: protectedProcedure.query(async () => {
    const [total, active, logs] = await Promise.all([
      db.select({ count: count() }).from(responsePlaybooks),
      db.select({ count: count() }).from(responsePlaybooks).where(eq(responsePlaybooks.isActive, true)),
      db.select({ count: count() }).from(responseActionLogs).where(eq(responseActionLogs.status, "success")),
    ]);
    return {
      total: Number(total[0]?.count ?? 0),
      active: Number(active[0]?.count ?? 0),
      executed: Number(logs[0]?.count ?? 0),
    };
  }),

  delete: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      await db.delete(playbookActions).where(eq(playbookActions.playbookId, input.id));
      await db.delete(responsePlaybooks).where(eq(responsePlaybooks.id, input.id));
      return { success: true };
    }),
});
