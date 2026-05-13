import { z } from "zod";
import { router, protectedProcedure } from "./trpc.js";
import { db } from "../db/index.js";
import { responseRules } from "../db/schema.js";
import { eq, desc } from "drizzle-orm";
import { TRPCError } from "@trpc/server";

const ruleInput = z.object({
  name: z.string().min(1),
  description: z.string().optional(),
  priority: z.number().default(50),
  conditionType: z.string().optional(),
  conditionMinSeverity: z.enum(["low", "medium", "high", "critical"]).optional(),
  conditionMinConfidence: z.number().min(0).max(1).optional(),
  conditionIpPattern: z.string().optional(),
  actions: z.array(z.object({ type: z.string(), params: z.record(z.unknown()).optional() })),
});

export const rulesRouter = router({
  list: protectedProcedure.query(async () => {
    return db.select().from(responseRules).orderBy(responseRules.priority, desc(responseRules.createdAt));
  }),

  create: protectedProcedure.input(ruleInput).mutation(async ({ input }) => {
    const [result] = await db.insert(responseRules).values({ ...input, actions: input.actions });
    return { id: (result as { insertId: number }).insertId };
  }),

  update: protectedProcedure
    .input(ruleInput.extend({ id: z.number() }))
    .mutation(async ({ input }) => {
      const { id, ...data } = input;
      await db.update(responseRules).set(data).where(eq(responseRules.id, id));
      return { success: true };
    }),

  toggle: protectedProcedure
    .input(z.object({ id: z.number(), enabled: z.boolean() }))
    .mutation(async ({ input }) => {
      await db.update(responseRules).set({ isEnabled: input.enabled }).where(eq(responseRules.id, input.id));
      return { success: true };
    }),

  delete: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      await db.delete(responseRules).where(eq(responseRules.id, input.id));
      return { success: true };
    }),
});
