import { z } from "zod";
import { router, protectedProcedure } from "./trpc.js";
import { db } from "../db/index.js";
import { blockedIps } from "../db/schema.js";
import { eq, desc, count } from "drizzle-orm";
import { broadcast } from "../services/sseManager.js";

export const blocklistRouter = router({
  list: protectedProcedure.query(async () => {
    return db.select().from(blockedIps).where(eq(blockedIps.isActive, true)).orderBy(desc(blockedIps.createdAt)).limit(100);
  }),

  count: protectedProcedure.query(async () => {
    const result = await db.select({ count: count() }).from(blockedIps).where(eq(blockedIps.isActive, true));
    return { count: Number(result[0]?.count ?? 0) };
  }),

  add: protectedProcedure
    .input(z.object({
      ipAddress: z.string().ip({ version: "v4" }).or(z.string().ip({ version: "v6" })),
      reason: z.string().max(500).optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      await db.insert(blockedIps)
        .values({ ipAddress: input.ipAddress, reason: input.reason, blockedBy: ctx.user.userId })
        .onDuplicateKeyUpdate({ set: { isActive: true, reason: input.reason } });
      broadcast("blocklist_update", { action: "block", ip: input.ipAddress });
      return { success: true };
    }),

  remove: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const entry = await db.query.blockedIps.findFirst({ where: eq(blockedIps.id, input.id) });
      await db.update(blockedIps).set({ isActive: false }).where(eq(blockedIps.id, input.id));
      if (entry?.ipAddress) broadcast("blocklist_update", { action: "unblock", ip: entry.ipAddress });
      return { success: true };
    }),
});
