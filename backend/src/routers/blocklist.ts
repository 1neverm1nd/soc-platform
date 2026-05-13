import { z } from "zod";
import { router, protectedProcedure } from "./trpc.js";
import { db } from "../db/index.js";
import { blockedIps } from "../db/schema.js";
import { eq, desc, count } from "drizzle-orm";

export const blocklistRouter = router({
  list: protectedProcedure.query(async () => {
    return db.select().from(blockedIps).where(eq(blockedIps.isActive, true)).orderBy(desc(blockedIps.createdAt)).limit(100);
  }),

  count: protectedProcedure.query(async () => {
    const result = await db.select({ count: count() }).from(blockedIps).where(eq(blockedIps.isActive, true));
    return { count: Number(result[0]?.count ?? 0) };
  }),

  add: protectedProcedure
    .input(z.object({ ipAddress: z.string(), reason: z.string().optional() }))
    .mutation(async ({ input, ctx }) => {
      await db.insert(blockedIps)
        .values({ ipAddress: input.ipAddress, reason: input.reason, blockedBy: ctx.user.userId })
        .onDuplicateKeyUpdate({ set: { isActive: true, reason: input.reason } });
      return { success: true };
    }),

  remove: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      await db.update(blockedIps).set({ isActive: false }).where(eq(blockedIps.id, input.id));
      return { success: true };
    }),
});
