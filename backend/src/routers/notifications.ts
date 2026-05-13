import { z } from "zod";
import { router, protectedProcedure } from "./trpc.js";
import { db } from "../db/index.js";
import { notifications, userNotificationPreferences } from "../db/schema.js";
import { eq, and, desc, count } from "drizzle-orm";

export const notificationsRouter = router({
  list: protectedProcedure
    .input(z.object({ type: z.string().optional() }))
    .query(async ({ ctx, input }) => {
      const conditions = [eq(notifications.userId, ctx.user.userId)];
      if (input.type) conditions.push(eq(notifications.type, input.type as "critical_incident" | "escalation" | "status_change" | "false_positive"));
      return db.select().from(notifications).where(and(...conditions)).orderBy(desc(notifications.createdAt)).limit(100);
    }),

  markRead: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      await db.update(notifications).set({ isRead: true }).where(eq(notifications.id, input.id));
      return { success: true };
    }),

  markAllRead: protectedProcedure.mutation(async ({ ctx }) => {
    await db.update(notifications).set({ isRead: true }).where(eq(notifications.userId, ctx.user.userId));
    return { success: true };
  }),

  unreadCount: protectedProcedure.query(async ({ ctx }) => {
    const result = await db.select({ count: count() }).from(notifications)
      .where(and(eq(notifications.userId, ctx.user.userId), eq(notifications.isRead, false)));
    return { count: Number(result[0]?.count ?? 0) };
  }),

  stats: protectedProcedure.query(async ({ ctx }) => {
    const [total, critical, unread] = await Promise.all([
      db.select({ count: count() }).from(notifications).where(eq(notifications.userId, ctx.user.userId)),
      db.select({ count: count() }).from(notifications).where(and(eq(notifications.userId, ctx.user.userId), eq(notifications.type, "critical_incident"))),
      db.select({ count: count() }).from(notifications).where(and(eq(notifications.userId, ctx.user.userId), eq(notifications.isRead, false))),
    ]);
    return {
      total: Number(total[0]?.count ?? 0),
      critical: Number(critical[0]?.count ?? 0),
      unread: Number(unread[0]?.count ?? 0),
    };
  }),

  getPreferences: protectedProcedure.query(async ({ ctx }) => {
    const pref = await db.query.userNotificationPreferences.findFirst({
      where: eq(userNotificationPreferences.userId, ctx.user.userId),
    });
    return pref;
  }),

  savePreferences: protectedProcedure
    .input(z.object({
      emailEnabled: z.boolean(),
      inAppEnabled: z.boolean(),
      minSeverity: z.enum(["low", "medium", "high", "critical"]),
      quietHoursStart: z.number().optional(),
      quietHoursEnd: z.number().optional(),
    }))
    .mutation(async ({ ctx, input }) => {
      await db.insert(userNotificationPreferences)
        .values({ userId: ctx.user.userId, ...input })
        .onDuplicateKeyUpdate({ set: input });
      return { success: true };
    }),
});
