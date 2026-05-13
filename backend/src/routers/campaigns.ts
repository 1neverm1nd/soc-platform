import { router, protectedProcedure } from "./trpc.js";
import { db } from "../db/index.js";
import { attackCampaigns } from "../db/schema.js";
import { eq, desc, count } from "drizzle-orm";
import { z } from "zod";

export const campaignsRouter = router({
  list: protectedProcedure.query(async () => {
    return db.select().from(attackCampaigns).where(eq(attackCampaigns.isActive, true)).orderBy(desc(attackCampaigns.lastSeen)).limit(20);
  }),

  count: protectedProcedure.query(async () => {
    const result = await db.select({ count: count() }).from(attackCampaigns).where(eq(attackCampaigns.isActive, true));
    return { count: Number(result[0]?.count ?? 0) };
  }),
});
