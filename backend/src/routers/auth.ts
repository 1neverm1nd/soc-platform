import { z } from "zod";
import bcrypt from "bcryptjs";
import { router, publicProcedure, protectedProcedure } from "./trpc.js";
import { db } from "../db/index.js";
import { users } from "../db/schema.js";
import { eq } from "drizzle-orm";
import { signToken } from "../middleware/auth.js";
import { TRPCError } from "@trpc/server";

export const authRouter = router({
  login: publicProcedure
    .input(z.object({ username: z.string(), password: z.string() }))
    .mutation(async ({ input }) => {
      const user = await db.query.users.findFirst({ where: eq(users.username, input.username) });
      if (!user || !user.isActive) throw new TRPCError({ code: "UNAUTHORIZED", message: "Invalid credentials" });

      const valid = await bcrypt.compare(input.password, user.passwordHash);
      if (!valid) throw new TRPCError({ code: "UNAUTHORIZED", message: "Invalid credentials" });

      const token = signToken({ userId: user.id, role: user.role, username: user.username });
      return { token, user: { id: user.id, username: user.username, email: user.email, role: user.role } };
    }),

  me: protectedProcedure.query(async ({ ctx }) => {
    const user = await db.query.users.findFirst({ where: eq(users.id, ctx.user.userId) });
    if (!user) throw new TRPCError({ code: "NOT_FOUND" });
    return { id: user.id, username: user.username, email: user.email, role: user.role };
  }),

  register: publicProcedure
    .input(z.object({ username: z.string().min(3), email: z.string().email(), password: z.string().min(6), role: z.enum(["user", "analyst", "admin"]).default("analyst") }))
    .mutation(async ({ input }) => {
      const passwordHash = await bcrypt.hash(input.password, 12);
      const [result] = await db.insert(users).values({ username: input.username, email: input.email, passwordHash, role: input.role });
      const user = await db.query.users.findFirst({ where: eq(users.id, (result as { insertId: number }).insertId) });
      if (!user) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR" });
      const token = signToken({ userId: user.id, role: user.role, username: user.username });
      return { token, user: { id: user.id, username: user.username, email: user.email, role: user.role } };
    }),
});
