import { initTRPC, TRPCError } from "@trpc/server";
import superjson from "superjson";
import type { Request } from "express";
import jwt from "jsonwebtoken";
import type { JwtPayload } from "../middleware/auth.js";

export interface Context {
  req: Request;
  user?: JwtPayload;
}

export function createContext({ req }: { req: Request }): Context {
  const auth = req.headers.authorization;
  let user: JwtPayload | undefined;
  if (auth?.startsWith("Bearer ")) {
    try {
      user = jwt.verify(auth.slice(7), process.env.JWT_SECRET!) as JwtPayload;
    } catch {}
  }
  return { req, user };
}

const t = initTRPC.context<Context>().create({ transformer: superjson });

export const router = t.router;
export const publicProcedure = t.procedure;
export const protectedProcedure = t.procedure.use(({ ctx, next }) => {
  if (!ctx.user) throw new TRPCError({ code: "UNAUTHORIZED" });
  return next({ ctx: { ...ctx, user: ctx.user } });
});
