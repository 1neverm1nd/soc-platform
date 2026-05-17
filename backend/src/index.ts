import "dotenv/config";
import express from "express";
import cors from "cors";
import { createExpressMiddleware } from "@trpc/server/adapters/express";
import { appRouter } from "./routers/index.js";
import { createContext } from "./routers/trpc.js";
import { addSseClient, getSseClientCount } from "./services/sseManager.js";
import { runEscalationCheck } from "./services/escalationManager.js";
import { db } from "./db/index.js";
import { users } from "./db/schema.js";
import bcrypt from "bcryptjs";
import { eq } from "drizzle-orm";

const app = express();
const PORT = Number(process.env.PORT ?? 3001);

app.use(cors({ origin: "*", credentials: true }));
app.use(express.json({ limit: "10mb" }));

app.get("/health", (_req, res) => res.json({ status: "ok", sseClients: getSseClientCount(), ts: Date.now() }));

app.get("/events", (req, res) => {
  addSseClient(res);
});

app.use(
  "/trpc",
  createExpressMiddleware({
    router: appRouter,
    createContext: ({ req }) => createContext({ req }),
  })
);

async function seedDefaultUser() {
  try {
    const existing = await db.query.users.findFirst({ where: eq(users.username, "admin") });
    if (!existing) {
      const passwordHash = await bcrypt.hash("admin123", 12);
      await db.insert(users).values({ username: "admin", email: "admin@soc.local", passwordHash, role: "admin" });
      console.log("[Seed] Default admin user created (admin/admin123)");
    }
    const analyst = await db.query.users.findFirst({ where: eq(users.username, "analyst") });
    if (!analyst) {
      const passwordHash = await bcrypt.hash("analyst123", 12);
      await db.insert(users).values({ username: "analyst", email: "analyst@soc.local", passwordHash, role: "analyst" });
      console.log("[Seed] Default analyst user created (analyst/analyst123)");
    }
  } catch (err) {
    console.error("[Seed] Error:", err);
  }
}

setInterval(() => runEscalationCheck(), 5 * 60 * 1000);

app.listen(PORT, async () => {
  console.log(`🚀 SOC Platform backend running on http://localhost:${PORT}`);
  await seedDefaultUser();
});
