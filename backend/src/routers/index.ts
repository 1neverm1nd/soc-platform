import { router } from "./trpc.js";
import { authRouter } from "./auth.js";
import { incidentsRouter } from "./incidents.js";
import { rulesRouter } from "./rules.js";
import { playbooksRouter } from "./playbooks.js";
import { notificationsRouter } from "./notifications.js";
import { campaignsRouter } from "./campaigns.js";
import { blocklistRouter } from "./blocklist.js";
import { mlRouter } from "./ml.js";

export const appRouter = router({
  auth: authRouter,
  incident: incidentsRouter,
  rules: rulesRouter,
  playbooks: playbooksRouter,
  notifications: notificationsRouter,
  campaigns: campaignsRouter,
  blocklist: blocklistRouter,
  ml: mlRouter,
});

export type AppRouter = typeof appRouter;
