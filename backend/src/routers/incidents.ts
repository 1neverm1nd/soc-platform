import { z } from "zod";
import { router, publicProcedure, protectedProcedure } from "./trpc.js";
import { db } from "../db/index.js";
import { incidents, blockedIps, auditLogs } from "../db/schema.js";
import { eq, desc, and, inArray, like, gte, lte, count, sql } from "drizzle-orm";
import { classifyLog } from "../services/mlClassifier.js";
import { checkIpReputation } from "../services/threatIntel.js";
import { correlateIncident } from "../services/incidentCorrelator.js";
import { runRulesEngine } from "../services/rulesEngine.js";
import { broadcast } from "../services/sseManager.js";
import { analyzeIncident as llmAnalyze } from "../services/incidentAnalyzer.js";
import { TRPCError } from "@trpc/server";

function calcSeverity(type: string, confidence: number, abuseScore: number): "low" | "medium" | "high" | "critical" {
  const criticalTypes = new Set([
    "malware", "data-exfiltration", "privilege-escalation", "vulnerability-exploit",
    "ransomware", "shellcode", "backdoor",
  ]);
  const highTypes = new Set([
    "sql-injection", "phishing", "brute-force", "ddos",
    "lateral-movement", "command-and-control", "worm",
  ]);
  const mediumTypes = new Set([
    "unauthorized-access", "port-scanning", "network-analysis", "fuzzing", "cryptomining",
  ]);

  if (type === "normal") return "low";
  if (criticalTypes.has(type) && confidence > 0.8) return "critical";
  if (criticalTypes.has(type) || (highTypes.has(type) && confidence > 0.75) || abuseScore > 80) return "high";
  if (highTypes.has(type) || mediumTypes.has(type) || abuseScore > 50) return "medium";
  return "low";
}

export const incidentsRouter = router({
  ingest: publicProcedure
    .input(z.object({
      rawLog: z.string().min(1).max(8192, "Log too long — max 8192 chars"),
      sourceIp: z.string().ip({ version: "v4" }).or(z.string().ip({ version: "v6" })).optional(),
      destinationIp: z.string().ip({ version: "v4" }).or(z.string().ip({ version: "v6" })).optional(),
      threatCountry: z.string().max(2).optional(),
    }))
    .mutation(async ({ input }) => {
      const [mlResult, threatResult] = await Promise.all([
        classifyLog(input.rawLog),
        input.sourceIp ? checkIpReputation(input.sourceIp) : Promise.resolve(null),
      ]);

      const abuseScore = threatResult?.abuseScore ?? 0;
      const country = input.threatCountry ?? threatResult?.country ?? null;
      const severity = calcSeverity(mlResult.type, mlResult.confidence, abuseScore);

      const [result] = await db.insert(incidents).values({
        rawLog: input.rawLog,
        sourceIp: input.sourceIp ?? null,
        destinationIp: input.destinationIp ?? null,
        mlType: mlResult.type,
        mlConfidence: mlResult.confidence,
        severity,
        status: "open",
        threatCountry: country,
        abuseScore,
        mitreId: mlResult.mitreId,
        mitreTechnique: mlResult.mitreTechnique,
        mitreTactic: mlResult.mitreTactic,
      });

      const insertId = (result as { insertId: number }).insertId;

      broadcast("new_incident", {
        id: insertId,
        mlType: mlResult.type,
        severity,
        sourceIp: input.sourceIp,
        threatCountry: country,
        createdAt: new Date().toISOString(),
      });

      setImmediate(() => {
        correlateIncident(insertId, input.sourceIp ?? null).catch(console.error);
        runRulesEngine({ id: insertId, mlType: mlResult.type, severity, mlConfidence: mlResult.confidence, sourceIp: input.sourceIp ?? null }).catch(console.error);
      });

      return { id: insertId, mlType: mlResult.type, severity, confidence: mlResult.confidence };
    }),

  list: protectedProcedure
    .input(z.object({
      page: z.number().default(1),
      limit: z.number().max(100).default(20),
      status: z.enum(["open", "investigating", "resolved", "false_positive"]).optional(),
      severity: z.enum(["low", "medium", "high", "critical"]).optional(),
      mlType: z.string().optional(),
      search: z.string().optional(),
    }))
    .query(async ({ input }) => {
      const offset = (input.page - 1) * input.limit;
      const conditions = [];
      if (input.status) conditions.push(eq(incidents.status, input.status));
      if (input.severity) conditions.push(eq(incidents.severity, input.severity));
      if (input.mlType) conditions.push(eq(incidents.mlType, input.mlType));
      if (input.search) conditions.push(like(incidents.rawLog, `%${input.search}%`));

      const where = conditions.length > 0 ? and(...conditions) : undefined;

      const [rows, total] = await Promise.all([
        db.select().from(incidents).where(where).orderBy(desc(incidents.createdAt)).limit(input.limit).offset(offset),
        db.select({ count: count() }).from(incidents).where(where),
      ]);

      return { incidents: rows, total: Number(total[0]?.count ?? 0), page: input.page, limit: input.limit };
    }),

  getById: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const incident = await db.query.incidents.findFirst({ where: eq(incidents.id, input.id) });
      if (!incident) throw new TRPCError({ code: "NOT_FOUND" });
      return incident;
    }),

  updateStatus: protectedProcedure
    .input(z.object({ id: z.number(), status: z.enum(["open", "investigating", "resolved", "false_positive"]), notes: z.string().optional() }))
    .mutation(async ({ input, ctx }) => {
      await db.update(incidents).set({ status: input.status, analystNotes: input.notes }).where(eq(incidents.id, input.id));
      await db.insert(auditLogs).values({ userId: ctx.user.userId, action: "update_incident_status", entityType: "incident", entityId: input.id, details: { status: input.status } });
      return { success: true };
    }),

  setAnalystLabel: protectedProcedure
    .input(z.object({ id: z.number(), label: z.string() }))
    .mutation(async ({ input }) => {
      await db.update(incidents).set({ analystLabel: input.label }).where(eq(incidents.id, input.id));
      return { success: true };
    }),

  analyze: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const inc = await db.query.incidents.findFirst({ where: eq(incidents.id, input.id) });
      if (!inc) throw new TRPCError({ code: "NOT_FOUND" });

      // Try Gemini first, fall back to rule-based analysis
      let analysis = await llmAnalyze(inc.rawLog, inc.mlType ?? "unknown", inc.severity, inc.sourceIp);

      if (!analysis) {
        const actionMap: Record<string, string[]> = {
          "malware":              ["Isolate affected host immediately", "Run full AV scan", "Check for lateral movement", "Preserve forensic artifacts"],
          "brute-force":          ["Block source IP in firewall", "Reset compromised credentials", "Enable account lockout policy", "Review authentication logs"],
          "sql-injection":        ["Block attacker IP via WAF", "Patch vulnerable endpoint", "Review and sanitize all inputs", "Audit database access logs"],
          "phishing":             ["Quarantine phishing emails", "Reset affected user credentials", "Block malicious domain/URL", "Run user awareness training"],
          "ddos":                 ["Enable rate limiting / traffic scrubbing", "Contact upstream provider", "Activate CDN DDoS protection", "Monitor bandwidth usage"],
          "data-exfiltration":    ["Block outbound connection immediately", "Identify exfiltrated data scope", "Notify compliance/legal team", "Rotate exposed credentials"],
          "privilege-escalation": ["Revoke elevated privileges", "Patch exploited vulnerability", "Audit sudo/admin logs", "Review privilege assignment policy"],
          "unauthorized-access":  ["Terminate active session", "Review access control lists", "Enable MFA on targeted account", "Audit access logs"],
          "port-scanning":        ["Block scanning IP at perimeter", "Review exposed services", "Enable port scan detection IDS", "Reduce attack surface"],
          "vulnerability-exploit":["Apply security patch immediately", "Enable exploit mitigation (ASLR/DEP)", "Isolate vulnerable system", "Scan for similar vulnerabilities"],
          "ransomware":           ["Isolate host from network immediately", "Restore from clean backup", "Do NOT pay ransom", "Preserve encrypted files for forensics", "Report to authorities"],
          "lateral-movement":     ["Isolate compromised segments", "Reset all privileged credentials", "Review east-west firewall rules", "Audit Active Directory for anomalies"],
          "command-and-control":  ["Block C2 domain/IP at firewall", "Kill malicious process", "Identify and remove persistence mechanisms", "Scan for other infected hosts"],
          "cryptomining":         ["Kill mining process", "Block mining pool domains", "Patch exploited vulnerability", "Audit cloud resources for cost spikes"],
          "backdoor":             ["Remove backdoor service/file", "Audit startup tasks and cron jobs", "Full system forensics", "Rotate all service credentials"],
          "shellcode":            ["Kill injected process", "Patch exploited vulnerability", "Check for privilege escalation", "Enable DEP/ASLR system-wide"],
          "worm":                 ["Network quarantine of infected hosts", "Patch SMB/network share vulnerability", "Remove worm binary", "Scan all accessible hosts"],
          "fuzzing":              ["Review application crash logs", "Patch boundary conditions", "Enable input validation", "Deploy WAF rules"],
          "network-analysis":     ["Identify promiscuous mode NICs", "Check for unauthorized packet captures", "Audit who has raw socket access"],
          "normal":               ["No action required — benign activity confirmed"],
        };
        const iocMap: Record<string, string[]> = {
          "malware":              ["Suspicious process execution", "Unusual network callbacks", "Registry modifications"],
          "brute-force":          ["Multiple failed auth attempts", "High frequency login requests", "Credential stuffing pattern"],
          "sql-injection":        ["Anomalous SQL syntax in request", "Error-based enumeration", "UNION SELECT pattern"],
          "phishing":             ["Spoofed sender domain", "Credential harvesting page", "Malicious attachment/link"],
          "ddos":                 ["Traffic volume spike", "SYN/UDP flood pattern", "Botnet source diversity"],
          "data-exfiltration":    ["Large outbound transfer", "Unusual destination IP", "Encrypted C2 channel"],
          "ransomware":           ["File encryption activity", "Shadow copy deletion", "Ransom note creation"],
          "lateral-movement":     ["Pass-the-hash attempt", "SMB lateral spread", "PsExec or WMI remote execution"],
          "command-and-control":  ["Periodic beacon traffic", "Encrypted C2 channel", "DNS tunneling pattern"],
          "cryptomining":         ["High CPU utilization", "Mining pool connection", "Stratum protocol traffic"],
          "backdoor":             ["Unexpected listening port", "Persistence entry in startup", "Unusual outbound connection"],
          "shellcode":            ["Heap spray pattern", "ROP chain detected", "Process hollowing"],
          "worm":                 ["Self-replication across shares", "Rapid internal scanning", "Identical payload on multiple hosts"],
          "fuzzing":              ["Malformed input patterns", "Application crash or exception", "High error rate"],
          "network-analysis":     ["Promiscuous mode NIC", "Unexpected packet capture process", "ARP spoofing"],
        };
        const type = inc.mlType ?? "unknown";
        analysis = {
          summary: `${type.replace(/-/g, " ")} attack detected from ${inc.sourceIp ?? "unknown source"} targeting internal infrastructure. ML model classified with ${Math.round((inc.mlConfidence ?? 0.8) * 100)}% confidence.`,
          attackVector: `${inc.sourceIp ?? "Unknown"} -> ${inc.destinationIp ?? "internal host"} via ${type}`,
          affectedAssets: [inc.destinationIp ?? "internal-host", "network-perimeter"],
          indicators: iocMap[type] ?? ["Anomalous network traffic", "Policy violation detected"],
          recommendedActions: actionMap[type] ?? ["Investigate further", "Block source IP", "Escalate to security team"],
          riskScore: inc.severity === "critical" ? 9 : inc.severity === "high" ? 7 : inc.severity === "medium" ? 5 : 3,
          falsePositiveRisk: (inc.mlConfidence ?? 0) > 0.85 ? "low" : (inc.mlConfidence ?? 0) > 0.7 ? "medium" : "high",
        };
      }

      await db.update(incidents).set({ aiAnalysis: analysis }).where(eq(incidents.id, input.id));
      return analysis;
    }),

  saveAiAnalysis: protectedProcedure
    .input(z.object({ id: z.number(), analysis: z.any() }))
    .mutation(async ({ input }) => {
      await db.update(incidents).set({ aiAnalysis: input.analysis }).where(eq(incidents.id, input.id));
      return { success: true };
    }),

  bulkResolve: protectedProcedure
    .input(z.object({ ids: z.array(z.number()) }))
    .mutation(async ({ input, ctx }) => {
      await db.update(incidents).set({ status: "resolved" }).where(inArray(incidents.id, input.ids));
      await db.insert(auditLogs).values({ userId: ctx.user.userId, action: "bulk_resolve", entityType: "incident", details: { ids: input.ids } });
      return { success: true, count: input.ids.length };
    }),

  exportTrainingData: protectedProcedure.query(async () => {
    const labeled = await db.select({ rawLog: incidents.rawLog, analystLabel: incidents.analystLabel, mlType: incidents.mlType })
      .from(incidents)
      .where(sql`analyst_label IS NOT NULL`);
    return labeled;
  }),

  stats: protectedProcedure.query(async () => {
    const [total, critical, open, bySeverity, byType] = await Promise.all([
      db.select({ count: count() }).from(incidents),
      db.select({ count: count() }).from(incidents).where(eq(incidents.severity, "critical")),
      db.select({ count: count() }).from(incidents).where(inArray(incidents.status, ["open", "investigating"])),
      db.select({ severity: incidents.severity, count: count() }).from(incidents).groupBy(incidents.severity),
      db.select({ mlType: incidents.mlType, count: count() }).from(incidents).groupBy(incidents.mlType).orderBy(desc(count())).limit(10),
    ]);
    return {
      total: Number(total[0]?.count ?? 0),
      critical: Number(critical[0]?.count ?? 0),
      open: Number(open[0]?.count ?? 0),
      bySeverity,
      byType,
    };
  }),

  timeSeries: protectedProcedure
    .input(z.object({ days: z.number().default(30) }))
    .query(async ({ input }) => {
      const since = new Date(Date.now() - input.days * 24 * 3600 * 1000);
      const rows = await db
        .select({ date: sql<string>`DATE(created_at)`, count: count() })
        .from(incidents)
        .where(gte(incidents.createdAt, since))
        .groupBy(sql`DATE(created_at)`)
        .orderBy(sql`DATE(created_at)`);
      return rows;
    }),

  geoData: protectedProcedure.query(async () => {
    const rows = await db
      .select({ country: incidents.threatCountry, count: count(), severity: incidents.severity })
      .from(incidents)
      .where(sql`threat_country IS NOT NULL`)
      .groupBy(incidents.threatCountry, incidents.severity);
    return rows;
  }),

  networkGraph: protectedProcedure.query(async () => {
    const rows = await db
      .select({ sourceIp: incidents.sourceIp, destinationIp: incidents.destinationIp, mlType: incidents.mlType, severity: incidents.severity })
      .from(incidents)
      .where(sql`source_ip IS NOT NULL AND destination_ip IS NOT NULL`)
      .limit(200);
    return rows;
  }),

  heatmap: protectedProcedure.query(async () => {
    const rows = await db
      .select({ hour: sql<number>`HOUR(created_at)`, count: count() })
      .from(incidents)
      .groupBy(sql`HOUR(created_at)`)
      .orderBy(sql`HOUR(created_at)`);
    return rows;
  }),

  // Analyst verdict — True Positive / False Positive / Investigating
  // Feeds analyst_label for model retraining loop
  feedback: protectedProcedure
    .input(z.object({
      id:          z.number(),
      verdict:     z.enum(["true_positive", "false_positive", "investigating"]),
      correctType: z.string().optional(), // if analyst corrects the ML label
    }))
    .mutation(async ({ input, ctx }) => {
      const inc = await db.query.incidents.findFirst({ where: eq(incidents.id, input.id) });
      if (!inc) throw new TRPCError({ code: "NOT_FOUND" });

      const analystLabel = input.verdict === "false_positive"
        ? "normal"
        : (input.correctType ?? inc.mlType ?? "unknown");

      const newStatus = input.verdict === "false_positive"
        ? "false_positive" as const
        : input.verdict === "investigating"
        ? "investigating" as const
        : "resolved" as const;

      await db.update(incidents)
        .set({ analystLabel, status: newStatus })
        .where(eq(incidents.id, input.id));

      await db.insert(auditLogs).values({
        userId: ctx.user.userId,
        action: `analyst_${input.verdict}`,
        entityType: "incident",
        entityId: input.id,
        details: { verdict: input.verdict, analystLabel, mlType: inc.mlType },
      });

      // Count false positives — high FP rate from same IP is intel
      if (input.verdict === "false_positive" && inc.sourceIp) {
        const fpCount = await db
          .select({ count: count() })
          .from(incidents)
          .where(and(eq(incidents.sourceIp, inc.sourceIp), eq(incidents.analystLabel, "normal")));
        broadcast("analyst_feedback", {
          incidentId: input.id, verdict: input.verdict,
          sourceIp: inc.sourceIp, fpCountFromIp: Number(fpCount[0]?.count ?? 0),
        });
      }

      return { success: true, analystLabel, newStatus };
    }),

  // Related incidents from same source IP — for campaign context
  relatedByIp: protectedProcedure
    .input(z.object({ sourceIp: z.string(), excludeId: z.number(), limit: z.number().default(5) }))
    .query(async ({ input }) => {
      const rows = await db.select()
        .from(incidents)
        .where(and(eq(incidents.sourceIp, input.sourceIp), sql`id != ${input.excludeId}`))
        .orderBy(desc(incidents.createdAt))
        .limit(input.limit);
      return rows;
    }),

  // ML agreement rate — how often ML matches analyst label
  mlAgreementRate: protectedProcedure.query(async () => {
    const labeled = await db.select({ mlType: incidents.mlType, analystLabel: incidents.analystLabel })
      .from(incidents)
      .where(sql`analyst_label IS NOT NULL AND ml_type IS NOT NULL`);

    if (labeled.length === 0) return { rate: null, total: 0, agreements: 0 };

    const agreements = labeled.filter((r) => r.mlType === r.analystLabel).length;
    return {
      rate: Math.round((agreements / labeled.length) * 100),
      total: labeled.length,
      agreements,
    };
  }),
});
