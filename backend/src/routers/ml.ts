import { z } from "zod";
import { router, protectedProcedure, publicProcedure } from "./trpc.js";
import { db } from "../db/index.js";
import { incidents } from "../db/schema.js";
import { eq, desc, isNotNull } from "drizzle-orm";
import { spawn } from "child_process";
import path from "path";
import { fileURLToPath } from "url";
import fs from "fs";
import { TRPCError } from "@trpc/server";
import { classifyLog, classifyWithFeatures, MITRE_MAP } from "../services/mlClassifier.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ML_DIR = path.join(__dirname, "../../ml");

const NetworkFeaturesSchema = z.object({
  proto:             z.string().optional(),
  service:           z.string().optional(),
  state:             z.string().optional(),
  dur:               z.number().optional(),
  spkts:             z.number().optional(),
  dpkts:             z.number().optional(),
  sbytes:            z.number().optional(),
  dbytes:            z.number().optional(),
  rate:              z.number().optional(),
  sttl:              z.number().optional(),
  dttl:              z.number().optional(),
  sload:             z.number().optional(),
  dload:             z.number().optional(),
  sloss:             z.number().optional(),
  dloss:             z.number().optional(),
  sinpkt:            z.number().optional(),
  dinpkt:            z.number().optional(),
  sjit:              z.number().optional(),
  djit:              z.number().optional(),
  swin:              z.number().optional(),
  stcpb:             z.number().optional(),
  dtcpb:             z.number().optional(),
  dwin:              z.number().optional(),
  tcprtt:            z.number().optional(),
  synack:            z.number().optional(),
  ackdat:            z.number().optional(),
  smean:             z.number().optional(),
  dmean:             z.number().optional(),
  trans_depth:       z.number().optional(),
  response_body_len: z.number().optional(),
  ct_srv_src:        z.number().optional(),
  ct_state_ttl:      z.number().optional(),
  ct_dst_ltm:        z.number().optional(),
  ct_src_dport_ltm:  z.number().optional(),
  ct_dst_sport_ltm:  z.number().optional(),
  ct_dst_src_ltm:    z.number().optional(),
  is_ftp_login:      z.number().optional(),
  ct_ftp_cmd:        z.number().optional(),
  ct_flw_http_mthd:  z.number().optional(),
  ct_src_ltm:        z.number().optional(),
  ct_srv_dst:        z.number().optional(),
  is_sm_ips_ports:   z.number().optional(),
});

function readJsonFile<T>(filename: string, fallback: T): T {
  const p = path.join(ML_DIR, filename);
  try {
    if (fs.existsSync(p)) {
      return JSON.parse(fs.readFileSync(p, "utf-8")) as T;
    }
  } catch {}
  return fallback;
}

export const mlRouter = router({
  // Model metadata: accuracy, F1, classes, feature importance, confusion matrix
  stats: protectedProcedure.query(async () => {
    const flowMeta  = readJsonFile("flow_model_metadata.json", null);
    const textMeta  = readJsonFile("model_metadata.json", null);
    const cm        = readJsonFile("flow_confusion_matrix.json", null);
    const shapData  = readJsonFile("shap_data.json", null);

    return {
      flowModel:  flowMeta,
      textModel:  textMeta,
      confusionMatrix: cm,
      shapData:   shapData,
      modelsAvailable: {
        flow:    fs.existsSync(path.join(ML_DIR, "flow_model.pkl")),
        text:    fs.existsSync(path.join(ML_DIR, "model.pkl")),
        anomaly: fs.existsSync(path.join(ML_DIR, "anomaly_model.pkl")),
      },
    };
  }),

  // Ingest an incident with optional network flow features
  ingestFlow: publicProcedure
    .input(z.object({
      rawLog:         z.string().min(1),
      sourceIp:       z.string().optional(),
      destinationIp:  z.string().optional(),
      threatCountry:  z.string().optional(),
      features:       NetworkFeaturesSchema.optional(),
    }))
    .mutation(async ({ input }) => {
      const mlResult = await classifyWithFeatures(input.rawLog, input.features ?? null);

      let abuseScore = 0;
      let country = input.threatCountry ?? null;

      const severity = calcSeverity(mlResult.type, mlResult.confidence, abuseScore);
      const mitre = MITRE_MAP[mlResult.type] ?? MITRE_MAP["normal"]!;

      const [result] = await db.insert(incidents).values({
        rawLog:        input.rawLog,
        sourceIp:      input.sourceIp ?? null,
        destinationIp: input.destinationIp ?? null,
        mlType:        mlResult.type,
        mlConfidence:  mlResult.confidence,
        severity,
        status:        "open",
        threatCountry: country,
        abuseScore,
        mitreId:       mitre.mitreId,
        mitreTechnique: mitre.mitreTechnique,
        mitreTactic:   mitre.mitreTactic,
      });

      const id = (result as { insertId: number }).insertId;
      return {
        id,
        mlType:      mlResult.type,
        severity,
        confidence:  mlResult.confidence,
        mode:        mlResult.mode        ?? "text",
        explanation: mlResult.explanation ?? [],
        anomalyScore: mlResult.anomalyScore ?? null,
        isAnomaly:   mlResult.isAnomaly   ?? false,
      };
    }),

  // Get SHAP explanation for a specific incident
  explainIncident: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const inc = await db.query.incidents.findFirst({ where: eq(incidents.id, input.id) });
      if (!inc) throw new TRPCError({ code: "NOT_FOUND" });

      const shapData = readJsonFile<{ perClassImportance: Record<string, Array<{ feature: string; importance: number }>> } | null>("shap_data.json", null);
      const perClass = shapData?.perClassImportance?.[inc.mlType ?? ""] ?? null;

      return {
        incidentId:        input.id,
        mlType:            inc.mlType,
        confidence:        inc.mlConfidence,
        severity:          inc.severity,
        topFeaturesGlobal: readJsonFile<{ globalImportance: Array<{ feature: string; importance: number }> } | null>("shap_data.json", null)?.globalImportance?.slice(0, 10) ?? [],
        topFeaturesForType: perClass?.slice(0, 10) ?? [],
        modelMode:         "flow+text ensemble",
      };
    }),

  // Per-class precision/recall breakdown
  perClassMetrics: protectedProcedure.query(async () => {
    const meta = readJsonFile<{ perClassMetrics?: Record<string, unknown> } | null>("flow_model_metadata.json", null);
    return meta?.perClassMetrics ?? {};
  }),

  // Confusion matrix data for visualization
  confusionMatrix: protectedProcedure.query(async () => {
    return readJsonFile("flow_confusion_matrix.json", null);
  }),

  // Feature importance (global SHAP)
  featureImportance: protectedProcedure.query(async () => {
    const shap = readJsonFile<{ globalImportance?: unknown; perClassImportance?: unknown } | null>("shap_data.json", null);
    return {
      global:   shap?.globalImportance ?? [],
      perClass: shap?.perClassImportance ?? {},
    };
  }),

  // Retrain text model with current analyst labels from DB
  retrain: protectedProcedure.mutation(async () => {
    const labeled = await db
      .select({ rawLog: incidents.rawLog, analystLabel: incidents.analystLabel })
      .from(incidents)
      .where(isNotNull(incidents.analystLabel));

    const realLabeled = labeled.filter((r) => r.analystLabel !== null);

    if (realLabeled.length < 20) {
      return {
        success: false,
        message: `Need at least 20 analyst-labeled incidents (have ${realLabeled.length}). Label incidents first.`,
        labeledCount: realLabeled.length,
      };
    }

    // Write combined CSV and trigger retrain
    const csvPath = path.join(ML_DIR, "analyst_labels.csv");
    const lines = ["text,label", ...realLabeled.map((r) =>
      `"${(r.rawLog ?? "").replace(/"/g, "'")}",${r.analystLabel}`
    )];
    fs.writeFileSync(csvPath, lines.join("\n"), "utf-8");

    return new Promise((resolve) => {
      const proc = spawn("python", [path.join(ML_DIR, "train_model.py"), csvPath], {
        timeout: 120000,
      });
      let out = "";
      proc.stdout.on("data", (d: Buffer) => { out += d.toString(); });
      proc.on("close", (code) => {
        resolve({
          success: code === 0,
          message: code === 0 ? "Model retrained with analyst labels" : "Retraining failed",
          labeledCount: realLabeled.length,
          output: out.slice(0, 500),
        });
      });
      proc.on("error", (e) => resolve({ success: false, message: String(e), labeledCount: 0, output: "" }));
    });
  }),

  // Live prediction test from UI
  predict: protectedProcedure
    .input(z.object({
      text:     z.string().min(1),
      features: NetworkFeaturesSchema.optional(),
    }))
    .mutation(async ({ input }) => {
      const result = await classifyWithFeatures(input.text, input.features ?? null);
      return result;
    }),
});

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
