import {
  mysqlTable, varchar, int, text, boolean, timestamp,
  float, json, mysqlEnum, index, bigint
} from "drizzle-orm/mysql-core";

export const users = mysqlTable("users", {
  id: int("id").primaryKey().autoincrement(),
  username: varchar("username", { length: 100 }).notNull().unique(),
  email: varchar("email", { length: 255 }).notNull().unique(),
  passwordHash: varchar("password_hash", { length: 255 }).notNull(),
  role: mysqlEnum("role", ["user", "analyst", "admin"]).notNull().default("analyst"),
  isActive: boolean("is_active").notNull().default(true),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().onUpdateNow().notNull(),
});

export const incidents = mysqlTable("incidents", {
  id: int("id").primaryKey().autoincrement(),
  rawLog: text("raw_log").notNull(),
  sourceIp: varchar("source_ip", { length: 45 }),
  destinationIp: varchar("destination_ip", { length: 45 }),
  mlType: varchar("ml_type", { length: 100 }),
  mlConfidence: float("ml_confidence"),
  analystLabel: varchar("analyst_label", { length: 100 }),
  severity: mysqlEnum("severity", ["low", "medium", "high", "critical"]).notNull().default("medium"),
  status: mysqlEnum("status", ["open", "investigating", "resolved", "false_positive"]).notNull().default("open"),
  threatCountry: varchar("threat_country", { length: 100 }),
  abuseScore: int("abuse_score"),
  mitreId: varchar("mitre_id", { length: 20 }),
  mitreTechnique: varchar("mitre_technique", { length: 200 }),
  mitreTactic: varchar("mitre_tactic", { length: 100 }),
  aiAnalysis: json("ai_analysis"),
  analystNotes: text("analyst_notes"),
  campaignId: int("campaign_id"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().onUpdateNow().notNull(),
}, (t) => [
  index("idx_source_ip").on(t.sourceIp),
  index("idx_status").on(t.status),
  index("idx_severity").on(t.severity),
  index("idx_created_at").on(t.createdAt),
]);

export const blockedIps = mysqlTable("blocked_ips", {
  id: int("id").primaryKey().autoincrement(),
  ipAddress: varchar("ip_address", { length: 45 }).notNull().unique(),
  reason: text("reason"),
  blockedBy: int("blocked_by"),
  isActive: boolean("is_active").notNull().default(true),
  expiresAt: timestamp("expires_at"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const auditLogs = mysqlTable("audit_logs", {
  id: bigint("id", { mode: "number" }).primaryKey().autoincrement(),
  userId: int("user_id"),
  action: varchar("action", { length: 100 }).notNull(),
  entityType: varchar("entity_type", { length: 50 }),
  entityId: int("entity_id"),
  details: json("details"),
  ipAddress: varchar("ip_address", { length: 45 }),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const responseRules = mysqlTable("response_rules", {
  id: int("id").primaryKey().autoincrement(),
  name: varchar("name", { length: 200 }).notNull(),
  description: text("description"),
  isEnabled: boolean("is_enabled").notNull().default(true),
  priority: int("priority").notNull().default(50),
  conditionType: varchar("condition_type", { length: 100 }),
  conditionMinSeverity: mysqlEnum("condition_min_severity", ["low", "medium", "high", "critical"]),
  conditionMinConfidence: float("condition_min_confidence"),
  conditionIpPattern: varchar("condition_ip_pattern", { length: 255 }),
  actions: json("actions").notNull(),
  triggerCount: int("trigger_count").notNull().default(0),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().onUpdateNow().notNull(),
});

export const responsePlaybooks = mysqlTable("response_playbooks", {
  id: int("id").primaryKey().autoincrement(),
  name: varchar("name", { length: 200 }).notNull(),
  description: text("description"),
  incidentType: varchar("incident_type", { length: 100 }),
  isActive: boolean("is_active").notNull().default(true),
  executionCount: int("execution_count").notNull().default(0),
  avgExecutionTime: float("avg_execution_time"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().onUpdateNow().notNull(),
});

export const playbookActions = mysqlTable("playbook_actions", {
  id: int("id").primaryKey().autoincrement(),
  playbookId: int("playbook_id").notNull(),
  sequence: int("sequence").notNull(),
  actionType: varchar("action_type", { length: 100 }).notNull(),
  actionParams: json("action_params"),
  description: text("description"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const notifications = mysqlTable("notifications", {
  id: int("id").primaryKey().autoincrement(),
  userId: int("user_id").notNull(),
  type: mysqlEnum("type", ["critical_incident", "escalation", "status_change", "false_positive"]).notNull(),
  title: varchar("title", { length: 500 }).notNull(),
  message: text("message").notNull(),
  incidentId: int("incident_id"),
  isRead: boolean("is_read").notNull().default(false),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const notificationTemplates = mysqlTable("notification_templates", {
  id: int("id").primaryKey().autoincrement(),
  name: varchar("name", { length: 200 }).notNull(),
  type: varchar("type", { length: 100 }).notNull(),
  lang: mysqlEnum("lang", ["en", "ru", "kk"]).notNull().default("en"),
  titleTemplate: varchar("title_template", { length: 500 }).notNull(),
  bodyTemplate: text("body_template").notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const userNotificationPreferences = mysqlTable("user_notification_preferences", {
  id: int("id").primaryKey().autoincrement(),
  userId: int("user_id").notNull().unique(),
  emailEnabled: boolean("email_enabled").notNull().default(true),
  inAppEnabled: boolean("in_app_enabled").notNull().default(true),
  minSeverity: mysqlEnum("min_severity", ["low", "medium", "high", "critical"]).notNull().default("medium"),
  quietHoursStart: int("quiet_hours_start"),
  quietHoursEnd: int("quiet_hours_end"),
  updatedAt: timestamp("updated_at").defaultNow().onUpdateNow().notNull(),
});

export const escalationPolicies = mysqlTable("escalation_policies", {
  id: int("id").primaryKey().autoincrement(),
  name: varchar("name", { length: 200 }).notNull(),
  incidentType: varchar("incident_type", { length: 100 }),
  minSeverity: mysqlEnum("min_severity", ["low", "medium", "high", "critical"]).notNull().default("high"),
  timeoutMinutes: int("timeout_minutes").notNull().default(30),
  action: mysqlEnum("action", ["notify_manager", "page_oncall", "escalate_severity"]).notNull(),
  isActive: boolean("is_active").notNull().default(true),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const responseActionLogs = mysqlTable("response_action_logs", {
  id: int("id").primaryKey().autoincrement(),
  incidentId: int("incident_id"),
  playbookId: int("playbook_id"),
  ruleId: int("rule_id"),
  actionType: varchar("action_type", { length: 100 }).notNull(),
  actionParams: json("action_params"),
  status: mysqlEnum("status", ["success", "failed", "pending"]).notNull().default("pending"),
  result: text("result"),
  executionTime: int("execution_time"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const attackCampaigns = mysqlTable("attack_campaigns", {
  id: int("id").primaryKey().autoincrement(),
  sourceIp: varchar("source_ip", { length: 45 }).notNull().unique(),
  incidentCount: int("incident_count").notNull().default(1),
  severity: mysqlEnum("severity", ["low", "medium", "high", "critical"]).notNull().default("medium"),
  attackTypes: json("attack_types"),
  firstSeen: timestamp("first_seen").defaultNow().notNull(),
  lastSeen: timestamp("last_seen").defaultNow().notNull(),
  isActive: boolean("is_active").notNull().default(true),
});
