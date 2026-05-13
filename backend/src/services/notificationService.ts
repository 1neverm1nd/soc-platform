import { db } from "../db/index.js";
import { notifications, notificationTemplates } from "../db/schema.js";

type NotifType = "critical_incident" | "escalation" | "status_change" | "false_positive";

interface NotifPayload {
  userId: number;
  type: NotifType;
  incidentId?: number;
  vars?: Record<string, string>;
  lang?: "en" | "ru" | "kk";
}

const BUILTIN_TEMPLATES: Record<NotifType, Record<string, { title: string; body: string }>> = {
  critical_incident: {
    en: { title: "Critical Incident Detected", body: "A new critical incident has been detected: {{type}} from {{ip}}" },
    ru: { title: "Обнаружен критический инцидент", body: "Новый критический инцидент: {{type}} с {{ip}}" },
    kk: { title: "Маңызды оқиға анықталды", body: "Жаңа оқиға: {{type}} бастап {{ip}}" },
  },
  escalation: {
    en: { title: "Incident Escalated", body: "Incident #{{id}} has been escalated due to {{reason}}" },
    ru: { title: "Инцидент эскалирован", body: "Инцидент #{{id}} эскалирован: {{reason}}" },
    kk: { title: "Оқиға ескалацияланды", body: "Оқиға #{{id}} ескалацияланды: {{reason}}" },
  },
  status_change: {
    en: { title: "Incident Status Changed", body: "Incident #{{id}} status changed to {{status}}" },
    ru: { title: "Статус инцидента изменён", body: "Статус инцидента #{{id}} изменён на {{status}}" },
    kk: { title: "Оқиға мәртебесі өзгерді", body: "Оқиға #{{id}} мәртебесі {{status}} болды" },
  },
  false_positive: {
    en: { title: "False Positive Identified", body: "Incident #{{id}} has been marked as false positive" },
    ru: { title: "Ложное срабатывание", body: "Инцидент #{{id}} помечен как ложное срабатывание" },
    kk: { title: "Жалған позитив", body: "Оқиға #{{id}} жалған позитив деп белгіленді" },
  },
};

function interpolate(template: string, vars: Record<string, string>): string {
  return template.replace(/\{\{(\w+)\}\}/g, (_, key) => vars[key] ?? `{{${key}}}`);
}

export async function sendNotification(payload: NotifPayload): Promise<void> {
  const lang = payload.lang ?? "en";
  const vars = payload.vars ?? {};

  const tmpl = BUILTIN_TEMPLATES[payload.type]?.[lang] ?? BUILTIN_TEMPLATES[payload.type]?.["en"]!;

  await db.insert(notifications).values({
    userId: payload.userId,
    type: payload.type,
    title: interpolate(tmpl.title, vars),
    message: interpolate(tmpl.body, vars),
    incidentId: payload.incidentId,
  });
}
