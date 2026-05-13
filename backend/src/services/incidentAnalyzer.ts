export interface AIAnalysis {
  summary: string;
  attackVector: string;
  affectedAssets: string[];
  indicators: string[];
  recommendedActions: string[];
  riskScore: number;
  falsePositiveRisk: "low" | "medium" | "high";
}

export async function analyzeIncident(
  rawLog: string,
  mlType: string,
  severity: string,
  sourceIp?: string | null
): Promise<AIAnalysis | null> {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) return null;

  const prompt = `You are a cybersecurity analyst. Analyze this security incident and respond with valid JSON only.

Incident:
- Type: ${mlType}
- Severity: ${severity}
- Source IP: ${sourceIp ?? "unknown"}
- Raw log: ${rawLog.slice(0, 500)}

Respond with this exact JSON structure:
{
  "summary": "brief description of what happened",
  "attackVector": "how the attack was carried out",
  "affectedAssets": ["asset1", "asset2"],
  "indicators": ["ioc1", "ioc2"],
  "recommendedActions": ["action1", "action2", "action3"],
  "riskScore": 7,
  "falsePositiveRisk": "low"
}`;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);

    const res = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/openai/chat/completions`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
        body: JSON.stringify({
          model: "gemini-2.0-flash",
          messages: [{ role: "user", content: prompt }],
          max_tokens: 800,
          temperature: 0.3,
        }),
        signal: controller.signal,
      }
    );
    clearTimeout(timeout);

    if (!res.ok) return null;

    const data = (await res.json()) as { choices: Array<{ message: { content: string } }> };
    const content = data.choices[0]?.message?.content ?? "";
    const jsonMatch = content.match(/\{[\s\S]*\}/);
    if (!jsonMatch) return null;

    return JSON.parse(jsonMatch[0]) as AIAnalysis;
  } catch {
    return null;
  }
}
