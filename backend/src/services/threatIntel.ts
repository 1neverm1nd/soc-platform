const CACHE = new Map<string, { score: number; country: string; reports: number; ts: number }>();
const CACHE_TTL = 1000 * 60 * 60; // 1 hour

const PRIVATE_RANGES = [
  /^10\./,
  /^192\.168\./,
  /^172\.(1[6-9]|2[0-9]|3[01])\./,
  /^127\./,
  /^::1$/,
  /^localhost$/i,
];

function isPrivateIp(ip: string): boolean {
  return PRIVATE_RANGES.some((r) => r.test(ip));
}

export interface ThreatIntelResult {
  abuseScore: number;
  country: string;
  reports: number;
  isMalicious: boolean;
}

export async function checkIpReputation(ip: string): Promise<ThreatIntelResult | null> {
  if (!ip || isPrivateIp(ip)) return null;

  const cached = CACHE.get(ip);
  if (cached && Date.now() - cached.ts < CACHE_TTL) {
    return { abuseScore: cached.score, country: cached.country, reports: cached.reports, isMalicious: cached.score > 50 };
  }

  const apiKey = process.env.ABUSEIPDB_API_KEY;
  if (!apiKey) return null;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6000);

    const res = await fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
      {
        headers: { Key: apiKey, Accept: "application/json" },
        signal: controller.signal,
      }
    );
    clearTimeout(timeout);

    if (!res.ok) return null;

    const data = (await res.json()) as { data: { abuseConfidenceScore: number; countryCode: string; totalReports: number } };
    const { abuseConfidenceScore: score, countryCode: country, totalReports: reports } = data.data;

    CACHE.set(ip, { score, country, reports, ts: Date.now() });
    return { abuseScore: score, country, reports, isMalicious: score > 50 };
  } catch {
    return null;
  }
}
