import { useMemo, useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card } from "@/components/ui/Card";
import { SeverityBadge } from "@/components/ui/Badge";
import { Globe } from "lucide-react";

function latLonToXY(lat: number, lon: number, w: number, h: number): [number, number] {
  return [((lon + 180) / 360) * w, ((90 - lat) / 180) * h];
}

const COUNTRY_COORDS: Record<string, [number, number]> = {
  "China":         [35.86, 104.19], "Russia":        [61.52, 105.32],
  "United States": [37.09, -95.71], "Germany":       [51.16, 10.45],
  "Netherlands":   [52.13, 5.29],   "Brazil":        [-14.23, -51.92],
  "South Korea":   [35.91, 127.77], "India":         [20.59, 78.96],
  "Ukraine":       [48.38, 31.16],  "France":        [46.23, 2.21],
  "Japan":         [36.20, 138.25], "Romania":       [45.94, 24.97],
  "Poland":        [51.92, 19.15],  "Nigeria":       [9.08, 8.67],
  "Iran":          [32.43, 53.69],  "United Kingdom":[55.38, -3.44],
  "Canada":        [56.13, -106.35],"Australia":     [-25.27, 133.78],
  "Singapore":     [1.35, 103.82],  "Turkey":        [38.96, 35.24],
};

const SVG_W = 960;
const SVG_H = 480;

const SEV_COLOR: Record<string, string> = {
  critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e",
};
const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

export function GeoMapPage() {
  const geoData  = trpc.incident.geoData.useQuery();
  const [selected, setSelected] = useState<string | null>(null);

  const byCountry = useMemo(() => {
    const map = new Map<string, { country: string; count: number; severities: Record<string, number> }>();
    for (const row of geoData.data ?? []) {
      const country = row.country ?? "";
      if (!country) continue;
      if (!map.has(country)) map.set(country, { country, count: 0, severities: {} });
      const entry = map.get(country)!;
      entry.count += Number(row.count);
      const sev = row.severity ?? "medium";
      entry.severities[sev] = (entry.severities[sev] ?? 0) + Number(row.count);
    }
    return map;
  }, [geoData.data]);

  const maxCount   = Math.max(...[...byCountry.values()].map((v) => v.count), 1);
  const selectedData = selected ? byCountry.get(selected) : null;

  function dominantSeverity(severities: Record<string, number>) {
    return Object.entries(severities).sort((a, b) => (SEV_RANK[b[0]] ?? 0) - (SEV_RANK[a[0]] ?? 0))[0]?.[0] ?? "medium";
  }

  return (
    <div className="p-6 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-[var(--text-primary)]">Geo Threat Map</h1>
          <p className="text-[var(--text-tertiary)] text-xs mt-0.5">{byCountry.size} countries with activity</p>
        </div>
        <Globe className="w-4 h-4 text-[var(--text-tertiary)]" />
      </div>

      {/* Map */}
      <Card className="p-0 overflow-hidden">
        <svg
          viewBox={`0 0 ${SVG_W} ${SVG_H}`}
          className="w-full"
          style={{ background: "radial-gradient(ellipse at center, rgba(29,78,216,0.06) 0%, rgba(6,9,18,0.95) 100%)" }}
        >
          <defs>
            <filter id="dot-glow">
              <feGaussianBlur stdDeviation="3" result="coloredBlur" />
              <feMerge><feMergeNode in="coloredBlur" /><feMergeNode in="SourceGraphic" /></feMerge>
            </filter>
          </defs>

          {/* Grid lines */}
          {Array.from({ length: 13 }, (_, i) => (
            <line key={`v${i}`} x1={(i * SVG_W) / 12} y1={0} x2={(i * SVG_W) / 12} y2={SVG_H}
              stroke="rgba(255,255,255,0.03)" strokeWidth={1} strokeDasharray="3,5" />
          ))}
          {Array.from({ length: 7 }, (_, i) => (
            <line key={`h${i}`} x1={0} y1={(i * SVG_H) / 6} x2={SVG_W} y2={(i * SVG_H) / 6}
              stroke="rgba(255,255,255,0.03)" strokeWidth={1} strokeDasharray="3,5" />
          ))}

          {/* Equator */}
          <line x1={0} y1={SVG_H / 2} x2={SVG_W} y2={SVG_H / 2} stroke="rgba(255,255,255,0.1)" strokeWidth={1} />
          <text x={8} y={SVG_H / 2 - 4} fill="rgba(255,255,255,0.15)" fontSize={8} fontFamily="monospace">Equator</text>

          {/* Dots */}
          {[...byCountry.entries()].map(([country, data]) => {
            const coords = COUNTRY_COORDS[country];
            if (!coords) return null;
            const [x, y] = latLonToXY(coords[0], coords[1], SVG_W, SVG_H);
            const sev    = dominantSeverity(data.severities);
            const color  = SEV_COLOR[sev] ?? "#eab308";
            const radius = 4 + (data.count / maxCount) * 14;
            const isSel  = selected === country;

            return (
              <g key={country} onClick={() => setSelected(isSel ? null : country)} style={{ cursor: "pointer" }}>
                <circle cx={x} cy={y} r={radius * 1.7} fill="none" stroke={color} strokeWidth={0.8} opacity={0.25}>
                  <animate attributeName="r" from={radius} to={radius * 2.4} dur="2.2s" repeatCount="indefinite" />
                  <animate attributeName="opacity" from={0.35} to={0} dur="2.2s" repeatCount="indefinite" />
                </circle>
                <circle cx={x} cy={y} r={radius} fill={color} opacity={0.82} filter="url(#dot-glow)"
                  stroke={isSel ? "#fff" : color} strokeWidth={isSel ? 1.5 : 0.5} />
                <text x={x + radius + 2} y={y + 4} fill="rgba(255,255,255,0.6)" fontSize={8} fontFamily="monospace">
                  {country.slice(0, 3).toUpperCase()}
                </text>
              </g>
            );
          })}
        </svg>
      </Card>

      {/* Legend */}
      <div className="flex items-center gap-5">
        {Object.entries(SEV_COLOR).map(([sev, color]) => (
          <div key={sev} className="flex items-center gap-1.5">
            <div className="w-2.5 h-2.5 rounded-full" style={{ background: color, boxShadow: `0 0 6px ${color}` }} />
            <span className="text-[var(--text-tertiary)] text-[11px] capitalize">{sev}</span>
          </div>
        ))}
        <div className="flex items-center gap-2 ml-auto">
          <div className="w-2 h-2 rounded-full" style={{ background: "rgba(255,255,255,0.25)" }} />
          <span className="text-[var(--text-tertiary)] text-[10px]">fewer</span>
          <div className="w-4 h-4 rounded-full" style={{ background: "rgba(255,255,255,0.25)" }} />
          <span className="text-[var(--text-tertiary)] text-[10px]">more attacks</span>
        </div>
      </div>

      {/* Selected country */}
      {selectedData && (
        <Card>
          <div className="flex items-start justify-between">
            <div>
              <h3 className="text-[var(--text-primary)] text-sm font-semibold">{selectedData.country}</h3>
              <p className="text-[var(--text-tertiary)] text-xs mt-0.5">{selectedData.count} total incidents</p>
            </div>
            <button
              onClick={() => setSelected(null)}
              className="text-lg leading-none"
              style={{ color: "var(--text-tertiary)", transition: "color 120ms" }}
              onMouseEnter={(e) => e.currentTarget.style.color = "var(--text-primary)"}
              onMouseLeave={(e) => e.currentTarget.style.color = "var(--text-tertiary)"}
            >×</button>
          </div>
          <div className="flex gap-2 mt-3 flex-wrap">
            {Object.entries(selectedData.severities).map(([sev, cnt]) => (
              <div key={sev} className="flex items-center gap-1.5">
                <SeverityBadge severity={sev} />
                <span className="text-[var(--text-tertiary)] text-[11px]">{cnt}</span>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Country list */}
      <div className="grid grid-cols-4 gap-2">
        {[...byCountry.entries()]
          .sort((a, b) => b[1].count - a[1].count)
          .slice(0, 12)
          .map(([country, data]) => {
            const sev   = dominantSeverity(data.severities);
            const color = SEV_COLOR[sev] ?? "#eab308";
            const isSel = country === selected;
            return (
              <button
                key={country}
                onClick={() => setSelected(isSel ? null : country)}
                className="text-left p-3 rounded-lg"
                style={{
                  background: isSel ? "rgba(255,255,255,0.04)" : "rgba(255,255,255,0.02)",
                  border: `1px solid ${isSel ? "rgba(255,255,255,0.12)" : "var(--border)"}`,
                  transition: "border-color 120ms, background-color 120ms",
                }}
                onMouseEnter={(e) => { if (!isSel) e.currentTarget.style.background = "rgba(255,255,255,0.04)"; }}
                onMouseLeave={(e) => { if (!isSel) e.currentTarget.style.background = "rgba(255,255,255,0.02)"; }}
                onMouseDown={(e) => e.currentTarget.style.transform = "scale(0.97)"}
                onMouseUp={(e) => e.currentTarget.style.transform = "scale(1)"}
              >
                <div className="flex items-center gap-1.5 mb-1">
                  <div className="w-1.5 h-1.5 rounded-full" style={{ background: color }} />
                  <span className="text-[var(--text-secondary)] text-[11px] font-medium truncate">{country}</span>
                </div>
                <span className="text-[var(--text-primary)] font-semibold text-sm tabular">{data.count}</span>
                <span className="text-[var(--text-tertiary)] text-[10px] ml-1">attacks</span>
              </button>
            );
          })}
      </div>
    </div>
  );
}
