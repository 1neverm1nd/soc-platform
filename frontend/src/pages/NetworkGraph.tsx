import { useMemo, useRef, useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card } from "@/components/ui/Card";
import { ATTACK_COLORS } from "@/lib/utils";
import { Network } from "lucide-react";

const W = 800, H = 520;

interface Node { id: string; x: number; y: number; isSource: boolean; connections: number }
interface Edge { source: string; target: string; type: string; severity: string }

export function NetworkGraphPage() {
  const data = trpc.incident.networkGraph.useQuery();
  const [hovered, setHovered] = useState<string | null>(null);
  const svgRef = useRef<SVGSVGElement>(null);

  const { nodes, edges } = useMemo(() => {
    const rows = data.data ?? [];
    const ipSet = new Map<string, { connections: number; isSource: boolean }>();

    for (const r of rows) {
      if (r.sourceIp) {
        const e = ipSet.get(r.sourceIp) ?? { connections: 0, isSource: true };
        e.connections++;
        ipSet.set(r.sourceIp, e);
      }
      if (r.destinationIp) {
        const e = ipSet.get(r.destinationIp) ?? { connections: 0, isSource: false };
        e.connections++;
        ipSet.set(r.destinationIp, e);
      }
    }

    const ips = [...ipSet.keys()];
    const nodes: Node[] = ips.slice(0, 60).map((ip, i) => {
      const angle = (i / Math.min(ips.length, 60)) * 2 * Math.PI;
      const info = ipSet.get(ip)!;
      const radius = info.isSource ? 140 + (info.connections / 5) * 60 : 200;
      return {
        id: ip,
        x: W / 2 + radius * Math.cos(angle),
        y: H / 2 + radius * Math.sin(angle),
        isSource: info.isSource,
        connections: info.connections,
      };
    });

    const nodeIds = new Set(nodes.map((n) => n.id));
    const edges: Edge[] = rows
      .filter((r) => r.sourceIp && r.destinationIp && nodeIds.has(r.sourceIp!) && nodeIds.has(r.destinationIp!))
      .slice(0, 150)
      .map((r) => ({ source: r.sourceIp!, target: r.destinationIp!, type: r.mlType ?? "", severity: r.severity ?? "medium" }));

    return { nodes, edges };
  }, [data.data]);

  const nodeMap = useMemo(() => new Map(nodes.map((n) => [n.id, n])), [nodes]);
  const SEV_COLORS: Record<string, string> = { critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e" };

  if (data.isLoading) return <div className="p-6 text-white/40">Loading network graph...</div>;

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center gap-3">
        <Network className="w-6 h-6 text-purple-400" />
        <div>
          <h1 className="text-2xl font-bold text-white">Network Graph</h1>
          <p className="text-white/40 text-sm">Source → Destination IP relationships ({nodes.length} nodes, {edges.length} edges)</p>
        </div>
      </div>

      <Card className="p-0 overflow-hidden">
        <svg ref={svgRef} width="100%" viewBox={`0 0 ${W} ${H}`} style={{ background: "rgba(0,0,0,0.3)" }}>
          <defs>
            <marker id="arrow" viewBox="0 0 10 10" refX="8" refY="3" markerWidth="6" markerHeight="6" orient="auto">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="rgba(255,255,255,0.2)" />
            </marker>
          </defs>

          {/* Edges */}
          {edges.map((e, i) => {
            const src = nodeMap.get(e.source);
            const tgt = nodeMap.get(e.target);
            if (!src || !tgt) return null;
            const color = ATTACK_COLORS[e.type] ?? "#6b7280";
            const isHighlighted = hovered === e.source || hovered === e.target;
            return (
              <line key={i} x1={src.x} y1={src.y} x2={tgt.x} y2={tgt.y}
                stroke={isHighlighted ? color : "rgba(255,255,255,0.06)"}
                strokeWidth={isHighlighted ? 1.5 : 0.8}
                markerEnd="url(#arrow)"
                style={{ transition: "stroke 0.2s" }}
              />
            );
          })}

          {/* Nodes */}
          {nodes.map((n) => {
            const isHighlighted = hovered === n.id;
            const r = n.isSource ? 4 + Math.min(n.connections, 8) : 4;
            return (
              <g key={n.id} onMouseEnter={() => setHovered(n.id)} onMouseLeave={() => setHovered(null)} style={{ cursor: "pointer" }}>
                {isHighlighted && <circle cx={n.x} cy={n.y} r={r + 8} fill="none" stroke="rgba(255,255,255,0.2)" strokeWidth={1} />}
                <circle cx={n.x} cy={n.y} r={r}
                  fill={n.isSource ? "#ef4444" : "#3b82f6"}
                  opacity={isHighlighted ? 1 : 0.7}
                />
                {isHighlighted && (
                  <text x={n.x + r + 4} y={n.y + 4} fill="white" fontSize={10} fontFamily="monospace">{n.id}</text>
                )}
              </g>
            );
          })}

          {/* Center label */}
          {nodes.length === 0 && (
            <text x={W / 2} y={H / 2} fill="rgba(255,255,255,0.2)" textAnchor="middle" fontSize={14}>
              No network data yet — fire some attacks to populate
            </text>
          )}
        </svg>
      </Card>

      <div className="flex gap-6">
        <div className="flex items-center gap-2"><div className="w-3 h-3 rounded-full bg-red-500" /><span className="text-white/50 text-xs">Source (attacker)</span></div>
        <div className="flex items-center gap-2"><div className="w-3 h-3 rounded-full bg-blue-500" /><span className="text-white/50 text-xs">Destination (target)</span></div>
        <div className="flex items-center gap-2 ml-auto text-white/30 text-xs">Hover over a node to highlight its connections</div>
      </div>
    </div>
  );
}
