import React, { useEffect, useMemo, useRef, useState } from 'react';
import * as d3 from 'd3';
import {
  Network,
  Globe,
  Laptop,
  Shield,
  ShieldAlert,
  Lock,
  CheckCircle,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  Search,
  Filter,
  Eye,
  Activity,
  AlertTriangle,
  ArrowRight,
  Crosshair,
  Server,
  Play,
  Pause,
  FileSearch,
  Layers,
  GitBranch,
} from 'lucide-react';
import {
  LogEntry,
  ThreatAnalysisResult,
  ActiveDefense,
  StopAction,
  SeverityLevel,
} from '../types';

interface ThreatTopologyD3GraphProps {
  logs: LogEntry[];
  analysis: ThreatAnalysisResult;
  activeDefenses: ActiveDefense[];
  deviceName?: string;
  onEnforceDefense: (action: StopAction) => Promise<void>;
  onInspectLog: (log: LogEntry) => void;
  onNavigateToCountermeasures: () => void;
}

export type TopologyNodeType = 'ATTACKER_IP' | 'GATEWAY' | 'LOCAL_TARGET';

export interface TopologyNode extends d3.SimulationNodeDatum {
  id: string;
  label: string;
  subLabel?: string;
  nodeType: TopologyNodeType;
  ip?: string;
  country?: string;
  hostName?: string;
  hostMac?: string;
  severity: SeverityLevel;
  eventCount: number;
  criticalCount: number;
  blockedCount: number;
  alertedCount: number;
  isBlockedOrIsolated: boolean;
  isCompromised: boolean;
  threats: string[];
  ports: number[];
  protocols: string[];
  relatedLogs: LogEntry[];
}

export interface TopologyLink extends d3.SimulationLinkDatum<TopologyNode> {
  id: string;
  source: string | TopologyNode;
  target: string | TopologyNode;
  srcIp: string;
  dstIp: string;
  severity: SeverityLevel;
  count: number;
  blockedCount: number;
  activeCount: number;
  isMitigated: boolean;
  protocols: string[];
  ports: number[];
  threatNames: string[];
  categories: string[];
  logs: LogEntry[];
}

type LayoutMode = 'FORCE_DIRECT' | 'TRI_ZONE_FLOW';
type SeverityFilter = 'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM_LOW';
type StatusFilter = 'ALL' | 'ACTIVE_ONLY' | 'BLOCKED_ONLY';

const SEVERITY_RANK: Record<SeverityLevel, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  INFO: 0,
};

const SEVERITY_COLORS: Record<SeverityLevel, string> = {
  CRITICAL: '#ef4444', // red-500
  HIGH: '#f97316',     // orange-500
  MEDIUM: '#eab308',   // yellow-500
  LOW: '#38bdf8',      // sky-400
  INFO: '#94a3b8',     // slate-400
};

export const ThreatTopologyD3Graph: React.FC<ThreatTopologyD3GraphProps> = ({
  logs,
  analysis,
  activeDefenses,
  deviceName = 'Zyxel Nebula ATP800',
  onEnforceDefense,
  onInspectLog,
  onNavigateToCountermeasures,
}) => {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const zoomBehaviorRef = useRef<d3.ZoomBehavior<SVGSVGElement, unknown> | null>(null);

  const [layoutMode, setLayoutMode] = useState<LayoutMode>('FORCE_DIRECT');
  const [includeGatewayNode, setIncludeGatewayNode] = useState<boolean>(false);
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('ALL');
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [animatePackets, setAnimatePackets] = useState<boolean>(true);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [selectedLinkId, setSelectedLinkId] = useState<string | null>(null);
  const [isEnforcingIp, setIsEnforcingIp] = useState<string | null>(null);
  const [dimensions, setDimensions] = useState<{ width: number; height: number }>({
    width: 920,
    height: 540,
  });

  // Observe container width for responsive SVG sizing
  useEffect(() => {
    const updateSize = () => {
      if (containerRef.current) {
        const rect = containerRef.current.getBoundingClientRect();
        setDimensions({
          width: Math.max(580, Math.floor(rect.width)),
          height: 540,
        });
      }
    };
    updateSize();
    window.addEventListener('resize', updateSize);
    return () => window.removeEventListener('resize', updateSize);
  }, []);

  const isTargetMitigated = (ip: string) => {
    return activeDefenses.some((d) => d.target === ip && d.status === 'ACTIVE');
  };

  // Filter logs based on interactive controls
  const filteredLogs = useMemo(() => {
    return logs.filter((log) => {
      if (severityFilter === 'CRITICAL' && log.severity !== 'CRITICAL') return false;
      if (severityFilter === 'HIGH' && log.severity !== 'CRITICAL' && log.severity !== 'HIGH')
        return false;
      if (
        severityFilter === 'MEDIUM_LOW' &&
        (log.severity === 'CRITICAL' || log.severity === 'HIGH')
      )
        return false;

      const isBlockedAction =
        log.action === 'Blocked' ||
        log.action === 'Dropped' ||
        log.action === 'Quarantined' ||
        isTargetMitigated(log.srcIp) ||
        isTargetMitigated(log.dstIp);

      if (statusFilter === 'ACTIVE_ONLY' && isBlockedAction) return false;
      if (statusFilter === 'BLOCKED_ONLY' && !isBlockedAction) return false;

      if (searchQuery.trim()) {
        const q = searchQuery.trim().toLowerCase();
        const hay = `${log.srcIp} ${log.dstIp} ${log.hostName || ''} ${log.threatName} ${
          log.category
        } ${log.country || ''} ${log.dstPort || ''} ${log.protocol || ''}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }

      return true;
    });
  }, [logs, severityFilter, statusFilter, searchQuery, activeDefenses]);

  // Build D3 Topology Graph (Nodes & Links) from filteredLogs + analysis
  const graphData = useMemo(() => {
    const nodesMap = new Map<string, TopologyNode>();
    const linksMap = new Map<string, TopologyLink>();

    const gatewayNodeId = 'GATEWAY_ZYXEL_ATP';

    if (includeGatewayNode && filteredLogs.length > 0) {
      const blockedTotal = filteredLogs.filter(
        (l) => l.action === 'Blocked' || l.action === 'Dropped' || l.action === 'Quarantined'
      ).length;
      const critTotal = filteredLogs.filter((l) => l.severity === 'CRITICAL').length;

      nodesMap.set(gatewayNodeId, {
        id: gatewayNodeId,
        label: deviceName,
        subLabel: 'Passerelle Zyxel Inspection',
        nodeType: 'GATEWAY',
        ip: '10.0.0.1',
        severity: critTotal > 0 ? 'CRITICAL' : 'HIGH',
        eventCount: filteredLogs.length,
        criticalCount: critTotal,
        blockedCount: blockedTotal,
        alertedCount: filteredLogs.length - blockedTotal,
        isBlockedOrIsolated: false,
        isCompromised: false,
        threats: Array.from(new Set(filteredLogs.map((l) => l.threatName))).slice(0, 6),
        ports: Array.from(
          new Set(filteredLogs.map((l) => l.dstPort).filter((p): p is number => Boolean(p)))
        ),
        protocols: Array.from(
          new Set(filteredLogs.map((l) => l.protocol).filter((p): p is string => Boolean(p)))
        ),
        relatedLogs: filteredLogs,
      });
    }

    const upgradeSeverity = (current: SeverityLevel, candidate: SeverityLevel): SeverityLevel => {
      return SEVERITY_RANK[candidate] > SEVERITY_RANK[current] ? candidate : current;
    };

    filteredLogs.forEach((log) => {
      const srcId = `ATT_${log.srcIp}`;
      const dstId = `LOC_${log.dstIp}`;

      const isBlockedEvent =
        log.action === 'Blocked' ||
        log.action === 'Dropped' ||
        log.action === 'Quarantined' ||
        isTargetMitigated(log.srcIp);

      // 1. Attacker IP Node
      const existingSrc = nodesMap.get(srcId);
      const iocMatch = analysis.iocList.find((i) => i.value === log.srcIp);
      if (!existingSrc) {
        nodesMap.set(srcId, {
          id: srcId,
          label: log.srcIp,
          subLabel: log.country || iocMatch?.country || 'WAN Externe',
          nodeType: 'ATTACKER_IP',
          ip: log.srcIp,
          country: log.country || iocMatch?.country || 'EXT',
          severity: log.severity,
          eventCount: 1,
          criticalCount: log.severity === 'CRITICAL' ? 1 : 0,
          blockedCount: isBlockedEvent ? 1 : 0,
          alertedCount: isBlockedEvent ? 0 : 1,
          isBlockedOrIsolated: isTargetMitigated(log.srcIp),
          isCompromised: false,
          threats: [log.threatName],
          ports: log.dstPort ? [log.dstPort] : [],
          protocols: log.protocol ? [log.protocol] : [],
          relatedLogs: [log],
        });
      } else {
        existingSrc.eventCount += 1;
        if (log.severity === 'CRITICAL') existingSrc.criticalCount += 1;
        if (isBlockedEvent) existingSrc.blockedCount += 1;
        else existingSrc.alertedCount += 1;
        existingSrc.severity = upgradeSeverity(existingSrc.severity, log.severity);
        existingSrc.isBlockedOrIsolated = isTargetMitigated(log.srcIp);
        if (!existingSrc.threats.includes(log.threatName)) {
          existingSrc.threats.push(log.threatName);
        }
        if (log.dstPort && !existingSrc.ports.includes(log.dstPort)) {
          existingSrc.ports.push(log.dstPort);
        }
        if (log.protocol && !existingSrc.protocols.includes(log.protocol)) {
          existingSrc.protocols.push(log.protocol);
        }
        existingSrc.relatedLogs.push(log);
      }

      // 2. Local Target Node
      const existingDst = nodesMap.get(dstId);
      const compromisedMatch = analysis.compromisedHosts.find((h) => h.ip === log.dstIp);
      const resolvedHostName = log.hostName || compromisedMatch?.hostname || 'Hôte LAN';
      if (!existingDst) {
        nodesMap.set(dstId, {
          id: dstId,
          label: log.dstIp,
          subLabel: resolvedHostName,
          nodeType: 'LOCAL_TARGET',
          ip: log.dstIp,
          hostName: resolvedHostName,
          hostMac: log.hostMac || compromisedMatch?.mac,
          severity: log.severity,
          eventCount: 1,
          criticalCount: log.severity === 'CRITICAL' ? 1 : 0,
          blockedCount: isBlockedEvent ? 1 : 0,
          alertedCount: isBlockedEvent ? 0 : 1,
          isBlockedOrIsolated: isTargetMitigated(log.dstIp),
          isCompromised: Boolean(compromisedMatch && compromisedMatch.status !== 'Clean'),
          threats: [log.threatName],
          ports: log.dstPort ? [log.dstPort] : [],
          protocols: log.protocol ? [log.protocol] : [],
          relatedLogs: [log],
        });
      } else {
        existingDst.eventCount += 1;
        if (log.severity === 'CRITICAL') existingDst.criticalCount += 1;
        if (isBlockedEvent) existingDst.blockedCount += 1;
        else existingDst.alertedCount += 1;
        existingDst.severity = upgradeSeverity(existingDst.severity, log.severity);
        existingDst.isBlockedOrIsolated = isTargetMitigated(log.dstIp);
        if (log.hostName && existingDst.subLabel === 'Hôte LAN') {
          existingDst.subLabel = log.hostName;
          existingDst.hostName = log.hostName;
        }
        if (!existingDst.threats.includes(log.threatName)) {
          existingDst.threats.push(log.threatName);
        }
        if (log.dstPort && !existingDst.ports.includes(log.dstPort)) {
          existingDst.ports.push(log.dstPort);
        }
        if (log.protocol && !existingDst.protocols.includes(log.protocol)) {
          existingDst.protocols.push(log.protocol);
        }
        existingDst.relatedLogs.push(log);
      }

      // Helper to upsert a link
      const upsertLink = (sourceId: string, targetId: string, srcIpAddr: string, dstIpAddr: string) => {
        const linkKey = `${sourceId}__${targetId}`;
        const existingLink = linksMap.get(linkKey);
        if (!existingLink) {
          linksMap.set(linkKey, {
            id: linkKey,
            source: sourceId,
            target: targetId,
            srcIp: srcIpAddr,
            dstIp: dstIpAddr,
            severity: log.severity,
            count: 1,
            blockedCount: isBlockedEvent ? 1 : 0,
            activeCount: isBlockedEvent ? 0 : 1,
            isMitigated: isTargetMitigated(srcIpAddr) || isBlockedEvent,
            protocols: log.protocol ? [log.protocol] : [],
            ports: log.dstPort ? [log.dstPort] : [],
            threatNames: [log.threatName],
            categories: [log.category],
            logs: [log],
          });
        } else {
          existingLink.count += 1;
          if (isBlockedEvent) existingLink.blockedCount += 1;
          else existingLink.activeCount += 1;
          existingLink.severity = upgradeSeverity(existingLink.severity, log.severity);
          existingLink.isMitigated =
            isTargetMitigated(srcIpAddr) || existingLink.activeCount === 0;
          if (log.protocol && !existingLink.protocols.includes(log.protocol)) {
            existingLink.protocols.push(log.protocol);
          }
          if (log.dstPort && !existingLink.ports.includes(log.dstPort)) {
            existingLink.ports.push(log.dstPort);
          }
          if (!existingLink.threatNames.includes(log.threatName)) {
            existingLink.threatNames.push(log.threatName);
          }
          if (!existingLink.categories.includes(log.category)) {
            existingLink.categories.push(log.category);
          }
          existingLink.logs.push(log);
        }
      };

      if (includeGatewayNode) {
        upsertLink(srcId, gatewayNodeId, log.srcIp, '10.0.0.1');
        upsertLink(gatewayNodeId, dstId, log.srcIp, log.dstIp);
      } else {
        upsertLink(srcId, dstId, log.srcIp, log.dstIp);
      }
    });

    const nodes = Array.from(nodesMap.values());
    const links = Array.from(linksMap.values());

    return { nodes, links };
  }, [filteredLogs, analysis, activeDefenses, includeGatewayNode, deviceName]);

  // Selected entity resolution
  const selectedNode = useMemo(
    () => graphData.nodes.find((n) => n.id === selectedNodeId) || null,
    [graphData.nodes, selectedNodeId]
  );

  const selectedLink = useMemo(
    () => graphData.links.find((l) => l.id === selectedLinkId) || null,
    [graphData.links, selectedLinkId]
  );

  // Render D3 Graph inside SVG
  useEffect(() => {
    const svgEl = svgRef.current;
    if (!svgEl) return;

    const width = dimensions.width;
    const height = dimensions.height;

    const svg = d3.select(svgEl);
    svg.selectAll('*').remove();

    if (graphData.nodes.length === 0) return;

    // Deep clone nodes and links so D3 mutation doesn't corrupt React memo state
    const nodes: TopologyNode[] = graphData.nodes.map((n) => ({ ...n }));
    const links: TopologyLink[] = graphData.links.map((l) => ({ ...l }));

    // Define SVG defs: arrowheads, glow filters, grid pattern
    const defs = svg.append('defs');

    // Subtle background tactical grid
    const pattern = defs
      .append('pattern')
      .attr('id', 'soc-topology-grid')
      .attr('width', 32)
      .attr('height', 32)
      .attr('patternUnits', 'userSpaceOnUse');

    pattern
      .append('path')
      .attr('d', 'M 32 0 L 0 0 0 32')
      .attr('fill', 'none')
      .attr('stroke', '#1e293b')
      .attr('stroke-width', 0.75);

    // Arrowhead markers per severity + mitigated
    const markerConfigs = [
      { id: 'arrow-CRITICAL', color: '#ef4444' },
      { id: 'arrow-HIGH', color: '#f97316' },
      { id: 'arrow-MEDIUM', color: '#eab308' },
      { id: 'arrow-LOW', color: '#38bdf8' },
      { id: 'arrow-INFO', color: '#94a3b8' },
      { id: 'arrow-MITIGATED', color: '#10b981' },
    ];

    markerConfigs.forEach(({ id, color }) => {
      defs
        .append('marker')
        .attr('id', id)
        .attr('viewBox', '0 -5 10 10')
        .attr('refX', 26)
        .attr('refY', 0)
        .attr('markerWidth', 6)
        .attr('markerHeight', 6)
        .attr('orient', 'auto')
        .append('path')
        .attr('d', 'M0,-4L10,0L0,4')
        .attr('fill', color);
    });

    // Background rect with grid + click to clear selection
    svg
      .append('rect')
      .attr('width', width)
      .attr('height', height)
      .attr('fill', 'url(#soc-topology-grid)')
      .style('cursor', 'grab')
      .on('click', () => {
        setSelectedNodeId(null);
        setSelectedLinkId(null);
      });

    // Root zoomable group
    const gRoot = svg.append('g').attr('class', 'topology-zoom-root');

    // Zone headers for TRI_ZONE_FLOW or FORCE_DIRECT
    const gZones = gRoot.append('g').attr('class', 'topology-zones');
    if (layoutMode === 'TRI_ZONE_FLOW') {
      const zones = includeGatewayNode
        ? [
            { x: width * 0.16, label: 'ZONE WAN EXTERNE (IPs Attaquantes)', color: '#ef4444' },
            { x: width * 0.5, label: 'PASSERELLE ZYXEL ATP (Filtrage)', color: '#06b6d4' },
            { x: width * 0.84, label: 'ZONE LAN INTERNE (Cibles Locales)', color: '#a855f7' },
          ]
        : [
            { x: width * 0.22, label: 'ZONE WAN EXTERNE (Attaquants IP)', color: '#ef4444' },
            { x: width * 0.78, label: 'ZONE LAN INTERNE (Cibles Locales)', color: '#38bdf8' },
          ];

      zones.forEach((z) => {
        gZones
          .append('line')
          .attr('x1', z.x)
          .attr('y1', 42)
          .attr('x2', z.x)
          .attr('y2', height - 24)
          .attr('stroke', z.color)
          .attr('stroke-opacity', 0.16)
          .attr('stroke-width', 1.5)
          .attr('stroke-dasharray', '4 4');

        gZones
          .append('text')
          .attr('x', z.x)
          .attr('y', 28)
          .attr('text-anchor', 'middle')
          .attr('fill', z.color)
          .attr('font-size', '10px')
          .attr('font-family', 'monospace')
          .attr('font-weight', '700')
          .text(z.label);
      });
    }

    // Zoom behavior
    const zoom = d3
      .zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.35, 3.5])
      .on('zoom', (event) => {
        gRoot.attr('transform', event.transform.toString());
      });

    svg.call(zoom);
    zoomBehaviorRef.current = zoom;

    // Position initialization for Tri-Zone or Force
    const attackerNodes = nodes.filter((n) => n.nodeType === 'ATTACKER_IP');
    const localNodes = nodes.filter((n) => n.nodeType === 'LOCAL_TARGET');
    const gatewayNodes = nodes.filter((n) => n.nodeType === 'GATEWAY');

    attackerNodes.forEach((n, idx) => {
      const spacing = (height - 100) / Math.max(1, attackerNodes.length);
      n.x = layoutMode === 'TRI_ZONE_FLOW' ? (includeGatewayNode ? width * 0.16 : width * 0.22) : width * 0.25 + (Math.random() - 0.5) * 60;
      n.y = 65 + spacing * (idx + 0.5);
    });

    gatewayNodes.forEach((n) => {
      n.x = width * 0.5;
      n.y = height * 0.5;
    });

    localNodes.forEach((n, idx) => {
      const spacing = (height - 100) / Math.max(1, localNodes.length);
      n.x = layoutMode === 'TRI_ZONE_FLOW' ? (includeGatewayNode ? width * 0.84 : width * 0.78) : width * 0.75 + (Math.random() - 0.5) * 60;
      n.y = 65 + spacing * (idx + 0.5);
    });

    // Links group
    const gLinks = gRoot.append('g').attr('class', 'topology-links');
    const gLinkLabels = gRoot.append('g').attr('class', 'topology-link-labels');
    const gNodes = gRoot.append('g').attr('class', 'topology-nodes');

    // Helper to determine connected nodes/links when an item is selected
    const isLinkHighlighted = (l: TopologyLink): boolean => {
      if (!selectedNodeId && !selectedLinkId) return true;
      if (selectedLinkId) return l.id === selectedLinkId;
      const sId = typeof l.source === 'object' ? l.source.id : l.source;
      const tId = typeof l.target === 'object' ? l.target.id : l.target;
      return sId === selectedNodeId || tId === selectedNodeId;
    };

    const isNodeHighlighted = (n: TopologyNode): boolean => {
      if (!selectedNodeId && !selectedLinkId) return true;
      if (selectedNodeId) {
        if (n.id === selectedNodeId) return true;
        return links.some((l) => {
          const sId = typeof l.source === 'object' ? l.source.id : l.source;
          const tId = typeof l.target === 'object' ? l.target.id : l.target;
          return (sId === selectedNodeId && tId === n.id) || (tId === selectedNodeId && sId === n.id);
        });
      }
      if (selectedLinkId) {
        const match = links.find((l) => l.id === selectedLinkId);
        if (!match) return true;
        const sId = typeof match.source === 'object' ? match.source.id : match.source;
        const tId = typeof match.target === 'object' ? match.target.id : match.target;
        return n.id === sId || n.id === tId;
      }
      return true;
    };

    // Draw link paths (base line)
    const linkPaths = gLinks
      .selectAll<SVGPathElement, TopologyLink>('path.link-base')
      .data(links, (d) => d.id)
      .join('path')
      .attr('class', 'link-base')
      .attr('fill', 'none')
      .attr('stroke', (d) => (d.isMitigated ? '#10b981' : SEVERITY_COLORS[d.severity]))
      .attr('stroke-width', (d) => Math.min(5, 1.6 + Math.log2(d.count + 1)))
      .attr('stroke-opacity', (d) => (isLinkHighlighted(d) ? 0.72 : 0.14))
      .attr('stroke-dasharray', (d) => (d.isMitigated ? '5 4' : null))
      .attr('marker-end', (d) =>
        d.isMitigated ? 'url(#arrow-MITIGATED)' : `url(#arrow-${d.severity})`
      )
      .style('cursor', 'pointer')
      .on('click', (event, d) => {
        event.stopPropagation();
        setSelectedLinkId(d.id);
        setSelectedNodeId(null);
      });

    // Animated traffic overlay paths for active non-mitigated links
    const animatedPaths = gLinks
      .selectAll<SVGPathElement, TopologyLink>('path.link-flow')
      .data(
        animatePackets ? links.filter((l) => !l.isMitigated) : [],
        (d) => d.id
      )
      .join('path')
      .attr('class', 'link-flow')
      .attr('fill', 'none')
      .attr('stroke', (d) => SEVERITY_COLORS[d.severity])
      .attr('stroke-width', 2.5)
      .attr('stroke-dasharray', '4 14')
      .attr('stroke-linecap', 'round')
      .attr('stroke-opacity', (d) => (isLinkHighlighted(d) ? 0.95 : 0.1))
      .style('pointer-events', 'none');

    // Animate dashoffset using D3 timer when animatePackets is true
    let flowTimer: d3.Timer | null = null;
    if (animatePackets) {
      flowTimer = d3.timer((elapsed) => {
        animatedPaths.attr('stroke-dashoffset', -(elapsed * 0.045));
      });
    }

    // Link protocol/port + count badges
    const linkLabelGroups = gLinkLabels
      .selectAll<SVGGElement, TopologyLink>('g.link-badge')
      .data(links, (d) => d.id)
      .join('g')
      .attr('class', 'link-badge')
      .style('cursor', 'pointer')
      .attr('opacity', (d) => (isLinkHighlighted(d) ? 0.95 : 0.15))
      .on('click', (event, d) => {
        event.stopPropagation();
        setSelectedLinkId(d.id);
        setSelectedNodeId(null);
      });

    linkLabelGroups
      .append('rect')
      .attr('rx', 5)
      .attr('ry', 5)
      .attr('x', -34)
      .attr('y', -9)
      .attr('width', 68)
      .attr('height', 18)
      .attr('fill', '#090d16')
      .attr('stroke', (d) =>
        d.id === selectedLinkId
          ? '#38bdf8'
          : d.isMitigated
          ? '#059669'
          : '#334155'
      )
      .attr('stroke-width', (d) => (d.id === selectedLinkId ? 1.5 : 1));

    linkLabelGroups
      .append('text')
      .attr('text-anchor', 'middle')
      .attr('dy', 3)
      .attr('fill', (d) => (d.isMitigated ? '#6ee7b7' : '#e2e8f0'))
      .attr('font-size', '9px')
      .attr('font-family', 'monospace')
      .text((d) => {
        const portStr = d.ports[0] ? `:${d.ports[0]}` : d.protocols[0] || 'IP';
        return `${d.count}x ${portStr}`;
      });

    // Draw Node groups
    const nodeGroups = gNodes
      .selectAll<SVGGElement, TopologyNode>('g.topology-node')
      .data(nodes, (d) => d.id)
      .join('g')
      .attr('class', 'topology-node')
      .style('cursor', 'pointer')
      .attr('opacity', (d) => (isNodeHighlighted(d) ? 1 : 0.22))
      .on('click', (event, d) => {
        event.stopPropagation();
        setSelectedNodeId(d.id);
        setSelectedLinkId(null);
      })
      .on('dblclick', (event, d) => {
        event.stopPropagation();
        d.fx = null;
        d.fy = null;
        simulation.alpha(0.35).restart();
      });

    // Outer Halo ring for selected or critical/compromised nodes
    nodeGroups
      .append('circle')
      .attr('r', (d) => (d.nodeType === 'GATEWAY' ? 28 : 22))
      .attr('fill', 'none')
      .attr('stroke', (d) => {
        if (d.id === selectedNodeId) return '#38bdf8';
        if (d.isBlockedOrIsolated) return '#10b981';
        if (d.nodeType === 'ATTACKER_IP') return SEVERITY_COLORS[d.severity];
        if (d.isCompromised) return '#a855f7';
        return '#06b6d4';
      })
      .attr('stroke-width', (d) => (d.id === selectedNodeId ? 2.5 : 1.2))
      .attr('stroke-opacity', (d) => (d.id === selectedNodeId ? 0.95 : 0.35))
      .attr('stroke-dasharray', (d) => (d.isBlockedOrIsolated ? '3 3' : null));

    // Main Node Circle
    nodeGroups
      .append('circle')
      .attr('r', (d) => (d.nodeType === 'GATEWAY' ? 21 : 16))
      .attr('fill', (d) => {
        if (d.isBlockedOrIsolated) return '#064e3b'; // emerald-950
        if (d.nodeType === 'GATEWAY') return '#083344'; // cyan-950
        if (d.nodeType === 'ATTACKER_IP') return '#450a0a'; // red-950
        if (d.isCompromised) return '#3b0764'; // purple-950
        return '#0f172a'; // slate-900
      })
      .attr('stroke', (d) => {
        if (d.id === selectedNodeId) return '#38bdf8';
        if (d.isBlockedOrIsolated) return '#10b981';
        if (d.nodeType === 'GATEWAY') return '#06b6d4';
        if (d.nodeType === 'ATTACKER_IP') return SEVERITY_COLORS[d.severity];
        if (d.isCompromised) return '#c084fc';
        return '#38bdf8';
      })
      .attr('stroke-width', 2);

    // Node Type Symbol / Text Inside Circle
    nodeGroups
      .append('text')
      .attr('text-anchor', 'middle')
      .attr('dy', 3.5)
      .attr('fill', '#ffffff')
      .attr('font-size', (d) => (d.nodeType === 'GATEWAY' ? '9px' : '8.5px'))
      .attr('font-family', 'monospace')
      .attr('font-weight', '700')
      .text((d) => {
        if (d.isBlockedOrIsolated) return 'BLK';
        if (d.nodeType === 'GATEWAY') return 'ATP';
        if (d.nodeType === 'ATTACKER_IP') return d.country || 'WAN';
        return d.isCompromised ? 'CDR' : 'LAN';
      });

    // Event Count Mini Counter on top-right of node
    const countBadge = nodeGroups
      .append('g')
      .attr('transform', (d) =>
        d.nodeType === 'GATEWAY' ? 'translate(16, -16)' : 'translate(13, -13)'
      );

    countBadge
      .append('circle')
      .attr('r', 8.5)
      .attr('fill', (d) =>
        d.isBlockedOrIsolated
          ? '#059669'
          : d.nodeType === 'ATTACKER_IP'
          ? SEVERITY_COLORS[d.severity]
          : '#1e293b'
      )
      .attr('stroke', '#090d16')
      .attr('stroke-width', 1.5);

    countBadge
      .append('text')
      .attr('text-anchor', 'middle')
      .attr('dy', 3)
      .attr('fill', '#ffffff')
      .attr('font-size', '8px')
      .attr('font-family', 'monospace')
      .attr('font-weight', '700')
      .text((d) => d.eventCount);

    // Primary Label (IP address or gateway name)
    nodeGroups
      .append('text')
      .attr('y', (d) => (d.nodeType === 'GATEWAY' ? 35 : 29))
      .attr('text-anchor', 'middle')
      .attr('fill', '#f8fafc')
      .attr('font-size', '10.5px')
      .attr('font-family', 'monospace')
      .attr('font-weight', '700')
      .text((d) => d.label);

    // SubLabel (Hostname / Country / Threat)
    nodeGroups
      .append('text')
      .attr('y', (d) => (d.nodeType === 'GATEWAY' ? 47 : 41))
      .attr('text-anchor', 'middle')
      .attr('fill', (d) => {
        if (d.isBlockedOrIsolated) return '#34d399';
        if (d.nodeType === 'ATTACKER_IP') return '#fca5a5';
        if (d.isCompromised) return '#d8b4fe';
        return '#94a3b8';
      })
      .attr('font-size', '9px')
      .attr('font-family', 'monospace')
      .text((d) => {
        if (d.isBlockedOrIsolated) return 'BLOQUÉ WAN';
        if (d.nodeType === 'ATTACKER_IP') {
          const primaryThreat = d.threats[0] || 'Menace WAN';
          return primaryThreat.length > 20 ? `${primaryThreat.slice(0, 18)}…` : primaryThreat;
        }
        return d.subLabel || '';
      });

    // Configure D3 Force Simulation
    const simulation = d3
      .forceSimulation<TopologyNode>(nodes)
      .force(
        'link',
        d3
          .forceLink<TopologyNode, TopologyLink>(links)
          .id((d) => d.id)
          .distance(() => (layoutMode === 'TRI_ZONE_FLOW' ? 210 : 165))
          .strength(layoutMode === 'TRI_ZONE_FLOW' ? 0.35 : 0.65)
      )
      .force(
        'charge',
        d3.forceManyBody().strength(layoutMode === 'TRI_ZONE_FLOW' ? -260 : -440)
      )
      .force('collide', d3.forceCollide().radius(48).iterations(2))
      .force(
        'x',
        d3
          .forceX<TopologyNode>((d) => {
            if (layoutMode === 'TRI_ZONE_FLOW') {
              if (d.nodeType === 'ATTACKER_IP')
                return includeGatewayNode ? width * 0.16 : width * 0.22;
              if (d.nodeType === 'GATEWAY') return width * 0.5;
              return includeGatewayNode ? width * 0.84 : width * 0.78;
            }
            if (d.nodeType === 'ATTACKER_IP') return width * 0.27;
            if (d.nodeType === 'GATEWAY') return width * 0.5;
            return width * 0.73;
          })
          .strength(layoutMode === 'TRI_ZONE_FLOW' ? 0.92 : 0.28)
      )
      .force('y', d3.forceY(height / 2).strength(0.16));

    // Drag behavior
    const dragBehavior = d3
      .drag<SVGGElement, TopologyNode>()
      .on('start', (event, d) => {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
      })
      .on('drag', (event, d) => {
        d.fx = event.x;
        d.fy = event.y;
      })
      .on('end', (event) => {
        if (!event.active) simulation.alphaTarget(0);
      });

    nodeGroups.call(dragBehavior);

    // Path geometry updater on tick
    const computeLinkPath = (d: TopologyLink): string => {
      const src = d.source as TopologyNode;
      const tgt = d.target as TopologyNode;
      const x1 = src.x || 0;
      const y1 = src.y || 0;
      const x2 = tgt.x || 0;
      const y2 = tgt.y || 0;

      if (layoutMode === 'TRI_ZONE_FLOW') {
        const midX = (x1 + x2) / 2;
        return `M ${x1},${y1} C ${midX},${y1} ${midX},${y2} ${x2},${y2}`;
      }

      // Slight quadratic curve for readability
      const dx = x2 - x1;
      const dy = y2 - y1;
      const dr = Math.sqrt(dx * dx + dy * dy) * 1.6;
      return `M ${x1},${y1} A ${dr},${dr} 0 0,1 ${x2},${y2}`;
    };

    simulation.on('tick', () => {
      // Keep nodes softly within canvas bounds
      nodes.forEach((n) => {
        n.x = Math.max(55, Math.min(width - 55, n.x || width / 2));
        n.y = Math.max(58, Math.min(height - 52, n.y || height / 2));
      });

      linkPaths.attr('d', computeLinkPath);
      animatedPaths.attr('d', computeLinkPath);

      linkLabelGroups.attr('transform', (d) => {
        const src = d.source as TopologyNode;
        const tgt = d.target as TopologyNode;
        const mx = ((src.x || 0) + (tgt.x || 0)) / 2;
        const my = ((src.y || 0) + (tgt.y || 0)) / 2 - 6;
        return `translate(${mx}, ${my})`;
      });

      nodeGroups.attr('transform', (d) => `translate(${d.x || 0}, ${d.y || 0})`);
    });

    return () => {
      simulation.stop();
      if (flowTimer) flowTimer.stop();
    };
  }, [
    graphData,
    dimensions,
    layoutMode,
    includeGatewayNode,
    animatePackets,
    selectedNodeId,
    selectedLinkId,
  ]);

  // Toolbar Zoom Handlers
  const handleZoomIn = () => {
    if (svgRef.current && zoomBehaviorRef.current) {
      d3.select(svgRef.current).transition().duration(200).call(zoomBehaviorRef.current.scaleBy, 1.25);
    }
  };

  const handleZoomOut = () => {
    if (svgRef.current && zoomBehaviorRef.current) {
      d3.select(svgRef.current).transition().duration(200).call(zoomBehaviorRef.current.scaleBy, 0.8);
    }
  };

  const handleResetView = () => {
    setSelectedNodeId(null);
    setSelectedLinkId(null);
    if (svgRef.current && zoomBehaviorRef.current) {
      d3.select(svgRef.current)
        .transition()
        .duration(250)
        .call(zoomBehaviorRef.current.transform, d3.zoomIdentity);
    }
  };

  // Trigger firewall block or host quarantine from topology inspector
  const handleBlockNodeIp = async (ip: string, isAttacker: boolean) => {
    setIsEnforcingIp(ip);
    try {
      const existingAction = analysis.stopActions.find((a) => a.target === ip);
      if (existingAction) {
        await onEnforceDefense(existingAction);
      } else {
        const synthesizedAction: StopAction = {
          id: `TOPOLOGY_${isAttacker ? 'BLOCK' : 'ISOLATE'}_${ip.replace(/\./g, '_')}`,
          title: isAttacker
            ? `Bloquer l'IP Attaquante ${ip} sur Zyxel WAN`
            : `Isoler l'Hôte LAN ${ip} via Nebula CDR`,
          type: isAttacker ? 'FIREWALL_BLOCK' : 'HOST_QUARANTINE',
          target: ip,
          priority: 'IMMEDIATE',
          rationale: isAttacker
            ? `Blocage déclenché depuis le graphe de topologie D3.js suite aux flux malveillants détectés depuis ${ip}.`
            : `Mise en quarantaine VLAN déclenchée depuis la topologie D3.js pour protéger le segment LAN.`,
          zyxelNebulaRule: {
            ruleName: isAttacker
              ? `SOC_D3_DROP_${ip.replace(/\./g, '_')}`
              : `SOC_CDR_ISOLATE_${ip.replace(/\./g, '_')}`,
            direction: isAttacker ? 'WAN to LAN' : 'LAN to WAN',
            action: 'DROP',
            sourceObject: ip,
            destinationObject: 'ANY',
          },
          zyxelCliCommand: `configure terminal\nfirewall rule-d3-${ip.replace(/\./g, '-')} action deny src ${ip}\nexit`,
          iptablesCommand: `iptables -I INPUT -s ${ip} -j DROP`,
          nftablesCommand: `nft add rule inet filter input ip saddr ${ip} drop`,
          pfSenseRule: `easyrule block wan ${ip}`,
        };
        await onEnforceDefense(synthesizedAction);
      }
    } finally {
      setIsEnforcingIp(null);
    }
  };

  // Summary counts for top strip
  const attackerCount = graphData.nodes.filter((n) => n.nodeType === 'ATTACKER_IP').length;
  const targetCount = graphData.nodes.filter((n) => n.nodeType === 'LOCAL_TARGET').length;
  const activeLinksCount = graphData.links.filter((l) => !l.isMitigated).length;
  const mitigatedLinksCount = graphData.links.filter((l) => l.isMitigated).length;

  return (
    <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-5">
      {/* Header & Top Controls */}
      <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div className="flex items-start gap-3">
          <div className="w-10 h-10 rounded-xl bg-cyan-950 text-cyan-400 border border-cyan-800 flex items-center justify-center flex-shrink-0">
            <Network className="w-5 h-5" />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="text-base font-bold text-white tracking-tight">
                Topologie Interactive des Menaces D3.js (Attaquant IP → Cible Locale)
              </h3>
              <span className="text-xs font-mono text-cyan-400">
                · {attackerCount} IPs sources · {targetCount} cibles LAN · {graphData.links.length} vecteurs
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              Cartographie dynamique basée sur les logs analysés : glissez les nœuds, zoomez et cliquez sur une IP ou un lien pour inspecter les paquets ou bloquer l'attaquant.
            </p>
          </div>
        </div>

        {/* Layout Mode & Gateway Toggle */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-1 p-1 rounded-xl bg-slate-950 border border-slate-800">
            <button
              onClick={() => setLayoutMode('FORCE_DIRECT')}
              className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition whitespace-nowrap shrink-0 ${
                layoutMode === 'FORCE_DIRECT'
                  ? 'bg-cyan-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <GitBranch className="w-3.5 h-3.5" />
              <span>Graphe de Force D3</span>
            </button>
            <button
              onClick={() => setLayoutMode('TRI_ZONE_FLOW')}
              className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition whitespace-nowrap shrink-0 ${
                layoutMode === 'TRI_ZONE_FLOW'
                  ? 'bg-cyan-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Layers className="w-3.5 h-3.5" />
              <span>Vue Tactique WAN → LAN</span>
            </button>
          </div>

          <button
            onClick={() => setIncludeGatewayNode(!includeGatewayNode)}
            className={`inline-flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-mono font-semibold border transition whitespace-nowrap shrink-0 ${
              includeGatewayNode
                ? 'bg-cyan-950/90 text-cyan-300 border-cyan-700'
                : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-white'
            }`}
            title="Afficher ou masquer la passerelle Zyxel ATP centrale entre les attaquants et les cibles locales"
          >
            <Shield className="w-3.5 h-3.5 text-cyan-400" />
            <span>{includeGatewayNode ? 'Passerelle Zyxel : Visible' : 'Flux Direct IP → Cible'}</span>
          </button>
        </div>
      </div>

      {/* Filter & Search Bar */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 p-3.5 rounded-xl bg-slate-950/80 border border-slate-800/90">
        <div className="flex flex-wrap items-center gap-2">
          {/* Search Input */}
          <div className="relative min-w-[230px] flex-1 sm:flex-initial">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filtrer IP, hôte, port, menace..."
              className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>

          {/* Severity Filter */}
          <div className="flex items-center gap-1 p-1 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono">
            <Filter className="w-3.5 h-3.5 text-slate-500 ml-1.5 mr-1" />
            {(
              [
                { id: 'ALL', label: 'Toutes' },
                { id: 'CRITICAL', label: 'Critiques' },
                { id: 'HIGH', label: 'Élevées+' },
                { id: 'MEDIUM_LOW', label: 'Moy/Faibles' },
              ] as { id: SeverityFilter; label: string }[]
            ).map((tab) => (
              <button
                key={tab.id}
                onClick={() => setSeverityFilter(tab.id)}
                className={`px-2.5 py-1 rounded-md text-[11px] font-semibold transition whitespace-nowrap shrink-0 ${
                  severityFilter === tab.id
                    ? 'bg-slate-800 text-cyan-300 border border-cyan-800/60'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Mitigation Status Filter */}
          <div className="flex items-center gap-1 p-1 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono">
            {(
              [
                { id: 'ALL', label: 'Tous statuts' },
                { id: 'ACTIVE_ONLY', label: 'Menaces actives' },
                { id: 'BLOCKED_ONLY', label: 'Bloquées' },
              ] as { id: StatusFilter; label: string }[]
            ).map((st) => (
              <button
                key={st.id}
                onClick={() => setStatusFilter(st.id)}
                className={`px-2.5 py-1 rounded-md text-[11px] font-semibold transition whitespace-nowrap shrink-0 ${
                  statusFilter === st.id
                    ? 'bg-slate-800 text-emerald-300 border border-emerald-800/60'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                {st.label}
              </button>
            ))}
          </div>
        </div>

        {/* Right Controls: Animation & Zoom */}
        <div className="flex items-center gap-2 self-end lg:self-auto">
          <button
            onClick={() => setAnimatePackets(!animatePackets)}
            className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[11px] font-mono font-semibold border transition whitespace-nowrap shrink-0 ${
              animatePackets
                ? 'bg-slate-900 text-cyan-300 border-cyan-800/60'
                : 'bg-slate-900 text-slate-400 border-slate-800'
            }`}
            title="Activer ou mettre en pause l'animation des paquets d'attaque"
          >
            {animatePackets ? <Pause className="w-3 h-3" /> : <Play className="w-3 h-3" />}
            <span>{animatePackets ? 'Flux animés' : 'Flux figés'}</span>
          </button>

          <div className="flex items-center gap-1 bg-slate-900 border border-slate-800 rounded-lg p-0.5">
            <button
              onClick={handleZoomIn}
              className="p-1.5 rounded hover:bg-slate-800 text-slate-300 hover:text-white transition"
              title="Zoomer"
            >
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={handleZoomOut}
              className="p-1.5 rounded hover:bg-slate-800 text-slate-300 hover:text-white transition"
              title="Dézoomer"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={handleResetView}
              className="px-2 py-1 rounded hover:bg-slate-800 text-slate-300 hover:text-cyan-300 text-[11px] font-mono flex items-center gap-1 transition"
              title="Réinitialiser le cadrage et la sélection"
            >
              <RotateCcw className="w-3 h-3" />
              <span>Centrer</span>
            </button>
          </div>
        </div>
      </div>

      {/* Main Content Split: D3 Canvas (8 cols) + Tactical Inspector Panel (4 cols) */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5 items-stretch">
        {/* Left/Center: Interactive D3 SVG Canvas */}
        <div
          ref={containerRef}
          className="xl:col-span-8 rounded-2xl bg-slate-950 border border-slate-800/90 relative overflow-hidden flex flex-col justify-between min-h-[540px]"
        >
          {graphData.nodes.length === 0 ? (
            <div className="flex-1 flex flex-col items-center justify-center p-10 text-center space-y-3">
              <Network className="w-10 h-10 text-slate-600" />
              <div className="space-y-1">
                <h4 className="text-sm font-bold text-white">
                  Aucun flux réseau ne correspond aux filtres actifs
                </h4>
                <p className="text-xs text-slate-400 font-mono">
                  Réinitialisez les filtres de gravité ou de recherche pour visualiser la topologie des menaces.
                </p>
              </div>
              <button
                onClick={() => {
                  setSeverityFilter('ALL');
                  setStatusFilter('ALL');
                  setSearchQuery('');
                }}
                className="px-3.5 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono font-semibold transition"
              >
                Réinitialiser les filtres
              </button>
            </div>
          ) : (
            <svg
              ref={svgRef}
              width={dimensions.width}
              height={dimensions.height}
              className="w-full h-[540px] block select-none"
            />
          )}

          {/* Legend & Telemetry Bar inside Canvas bottom */}
          <div className="px-4 py-2.5 bg-slate-900/95 border-t border-slate-800/90 flex flex-wrap items-center justify-between gap-3 text-[11px] font-mono">
            <div className="flex flex-wrap items-center gap-4">
              <span className="flex items-center gap-1.5 text-slate-300">
                <span className="w-2.5 h-2.5 rounded-full bg-red-500 inline-block" />
                IP Attaquante (WAN)
              </span>
              {includeGatewayNode && (
                <span className="flex items-center gap-1.5 text-slate-300">
                  <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 inline-block" />
                  Passerelle Zyxel ATP
                </span>
              )}
              <span className="flex items-center gap-1.5 text-slate-300">
                <span className="w-2.5 h-2.5 rounded-full bg-sky-400 inline-block" />
                Cible Locale (LAN)
              </span>
              <span className="flex items-center gap-1.5 text-slate-300">
                <span className="w-2.5 h-2.5 rounded-full bg-purple-400 inline-block" />
                Hôte Compromis (CDR)
              </span>
              <span className="flex items-center gap-1.5 text-slate-300">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 inline-block" />
                IP Bloquée / Neutralisée
              </span>
            </div>

            <div className="text-slate-400 tabular-nums">
              <span>{activeLinksCount} flux actifs</span>
              <span className="mx-1.5">·</span>
              <span className="text-emerald-400">{mitigatedLinksCount} neutralisés</span>
            </div>
          </div>
        </div>

        {/* Right: Interactive Node / Vector Inspector Panel */}
        <div className="xl:col-span-4 rounded-2xl bg-slate-950/90 border border-slate-800 p-5 flex flex-col justify-between space-y-4">
          {selectedNode ? (
            <div className="space-y-4">
              <div className="flex items-start justify-between gap-2 border-b border-slate-800 pb-3">
                <div className="flex items-center gap-2.5">
                  <div
                    className={`w-9 h-9 rounded-xl border flex items-center justify-center ${
                      selectedNode.nodeType === 'ATTACKER_IP'
                        ? 'bg-red-950/80 border-red-800 text-red-400'
                        : selectedNode.nodeType === 'GATEWAY'
                        ? 'bg-cyan-950/80 border-cyan-800 text-cyan-400'
                        : 'bg-sky-950/80 border-sky-800 text-sky-400'
                    }`}
                  >
                    {selectedNode.nodeType === 'ATTACKER_IP' ? (
                      <Globe className="w-4 h-4" />
                    ) : selectedNode.nodeType === 'GATEWAY' ? (
                      <Shield className="w-4 h-4" />
                    ) : (
                      <Laptop className="w-4 h-4" />
                    )}
                  </div>
                  <div>
                    <span className="text-[10px] font-mono text-slate-400 block">
                      {selectedNode.nodeType === 'ATTACKER_IP'
                        ? `SOURCE ATTAQUANTE WAN · ${selectedNode.country || 'EXT'}`
                        : selectedNode.nodeType === 'GATEWAY'
                        ? 'PASSERELLE DE SÉCURITÉ'
                        : `CIBLE LOCALE LAN · ${selectedNode.hostName || 'Hôte interne'}`}
                    </span>
                    <h4 className="text-sm font-bold font-mono text-white">{selectedNode.label}</h4>
                  </div>
                </div>

                <button
                  onClick={() => setSelectedNodeId(null)}
                  className="text-xs font-mono text-slate-400 hover:text-white px-2 py-1 rounded bg-slate-900 border border-slate-800"
                >
                  Fermer
                </button>
              </div>

              {/* Node Telemetry Counters */}
              <div className="grid grid-cols-3 gap-2.5 text-center font-mono">
                <div className="p-2.5 rounded-xl bg-slate-900 border border-slate-800">
                  <span className="text-[10px] text-slate-400 block">Logs Totaux</span>
                  <span className="text-base font-bold text-white tabular-nums">
                    {selectedNode.eventCount}
                  </span>
                </div>
                <div className="p-2.5 rounded-xl bg-slate-900 border border-slate-800">
                  <span className="text-[10px] text-slate-400 block">Critiques</span>
                  <span className="text-base font-bold text-red-400 tabular-nums">
                    {selectedNode.criticalCount}
                  </span>
                </div>
                <div className="p-2.5 rounded-xl bg-slate-900 border border-slate-800">
                  <span className="text-[10px] text-slate-400 block">Bloqués</span>
                  <span className="text-base font-bold text-emerald-400 tabular-nums">
                    {selectedNode.blockedCount}
                  </span>
                </div>
              </div>

              {/* Signatures & Targeted Ports */}
              <div className="space-y-2.5 text-xs font-mono">
                <div className="p-3 rounded-xl bg-slate-900/90 border border-slate-800 space-y-1.5">
                  <span className="text-[10px] text-slate-400 block">
                    Menaces & Signatures Associées ({selectedNode.threats.length})
                  </span>
                  <div className="text-slate-200 space-y-1">
                    {selectedNode.threats.slice(0, 4).map((t, i) => (
                      <div key={i} className="truncate text-[11px] flex items-center gap-1.5">
                        <AlertTriangle className="w-3 h-3 text-amber-400 shrink-0" />
                        <span className="truncate">{t}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="p-3 rounded-xl bg-slate-900/90 border border-slate-800 flex items-center justify-between">
                  <span className="text-[11px] text-slate-400">Ports & Protocoles :</span>
                  <span className="text-[11px] text-cyan-300 font-bold truncate max-w-[180px]">
                    {selectedNode.protocols.join('/') || 'TCP'}{' '}
                    {selectedNode.ports.length > 0
                      ? `(${selectedNode.ports.slice(0, 4).join(', ')})`
                      : ''}
                  </span>
                </div>
              </div>

              {/* Direct Response Action Button (Block WAN IP or Isolate Host) */}
              {selectedNode.nodeType !== 'GATEWAY' && selectedNode.ip && (
                <div>
                  {selectedNode.isBlockedOrIsolated ? (
                    <div className="p-3 rounded-xl bg-emerald-950/50 border border-emerald-800/70 flex items-center justify-center gap-2 text-xs font-mono text-emerald-300 font-bold">
                      <CheckCircle className="w-4 h-4 text-emerald-400" />
                      <span>
                        {selectedNode.nodeType === 'ATTACKER_IP'
                          ? 'IP Bloquée sur le pare-feu Zyxel WAN'
                          : 'Hôte LAN Isolé en Quarantaine CDR'}
                      </span>
                    </div>
                  ) : (
                    <button
                      onClick={() =>
                        handleBlockNodeIp(
                          selectedNode.ip!,
                          selectedNode.nodeType === 'ATTACKER_IP'
                        )
                      }
                      disabled={isEnforcingIp === selectedNode.ip}
                      className="w-full py-2.5 px-4 rounded-xl bg-red-600 hover:bg-red-500 disabled:opacity-50 text-white font-mono text-xs font-bold flex items-center justify-center gap-2 transition shadow-lg shadow-red-950/50"
                    >
                      <Lock className="w-3.5 h-3.5" />
                      <span>
                        {isEnforcingIp === selectedNode.ip
                          ? 'Application de la règle Nebula...'
                          : selectedNode.nodeType === 'ATTACKER_IP'
                          ? `Bloquer l'IP ${selectedNode.ip} sur WAN`
                          : `Isoler la cible ${selectedNode.ip} (CDR)`}
                      </span>
                    </button>
                  )}
                </div>
              )}

              {/* Related Logs List with Inspect trigger */}
              <div className="space-y-2">
                <span className="text-[11px] font-mono text-slate-400 font-semibold block">
                  Journaux d'événements liés ({selectedNode.relatedLogs.length}) :
                </span>
                <div className="space-y-1.5 max-h-[165px] overflow-y-auto pr-1">
                  {selectedNode.relatedLogs.slice(0, 6).map((log) => (
                    <button
                      key={log.id}
                      onClick={() => onInspectLog(log)}
                      className="w-full text-left p-2.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-cyan-700/60 transition flex items-center justify-between gap-2 text-[11px] font-mono"
                    >
                      <div className="min-w-0">
                        <div className="text-white font-semibold truncate">{log.threatName}</div>
                        <div className="text-[10px] text-slate-400 truncate">
                          {log.srcIp} → {log.dstIp}:{log.dstPort || 443} · {log.action}
                        </div>
                      </div>
                      <FileSearch className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                    </button>
                  ))}
                </div>
              </div>
            </div>
          ) : selectedLink ? (
            <div className="space-y-4">
              <div className="flex items-start justify-between gap-2 border-b border-slate-800 pb-3">
                <div>
                  <span className="text-[10px] font-mono text-cyan-400 block">
                    VECTEUR DE FLUX RÉSEAU SÉLECTIONNÉ
                  </span>
                  <h4 className="text-xs font-bold font-mono text-white flex items-center gap-1.5 mt-0.5">
                    <span className="text-red-400">{selectedLink.srcIp}</span>
                    <ArrowRight className="w-3.5 h-3.5 text-slate-500" />
                    <span className="text-sky-400">{selectedLink.dstIp}</span>
                  </h4>
                </div>
                <button
                  onClick={() => setSelectedLinkId(null)}
                  className="text-xs font-mono text-slate-400 hover:text-white px-2 py-1 rounded bg-slate-900 border border-slate-800"
                >
                  Fermer
                </button>
              </div>

              <div className="grid grid-cols-3 gap-2 text-center font-mono">
                <div className="p-2.5 rounded-xl bg-slate-900 border border-slate-800">
                  <span className="text-[10px] text-slate-400 block">Occurrences</span>
                  <span className="text-base font-bold text-white tabular-nums">
                    {selectedLink.count}
                  </span>
                </div>
                <div className="p-2.5 rounded-xl bg-slate-900 border border-slate-800">
                  <span className="text-[10px] text-slate-400 block">Gravité Max</span>
                  <span className="text-xs font-bold text-red-400 mt-1 block">
                    {selectedLink.severity}
                  </span>
                </div>
                <div className="p-2.5 rounded-xl bg-slate-900 border border-slate-800">
                  <span className="text-[10px] text-slate-400 block">Bloqués</span>
                  <span className="text-base font-bold text-emerald-400 tabular-nums">
                    {selectedLink.blockedCount}
                  </span>
                </div>
              </div>

              <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5 text-xs font-mono">
                <div className="flex justify-between">
                  <span className="text-slate-400">Protocoles / Ports :</span>
                  <span className="text-cyan-300 font-bold">
                    {selectedLink.protocols.join(', ') || 'TCP'} ·{' '}
                    {selectedLink.ports.join(', ') || 'Multi'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Modules Nebula :</span>
                  <span className="text-slate-200">{selectedLink.categories.join(', ')}</span>
                </div>
              </div>

              {!isTargetMitigated(selectedLink.srcIp) && (
                <button
                  onClick={() => handleBlockNodeIp(selectedLink.srcIp, true)}
                  disabled={isEnforcingIp === selectedLink.srcIp}
                  className="w-full py-2.5 px-4 rounded-xl bg-red-600 hover:bg-red-500 text-white font-mono text-xs font-bold flex items-center justify-center gap-2 transition"
                >
                  <Lock className="w-3.5 h-3.5" />
                  <span>Bloquer la source {selectedLink.srcIp}</span>
                </button>
              )}

              <div className="space-y-2">
                <span className="text-[11px] font-mono text-slate-400 font-semibold block">
                  Paquets & Alertes sur ce vecteur ({selectedLink.logs.length}) :
                </span>
                <div className="space-y-1.5 max-h-[180px] overflow-y-auto pr-1">
                  {selectedLink.logs.map((log) => (
                    <button
                      key={log.id}
                      onClick={() => onInspectLog(log)}
                      className="w-full text-left p-2.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-cyan-700/60 transition flex items-center justify-between gap-2 text-[11px] font-mono"
                    >
                      <div className="min-w-0">
                        <div className="text-white font-semibold truncate">{log.threatName}</div>
                        <div className="text-[10px] text-slate-400">
                          Port {log.dstPort || 443}/{log.protocol || 'TCP'} · {log.action}
                        </div>
                      </div>
                      <FileSearch className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                    </button>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            /* Default Overview when no specific node/link is clicked */
            <div className="space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div className="flex items-center gap-2">
                  <Crosshair className="w-4 h-4 text-cyan-400" />
                  <h4 className="text-sm font-bold text-white">
                    Synthèse des Couloirs d'Attaque
                  </h4>
                </div>
                <span className="text-[11px] font-mono text-slate-400">
                  Cliquez un nœud
                </span>
              </div>

              <p className="text-xs text-slate-400 leading-relaxed">
                Sélectionnez un <strong className="text-red-300">nœud attaquant (WAN)</strong>, une{' '}
                <strong className="text-sky-300">cible locale (LAN)</strong> ou un{' '}
                <strong className="text-cyan-300">lien directionnel</strong> dans le graphe D3.js pour inspecter les logs et déclencher un blocage immédiat.
              </p>

              {/* Top Active Attack Pairs List */}
              <div className="space-y-2">
                <span className="text-[11px] font-mono text-slate-400 font-semibold block">
                  Principaux Couples Attaquant IP → Cible Locale :
                </span>
                <div className="space-y-2 max-h-[310px] overflow-y-auto pr-1">
                  {graphData.links
                    .slice()
                    .sort((a, b) => b.count - a.count)
                    .slice(0, 6)
                    .map((link) => (
                      <div
                        key={link.id}
                        onClick={() => {
                          setSelectedLinkId(link.id);
                          setSelectedNodeId(null);
                        }}
                        className="p-3 rounded-xl bg-slate-900/90 hover:bg-slate-900 border border-slate-800 hover:border-cyan-700/60 transition cursor-pointer space-y-1.5 font-mono text-xs"
                      >
                        <div className="flex items-center justify-between gap-2">
                          <div className="flex items-center gap-1.5 min-w-0">
                            <span className="text-red-400 font-bold truncate">{link.srcIp}</span>
                            <ArrowRight className="w-3 h-3 text-slate-500 shrink-0" />
                            <span className="text-sky-300 font-bold truncate">{link.dstIp}</span>
                          </div>
                          <span className="text-[11px] text-white font-bold tabular-nums shrink-0">
                            {link.count} logs
                          </span>
                        </div>
                        <div className="flex items-center justify-between text-[11px] text-slate-400">
                          <span className="truncate max-w-[190px]">
                            {link.threatNames[0] || 'Flux suspect'}
                          </span>
                          <span
                            className={
                              link.isMitigated ? 'text-emerald-400 font-semibold' : 'text-amber-400'
                            }
                          >
                            {link.isMitigated ? 'Neutralisé' : `Port ${link.ports[0] || 443}`}
                          </span>
                        </div>
                      </div>
                    ))}
                </div>
              </div>
            </div>
          )}

          {/* Footer Quick Action */}
          <div className="pt-3 border-t border-slate-800 flex items-center justify-between text-[11px] font-mono text-slate-400">
            <span>Astuce : Double-clic pour libérer un nœud</span>
            <button
              onClick={onNavigateToCountermeasures}
              className="text-cyan-400 hover:text-cyan-300 font-semibold inline-flex items-center gap-1"
            >
              <span>Riposte globale</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
