import React, { useMemo, useState } from 'react';
import {
  ResponsiveContainer,
  ComposedChart,
  AreaChart,
  BarChart,
  Area,
  Bar,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ReferenceLine,
  Cell,
} from 'recharts';
import {
  TrendingUp,
  Clock,
  Flame,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Zap,
  BarChart3,
  Layers,
  Filter,
  Lock,
  ArrowUpRight,
  Sparkles,
  RefreshCw,
  Radio,
  Eye,
  Info,
} from 'lucide-react';
import { LogEntry, ThreatAnalysisResult, StopAction } from '../types';

export interface SecurityAlertsHourlyChartProps {
  logs: LogEntry[];
  analysis: ThreatAnalysisResult;
  onInspectLog?: (log: LogEntry) => void;
  onEnforceDefense?: (action: StopAction) => Promise<void>;
  onNavigateToCountermeasures?: () => void;
  deviceName?: string;
  isCompact?: boolean;
}

export type ChartDisplayMode = 'AREA_COMPOSED' | 'BAR_STACKED' | 'LINE_SHARP';
export type TimeScopeFilter = 'FULL_24H' | 'ACTIVE_HOURS_ONLY' | 'PEAK_BURST_10M';

export interface HourlyAlertDataPoint {
  hourIndex: number;
  hourLabel: string; // e.g. "14h00"
  timeRangeLabel: string; // e.g. "14h00 - 14h59"
  total: number;
  critical: number;
  high: number;
  mediumLow: number;
  blocked: number;
  unmitigated: number;
  isPeak: boolean;
  dominantThreat: string;
  topAttackerIp: string;
  topAttackerCountry?: string;
  sampleLogs: LogEntry[];
}

export interface BurstIntervalPoint {
  minuteIndex: number;
  timeLabel: string; // e.g. "14:20"
  total: number;
  critical: number;
  blocked: number;
  dominantThreat: string;
}

// Custom Tooltip for Recharts Hourly Chart
const CustomHourlyTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload || payload.length === 0) return null;
  const data: HourlyAlertDataPoint = payload[0]?.payload;
  if (!data) return null;

  return (
    <div className="bg-slate-950/95 border border-slate-700/80 rounded-xl p-3.5 shadow-2xl backdrop-blur-md text-xs font-mono space-y-2 min-w-[280px] z-50">
      {/* Header with hour and peak badge */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-2">
        <div className="flex items-center gap-1.5 text-white font-bold">
          <Clock className="w-3.5 h-3.5 text-cyan-400" />
          <span>{data.timeRangeLabel || label}</span>
        </div>
        {data.isPeak ? (
          <span className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950 text-rose-300 border border-rose-800 animate-pulse">
            <Flame className="w-3 h-3 text-rose-400" /> PIC D'ATTAQUE
          </span>
        ) : (
          <span className="text-[10px] text-slate-400">Créneau horaire</span>
        )}
      </div>

      {/* Metrics Breakdown */}
      <div className="space-y-1.5">
        <div className="flex items-center justify-between text-[11px]">
          <span className="text-slate-400 flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-cyan-400" />
            Volume Total d'Alertes :
          </span>
          <span className="font-bold text-white font-mono">{data.total} alertes</span>
        </div>

        <div className="flex items-center justify-between text-[11px]">
          <span className="text-rose-400 flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-rose-500" />
            Alertes Critiques :
          </span>
          <span className="font-bold text-rose-300 font-mono">{data.critical}</span>
        </div>

        <div className="flex items-center justify-between text-[11px]">
          <span className="text-amber-400 flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-amber-400" />
            Alertes Élevées :
          </span>
          <span className="font-bold text-amber-300 font-mono">{data.high}</span>
        </div>

        <div className="flex items-center justify-between text-[11px]">
          <span className="text-emerald-400 flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-400" />
            Bloquées par Passerelle Zyxel :
          </span>
          <span className="font-bold text-emerald-300 font-mono">{data.blocked}</span>
        </div>
      </div>

      {/* Dominant Attack Vector and Top Source */}
      {data.total > 0 && (
        <div className="pt-2 border-t border-slate-800/80 space-y-1 text-[11px]">
          {data.dominantThreat && (
            <div className="flex items-center justify-between">
              <span className="text-slate-500">Vecteur dominant :</span>
              <span className="text-cyan-300 font-semibold truncate max-w-[170px]" title={data.dominantThreat}>
                {data.dominantThreat}
              </span>
            </div>
          )}
          {data.topAttackerIp && (
            <div className="flex items-center justify-between">
              <span className="text-slate-500">Attaquant principal :</span>
              <span className="text-rose-300 font-mono">
                {data.topAttackerIp} {data.topAttackerCountry ? `(${data.topAttackerCountry})` : ''}
              </span>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

// Custom Pulse Dot on the Peak Value for Recharts
const CustomPeakDot = (props: any) => {
  const { cx, cy, payload } = props;
  if (!payload || !payload.isPeak || !payload.total) return null;

  return (
    <g>
      <circle cx={cx} cy={cy} r={9} fill="#ef4444" fillOpacity={0.25} className="animate-ping" />
      <circle cx={cx} cy={cy} r={6} fill="#ef4444" stroke="#ffffff" strokeWidth={2} />
      <circle cx={cx} cy={cy} r={2.5} fill="#ffffff" />
    </g>
  );
};

export const SecurityAlertsHourlyChart: React.FC<SecurityAlertsHourlyChartProps> = ({
  logs,
  analysis,
  onInspectLog,
  onEnforceDefense,
  onNavigateToCountermeasures,
  deviceName,
  isCompact = false,
}) => {
  const [displayMode, setDisplayMode] = useState<ChartDisplayMode>('AREA_COMPOSED');
  const [timeScope, setTimeScope] = useState<TimeScopeFilter>('FULL_24H');
  const [selectedHour, setSelectedHour] = useState<number | null>(null);
  const [showCriticalOnly, setShowCriticalOnly] = useState<boolean>(false);

  // 1. Process logs into 24-hour buckets
  const hourlyData = useMemo<HourlyAlertDataPoint[]>(() => {
    // Initialize 24 hourly buckets: 00h to 23h
    const buckets: HourlyAlertDataPoint[] = Array.from({ length: 24 }, (_, h) => {
      const paddedHour = String(h).padStart(2, '0');
      return {
        hourIndex: h,
        hourLabel: `${paddedHour}h00`,
        timeRangeLabel: `${paddedHour}h00 - ${paddedHour}h59`,
        total: 0,
        critical: 0,
        high: 0,
        mediumLow: 0,
        blocked: 0,
        unmitigated: 0,
        isPeak: false,
        dominantThreat: '',
        topAttackerIp: '',
        sampleLogs: [],
      };
    });

    if (!logs || logs.length === 0) {
      return buckets;
    }

    // Helper map for threat frequencies per hour
    const threatCountByHour: Record<number, Record<string, number>> = {};
    const ipCountByHour: Record<number, Record<string, { count: number; country?: string }>> = {};

    logs.forEach((log) => {
      let hour = 0;
      let matched = false;

      // Try parsing standard timestamp
      try {
        const d = new Date(log.timestamp);
        if (!isNaN(d.getTime())) {
          hour = d.getHours();
          matched = true;
        }
      } catch {
        // Fall back to regex
      }

      if (!matched && log.timestamp) {
        // Match HH:mm:ss or "T14:22" or " 14:22"
        const match = log.timestamp.match(/(?:T|\s|^)(\d{2}):\d{2}/);
        if (match && match[1]) {
          const parsed = parseInt(match[1], 10);
          if (!isNaN(parsed) && parsed >= 0 && parsed <= 23) {
            hour = parsed;
            matched = true;
          }
        }
      }

      // Safe clamp
      hour = Math.max(0, Math.min(23, hour));

      const bucket = buckets[hour];
      bucket.total += 1;
      bucket.sampleLogs.push(log);

      if (log.severity === 'CRITICAL') {
        bucket.critical += 1;
      } else if (log.severity === 'HIGH') {
        bucket.high += 1;
      } else {
        bucket.mediumLow += 1;
      }

      const isBlocked =
        log.action === 'Blocked' ||
        log.action === 'Dropped' ||
        log.action === 'Quarantined';
      if (isBlocked) {
        bucket.blocked += 1;
      } else {
        bucket.unmitigated += 1;
      }

      // Track threats
      if (!threatCountByHour[hour]) threatCountByHour[hour] = {};
      const threatName = log.threatName || log.category || 'Alerte générique';
      threatCountByHour[hour][threatName] = (threatCountByHour[hour][threatName] || 0) + 1;

      // Track attacker IP
      if (!ipCountByHour[hour]) ipCountByHour[hour] = {};
      const attackerIp = log.srcIp || log.source;
      if (attackerIp) {
        if (!ipCountByHour[hour][attackerIp]) {
          ipCountByHour[hour][attackerIp] = { count: 0, country: log.country };
        }
        ipCountByHour[hour][attackerIp].count += 1;
      }
    });

    // Determine max peak volume
    const maxVolume = Math.max(...buckets.map((b) => b.total), 0);

    // Populate dominant threat, top IP and peak flags
    buckets.forEach((b) => {
      // Mark as peak if this hour holds the maximum volume and total > 0
      if (maxVolume > 0 && b.total === maxVolume) {
        b.isPeak = true;
      }

      // Calculate dominant threat
      const threats = threatCountByHour[b.hourIndex];
      if (threats) {
        const sortedThreats = Object.entries(threats).sort((a, b) => b[1] - a[1]);
        if (sortedThreats.length > 0) {
          b.dominantThreat = sortedThreats[0][0];
        }
      }

      // Calculate top attacker IP
      const ips = ipCountByHour[b.hourIndex];
      if (ips) {
        const sortedIps = Object.entries(ips).sort((a, b) => b[1].count - a[1].count);
        if (sortedIps.length > 0) {
          b.topAttackerIp = sortedIps[0][0];
          b.topAttackerCountry = sortedIps[0][1].country;
        }
      }
    });

    return buckets;
  }, [logs]);

  // 2. Identify the absolute peak attack hour and related statistics
  const peakSummary = useMemo(() => {
    const activeBuckets = hourlyData.filter((b) => b.total > 0);
    if (activeBuckets.length === 0) return null;

    const peakBucket = hourlyData.reduce((max, cur) => (cur.total > max.total ? cur : max), hourlyData[0]);
    if (peakBucket.total === 0) return null;

    const totalLogsCount = logs.length || 1;
    const peakPercentage = Math.round((peakBucket.total / totalLogsCount) * 100);
    const avgVolumeActiveHours =
      activeBuckets.length > 0
        ? Math.round((logs.length / activeBuckets.length) * 10) / 10
        : 0;

    const surgeRate =
      avgVolumeActiveHours > 0
        ? Math.round(((peakBucket.total - avgVolumeActiveHours) / avgVolumeActiveHours) * 100)
        : 0;

    // Rate of critical alerts in peak
    const peakCriticalRatio =
      peakBucket.total > 0 ? Math.round((peakBucket.critical / peakBucket.total) * 100) : 0;

    // Mitigation rate during peak
    const peakMitigationRatio =
      peakBucket.total > 0 ? Math.round((peakBucket.blocked / peakBucket.total) * 100) : 0;

    return {
      peakBucket,
      peakPercentage,
      avgVolumeActiveHours,
      surgeRate,
      peakCriticalRatio,
      peakMitigationRatio,
      activeHoursCount: activeBuckets.length,
    };
  }, [hourlyData, logs]);

  // 3. Sub-interval burst (10-minute slices) when viewing the Peak Burst mode
  const burstData = useMemo<BurstIntervalPoint[]>(() => {
    if (!peakSummary) return [];
    const peakHour = peakSummary.peakBucket.hourIndex;
    const peakLogs = peakSummary.peakBucket.sampleLogs;

    // 6 slices of 10 minutes: 00-09, 10-19, 20-29, 30-39, 40-49, 50-59
    const slices: BurstIntervalPoint[] = Array.from({ length: 6 }, (_, i) => {
      const minStart = i * 10;
      const minEnd = minStart + 9;
      const hourStr = String(peakHour).padStart(2, '0');
      return {
        minuteIndex: i,
        timeLabel: `${hourStr}h${String(minStart).padStart(2, '0')}`,
        total: 0,
        critical: 0,
        blocked: 0,
        dominantThreat: '',
      };
    });

    const threatBySlice: Record<number, Record<string, number>> = {};

    peakLogs.forEach((log) => {
      let minute = 0;
      try {
        const d = new Date(log.timestamp);
        if (!isNaN(d.getTime())) {
          minute = d.getMinutes();
        } else {
          const match = log.timestamp.match(/:(\d{2}):/);
          if (match && match[1]) minute = parseInt(match[1], 10);
        }
      } catch {
        minute = 0;
      }
      const sliceIdx = Math.max(0, Math.min(5, Math.floor(minute / 10)));
      slices[sliceIdx].total += 1;
      if (log.severity === 'CRITICAL') slices[sliceIdx].critical += 1;
      if (log.action === 'Blocked' || log.action === 'Dropped' || log.action === 'Quarantined') {
        slices[sliceIdx].blocked += 1;
      }

      if (!threatBySlice[sliceIdx]) threatBySlice[sliceIdx] = {};
      const t = log.threatName || log.category || 'Hostile';
      threatBySlice[sliceIdx][t] = (threatBySlice[sliceIdx][t] || 0) + 1;
    });

    slices.forEach((s) => {
      const tMap = threatBySlice[s.minuteIndex];
      if (tMap) {
        const sorted = Object.entries(tMap).sort((a, b) => b[1] - a[1]);
        if (sorted.length > 0) s.dominantThreat = sorted[0][0];
      }
    });

    return slices;
  }, [peakSummary]);

  // 4. Filtered dataset based on user scope
  const chartData = useMemo(() => {
    if (timeScope === 'ACTIVE_HOURS_ONLY') {
      const activeOnly = hourlyData.filter((b) => b.total > 0);
      return activeOnly.length > 0 ? activeOnly : hourlyData;
    }
    return hourlyData;
  }, [hourlyData, timeScope]);

  // Selected hour logs for quick drilldown
  const activeDrilldownLogs = useMemo(() => {
    if (selectedHour === null) return [];
    const bucket = hourlyData.find((b) => b.hourIndex === selectedHour);
    return bucket ? bucket.sampleLogs : [];
  }, [hourlyData, selectedHour]);

  // Matching StopAction if peak IP needs blocking
  const peakMatchingAction = useMemo(() => {
    if (!peakSummary?.peakBucket?.topAttackerIp) return null;
    return analysis.stopActions.find(
      (a) => a.target === peakSummary.peakBucket.topAttackerIp || a.type === 'FIREWALL_BLOCK'
    );
  }, [analysis.stopActions, peakSummary]);

  return (
    <div className="p-5 sm:p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-5 h-full flex flex-col justify-between">
      {/* Header section with Title, Description, and Live Peak Callout */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div className="flex items-start sm:items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-cyan-950 text-cyan-400 border border-cyan-800 flex items-center justify-center flex-shrink-0 shadow-inner">
            <TrendingUp className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-base font-bold text-white tracking-tight">
                Volume des Alertes de Sécurité par Heure (Recharts)
              </h3>
              <span className="text-[10px] font-mono font-bold text-cyan-400 bg-cyan-950/70 border border-cyan-800/80 px-2 py-0.5 rounded">
                Cycle 24h
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              Visualisation temporelle du trafic hostile par créneau horaire (00h-23h) & détection des pics d’assaut
            </p>
          </div>
        </div>

        {/* Peak Alert Callout Badge */}
        {peakSummary && (
          <div className="flex items-center gap-2.5 self-start lg:self-auto bg-gradient-to-r from-rose-950/80 via-slate-950 to-slate-900 border border-rose-800/80 rounded-xl px-3.5 py-2 shadow-lg">
            <div className="w-2.5 h-2.5 rounded-full bg-rose-500 animate-ping flex-shrink-0" />
            <div className="text-xs font-mono">
              <div className="flex items-center gap-2">
                <span className="text-rose-300 font-bold flex items-center gap-1">
                  <Flame className="w-3.5 h-3.5 text-rose-400" />
                  Pic Maximal : {peakSummary.peakBucket.hourLabel}
                </span>
                <span className="text-white font-extrabold px-1.5 py-0.2 rounded bg-rose-900/60 text-[11px]">
                  {peakSummary.peakBucket.total} alertes
                </span>
              </div>
              <div className="text-[10px] text-slate-400 flex items-center gap-2 mt-0.5">
                <span>{peakSummary.peakPercentage}% du total journalier</span>
                <span>·</span>
                <span className="text-rose-400 font-semibold">
                  +{peakSummary.surgeRate}% vs moyenne
                </span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Control Bar: Time Scope Filter & Chart Display Modes */}
      <div className="flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
        {/* Scope selector */}
        <div className="flex items-center gap-1 p-1 bg-slate-950/80 border border-slate-800 rounded-xl">
          <button
            onClick={() => setTimeScope('FULL_24H')}
            className={`px-3 py-1.5 rounded-lg font-semibold transition ${
              timeScope === 'FULL_24H'
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-800 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Toutes les 24h (00h-23h)
          </button>
          <button
            onClick={() => setTimeScope('ACTIVE_HOURS_ONLY')}
            className={`px-3 py-1.5 rounded-lg font-semibold transition ${
              timeScope === 'ACTIVE_HOURS_ONLY'
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-800 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Heures Actives ({hourlyData.filter((b) => b.total > 0).length}h)
          </button>
          {peakSummary && (
            <button
              onClick={() => setTimeScope('PEAK_BURST_10M')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-semibold transition ${
                timeScope === 'PEAK_BURST_10M'
                  ? 'bg-rose-950 text-rose-300 border border-rose-800 shadow-sm'
                  : 'text-slate-400 hover:text-rose-300'
              }`}
            >
              <Flame className="w-3.5 h-3.5 text-rose-400" />
              Zoom Rafale Pic ({peakSummary.peakBucket.hourLabel})
            </button>
          )}
        </div>

        {/* Display mode buttons */}
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1 p-1 bg-slate-950/80 border border-slate-800 rounded-xl">
            <button
              onClick={() => setDisplayMode('AREA_COMPOSED')}
              title="Aires et Courbes Recharts"
              className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg transition ${
                displayMode === 'AREA_COMPOSED'
                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-800 font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <TrendingUp className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Aires</span>
            </button>
            <button
              onClick={() => setDisplayMode('BAR_STACKED')}
              title="Histogramme Horaire Empilé Recharts"
              className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg transition ${
                displayMode === 'BAR_STACKED'
                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-800 font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <BarChart3 className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Histogramme</span>
            </button>
            <button
              onClick={() => setDisplayMode('LINE_SHARP')}
              title="Courbes Multi-Séries Recharts"
              className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg transition ${
                displayMode === 'LINE_SHARP'
                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-800 font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Layers className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Lignes</span>
            </button>
          </div>

          <button
            onClick={() => setShowCriticalOnly((prev) => !prev)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl border text-xs transition ${
              showCriticalOnly
                ? 'bg-rose-950 text-rose-300 border-rose-700 shadow-sm font-bold'
                : 'bg-slate-950/80 text-slate-400 border-slate-800 hover:text-slate-200'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
            <span>Critiques Seuls</span>
          </button>
        </div>
      </div>

      {/* Recharts Interactive Time Series Chart Canvas */}
      <div className="w-full h-[280px] sm:h-[320px] pt-1">
        {timeScope === 'PEAK_BURST_10M' ? (
          // 10-Minute Burst Chart for Peak Hour
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={burstData} margin={{ top: 15, right: 15, left: -15, bottom: 5 }}>
              <defs>
                <linearGradient id="burstGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#f43f5e" stopOpacity={0.9} />
                  <stop offset="100%" stopColor="#881337" stopOpacity={0.4} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
              <XAxis
                dataKey="timeLabel"
                stroke="#64748b"
                fontSize={11}
                tickLine={false}
                axisLine={{ stroke: '#334155' }}
              />
              <YAxis
                stroke="#64748b"
                fontSize={11}
                tickLine={false}
                axisLine={{ stroke: '#334155' }}
                allowDecimals={false}
              />
              <Tooltip
                content={({ active, payload }: any) => {
                  if (!active || !payload || !payload.length) return null;
                  const d: BurstIntervalPoint = payload[0].payload;
                  return (
                    <div className="bg-slate-950/95 border border-rose-800/80 rounded-xl p-3 shadow-2xl text-xs font-mono space-y-1.5">
                      <div className="text-white font-bold flex items-center justify-between gap-4 border-b border-slate-800 pb-1">
                        <span className="flex items-center gap-1 text-rose-400">
                          <Flame className="w-3.5 h-3.5" /> Rafale {d.timeLabel}
                        </span>
                        <span className="text-white font-bold">{d.total} alertes</span>
                      </div>
                      <div className="flex items-center justify-between text-[11px] text-slate-300">
                        <span>Événements Critiques :</span>
                        <span className="text-rose-400 font-bold">{d.critical}</span>
                      </div>
                      <div className="flex items-center justify-between text-[11px] text-slate-300">
                        <span>Bloqués par Zyxel :</span>
                        <span className="text-emerald-400 font-bold">{d.blocked}</span>
                      </div>
                      {d.dominantThreat && (
                        <div className="text-[11px] text-slate-400 pt-1 border-t border-slate-800">
                          Menace : <span className="text-cyan-300 font-semibold">{d.dominantThreat}</span>
                        </div>
                      )}
                    </div>
                  );
                }}
              />
              <Legend
                verticalAlign="top"
                align="right"
                wrapperStyle={{ paddingBottom: '12px', fontSize: '11px', fontFamily: 'monospace' }}
              />
              <Bar dataKey="total" name="Alertes par tranche de 10 min" fill="url(#burstGradient)" radius={[6, 6, 0, 0]} />
              <Bar dataKey="critical" name="Gravité Critique" fill="#ef4444" radius={[4, 4, 0, 0]} />
              <Bar dataKey="blocked" name="Bloquées Passerelle" fill="#10b981" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        ) : displayMode === 'BAR_STACKED' ? (
          // Recharts Stacked Hourly Bar Chart
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              data={chartData}
              margin={{ top: 15, right: 15, left: -15, bottom: 5 }}
              onClick={(state: any) => {
                if (state && state.activePayload && state.activePayload.length > 0) {
                  const clicked: HourlyAlertDataPoint = state.activePayload[0].payload;
                  setSelectedHour((prev) => (prev === clicked.hourIndex ? null : clicked.hourIndex));
                }
              }}
            >
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
              <XAxis
                dataKey="hourLabel"
                stroke="#64748b"
                fontSize={11}
                tickLine={false}
                axisLine={{ stroke: '#334155' }}
              />
              <YAxis
                stroke="#64748b"
                fontSize={11}
                tickLine={false}
                axisLine={{ stroke: '#334155' }}
                allowDecimals={false}
              />
              <Tooltip content={<CustomHourlyTooltip />} />
              <Legend
                verticalAlign="top"
                align="right"
                wrapperStyle={{ paddingBottom: '12px', fontSize: '11px', fontFamily: 'monospace' }}
              />
              {peakSummary && (
                <ReferenceLine
                  x={peakSummary.peakBucket.hourLabel}
                  stroke="#ef4444"
                  strokeDasharray="4 4"
                  strokeWidth={2}
                  label={{
                    value: `PIC (${peakSummary.peakBucket.total})`,
                    fill: '#ef4444',
                    fontSize: 10,
                    position: 'top',
                    fontFamily: 'monospace',
                  }}
                />
              )}
              {!showCriticalOnly && (
                <Bar
                  dataKey="mediumLow"
                  name="Faible / Moyen"
                  stackId="alerts"
                  fill="#06b6d4"
                  radius={[0, 0, 0, 0]}
                />
              )}
              {!showCriticalOnly && (
                <Bar
                  dataKey="high"
                  name="Sévérité Élevée"
                  stackId="alerts"
                  fill="#f59e0b"
                  radius={[0, 0, 0, 0]}
                />
              )}
              <Bar
                dataKey="critical"
                name="Sévérité Critique"
                stackId="alerts"
                fill="#ef4444"
                radius={[4, 4, 0, 0]}
              >
                {chartData.map((entry, index) => (
                  <Cell
                    key={`cell-${index}`}
                    fill={entry.isPeak ? '#f43f5e' : entry.critical > 0 ? '#ef4444' : '#64748b'}
                    stroke={entry.isPeak ? '#ffffff' : 'none'}
                    strokeWidth={entry.isPeak ? 1.5 : 0}
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        ) : displayMode === 'LINE_SHARP' ? (
          // Recharts Sharp Multi-Line Chart
          <ResponsiveContainer width="100%" height="100%">
            <ComposedChart
              data={chartData}
              margin={{ top: 15, right: 15, left: -15, bottom: 5 }}
              onClick={(state: any) => {
                if (state && state.activePayload && state.activePayload.length > 0) {
                  const clicked: HourlyAlertDataPoint = state.activePayload[0].payload;
                  setSelectedHour((prev) => (prev === clicked.hourIndex ? null : clicked.hourIndex));
                }
              }}
            >
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
              <XAxis
                dataKey="hourLabel"
                stroke="#64748b"
                fontSize={11}
                tickLine={false}
                axisLine={{ stroke: '#334155' }}
              />
              <YAxis
                stroke="#64748b"
                fontSize={11}
                tickLine={false}
                axisLine={{ stroke: '#334155' }}
                allowDecimals={false}
              />
              <Tooltip content={<CustomHourlyTooltip />} />
              <Legend
                verticalAlign="top"
                align="right"
                wrapperStyle={{ paddingBottom: '12px', fontSize: '11px', fontFamily: 'monospace' }}
              />
              {peakSummary && (
                <ReferenceLine
                  x={peakSummary.peakBucket.hourLabel}
                  stroke="#ef4444"
                  strokeDasharray="4 4"
                  strokeWidth={2}
                  label={{
                    value: `PIC (${peakSummary.peakBucket.total})`,
                    fill: '#ef4444',
                    fontSize: 10,
                    position: 'top',
                    fontFamily: 'monospace',
                  }}
                />
              )}
              {!showCriticalOnly && (
                <Line
                  type="monotone"
                  dataKey="total"
                  name="Volume Total"
                  stroke="#06b6d4"
                  strokeWidth={3}
                  dot={<CustomPeakDot />}
                  activeDot={{ r: 7, stroke: '#67e8f9', strokeWidth: 2 }}
                />
              )}
              <Line
                type="monotone"
                dataKey="critical"
                name="Alertes Critiques"
                stroke="#ef4444"
                strokeWidth={2.5}
                dot={{ fill: '#ef4444', r: 3 }}
                activeDot={{ r: 6, stroke: '#fecaca', strokeWidth: 2 }}
              />
              <Line
                type="monotone"
                dataKey="blocked"
                name="Neutralisées Passerelle"
                stroke="#10b981"
                strokeWidth={2}
                dot={{ fill: '#10b981', r: 3 }}
                activeDot={{ r: 5, stroke: '#a7f3d0', strokeWidth: 2 }}
              />
            </ComposedChart>
          </ResponsiveContainer>
        ) : (
          // Default: Recharts Composed Area + Line Chart with smooth Gradients
          <ResponsiveContainer width="100%" height="100%">
            <ComposedChart
              data={chartData}
              margin={{ top: 15, right: 15, left: -15, bottom: 5 }}
              onClick={(state: any) => {
                if (state && state.activePayload && state.activePayload.length > 0) {
                  const clicked: HourlyAlertDataPoint = state.activePayload[0].payload;
                  setSelectedHour((prev) => (prev === clicked.hourIndex ? null : clicked.hourIndex));
                }
              }}
            >
              <defs>
                <linearGradient id="hourlyCyanGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.45} />
                  <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                </linearGradient>
                <linearGradient id="hourlyRoseGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.5} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
              <XAxis
                dataKey="hourLabel"
                stroke="#64748b"
                fontSize={11}
                tickLine={false}
                axisLine={{ stroke: '#334155' }}
              />
              <YAxis
                stroke="#64748b"
                fontSize={11}
                tickLine={false}
                axisLine={{ stroke: '#334155' }}
                allowDecimals={false}
              />
              <Tooltip content={<CustomHourlyTooltip />} />
              <Legend
                verticalAlign="top"
                align="right"
                wrapperStyle={{ paddingBottom: '12px', fontSize: '11px', fontFamily: 'monospace' }}
              />

              {/* Peak Reference Line */}
              {peakSummary && (
                <ReferenceLine
                  x={peakSummary.peakBucket.hourLabel}
                  stroke="#ef4444"
                  strokeDasharray="4 4"
                  strokeWidth={2}
                  label={{
                    value: `PIC D'ATTAQUE : ${peakSummary.peakBucket.total} ALERTES`,
                    fill: '#f87171',
                    fontSize: 10,
                    position: 'top',
                    fontFamily: 'monospace',
                  }}
                />
              )}

              {/* Smooth Area for Total Volume */}
              {!showCriticalOnly && (
                <Area
                  type="monotone"
                  dataKey="total"
                  name="Volume Total d'Alertes"
                  stroke="#06b6d4"
                  strokeWidth={2.5}
                  fillOpacity={1}
                  fill="url(#hourlyCyanGradient)"
                  dot={<CustomPeakDot />}
                  activeDot={{ r: 7, stroke: '#67e8f9', strokeWidth: 2 }}
                />
              )}

              {/* Area for Critical Volume */}
              <Area
                type="monotone"
                dataKey="critical"
                name="Volume Critique"
                stroke="#ef4444"
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#hourlyRoseGradient)"
                dot={{ fill: '#ef4444', r: 3 }}
                activeDot={{ r: 6, stroke: '#fecaca', strokeWidth: 2 }}
              />

              {/* Line for Blocked Volume */}
              <Line
                type="monotone"
                dataKey="blocked"
                name="Neutralisées Zyxel"
                stroke="#10b981"
                strokeWidth={2}
                dot={{ fill: '#10b981', r: 2.5 }}
                activeDot={{ r: 5, stroke: '#a7f3d0', strokeWidth: 2 }}
              />
            </ComposedChart>
          </ResponsiveContainer>
        )}
      </div>

      {/* Peak Analysis & Action Card */}
      {peakSummary && (
        <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800/80 space-y-3">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-rose-500 animate-pulse" />
              <h4 className="text-xs font-bold text-white uppercase font-mono tracking-wider">
                Analyse Détaillée du Pic d'Attaque ({peakSummary.peakBucket.timeRangeLabel})
              </h4>
            </div>

            {peakMatchingAction && (
              <div className="flex items-center gap-2">
                <span className="text-[11px] text-slate-400 font-mono hidden sm:inline">
                  Riposte recommandée :
                </span>
                <button
                  onClick={() => {
                    if (onEnforceDefense) {
                      onEnforceDefense(peakMatchingAction);
                    } else if (onNavigateToCountermeasures) {
                      onNavigateToCountermeasures();
                    }
                  }}
                  className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-red-600/90 hover:bg-red-500 text-white font-mono text-xs font-semibold transition shadow-sm"
                >
                  <Lock className="w-3 h-3" /> Bloquer l'IP Hostile ({peakSummary.peakBucket.topAttackerIp})
                </button>
              </div>
            )}
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
              <span className="text-[10px] text-slate-500 block mb-0.5">Intensité du Pic</span>
              <span className="text-white font-bold text-sm">
                {peakSummary.peakBucket.total} alertes / heure
              </span>
              <span className="text-[10px] text-rose-400 block mt-0.5">
                +{peakSummary.surgeRate}% vs moyenne ({peakSummary.avgVolumeActiveHours}/h)
              </span>
            </div>

            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
              <span className="text-[10px] text-slate-500 block mb-0.5">Gravité Critique au Pic</span>
              <span className="text-rose-400 font-bold text-sm">
                {peakSummary.peakBucket.critical} alertes
              </span>
              <span className="text-[10px] text-slate-400 block mt-0.5">
                {peakSummary.peakCriticalRatio}% des alertes du pic
              </span>
            </div>

            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
              <span className="text-[10px] text-slate-500 block mb-0.5">Efficacité de Blocage</span>
              <span className="text-emerald-400 font-bold text-sm">
                {peakSummary.peakBucket.blocked} bloquées
              </span>
              <span className="text-[10px] text-slate-400 block mt-0.5">
                {peakSummary.peakMitigationRatio}% de taux d'interception
              </span>
            </div>

            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
              <span className="text-[10px] text-slate-500 block mb-0.5">Attaquant Principal</span>
              <span className="text-cyan-300 font-bold text-sm truncate block font-mono">
                {peakSummary.peakBucket.topAttackerIp || 'N/A'}
              </span>
              <span className="text-[10px] text-slate-400 block mt-0.5 truncate">
                {peakSummary.peakBucket.dominantThreat || 'Multi-vecteurs'}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Drilldown modal/drawer when user clicks on an hour bar/point */}
      {selectedHour !== null && (
        <div className="p-4 rounded-xl bg-slate-950 border border-cyan-800/80 space-y-3 animate-fadeIn">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <div className="flex items-center gap-2">
              <Eye className="w-4 h-4 text-cyan-400" />
              <span className="text-xs font-bold font-mono text-white">
                Inspection des événements du créneau {String(selectedHour).padStart(2, '0')}h00 - {String(selectedHour).padStart(2, '0')}h59
              </span>
              <span className="text-xs font-mono text-cyan-400 bg-cyan-950 px-2 py-0.5 rounded">
                {activeDrilldownLogs.length} logs
              </span>
            </div>
            <button
              onClick={() => setSelectedHour(null)}
              className="text-xs font-mono text-slate-400 hover:text-white px-2 py-0.5 rounded hover:bg-slate-800"
            >
              Fermer l'inspection
            </button>
          </div>

          <div className="max-h-44 overflow-y-auto space-y-1.5 pr-1 font-mono text-xs">
            {activeDrilldownLogs.length === 0 ? (
              <p className="text-slate-500 text-center py-2">Aucun log dans ce créneau.</p>
            ) : (
              activeDrilldownLogs.map((log) => (
                <div
                  key={log.id}
                  onClick={() => onInspectLog?.(log)}
                  className="p-2 rounded bg-slate-900/80 hover:bg-slate-800 border border-slate-800 flex items-center justify-between gap-3 cursor-pointer transition text-[11px]"
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <span
                      className={`px-1.5 py-0.2 rounded font-bold text-[10px] ${
                        log.severity === 'CRITICAL'
                          ? 'bg-rose-950 text-rose-300 border border-rose-800'
                          : log.severity === 'HIGH'
                          ? 'bg-amber-950 text-amber-300 border border-amber-800'
                          : 'bg-slate-800 text-slate-300'
                      }`}
                    >
                      {log.severity}
                    </span>
                    <span className="text-slate-400 truncate">{log.timestamp.slice(11, 19)}</span>
                    <span className="text-white font-semibold truncate">{log.threatName}</span>
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0">
                    {(log.srcIp || log.source) && (
                      <span className="text-cyan-400">{log.srcIp || log.source}</span>
                    )}
                    <span
                      className={`text-[10px] px-1.5 py-0.2 rounded ${
                        log.action === 'Blocked' || log.action === 'Dropped'
                          ? 'bg-emerald-950 text-emerald-300'
                          : 'bg-slate-800 text-slate-400'
                      }`}
                    >
                      {log.action}
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* Hourly Quick Metric Footer */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-3 border-t border-slate-800/80 text-xs font-mono">
        <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 flex items-center justify-between">
          <span className="text-slate-400">Total Flux Analysés</span>
          <span className="text-cyan-400 font-bold">{logs.length}</span>
        </div>
        <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 flex items-center justify-between">
          <span className="text-slate-400">Heures Sous Attaque</span>
          <span className="text-white font-bold">
            {hourlyData.filter((b) => b.total > 0).length} / 24h
          </span>
        </div>
        <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 flex items-center justify-between">
          <span className="text-slate-400">Gravité Critique</span>
          <span className="text-red-400 font-bold">
            {logs.filter((l) => l.severity === 'CRITICAL').length}
          </span>
        </div>
        <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 flex items-center justify-between">
          <span className="text-slate-400">Bloquées en Temps Réel</span>
          <span className="text-emerald-400 font-bold">
            {logs.filter((l) => l.action === 'Blocked' || l.action === 'Dropped' || l.action === 'Quarantined').length}
          </span>
        </div>
      </div>
    </div>
  );
};
