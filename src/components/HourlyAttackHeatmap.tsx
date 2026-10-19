import React, { useMemo, useState } from 'react';
import {
  ResponsiveContainer,
  ComposedChart,
  Area,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  Legend,
} from 'recharts';
import {
  Flame,
  Clock,
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  TrendingUp,
  Filter,
  Layers,
  Sparkles,
  Calendar,
  CheckCircle,
  Eye,
  ArrowRight,
  Info,
  Zap,
  Globe,
  Radio,
  SlidersHorizontal,
  ChevronRight,
  RefreshCw,
} from 'lucide-react';
import { LogEntry, ThreatAnalysisResult, StopAction, SeverityLevel } from '../types';

interface HourlyAttackHeatmapProps {
  logs: LogEntry[];
  analysis: ThreatAnalysisResult;
  onInspectLog?: (log: LogEntry) => void;
  onEnforceDefense?: (action: StopAction) => Promise<void>;
  onNavigateToCountermeasures?: () => void;
  deviceName?: string;
}

export type HeatmapMatrixMode = '24_HOURS' | 'WEEK_7X24' | 'CATEGORY_HOURLY';
export type SeverityFilterType = 'ALL' | 'CRITICAL_HIGH' | 'UNMITIGATED_ONLY' | 'BLOCKED_ONLY';

const DAYS_OF_WEEK = [
  { id: 0, label: 'Lundi', short: 'Lun' },
  { id: 1, label: 'Mardi', short: 'Mar' },
  { id: 2, label: 'Mercredi', short: 'Mer' },
  { id: 3, label: 'Jeudi', short: 'Jeu' },
  { id: 4, label: 'Vendredi', short: 'Ven' },
  { id: 5, label: 'Samedi', short: 'Sam' },
  { id: 6, label: 'Dimanche', short: 'Dim' },
];

const CATEGORIES_LIST = [
  'IDP/IPS',
  'Anti-Malware',
  'IP_Reputation',
  'Traffic_Anomaly',
  'VPN_Auth',
  'Content_Filter',
  'CDR_Quarantine',
];

// Helper to determine heat color scale from 0 to max
function getHeatColor(count: number, max: number, hasCritical: boolean): { bg: string; border: string; text: string; glow?: string } {
  if (count === 0) {
    return { bg: 'bg-slate-900/60', border: 'border-slate-800/80', text: 'text-slate-600' };
  }
  const ratio = max > 0 ? count / max : 0;

  if (ratio >= 0.75 || hasCritical && count >= 5) {
    return {
      bg: 'bg-gradient-to-br from-rose-950 to-red-900/90',
      border: 'border-rose-500/80',
      text: 'text-rose-200',
      glow: 'shadow-[0_0_15px_-3px_rgba(244,63,94,0.4)]',
    };
  }
  if (ratio >= 0.5) {
    return {
      bg: 'bg-gradient-to-br from-orange-950 to-amber-900/80',
      border: 'border-amber-500/70',
      text: 'text-amber-200',
      glow: 'shadow-[0_0_12px_-3px_rgba(245,158,11,0.3)]',
    };
  }
  if (ratio >= 0.25) {
    return {
      bg: 'bg-gradient-to-br from-cyan-950 to-blue-900/80',
      border: 'border-cyan-500/70',
      text: 'text-cyan-200',
      glow: 'shadow-[0_0_10px_-3px_rgba(6,182,212,0.25)]',
    };
  }
  return {
    bg: 'bg-gradient-to-br from-emerald-950/90 to-teal-900/60',
    border: 'border-emerald-600/60',
    text: 'text-emerald-300',
  };
}

export const HourlyAttackHeatmap: React.FC<HourlyAttackHeatmapProps> = ({
  logs,
  analysis,
  onInspectLog,
  onEnforceDefense,
  onNavigateToCountermeasures,
  deviceName = 'Passerelle Zyxel Nebula ATP',
}) => {
  const [matrixMode, setMatrixMode] = useState<HeatmapMatrixMode>('24_HOURS');
  const [severityFilter, setSeverityFilter] = useState<SeverityFilterType>('ALL');
  const [selectedHour, setSelectedHour] = useState<number | null>(null);
  const [selectedCell, setSelectedCell] = useState<{ day?: number; hour: number; category?: string } | null>(null);

  // Extract hour & day from log
  const parseLogTime = (log: LogEntry): { hour: number; dayOfWeek: number } => {
    if (log.timestamp) {
      const d = new Date(log.timestamp);
      if (!isNaN(d.getTime())) {
        const frenchDay = (d.getDay() + 6) % 7;
        return { hour: d.getHours(), dayOfWeek: frenchDay };
      }
      const match = log.timestamp.match(/(?:T|\s)(\d{2}):(\d{2})/);
      if (match) {
        return { hour: parseInt(match[1], 10) % 24, dayOfWeek: 3 };
      }
    }
    const hash = log.id.split('').reduce((acc, c) => acc + c.charCodeAt(0), 0);
    return { hour: (hash * 7) % 24, dayOfWeek: hash % 7 };
  };

  // Filter logs by selected severity filter
  const filteredLogs = useMemo(() => {
    return logs.filter((log) => {
      if (severityFilter === 'CRITICAL_HIGH') {
        if (log.severity !== 'CRITICAL' && log.severity !== 'HIGH') return false;
      } else if (severityFilter === 'UNMITIGATED_ONLY') {
        if (log.action === 'Blocked' || log.action === 'Dropped' || log.action === 'Quarantined') {
          return false;
        }
      } else if (severityFilter === 'BLOCKED_ONLY') {
        if (log.action !== 'Blocked' && log.action !== 'Dropped' && log.action !== 'Quarantined') {
          return false;
        }
      }
      return true;
    });
  }, [logs, severityFilter]);

  // Aggregate by 24 Hours
  const hourlyStats = useMemo(() => {
    const hours = Array.from({ length: 24 }, (_, h) => {
      return {
        hour: h,
        hourLabel: `${h.toString().padStart(2, '0')}h`,
        timeRange: `${h.toString().padStart(2, '0')}:00 - ${h.toString().padStart(2, '0')}:59`,
        total: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        blocked: 0,
        alerted: 0,
        threatsMap: new Map<string, number>(),
        sourceIps: new Set<string>(),
        targetIps: new Set<string>(),
        categoriesMap: new Map<string, number>(),
        logs: [] as LogEntry[],
      };
    });

    filteredLogs.forEach((log) => {
      const { hour } = parseLogTime(log);
      const slot = hours[hour];
      if (slot) {
        slot.total += 1;
        if (log.severity === 'CRITICAL') slot.critical += 1;
        else if (log.severity === 'HIGH') slot.high += 1;
        else if (log.severity === 'MEDIUM') slot.medium += 1;
        else slot.low += 1;

        if (log.action === 'Blocked' || log.action === 'Dropped' || log.action === 'Quarantined') {
          slot.blocked += 1;
        } else {
          slot.alerted += 1;
        }

        const threat = log.threatName || log.signature || 'Attaque indéterminée';
        slot.threatsMap.set(threat, (slot.threatsMap.get(threat) || 0) + 1);
        if (log.srcIp) slot.sourceIps.add(log.srcIp);
        if (log.dstIp) slot.targetIps.add(log.dstIp);
        slot.categoriesMap.set(log.category, (slot.categoriesMap.get(log.category) || 0) + 1);
        slot.logs.push(log);
      }
    });

    const maxTotal = Math.max(...hours.map((h) => h.total), 1);

    return hours.map((h) => {
      const sortedThreats = Array.from(h.threatsMap.entries()).sort((a, b) => b[1] - a[1]);
      const dominantThreat = sortedThreats[0]?.[0] || 'Calme / Trafic résiduel';
      const dominantCategory = Array.from(h.categoriesMap.entries()).sort((a, b) => b[1] - a[1])[0]?.[0] || 'Général';
      const blockRate = h.total > 0 ? Math.round((h.blocked / h.total) * 100) : 100;
      const riskScore = Math.min(
        100,
        Math.round((h.critical * 25 + h.high * 15 + h.medium * 8 + h.alerted * 12) / Math.max(1, h.total * 0.25))
      );

      return {
        ...h,
        dominantThreat,
        dominantCategory,
        blockRate,
        riskScore,
        maxTotal,
        heat: getHeatColor(h.total, maxTotal, h.critical > 0),
      };
    });
  }, [filteredLogs]);

  const maxHourlyVolume = useMemo(() => {
    return Math.max(...hourlyStats.map((h) => h.total), 1);
  }, [hourlyStats]);

  // Aggregate by 7 Days x 24 Hours Matrix
  const weekMatrix = useMemo(() => {
    // 7 days x 24 hours
    const matrix: Array<Array<{
      day: number;
      dayLabel: string;
      hour: number;
      hourLabel: string;
      count: number;
      critical: number;
      blocked: number;
      dominantThreat: string;
      logs: LogEntry[];
    }>> = DAYS_OF_WEEK.map((d) =>
      Array.from({ length: 24 }, (_, h) => ({
        day: d.id,
        dayLabel: d.label,
        hour: h,
        hourLabel: `${h.toString().padStart(2, '0')}h`,
        count: 0,
        critical: 0,
        blocked: 0,
        dominantThreat: '',
        logs: [],
      }))
    );

    filteredLogs.forEach((log) => {
      const { hour, dayOfWeek } = parseLogTime(log);
      const cell = matrix[dayOfWeek]?.[hour];
      if (cell) {
        cell.count += 1;
        if (log.severity === 'CRITICAL') cell.critical += 1;
        if (log.action === 'Blocked' || log.action === 'Dropped' || log.action === 'Quarantined') {
          cell.blocked += 1;
        }
        if (!cell.dominantThreat) {
          cell.dominantThreat = log.threatName || log.signature || 'Attaque';
        }
        cell.logs.push(log);
      }
    });

    let maxCellCount = 1;
    matrix.forEach((row) => {
      row.forEach((cell) => {
        if (cell.count > maxCellCount) maxCellCount = cell.count;
      });
    });

    return { matrix, maxCellCount };
  }, [filteredLogs]);

  // Identify the Most Critical Time Slots (e.g. 4-hour windows or peak hours)
  const criticalTimeSlots = useMemo(() => {
    // Group into 6 4-hour slots to provide strategic executive summary
    const slots = [
      { id: 'slot-night', label: '00h - 04h', title: 'Nuit Profonde / Furtivité', hours: [0, 1, 2, 3] },
      { id: 'slot-dawn', label: '04h - 08h', title: 'Aube & Prémices d\'Assaut', hours: [4, 5, 6, 7] },
      { id: 'slot-morning', label: '08h - 12h', title: 'Matinée & Début d\'Activité', hours: [8, 9, 10, 11] },
      { id: 'slot-afternoon', label: '12h - 16h', title: 'Après-Midi & Flux Métier', hours: [12, 13, 14, 15] },
      { id: 'slot-evening', label: '16h - 20h', title: 'Fin de Journée & Post-Travail', hours: [16, 17, 18, 19] },
      { id: 'slot-late', label: '20h - 24h', title: 'Soirée & Scans Automatisés', hours: [20, 21, 22, 23] },
    ].map((s) => {
      let totalAttacks = 0;
      let criticalAttacks = 0;
      let blockedAttacks = 0;
      let alertedAttacks = 0;
      const threatsMap = new Map<string, number>();
      const involvedLogs: LogEntry[] = [];

      s.hours.forEach((h) => {
        const stat = hourlyStats[h];
        if (stat) {
          totalAttacks += stat.total;
          criticalAttacks += stat.critical;
          blockedAttacks += stat.blocked;
          alertedAttacks += stat.alerted;
          stat.threatsMap.forEach((v, k) => threatsMap.set(k, (threatsMap.get(k) || 0) + v));
          involvedLogs.push(...stat.logs);
        }
      });

      const topThreat = Array.from(threatsMap.entries()).sort((a, b) => b[1] - a[1])[0]?.[0] || 'Flux résiduel normal';
      const blockRate = totalAttacks > 0 ? Math.round((blockedAttacks / totalAttacks) * 100) : 100;
      // Criticality Score out of 100
      const criticalityScore = Math.min(
        100,
        Math.round(criticalAttacks * 20 + alertedAttacks * 10 + totalAttacks * 3)
      );

      return {
        ...s,
        totalAttacks,
        criticalAttacks,
        blockedAttacks,
        alertedAttacks,
        topThreat,
        blockRate,
        criticalityScore,
        involvedLogs,
      };
    });

    // Sort by criticality score descending
    return slots.sort((a, b) => b.criticalityScore - a.criticalityScore);
  }, [hourlyStats]);

  const topCriticalSlot = criticalTimeSlots[0];
  const peakHourStat = useMemo(() => {
    return hourlyStats.reduce((max, cur) => (cur.total > max.total ? cur : max), hourlyStats[0]);
  }, [hourlyStats]);

  // Selected hour details
  const activeHourDetail = useMemo(() => {
    if (selectedHour === null) return peakHourStat;
    return hourlyStats[selectedHour] || peakHourStat;
  }, [selectedHour, hourlyStats, peakHourStat]);

  return (
    <div className="p-6 rounded-3xl bg-slate-900/90 border border-slate-800 shadow-2xl space-y-6">
      {/* Top Header & Overview */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2 flex-wrap">
            <div className="w-8 h-8 rounded-xl bg-rose-950/80 border border-rose-600/70 flex items-center justify-center text-rose-400">
              <Flame className="w-4 h-4 animate-pulse" />
            </div>
            <h3 className="text-base font-bold text-white tracking-tight flex items-center gap-2">
              Heatmap Temporelle : Fréquence des Attaques par Heure
            </h3>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded-lg bg-slate-800 text-cyan-300 border border-slate-700">
              24 Heures & Détection des Créneaux Critiques
            </span>
          </div>
          <p className="text-xs text-slate-400 font-mono">
            Cartographie thermique de l'intensité des assauts sur <span className="text-slate-200 font-semibold">{deviceName}</span> pour anticiper les pics et adapter les politiques pare-feu.
          </p>
        </div>

        {/* View Mode Switcher */}
        <div className="flex items-center gap-1.5 p-1 rounded-xl bg-slate-950 border border-slate-800 self-start lg:self-auto text-xs font-mono">
          <button
            onClick={() => setMatrixMode('24_HOURS')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-semibold transition ${
              matrixMode === '24_HOURS'
                ? 'bg-rose-950 text-rose-200 border border-rose-800/80 shadow-sm'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
            }`}
          >
            <Clock className="w-3.5 h-3.5" />
            <span>Vue 24 Heures</span>
          </button>

          <button
            onClick={() => setMatrixMode('WEEK_7X24')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-semibold transition ${
              matrixMode === 'WEEK_7X24'
                ? 'bg-rose-950 text-rose-200 border border-rose-800/80 shadow-sm'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
            }`}
          >
            <Calendar className="w-3.5 h-3.5" />
            <span>Matrice 7 Jours × 24h</span>
          </button>
        </div>
      </div>

      {/* Critical Slots Intelligence Banner */}
      <div className="p-5 rounded-2xl bg-gradient-to-r from-rose-950/70 via-slate-900 to-slate-900 border border-rose-600/50 shadow-xl space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-2xl bg-rose-900/60 border border-rose-500/70 flex items-center justify-center text-rose-400 flex-shrink-0 animate-pulse">
              <AlertTriangle className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono font-bold text-rose-300 uppercase tracking-wider">
                  Diagnostic SOC : Créneaux Horaires à Haut Risque
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-rose-950 text-rose-300 border border-rose-800 font-bold">
                  Score de Criticité : {topCriticalSlot.criticalityScore}/100
                </span>
              </div>
              <p className="text-xs text-slate-300 font-sans mt-0.5">
                Le créneau le plus exposé est <strong className="text-white font-mono">{topCriticalSlot.label}</strong> ({topCriticalSlot.title}) avec <strong className="text-rose-400 font-mono">{topCriticalSlot.totalAttacks} attaques</strong>, dont <strong className="text-rose-300 font-mono">{topCriticalSlot.criticalAttacks} critiques</strong>.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 flex-shrink-0">
            {onNavigateToCountermeasures && (
              <button
                onClick={onNavigateToCountermeasures}
                className="inline-flex items-center gap-2 px-3.5 py-2 rounded-xl bg-rose-600 hover:bg-rose-500 text-white font-mono text-xs font-bold transition shadow-md shadow-rose-950"
              >
                <Zap className="w-3.5 h-3.5" />
                <span>Renforcer Riposte Pare-feu</span>
              </button>
            )}
          </div>
        </div>

        {/* 3 Top Critical Slot Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2 border-t border-rose-900/40 text-xs font-mono">
          {criticalTimeSlots.slice(0, 3).map((slot, idx) => (
            <div
              key={slot.id}
              onClick={() => {
                setSelectedHour(slot.hours[0]);
              }}
              className={`p-3 rounded-xl border transition cursor-pointer flex flex-col justify-between ${
                idx === 0
                  ? 'bg-rose-950/40 border-rose-600/60 hover:border-rose-400'
                  : 'bg-slate-950/50 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-white flex items-center gap-1.5">
                    <Clock className="w-3.5 h-3.5 text-cyan-400" />
                    {slot.label}
                  </span>
                  <span
                    className={`text-[10px] font-bold px-1.5 py-0.2 rounded ${
                      idx === 0 ? 'bg-rose-900 text-rose-200' : 'bg-slate-800 text-slate-300'
                    }`}
                  >
                    Rang #{idx + 1}
                  </span>
                </div>
                <div className="text-[11px] text-slate-400 truncate">{slot.title}</div>
                <div className="text-slate-300 pt-1">
                  Menace : <strong className="text-rose-300">{slot.topThreat}</strong>
                </div>
              </div>

              <div className="pt-2 mt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-400">
                <span>{slot.totalAttacks} événements</span>
                <span className="text-emerald-400 font-bold">{slot.blockRate}% bloqués</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Filter and Legend Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono">
        {/* Severity Filter */}
        <div className="flex items-center gap-1.5 flex-wrap">
          <span className="text-slate-400 flex items-center gap-1">
            <Filter className="w-3.5 h-3.5 text-slate-500" />
            Filtre :
          </span>
          {(
            [
              { id: 'ALL', label: `Tous les flux (${logs.length})` },
              { id: 'CRITICAL_HIGH', label: 'Critiques & Élevés' },
              { id: 'UNMITIGATED_ONLY', label: 'Non-bloqués (Alertes)' },
              { id: 'BLOCKED_ONLY', label: 'Interceptions IDP' },
            ] as const
          ).map((filter) => (
            <button
              key={filter.id}
              onClick={() => setSeverityFilter(filter.id)}
              className={`px-2.5 py-1 rounded-lg border transition ${
                severityFilter === filter.id
                  ? 'bg-slate-800 text-cyan-300 border-cyan-700 font-bold'
                  : 'bg-slate-950/60 text-slate-400 border-slate-800 hover:text-white'
              }`}
            >
              {filter.label}
            </button>
          ))}
        </div>

        {/* Heatmap Color Scale Legend */}
        <div className="flex items-center gap-2 text-[11px] text-slate-400 flex-shrink-0">
          <span className="text-slate-500">Intensité :</span>
          <span className="flex items-center gap-1">
            <span className="w-3 h-3 rounded bg-slate-900 border border-slate-800 inline-block" /> 0
          </span>
          <span className="flex items-center gap-1">
            <span className="w-3 h-3 rounded bg-emerald-950 border border-emerald-600 inline-block" /> Faible
          </span>
          <span className="flex items-center gap-1">
            <span className="w-3 h-3 rounded bg-cyan-950 border border-cyan-500 inline-block" /> Modéré
          </span>
          <span className="flex items-center gap-1">
            <span className="w-3 h-3 rounded bg-amber-950 border border-amber-500 inline-block" /> Élevé
          </span>
          <span className="flex items-center gap-1">
            <span className="w-3 h-3 rounded bg-rose-950 border border-rose-500 inline-block" /> Critique (Pic)
          </span>
        </div>
      </div>

      {/* VIEW 1: 24-HOUR INTERACTIVE HEATMAP GRID */}
      {matrixMode === '24_HOURS' && (
        <div className="space-y-4">
          <div className="grid grid-cols-4 sm:grid-cols-6 lg:grid-cols-12 gap-2 font-mono">
            {hourlyStats.map((slot) => {
              const isSelected = selectedHour === slot.hour;
              const isPeak = slot.hour === peakHourStat.hour && slot.total > 0;

              return (
                <div
                  key={slot.hour}
                  onClick={() => setSelectedHour(slot.hour)}
                  className={`p-2.5 rounded-2xl border transition cursor-pointer flex flex-col justify-between relative group ${
                    slot.heat.bg
                  } ${slot.heat.border} ${slot.heat.glow || ''} ${
                    isSelected ? 'ring-2 ring-cyan-400 scale-[1.03] z-10' : 'hover:scale-[1.02]'
                  }`}
                  title={`${slot.timeRange}: ${slot.total} attaques (${slot.dominantThreat})`}
                >
                  {isPeak && (
                    <span className="absolute -top-1.5 -right-1.5 px-1.5 py-0.2 rounded-full bg-rose-600 text-white text-[9px] font-bold shadow-md animate-pulse">
                      PIC
                    </span>
                  )}

                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-300">{slot.hourLabel}</span>
                    <span className="text-[10px] text-slate-400">{slot.total}</span>
                  </div>

                  <div className="my-1.5 text-center">
                    <div className="text-lg font-extrabold text-white leading-none">
                      {slot.total}
                    </div>
                    <span className="text-[9px] text-slate-400 block truncate mt-1" title={slot.dominantThreat}>
                      {slot.dominantThreat}
                    </span>
                  </div>

                  <div className="pt-1 border-t border-white/10 flex items-center justify-between text-[9px]">
                    <span className={slot.critical > 0 ? 'text-rose-400 font-bold' : 'text-slate-500'}>
                      {slot.critical > 0 ? `${slot.critical} crit.` : '0 crit.'}
                    </span>
                    <span className="text-emerald-400 font-semibold">{slot.blockRate}%</span>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Continuous Trend Curve using Recharts ComposedChart */}
          <div className="p-4 rounded-2xl bg-slate-950/70 border border-slate-800 space-y-2">
            <div className="flex items-center justify-between text-xs font-mono text-slate-400">
              <span className="flex items-center gap-1.5 text-slate-200 font-semibold">
                <TrendingUp className="w-3.5 h-3.5 text-cyan-400" />
                Courbe Continue de la Vélocité Horaire (Attaques Totales vs Événements Bloqués)
              </span>
              <span>Pic à {peakHourStat.hourLabel} ({peakHourStat.total} flux)</span>
            </div>

            <div className="h-44 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <ComposedChart data={hourlyStats} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                  <defs>
                    <linearGradient id="hourlyAreaGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.6} />
                      <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                  <XAxis
                    dataKey="hourLabel"
                    tick={{ fill: '#94a3b8', fontSize: 10, fontFamily: 'monospace' }}
                    interval={1}
                  />
                  <YAxis tick={{ fill: '#94a3b8', fontSize: 10, fontFamily: 'monospace' }} />
                  <Tooltip
                    content={({ active, payload }) => {
                      if (!active || !payload || !payload.length) return null;
                      const data = payload[0].payload;
                      return (
                        <div className="p-3 rounded-xl bg-slate-950 border border-slate-700 shadow-2xl text-xs font-mono space-y-1">
                          <div className="text-cyan-400 font-bold">{data.timeRange}</div>
                          <div className="text-white">Attaques totales : <strong>{data.total}</strong></div>
                          <div className="text-rose-400">Critiques : <strong>{data.critical}</strong></div>
                          <div className="text-emerald-400">Bloquées IDP : <strong>{data.blocked}</strong> ({data.blockRate}%)</div>
                          <div className="text-slate-400 text-[11px] pt-1 border-t border-slate-800">
                            Vecteur : {data.dominantThreat}
                          </div>
                        </div>
                      );
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="total"
                    name="Attaques Totales"
                    stroke="#f43f5e"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#hourlyAreaGrad)"
                  />
                  <Bar
                    dataKey="blocked"
                    name="Flux Bloqués IDP"
                    fill="#10b981"
                    radius={[4, 4, 0, 0]}
                    maxBarSize={18}
                  />
                </ComposedChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      )}

      {/* VIEW 2: 7 DAYS X 24 HOURS MATRIX HEATMAP */}
      {matrixMode === 'WEEK_7X24' && (
        <div className="space-y-4">
          <div className="p-4 rounded-2xl bg-slate-950 border border-slate-800 overflow-x-auto">
            <div className="min-w-[760px] space-y-2">
              {/* Header: 24 hour numbers */}
              <div className="flex items-center gap-1 pl-16 text-[10px] font-mono text-slate-500">
                {Array.from({ length: 24 }, (_, h) => (
                  <div key={h} className="flex-1 text-center">
                    {h % 2 === 0 ? `${h}h` : ''}
                  </div>
                ))}
              </div>

              {/* 7 Rows for Days of Week */}
              {weekMatrix.matrix.map((row, dayIdx) => (
                <div key={dayIdx} className="flex items-center gap-1">
                  <span className="w-14 text-xs font-mono font-bold text-slate-400 flex-shrink-0">
                    {DAYS_OF_WEEK[dayIdx].short}
                  </span>
                  <div className="flex-1 flex items-center gap-1">
                    {row.map((cell) => {
                      const heat = getHeatColor(cell.count, weekMatrix.maxCellCount, cell.critical > 0);
                      const isCellSelected =
                        selectedCell?.day === cell.day && selectedCell?.hour === cell.hour;

                      return (
                        <div
                          key={cell.hour}
                          onClick={() => {
                            setSelectedCell({ day: cell.day, hour: cell.hour });
                            setSelectedHour(cell.hour);
                          }}
                          className={`flex-1 h-7 rounded-md border transition cursor-pointer flex items-center justify-center text-[10px] font-mono font-bold ${
                            heat.bg
                          } ${heat.border} ${heat.text} ${
                            isCellSelected ? 'ring-2 ring-cyan-400 scale-110 z-10' : 'hover:scale-105'
                          }`}
                          title={`${cell.dayLabel} à ${cell.hourLabel}: ${cell.count} attaques (${cell.critical} critiques)`}
                        >
                          {cell.count > 0 ? cell.count : ''}
                        </div>
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Selected Hour Details Panel */}
      <div className="p-4 rounded-2xl bg-slate-950/80 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4 font-mono text-xs">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="text-slate-400">Créneau Sélectionné :</span>
            <span className="px-2.5 py-0.5 rounded-lg bg-cyan-950 text-cyan-300 font-bold border border-cyan-800 text-sm">
              {activeHourDetail.timeRange}
            </span>
            <span className="text-slate-400">• Total : <strong className="text-white">{activeHourDetail.total} flux</strong></span>
            <span className="text-rose-400">• Critiques : <strong>{activeHourDetail.critical}</strong></span>
          </div>
          <div className="text-slate-400 text-[11px]">
            Vecteur dominant : <strong className="text-slate-200">{activeHourDetail.dominantThreat}</strong> · {activeHourDetail.sourceIps.size} adresses IP attaquantes uniques
          </div>
        </div>

        <div className="flex items-center gap-2 flex-shrink-0">
          {onInspectLog && activeHourDetail.logs.length > 0 && (
            <button
              onClick={() => onInspectLog(activeHourDetail.logs[0])}
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 transition"
              title="Inspecter le premier log de ce créneau horaire avec l'IA"
            >
              <Eye className="w-3.5 h-3.5 text-cyan-400" />
              <span>Inspecter Logs du Créneau</span>
            </button>
          )}

          {activeHourDetail.critical > 0 && onNavigateToCountermeasures && (
            <button
              onClick={onNavigateToCountermeasures}
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl bg-rose-600 hover:bg-rose-500 text-white text-xs font-bold transition shadow-sm"
            >
              <Zap className="w-3.5 h-3.5" />
              <span>Bloquer les IPs de ce Créneau</span>
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
