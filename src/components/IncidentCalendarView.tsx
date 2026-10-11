import React, { useState, useMemo } from 'react';
import {
  Calendar,
  TrendingUp,
  Flame,
  AlertTriangle,
  BarChart3,
  Clock,
  ShieldAlert,
  ChevronLeft,
  ChevronRight,
  Layers,
  Activity,
} from 'lucide-react';
import {
  ResponsiveContainer,
  ComposedChart,
  BarChart,
  Bar,
  Line,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  Cell,
} from 'recharts';
import { LogEntry, AnalysisHistoryItem } from '../types';

interface IncidentCalendarViewProps {
  logs: LogEntry[];
  historyList?: AnalysisHistoryItem[];
}

interface MonthlyIncidentData {
  month: string;
  shortMonth: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
  blockedRate: number;
  peakThreat: string;
}

interface WeeklyIncidentData {
  week: string;
  period: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
  avgRiskScore: number;
  dominantVector: string;
}

const CustomCalendarTooltip = ({ active, payload, label }: any) => {
  if (active && payload && payload.length) {
    const data = payload[0]?.payload;
    return (
      <div className="bg-slate-900 border border-slate-700 rounded-xl p-3.5 shadow-2xl backdrop-blur-md text-xs font-mono space-y-2 min-w-[230px]">
        <div className="flex items-center justify-between border-b border-slate-800 pb-1.5">
          <span className="font-bold text-white flex items-center gap-1.5">
            <Calendar className="w-3.5 h-3.5 text-cyan-400" />
            {data?.month || data?.week || label}
          </span>
          <span className="px-1.5 py-0.5 rounded bg-slate-800 text-cyan-300 text-[10px] font-bold">
            Total : {data?.total} incidents
          </span>
        </div>

        <div className="space-y-1 text-[11px]">
          <div className="flex items-center justify-between">
            <span className="flex items-center gap-1.5 text-red-400">
              <span className="w-2 h-2 rounded-full bg-red-500" />
              CRITICAL :
            </span>
            <span className="font-bold text-white">{data?.critical}</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="flex items-center gap-1.5 text-amber-400">
              <span className="w-2 h-2 rounded-full bg-amber-500" />
              HIGH :
            </span>
            <span className="font-bold text-white">{data?.high}</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="flex items-center gap-1.5 text-yellow-400">
              <span className="w-2 h-2 rounded-full bg-yellow-500" />
              MEDIUM :
            </span>
            <span className="font-bold text-white">{data?.medium}</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="flex items-center gap-1.5 text-blue-400">
              <span className="w-2 h-2 rounded-full bg-blue-500" />
              LOW :
            </span>
            <span className="font-bold text-white">{data?.low}</span>
          </div>
        </div>

        {(data?.peakThreat || data?.dominantVector) && (
          <div className="pt-1.5 border-t border-slate-800 text-[10px] text-slate-300">
            <span className="text-slate-500 block uppercase">Menace Dominante :</span>
            <span className="text-cyan-300 font-bold">
              {data?.peakThreat || data?.dominantVector}
            </span>
          </div>
        )}
      </div>
    );
  }
  return null;
};

export const IncidentCalendarView: React.FC<IncidentCalendarViewProps> = ({
  logs,
  historyList = [],
}) => {
  const [viewMode, setViewMode] = useState<'monthly' | 'weekly' | 'heatmap'>('monthly');
  const [selectedSeverityFilter, setSelectedSeverityFilter] = useState<
    'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM'
  >('ALL');
  const [selectedMonthIndex, setSelectedMonthIndex] = useState<number>(11); // Current month

  // Current log counts by severity to anchor current period
  const currentCounts = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0 };
    logs.forEach((l) => {
      if (l.severity === 'CRITICAL') c.critical++;
      else if (l.severity === 'HIGH') c.high++;
      else if (l.severity === 'MEDIUM') c.medium++;
      else c.low++;
    });
    return c;
  }, [logs]);

  // 12-Month Long-Term Frequency Data
  const monthlyData = useMemo<MonthlyIncidentData[]>(() => {
    const baseMonths: Omit<MonthlyIncidentData, 'total'>[] = [
      {
        month: 'Octobre 2025',
        shortMonth: 'Oct',
        critical: 4,
        high: 11,
        medium: 19,
        low: 14,
        blockedRate: 94,
        peakThreat: 'Scan Botnet SSH & Telnet',
      },
      {
        month: 'Novembre 2025',
        shortMonth: 'Nov',
        critical: 7,
        high: 15,
        medium: 24,
        low: 18,
        blockedRate: 92,
        peakThreat: 'Campagne Phishing Financier',
      },
      {
        month: 'Décembre 2025',
        shortMonth: 'Déc',
        critical: 14,
        high: 28,
        medium: 35,
        low: 22,
        blockedRate: 89,
        peakThreat: 'Pic Fin d’Année : DDoS SYN Flood & VPN Brute-Force',
      },
      {
        month: 'Janvier 2026',
        shortMonth: 'Jan',
        critical: 6,
        high: 14,
        medium: 21,
        low: 16,
        blockedRate: 95,
        peakThreat: 'Credential Stuffing SSL-VPN',
      },
      {
        month: 'Février 2026',
        shortMonth: 'Fév',
        critical: 5,
        high: 12,
        medium: 18,
        low: 15,
        blockedRate: 96,
        peakThreat: 'Probing Directory Traversal HTTP',
      },
      {
        month: 'Mars 2026',
        shortMonth: 'Mar',
        critical: 11,
        high: 22,
        medium: 29,
        low: 20,
        blockedRate: 91,
        peakThreat: 'Exploitation CVE-2021-44228 Log4Shell',
      },
      {
        month: 'Avril 2026',
        shortMonth: 'Avr',
        critical: 8,
        high: 16,
        medium: 23,
        low: 17,
        blockedRate: 94,
        peakThreat: 'Distribution RedLine InfoStealer',
      },
      {
        month: 'Mai 2026',
        shortMonth: 'Mai',
        critical: 6,
        high: 13,
        medium: 20,
        low: 12,
        blockedRate: 97,
        peakThreat: 'Reconnaissance Ports WAN',
      },
      {
        month: 'Juin 2026',
        shortMonth: 'Juin',
        critical: 16,
        high: 31,
        medium: 38,
        low: 25,
        blockedRate: 88,
        peakThreat: 'Pic Estival : Intrusion C2 & Exfiltration DNS',
      },
      {
        month: 'Juillet 2026',
        shortMonth: 'Juil',
        critical: 9,
        high: 18,
        medium: 25,
        low: 19,
        blockedRate: 93,
        peakThreat: 'Brute Force IKEv2 PSK',
      },
      {
        month: 'Août 2026',
        shortMonth: 'Août',
        critical: 7,
        high: 14,
        medium: 22,
        low: 16,
        blockedRate: 95,
        peakThreat: 'Botnet Mirai Variant Scan',
      },
      {
        month: 'Septembre 2026 (Actuel)',
        shortMonth: 'Sep*',
        critical: Math.max(12, currentCounts.critical * 3 + historyList.length * 2),
        high: Math.max(19, currentCounts.high * 3 + historyList.length * 3),
        medium: Math.max(26, currentCounts.medium * 4 + 14),
        low: Math.max(15, currentCounts.low * 3 + 10),
        blockedRate: 92,
        peakThreat: logs[0]?.threatName || 'Cobalt Strike C2 & LockBit Ransomware',
      },
    ];

    return baseMonths.map((m) => ({
      ...m,
      total: m.critical + m.high + m.medium + m.low,
    }));
  }, [currentCounts, historyList.length, logs]);

  // 12-Week Frequency Data
  const weeklyData = useMemo<WeeklyIncidentData[]>(() => {
    const baseWeeks: Omit<WeeklyIncidentData, 'total'>[] = [
      {
        week: 'Sem 29',
        period: '13 - 19 Juil',
        critical: 2,
        high: 5,
        medium: 8,
        low: 6,
        avgRiskScore: 54,
        dominantVector: 'Port Scan WAN',
      },
      {
        week: 'Sem 30',
        period: '20 - 26 Juil',
        critical: 3,
        high: 6,
        medium: 9,
        low: 5,
        avgRiskScore: 61,
        dominantVector: 'Brute Force SSH',
      },
      {
        week: 'Sem 31',
        period: '27 Juil - 02 Août',
        critical: 1,
        high: 4,
        medium: 7,
        low: 6,
        avgRiskScore: 48,
        dominantVector: 'Filtrage Contenu Web',
      },
      {
        week: 'Sem 32',
        period: '03 - 09 Août',
        critical: 2,
        high: 5,
        medium: 8,
        low: 4,
        avgRiskScore: 52,
        dominantVector: 'Tentatives VPN SSL',
      },
      {
        week: 'Sem 33',
        period: '10 - 16 Août',
        critical: 6,
        high: 11,
        medium: 14,
        low: 8,
        avgRiskScore: 79,
        dominantVector: 'Pic Hebdo : Attaque DDoS SYN Flood',
      },
      {
        week: 'Sem 34',
        period: '17 - 23 Août',
        critical: 2,
        high: 4,
        medium: 6,
        low: 5,
        avgRiskScore: 49,
        dominantVector: 'Sondage HTTP /etc/passwd',
      },
      {
        week: 'Sem 35',
        period: '24 - 30 Août',
        critical: 3,
        high: 7,
        medium: 10,
        low: 6,
        avgRiskScore: 64,
        dominantVector: 'Phishing & Malicious Domain',
      },
      {
        week: 'Sem 36',
        period: '31 Août - 06 Sep',
        critical: 4,
        high: 8,
        medium: 11,
        low: 7,
        avgRiskScore: 68,
        dominantVector: 'Exploit Log4j JNDI',
      },
      {
        week: 'Sem 37',
        period: '07 - 13 Sep',
        critical: 3,
        high: 6,
        medium: 9,
        low: 5,
        avgRiskScore: 62,
        dominantVector: 'Tor Exit Node Traffic',
      },
      {
        week: 'Sem 38',
        period: '14 - 20 Sep',
        critical: 8,
        high: 14,
        medium: 17,
        low: 9,
        avgRiskScore: 86,
        dominantVector: 'Pic Critique : Mouvement Latéral SMB & Mimikatz',
      },
      {
        week: 'Sem 39',
        period: '21 - 27 Sep',
        critical: Math.max(5, currentCounts.critical),
        high: Math.max(8, currentCounts.high),
        medium: Math.max(9, currentCounts.medium + 4),
        low: Math.max(4, currentCounts.low + 3),
        avgRiskScore: 89,
        dominantVector: logs[0]?.threatName || 'Cobalt Strike C2 & Ransomware',
      },
      {
        week: 'Sem 40 (En cours)',
        period: '28 Sep - 04 Oct',
        critical: Math.max(4, currentCounts.critical),
        high: Math.max(6, currentCounts.high),
        medium: Math.max(7, currentCounts.medium + 2),
        low: Math.max(3, currentCounts.low + 2),
        avgRiskScore: 84,
        dominantVector: 'Activité C2 & Quarantaine CDR',
      },
    ];

    return baseWeeks.map((w) => ({
      ...w,
      total: w.critical + w.high + w.medium + w.low,
    }));
  }, [currentCounts, logs]);

  // Generate 28-day calendar heatmap cells for the selected month
  const calendarDays = useMemo(() => {
    const selectedMonth = monthlyData[selectedMonthIndex] || monthlyData[11];
    const daysInMonth = 30;
    const days = [];
    const dayNames = ['Lun', 'Mar', 'Mer', 'Jeu', 'Ven', 'Sam', 'Dim'];

    for (let d = 1; d <= daysInMonth; d++) {
      // Deterministic pseudo-random distribution weighted by selectedMonth totals
      const seed = (d * 17 + selectedMonthIndex * 31) % 100;
      const isWeekend = d % 7 === 6 || d % 7 === 0;
      const isPeakDay = d === 12 || d === 24 || d === 25;

      let count = Math.max(0, Math.round((selectedMonth.total / 28) * (0.4 + (seed % 14) / 10)));
      let criticalCount = 0;

      if (isPeakDay) {
        count += Math.round(selectedMonth.critical * 0.45) + 4;
        criticalCount = Math.max(2, Math.round(selectedMonth.critical * 0.35));
      } else if (isWeekend && seed > 45) {
        count += 3;
        criticalCount = seed > 75 ? 2 : 1;
      } else if (seed > 80) {
        criticalCount = 1;
      }

      days.push({
        day: d,
        dayName: dayNames[(d - 1) % 7],
        count,
        criticalCount,
        intensity:
          criticalCount >= 2 || count >= 8
            ? 'CRITICAL'
            : count >= 5
            ? 'HIGH'
            : count >= 2
            ? 'MEDIUM'
            : 'LOW',
      });
    }
    return days;
  }, [monthlyData, selectedMonthIndex]);

  // Identify Peak Month and Peak Week
  const peakMonth = useMemo(() => {
    return monthlyData.reduce((max, cur) => (cur.total > max.total ? cur : max), monthlyData[0]);
  }, [monthlyData]);

  const peakWeek = useMemo(() => {
    return weeklyData.reduce((max, cur) => (cur.total > max.total ? cur : max), weeklyData[0]);
  }, [weeklyData]);

  const totalAnnualIncidents = useMemo(() => {
    return monthlyData.reduce((acc, m) => acc + m.total, 0);
  }, [monthlyData]);

  return (
    <div className="rounded-3xl bg-slate-900/90 border border-slate-800 shadow-2xl p-6 sm:p-7 space-y-6 backdrop-blur-xl">
      {/* Header & View Mode Controls */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div className="flex items-center gap-3.5">
          <div className="w-11 h-11 rounded-2xl bg-cyan-950 border border-cyan-700/60 flex items-center justify-center text-cyan-400 shadow-lg shadow-cyan-950/50">
            <Calendar className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h3 className="text-base sm:text-lg font-bold text-white">
                Calendrier des Incidents & Saisonnalité des Menaces
              </h3>
              <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-cyan-950 text-cyan-300 border border-cyan-800">
                Tendances Long Terme
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono">
              Analyse de la fréquence des menaces par mois et par semaine pour isoler les pics d'activité cyber.
            </p>
          </div>
        </div>

        {/* Mode Selector Tabs */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center bg-slate-950 p-1 rounded-xl border border-slate-800 text-xs font-mono">
            <button
              onClick={() => setViewMode('monthly')}
              className={`px-3 py-1.5 rounded-lg transition font-semibold ${
                viewMode === 'monthly'
                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-800 shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Par Mois (12M)
            </button>
            <button
              onClick={() => setViewMode('weekly')}
              className={`px-3 py-1.5 rounded-lg transition font-semibold ${
                viewMode === 'weekly'
                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-800 shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Par Semaine (12S)
            </button>
            <button
              onClick={() => setViewMode('heatmap')}
              className={`px-3 py-1.5 rounded-lg transition font-semibold ${
                viewMode === 'heatmap'
                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-800 shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Grille Calendrier
            </button>
          </div>

          {/* Severity Filter for Chart */}
          {viewMode !== 'heatmap' && (
            <select
              value={selectedSeverityFilter}
              onChange={(e) => setSelectedSeverityFilter(e.target.value as any)}
              className="bg-slate-950 border border-slate-800 text-xs text-slate-300 rounded-xl px-3 py-2 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono"
            >
              <option value="ALL">Toutes Sévérités Empilées</option>
              <option value="CRITICAL">Focus CRITICAL uniquement</option>
              <option value="HIGH">Focus HIGH uniquement</option>
              <option value="MEDIUM">Focus MEDIUM uniquement</option>
            </select>
          )}
        </div>
      </div>

      {/* 4 Long-Term Peak Summary KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        <div className="p-3.5 rounded-2xl bg-slate-950/70 border border-slate-800/90 space-y-1">
          <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
            <span>Mois Pic d'Activité</span>
            <Flame className="w-3.5 h-3.5 text-red-400" />
          </div>
          <div className="text-sm font-bold text-white font-mono truncate">{peakMonth.month}</div>
          <div className="text-[11px] font-mono text-red-400 font-semibold">
            {peakMonth.total} incidents ({peakMonth.critical} critiques)
          </div>
        </div>

        <div className="p-3.5 rounded-2xl bg-slate-950/70 border border-slate-800/90 space-y-1">
          <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
            <span>Semaine Record</span>
            <TrendingUp className="w-3.5 h-3.5 text-amber-400" />
          </div>
          <div className="text-sm font-bold text-white font-mono">
            {peakWeek.week} ({peakWeek.period})
          </div>
          <div className="text-[11px] font-mono text-amber-400 font-semibold">
            {peakWeek.total} alertes • Score moy. {peakWeek.avgRiskScore}/100
          </div>
        </div>

        <div className="p-3.5 rounded-2xl bg-slate-950/70 border border-slate-800/90 space-y-1">
          <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
            <span>Volume Annuel Cumulé</span>
            <BarChart3 className="w-3.5 h-3.5 text-cyan-400" />
          </div>
          <div className="text-sm font-bold text-white font-mono">
            {totalAnnualIncidents} événements
          </div>
          <div className="text-[11px] font-mono text-cyan-400">
            Moyenne : {Math.round(totalAnnualIncidents / 12)} incidents / mois
          </div>
        </div>

        <div className="p-3.5 rounded-2xl bg-slate-950/70 border border-slate-800/90 space-y-1">
          <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
            <span>Fenêtre de Vulnérabilité</span>
            <Clock className="w-3.5 h-3.5 text-purple-400" />
          </div>
          <div className="text-sm font-bold text-white font-mono">Ven 22h00 – Dim 04h00</div>
          <div className="text-[11px] font-mono text-purple-300">
            +42% de tentatives C2 & Brute-Force
          </div>
        </div>
      </div>

      {/* Main Chart / Calendar Content */}
      {viewMode === 'monthly' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <h4 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              <span>Fréquence Mensuelle des Menaces (12 Derniers Mois)</span>
            </h4>
            <span className="text-[11px] font-mono text-slate-400">
              Cliquez sur une barre pour inspecter la grille quotidienne du mois
            </span>
          </div>

          <div className="h-72 w-full bg-slate-950/50 rounded-2xl p-3 border border-slate-800/80">
            <ResponsiveContainer width="100%" height="100%">
              <ComposedChart
                data={monthlyData}
                margin={{ top: 10, right: 15, left: -15, bottom: 0 }}
                onClick={(state) => {
                  if (state && typeof state.activeTooltipIndex === 'number') {
                    setSelectedMonthIndex(state.activeTooltipIndex);
                  }
                }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis
                  dataKey="shortMonth"
                  stroke="#64748b"
                  tick={{ fill: '#94a3b8', fontSize: 11, fontFamily: 'monospace' }}
                />
                <YAxis
                  stroke="#64748b"
                  tick={{ fill: '#94a3b8', fontSize: 11, fontFamily: 'monospace' }}
                />
                <Tooltip content={<CustomCalendarTooltip />} />
                <Legend
                  wrapperStyle={{ fontSize: '11px', fontFamily: 'monospace', paddingTop: '8px' }}
                />

                {(selectedSeverityFilter === 'ALL' || selectedSeverityFilter === 'CRITICAL') && (
                  <Bar
                    dataKey="critical"
                    name="CRITICAL"
                    stackId="a"
                    fill="#ef4444"
                    radius={selectedSeverityFilter === 'CRITICAL' ? [6, 6, 0, 0] : [0, 0, 0, 0]}
                  />
                )}
                {(selectedSeverityFilter === 'ALL' || selectedSeverityFilter === 'HIGH') && (
                  <Bar
                    dataKey="high"
                    name="HIGH"
                    stackId="a"
                    fill="#f97316"
                    radius={selectedSeverityFilter === 'HIGH' ? [6, 6, 0, 0] : [0, 0, 0, 0]}
                  />
                )}
                {(selectedSeverityFilter === 'ALL' || selectedSeverityFilter === 'MEDIUM') && (
                  <Bar
                    dataKey="medium"
                    name="MEDIUM"
                    stackId="a"
                    fill="#eab308"
                    radius={selectedSeverityFilter === 'MEDIUM' ? [6, 6, 0, 0] : [0, 0, 0, 0]}
                  />
                )}
                {selectedSeverityFilter === 'ALL' && (
                  <Bar
                    dataKey="low"
                    name="LOW"
                    stackId="a"
                    fill="#3b82f6"
                    radius={[6, 6, 0, 0]}
                  />
                )}
                <Line
                  type="monotone"
                  dataKey="total"
                  name="Courbe de Tendance Globale"
                  stroke="#22d3ee"
                  strokeWidth={2}
                  dot={{ r: 3, fill: '#22d3ee' }}
                />
              </ComposedChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {viewMode === 'weekly' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <h4 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-amber-400" />
              <span>Distribution Hebdomadaire des Incidents (12 Dernières Semaines)</span>
            </h4>
            <span className="text-[11px] font-mono text-slate-400">
              Identification des vagues d'assauts hebdomadaires et corrélation du score de risque
            </span>
          </div>

          <div className="h-72 w-full bg-slate-950/50 rounded-2xl p-3 border border-slate-800/80">
            <ResponsiveContainer width="100%" height="100%">
              <ComposedChart
                data={weeklyData}
                margin={{ top: 10, right: 15, left: -15, bottom: 0 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis
                  dataKey="week"
                  stroke="#64748b"
                  tick={{ fill: '#94a3b8', fontSize: 11, fontFamily: 'monospace' }}
                />
                <YAxis
                  stroke="#64748b"
                  tick={{ fill: '#94a3b8', fontSize: 11, fontFamily: 'monospace' }}
                />
                <Tooltip content={<CustomCalendarTooltip />} />
                <Legend
                  wrapperStyle={{ fontSize: '11px', fontFamily: 'monospace', paddingTop: '8px' }}
                />

                {(selectedSeverityFilter === 'ALL' || selectedSeverityFilter === 'CRITICAL') && (
                  <Bar
                    dataKey="critical"
                    name="CRITICAL"
                    stackId="w"
                    fill="#ef4444"
                    radius={selectedSeverityFilter === 'CRITICAL' ? [6, 6, 0, 0] : [0, 0, 0, 0]}
                  />
                )}
                {(selectedSeverityFilter === 'ALL' || selectedSeverityFilter === 'HIGH') && (
                  <Bar
                    dataKey="high"
                    name="HIGH"
                    stackId="w"
                    fill="#f97316"
                    radius={selectedSeverityFilter === 'HIGH' ? [6, 6, 0, 0] : [0, 0, 0, 0]}
                  />
                )}
                {(selectedSeverityFilter === 'ALL' || selectedSeverityFilter === 'MEDIUM') && (
                  <Bar
                    dataKey="medium"
                    name="MEDIUM"
                    stackId="w"
                    fill="#eab308"
                    radius={selectedSeverityFilter === 'MEDIUM' ? [6, 6, 0, 0] : [0, 0, 0, 0]}
                  />
                )}
                {selectedSeverityFilter === 'ALL' && (
                  <Bar
                    dataKey="low"
                    name="LOW"
                    stackId="w"
                    fill="#3b82f6"
                    radius={[6, 6, 0, 0]}
                  />
                )}
                <Line
                  type="monotone"
                  dataKey="total"
                  name="Total Hebdomadaire"
                  stroke="#a855f7"
                  strokeWidth={2.5}
                  dot={{ r: 3.5, fill: '#a855f7' }}
                />
              </ComposedChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {viewMode === 'heatmap' && (
        <div className="space-y-4">
          {/* Month Navigator */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-slate-950/70 p-3.5 rounded-2xl border border-slate-800">
            <div className="flex items-center gap-3">
              <button
                onClick={() => setSelectedMonthIndex((prev) => Math.max(0, prev - 1))}
                disabled={selectedMonthIndex === 0}
                className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 hover:text-white disabled:opacity-40"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <div>
                <span className="text-sm font-bold text-white font-mono block">
                  {monthlyData[selectedMonthIndex]?.month}
                </span>
                <span className="text-[11px] text-cyan-400 font-mono">
                  Menace Principale : {monthlyData[selectedMonthIndex]?.peakThreat}
                </span>
              </div>
              <button
                onClick={() =>
                  setSelectedMonthIndex((prev) => Math.min(monthlyData.length - 1, prev + 1))
                }
                disabled={selectedMonthIndex === monthlyData.length - 1}
                className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 hover:text-white disabled:opacity-40"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>

            {/* Heatmap Legend */}
            <div className="flex items-center gap-3 text-[11px] font-mono">
              <span className="text-slate-400">Intensité :</span>
              <span className="flex items-center gap-1 text-blue-300">
                <span className="w-2.5 h-2.5 rounded bg-slate-800 border border-slate-700" /> Faible
              </span>
              <span className="flex items-center gap-1 text-yellow-300">
                <span className="w-2.5 h-2.5 rounded bg-yellow-950 border border-yellow-700" /> Modérée
              </span>
              <span className="flex items-center gap-1 text-amber-300">
                <span className="w-2.5 h-2.5 rounded bg-amber-950 border border-amber-600" /> Élevée
              </span>
              <span className="flex items-center gap-1 text-red-300">
                <span className="w-2.5 h-2.5 rounded bg-red-950 border border-red-600" /> Critique
              </span>
            </div>
          </div>

          {/* 7-Column Calendar Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-5 md:grid-cols-7 gap-2.5">
            {calendarDays.map((item) => {
              const cellStyle =
                item.intensity === 'CRITICAL'
                  ? 'bg-red-950/70 border-red-700/80 text-red-200 shadow-lg shadow-red-950/30'
                  : item.intensity === 'HIGH'
                  ? 'bg-amber-950/60 border-amber-700/70 text-amber-200'
                  : item.intensity === 'MEDIUM'
                  ? 'bg-yellow-950/40 border-yellow-800/60 text-yellow-200'
                  : 'bg-slate-950/70 border-slate-800/80 text-slate-400';

              return (
                <div
                  key={item.day}
                  className={`p-3 rounded-xl border font-mono transition hover:scale-[1.02] flex flex-col justify-between min-h-[78px] ${cellStyle}`}
                >
                  <div className="flex items-center justify-between text-[10px]">
                    <span className="font-bold opacity-80">
                      {item.dayName} {item.day}
                    </span>
                    {item.criticalCount > 0 && (
                      <span className="px-1.5 py-0.2 rounded bg-red-600 text-white text-[9px] font-bold">
                        {item.criticalCount} CRIT
                      </span>
                    )}
                  </div>

                  <div className="mt-2">
                    <span className="text-base font-extrabold text-white block">
                      {item.count} <span className="text-[10px] font-normal opacity-75">logs</span>
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};
