import React, { useMemo, useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Server,
  Activity,
  Globe,
  Lock,
  ArrowRight,
  Zap,
  Target,
  FileCode,
  Laptop,
  CheckCircle,
  PieChart as PieChartIcon,
  TrendingUp,
  Clock,
  History,
  RotateCcw,
  Trash2,
  Archive,
  ChevronDown,
  ChevronUp,
  GitCompare,
} from 'lucide-react';
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Legend,
} from 'recharts';
import { ThreatScoreGauge } from './ThreatScoreGauge';
import { LogEntry, StopAction, ThreatAnalysisResult, ActiveDefense, AnalysisHistoryItem } from '../types';
import { ReportComparisonSection } from './ReportComparisonSection';
import { ThreatAudioBriefing } from './ThreatAudioBriefing';

interface DashboardViewProps {
  analysis: ThreatAnalysisResult;
  logs: LogEntry[];
  activeDefenses: ActiveDefense[];
  onNavigateToCountermeasures: () => void;
  onEnforceDefense: (action: StopAction) => Promise<void>;
  onInspectLog: (log: LogEntry) => void;
  historyList?: AnalysisHistoryItem[];
  onRestoreAnalysis?: (item: AnalysisHistoryItem) => void;
  onDeleteHistoryItem?: (id: string) => void;
  onClearHistory?: () => void;
  deviceName?: string;
}

const THREAT_COLORS: Record<string, string> = {
  'Malwares & Ransomware': '#ef4444',
  'Brute Force & Auth': '#f97316',
  'DDoS & Floods': '#eab308',
  'C2 & Botnets': '#a855f7',
  'Exploits Web & RCE': '#06b6d4',
  'Phishing & DNS Tunneling': '#10b981',
  'Autres Menaces': '#64748b',
};

const classifyThreat = (log: LogEntry): string => {
  const text = `${log.threatName} ${log.category} ${log.raw}`.toLowerCase();
  if (
    text.includes('brute') ||
    text.includes('password') ||
    text.includes('auth') ||
    text.includes('login') ||
    text.includes('credential') ||
    text.includes('psk') ||
    text.includes('dictionary')
  ) {
    return 'Brute Force & Auth';
  }
  if (
    text.includes('syn_flood') ||
    text.includes('flood') ||
    text.includes('ddos') ||
    text.includes('port_scan') ||
    text.includes('anomaly') ||
    text.includes('dos') ||
    text.includes('packets_sec')
  ) {
    return 'DDoS & Floods';
  }
  if (
    text.includes('malware') ||
    text.includes('ransomware') ||
    text.includes('lockbit') ||
    text.includes('trojan') ||
    text.includes('virus') ||
    text.includes('stealer') ||
    text.includes('mimikatz')
  ) {
    return 'Malwares & Ransomware';
  }
  if (
    text.includes('c2') ||
    text.includes('botnet') ||
    text.includes('beacon') ||
    text.includes('cobalt') ||
    text.includes('tor_exit') ||
    text.includes('mirai')
  ) {
    return 'C2 & Botnets';
  }
  if (
    text.includes('log4j') ||
    text.includes('rce') ||
    text.includes('cve') ||
    text.includes('shell') ||
    text.includes('traversal') ||
    text.includes('idp') ||
    text.includes('exploit') ||
    text.includes('psexec')
  ) {
    return 'Exploits Web & RCE';
  }
  if (
    text.includes('phishing') ||
    text.includes('domain') ||
    text.includes('dns') ||
    text.includes('content_filter')
  ) {
    return 'Phishing & DNS Tunneling';
  }
  return 'Autres Menaces';
};

const CustomTooltip = ({ active, payload }: any) => {
  if (active && payload && payload.length) {
    const data = payload[0].payload;
    return (
      <div className="bg-slate-900 border border-slate-700 rounded-xl p-3 shadow-2xl backdrop-blur-md text-xs font-mono">
        <div className="flex items-center gap-2 mb-1">
          <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: data.color }} />
          <span className="font-bold text-white">{data.name}</span>
        </div>
        <div className="text-slate-300">
          Occurrences : <strong className="text-cyan-400">{data.value}</strong> alertes
        </div>
        <div className="text-slate-400 text-[11px]">
          Part du total : <strong className="text-white">{data.percentage}%</strong>
        </div>
      </div>
    );
  }
  return null;
};

const CustomLineTooltip = ({ active, payload, label }: any) => {
  if (active && payload && payload.length) {
    return (
      <div className="bg-slate-900 border border-slate-700 rounded-xl p-3 shadow-2xl backdrop-blur-md text-xs font-mono space-y-1.5 min-w-[200px]">
        <div className="text-white font-bold border-b border-slate-800 pb-1 flex items-center justify-between">
          <span className="flex items-center gap-1.5 text-cyan-400">
            <Clock className="w-3.5 h-3.5" /> {label}
          </span>
          <span className="text-[10px] text-slate-500 uppercase">Horodatage</span>
        </div>
        {payload.map((entry: any, i: number) => (
          <div key={i} className="flex items-center justify-between gap-4 text-[11px]">
            <span className="flex items-center gap-1.5" style={{ color: entry.color }}>
              <span className="w-2 h-2 rounded-full" style={{ backgroundColor: entry.color }} />
              {entry.name} :
            </span>
            <span className="font-bold text-white font-mono">{entry.value}</span>
          </div>
        ))}
      </div>
    );
  }
  return null;
};

export const DashboardView: React.FC<DashboardViewProps> = ({
  analysis,
  logs,
  activeDefenses,
  onNavigateToCountermeasures,
  onEnforceDefense,
  onInspectLog,
  historyList = [],
  onRestoreAnalysis,
  onDeleteHistoryItem,
  onClearHistory,
  deviceName = 'Passerelle Zyxel Nebula ATP',
}) => {
  const [isHistoryOpen, setIsHistoryOpen] = useState(true);
  const [isComparisonOpen, setIsComparisonOpen] = useState(false);

  // Aggregate log statistics
  const criticalLogs = logs.filter((l) => l.severity === 'CRITICAL');
  const highLogs = logs.filter((l) => l.severity === 'HIGH');
  const blockedLogs = logs.filter((l) => l.action === 'Blocked' || l.action === 'Dropped' || l.action === 'Quarantined');

  // Category counts
  const categoryCounts: Record<string, number> = {};
  logs.forEach((l) => {
    categoryCounts[l.category] = (categoryCounts[l.category] || 0) + 1;
  });

  // Threat type pie data calculation
  const pieData = useMemo(() => {
    const counts: Record<string, number> = {};
    logs.forEach((log) => {
      const type = classifyThreat(log);
      counts[type] = (counts[type] || 0) + 1;
    });

    const total = logs.length || 1;
    return Object.entries(counts)
      .map(([name, count]) => ({
        name,
        value: count,
        color: THREAT_COLORS[name] || '#64748b',
        percentage: Math.round((count / total) * 100),
      }))
      .sort((a, b) => b.value - a.value);
  }, [logs]);

  // Chronological timeline data calculation for LineChart
  const timelineData = useMemo(() => {
    if (!logs || logs.length === 0) return [];

    const sorted = [...logs].sort((a, b) => {
      const timeA = new Date(a.timestamp).getTime();
      const timeB = new Date(b.timestamp).getTime();
      return (isNaN(timeA) ? 0 : timeA) - (isNaN(timeB) ? 0 : timeB);
    });

    const timeMap: Record<
      string,
      { time: string; total: number; critical: number; blocked: number }
    > = {};

    sorted.forEach((log) => {
      let timeKey = log.timestamp;
      try {
        const d = new Date(log.timestamp);
        if (!isNaN(d.getTime())) {
          timeKey = d.toLocaleTimeString('fr-FR', {
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
          });
        } else {
          const match = log.timestamp.match(/\d{2}:\d{2}(:\d{2})?/);
          if (match) timeKey = match[0];
        }
      } catch {
        timeKey = log.timestamp.slice(11, 19) || log.timestamp;
      }

      if (!timeMap[timeKey]) {
        timeMap[timeKey] = {
          time: timeKey,
          total: 0,
          critical: 0,
          blocked: 0,
        };
      }

      timeMap[timeKey].total += 1;
      if (log.severity === 'CRITICAL') {
        timeMap[timeKey].critical += 1;
      }
      if (log.action === 'Blocked' || log.action === 'Dropped' || log.action === 'Quarantined') {
        timeMap[timeKey].blocked += 1;
      }
    });

    return Object.values(timeMap);
  }, [logs]);

  const peakAttack = useMemo(() => {
    if (timelineData.length === 0) return null;
    return timelineData.reduce((max, cur) => (cur.total > max.total ? cur : max), timelineData[0]);
  }, [timelineData]);

  const isIpBlocked = (ip: string) => {
    return activeDefenses.some((d) => d.target === ip && d.status === 'ACTIVE');
  };

  return (
    <div className="space-y-8">
      {/* Top Controls Bar: Security Posture Status & Comparison Mode Trigger */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl backdrop-blur-md">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-2xl bg-cyan-950 border border-cyan-800 flex items-center justify-center text-cyan-400">
            <Activity className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-bold text-white uppercase tracking-wider">
                Analyse Active Nebula
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-slate-300">
                {deviceName}
              </span>
            </div>
            <p className="text-[11px] text-slate-400 font-mono">
              Score : <strong className={analysis.riskScore >= 75 ? 'text-red-400 font-bold' : 'text-amber-400 font-bold'}>{analysis.riskScore}/100</strong> ({analysis.threatLevel}) • {analysis.attackVectors.length} vecteurs d'attaques • {logs.length} logs
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={() => setIsComparisonOpen(!isComparisonOpen)}
            className={`inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs font-mono font-bold transition shadow-lg ${
              isComparisonOpen
                ? 'bg-gradient-to-r from-cyan-600 to-blue-600 text-white border border-cyan-400/50 shadow-cyan-900/50 ring-2 ring-cyan-500/30'
                : 'bg-slate-800/90 hover:bg-slate-700 text-cyan-300 hover:text-white border border-cyan-800/60 shadow-slate-950/50'
            }`}
            title="Activer la vue comparative côte à côte pour détecter les régressions de sécurité"
          >
            <GitCompare className="w-4 h-4 text-cyan-300" />
            <span>{isComparisonOpen ? 'Masquer la Comparaison' : 'Comparer deux Rapports'}</span>
            <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-slate-900 text-cyan-200 border border-cyan-700/60 font-mono font-bold">
              Diff Régressions
            </span>
          </button>
        </div>
      </div>

      {/* Side-by-Side Report Comparison & Regression Section (when opened) */}
      {isComparisonOpen && (
        <ReportComparisonSection
          currentAnalysis={analysis}
          historyList={historyList}
          currentDeviceName={deviceName}
          onRestoreAnalysis={onRestoreAnalysis}
          onClose={() => setIsComparisonOpen(false)}
        />
      )}

      {/* Voice Synthesis (TTS) Audio Briefing for On-The-Go / Mobility SOC Analysts */}
      <ThreatAudioBriefing
        analysis={analysis}
        deviceName={deviceName}
        activeDefensesCount={activeDefenses.filter((d) => d.status === 'ACTIVE').length}
      />

      {/* Top Hero Section: Score Gauge & Key Metrics */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Threat Gauge */}
        <div className="lg:col-span-1">
          <ThreatScoreGauge
            score={analysis.riskScore}
            threatLevel={analysis.threatLevel}
            activeAttacks={analysis.attackVectors.length}
          />
        </div>

        {/* 4 Metric Cards */}
        <div className="lg:col-span-2 grid grid-cols-2 sm:grid-cols-4 gap-4">
          {/* Card 1 */}
          <div className="p-4 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl flex flex-col justify-between">
            <div className="flex items-center justify-between text-slate-400">
              <span className="text-xs font-mono">Attaques Détectées</span>
              <AlertTriangle className="w-4 h-4 text-red-400" />
            </div>
            <div className="my-2">
              <span className="text-2xl sm:text-3xl font-bold font-mono text-white">
                {analysis.activeAttacksDetected}
              </span>
            </div>
            <span className="text-[11px] text-red-400 font-mono flex items-center gap-1">
              {criticalLogs.length} événements critiques
            </span>
          </div>

          {/* Card 2 */}
          <div className="p-4 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl flex flex-col justify-between">
            <div className="flex items-center justify-between text-slate-400">
              <span className="text-xs font-mono">IPs Malveillantes</span>
              <Globe className="w-4 h-4 text-amber-400" />
            </div>
            <div className="my-2">
              <span className="text-2xl sm:text-3xl font-bold font-mono text-white">
                {analysis.iocList.filter((i) => i.type === 'IP').length}
              </span>
            </div>
            <span className="text-[11px] text-amber-400 font-mono">
              Serveurs C2 & Scanners
            </span>
          </div>

          {/* Card 3 */}
          <div className="p-4 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl flex flex-col justify-between">
            <div className="flex items-center justify-between text-slate-400">
              <span className="text-xs font-mono">Hôtes LAN Menacés</span>
              <Laptop className="w-4 h-4 text-purple-400" />
            </div>
            <div className="my-2">
              <span className="text-2xl sm:text-3xl font-bold font-mono text-white">
                {analysis.compromisedHosts.length}
              </span>
            </div>
            <span className="text-[11px] text-purple-400 font-mono">
              Quarantaine CDR prête
            </span>
          </div>

          {/* Card 4 */}
          <div className="p-4 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl flex flex-col justify-between">
            <div className="flex items-center justify-between text-slate-400">
              <span className="text-xs font-mono">Règles de Riposte</span>
              <Zap className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="my-2">
              <span className="text-2xl sm:text-3xl font-bold font-mono text-cyan-300">
                {analysis.stopActions.length}
              </span>
            </div>
            <span className="text-[11px] text-cyan-400 font-mono">
              1-Clic Déploiement
            </span>
          </div>
        </div>
      </div>

      {/* Visual Analytics: LineChart Chronological Timeline of Attacks */}
      <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-4">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-cyan-950 text-cyan-400 border border-cyan-800 flex items-center justify-center">
              <TrendingUp className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white tracking-tight">
                Évolution Chronologique du Volume des Attaques
              </h3>
              <p className="text-xs text-slate-400 font-mono">
                Courbes temporelles des flux hostiles, événements critiques et attaques neutralisées
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 self-start sm:self-auto">
            {peakAttack && (
              <span className="text-xs font-mono text-cyan-300 px-2.5 py-1 rounded-lg bg-cyan-950/70 border border-cyan-800/60 flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5 text-cyan-400" />
                Pic d'activité : <strong>{peakAttack.total} alertes</strong> ({peakAttack.time})
              </span>
            )}
          </div>
        </div>

        {/* Recharts LineChart */}
        <div className="h-[280px] w-full pt-1">
          {timelineData.length > 0 ? (
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={timelineData} margin={{ top: 10, right: 15, left: -15, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis
                  dataKey="time"
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
                <Tooltip content={<CustomLineTooltip />} />
                <Legend
                  verticalAlign="top"
                  align="right"
                  wrapperStyle={{ paddingBottom: '14px', fontSize: '11px', fontFamily: 'monospace' }}
                />
                <Line
                  type="monotone"
                  dataKey="total"
                  name="Volume Total"
                  stroke="#06b6d4"
                  strokeWidth={2.5}
                  dot={{ fill: '#06b6d4', r: 4, strokeWidth: 1, stroke: '#083344' }}
                  activeDot={{ r: 6, stroke: '#cffafe', strokeWidth: 2 }}
                />
                <Line
                  type="monotone"
                  dataKey="critical"
                  name="Alertes Critiques"
                  stroke="#ef4444"
                  strokeWidth={2}
                  strokeDasharray="4 2"
                  dot={{ fill: '#ef4444', r: 3 }}
                  activeDot={{ r: 5, stroke: '#fecaca', strokeWidth: 2 }}
                />
                <Line
                  type="monotone"
                  dataKey="blocked"
                  name="Bloquées par Passerelle"
                  stroke="#10b981"
                  strokeWidth={2}
                  dot={{ fill: '#10b981', r: 3 }}
                  activeDot={{ r: 5, stroke: '#a7f3d0', strokeWidth: 2 }}
                />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-full flex items-center justify-center text-xs text-slate-500 font-mono">
              Aucune donnée chronologique disponible.
            </div>
          )}
        </div>

        {/* Quick Timeline KPI Footer */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-3 border-t border-slate-800/80 text-xs font-mono">
          <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 flex items-center justify-between">
            <span className="text-slate-400">Total Flux Hostiles</span>
            <span className="text-cyan-400 font-bold">{logs.length} événements</span>
          </div>
          <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 flex items-center justify-between">
            <span className="text-slate-400">Gravité Critique</span>
            <span className="text-red-400 font-bold">{criticalLogs.length} événements</span>
          </div>
          <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 flex items-center justify-between">
            <span className="text-slate-400">Arrêtées en Temps Réel</span>
            <span className="text-emerald-400 font-bold">{blockedLogs.length} événements</span>
          </div>
        </div>
      </div>

      {/* Visual Analytics: Pie-Chart Threat Type Distribution (Recharts) */}
      <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/80 pb-4">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-cyan-950 text-cyan-400 border border-cyan-800 flex items-center justify-center">
              <PieChartIcon className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white tracking-tight">
                Répartition des Types de Menaces Détectées
              </h3>
              <p className="text-xs text-slate-400 font-mono">
                Visualisation par vecteur d'attaque (Malwares, Brute Force, DDoS, C2 / Botnet, Exploits, Phishing)
              </p>
            </div>
          </div>
          <span className="text-xs font-mono text-cyan-400 px-2.5 py-1 rounded-lg bg-cyan-950/60 border border-cyan-800/60 self-start sm:self-auto">
            {logs.length} Alertes Analysées
          </span>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
          {/* Recharts Pie Chart (5 cols) */}
          <div className="lg:col-span-5 h-[270px] w-full flex items-center justify-center relative">
            {pieData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={95}
                    paddingAngle={4}
                    dataKey="value"
                    nameKey="name"
                    stroke="#0f172a"
                    strokeWidth={2}
                  >
                    {pieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip content={<CustomTooltip />} />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="text-xs text-slate-500 font-mono">Aucune donnée disponible</div>
            )}
            {/* Center Summary Label */}
            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
              <span className="text-2xl font-bold font-mono text-white">{logs.length}</span>
              <span className="text-[10px] font-mono text-slate-400 uppercase tracking-widest">Événements</span>
            </div>
          </div>

          {/* Interactive Legend & Breakdown Bars (7 cols) */}
          <div className="lg:col-span-7 grid grid-cols-1 sm:grid-cols-2 gap-3">
            {pieData.map((item, idx) => (
              <div
                key={idx}
                className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 hover:border-slate-700 transition flex flex-col justify-between space-y-2"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span
                      className="w-3 h-3 rounded-full flex-shrink-0"
                      style={{ backgroundColor: item.color }}
                    />
                    <span className="text-xs font-semibold text-slate-200 truncate">
                      {item.name}
                    </span>
                  </div>
                  <span className="text-xs font-mono font-bold text-white">
                    {item.value} <span className="text-slate-500 font-normal">({item.percentage}%)</span>
                  </span>
                </div>
                {/* Progress bar */}
                <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-500"
                    style={{
                      width: `${item.percentage}%`,
                      backgroundColor: item.color,
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Banner Callout to Countermeasures */}
      <div className="p-5 rounded-2xl bg-gradient-to-r from-red-950/60 via-slate-900 to-slate-900 border border-red-800/50 shadow-xl flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-red-600/20 border border-red-500/40 flex items-center justify-center text-red-400 flex-shrink-0">
            <ShieldAlert className="w-6 h-6 animate-pulse" />
          </div>
          <div>
            <h4 className="text-sm font-bold text-white">
              {analysis.stopActions.length} Contre-mesures prêtes pour neutraliser les attaques en cours
            </h4>
            <p className="text-xs text-slate-400">
              Générez instantanément les règles de filtrage WAN Zyxel Nebula Cloud & isolez les machines infectées.
            </p>
          </div>
        </div>

        <button
          onClick={onNavigateToCountermeasures}
          className="inline-flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 text-white font-bold text-xs shadow-lg shadow-red-900/40 transition whitespace-nowrap"
        >
          <span>Accéder au Centre de Riposte</span>
          <ArrowRight className="w-4 h-4" />
        </button>
      </div>

      {/* Historique Local (localStorage) des 10 Dernières Analyses */}
      <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-4">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-indigo-950 text-indigo-400 border border-indigo-800 flex items-center justify-center">
              <History className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-white tracking-tight">
                  Historique Local des Analyses Récentes
                </h3>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-indigo-950 text-indigo-300 border border-indigo-800">
                  {historyList.length} / 10 sauvegardées
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono">
                Stockage persistant (localStorage) des 10 derniers rapports de sécurité
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 self-start sm:self-auto">
            {historyList.length > 0 && onClearHistory && (
              <button
                onClick={onClearHistory}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800/80 hover:bg-red-950/60 hover:text-red-300 text-slate-400 text-xs font-mono border border-slate-700 hover:border-red-800/60 transition"
                title="Vider l'historique local du navigateur"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Vider l'historique</span>
              </button>
            )}
            <button
              onClick={() => setIsHistoryOpen(!isHistoryOpen)}
              className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition"
              title={isHistoryOpen ? 'Réduire' : 'Déplier'}
            >
              {isHistoryOpen ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            </button>
          </div>
        </div>

        {isHistoryOpen && (
          <>
            {historyList.length === 0 ? (
              <div className="p-8 text-center rounded-xl bg-slate-950/40 border border-slate-800/50 space-y-2">
                <Archive className="w-8 h-8 text-slate-600 mx-auto" />
                <p className="text-xs text-slate-400">
                  Aucune analyse archivée dans le navigateur pour le moment.
                </p>
                <p className="text-[11px] text-slate-500 font-mono">
                  Chaque nouvelle analyse de logs Nebula sera automatiquement mémorisée ici (jusqu'à 10 analyses).
                </p>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 max-h-[380px] overflow-y-auto pr-1">
                {historyList.map((item) => {
                  const isCurrent = analysis.summary === item.analysis.summary;
                  const dateFormatted = new Date(item.timestamp).toLocaleString('fr-FR', {
                    day: '2-digit',
                    month: '2-digit',
                    year: 'numeric',
                    hour: '2-digit',
                    minute: '2-digit',
                    second: '2-digit',
                  });

                  return (
                    <div
                      key={item.id}
                      className={`p-3.5 rounded-xl border text-xs transition flex flex-col justify-between space-y-3 ${
                        isCurrent
                          ? 'bg-slate-950/90 border-cyan-700/70 shadow-md shadow-cyan-950/20'
                          : 'bg-slate-950/60 border-slate-800/80 hover:border-slate-700'
                      }`}
                    >
                      <div className="space-y-1.5">
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-[11px] font-mono text-slate-400 flex items-center gap-1">
                            <Clock className="w-3 h-3 text-slate-500" />
                            {dateFormatted}
                          </span>
                          <div className="flex items-center gap-1.5">
                            <span
                              className={`text-[10px] font-mono font-bold px-1.5 py-0.2 rounded ${
                                item.threatLevel === 'CRITICAL'
                                  ? 'bg-red-950 text-red-400 border border-red-800'
                                  : item.threatLevel === 'HIGH'
                                  ? 'bg-amber-950 text-amber-400 border border-amber-800'
                                  : 'bg-slate-800 text-slate-300'
                              }`}
                            >
                              {item.threatLevel} ({item.riskScore}/100)
                            </span>
                            {isCurrent && (
                              <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                                ACTIVE
                              </span>
                            )}
                          </div>
                        </div>

                        <h4 className="text-xs font-bold text-white truncate" title={item.title}>
                          {item.title}
                        </h4>
                        <p className="text-[11px] text-slate-400 font-mono truncate">
                          {item.deviceName} • {item.logCount} logs • {item.attacksCount} attaques
                        </p>
                      </div>

                      <div className="flex items-center justify-between pt-2 border-t border-slate-800/60 text-[11px] font-mono">
                        <span className="text-slate-500 truncate max-w-[140px]">
                          {item.analysis.attackVectors[0]?.name || 'Attaque analysée'}
                        </span>

                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => {
                              setIsComparisonOpen(true);
                              window.scrollTo({ top: 0, behavior: 'smooth' });
                            }}
                            className="inline-flex items-center gap-1 px-2 py-1 rounded-lg text-xs font-mono font-semibold bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 transition"
                            title="Comparer ce rapport avec le rapport actif dans le comparateur côte à côte"
                          >
                            <GitCompare className="w-3 h-3" />
                            <span>Comparer</span>
                          </button>

                          {onDeleteHistoryItem && (
                            <button
                              onClick={() => onDeleteHistoryItem(item.id)}
                              className="p-1 rounded hover:bg-slate-800 text-slate-500 hover:text-red-400 transition"
                              title="Supprimer cette entrée de l'historique"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          )}
                          {onRestoreAnalysis && (
                            <button
                              onClick={() => onRestoreAnalysis(item)}
                              disabled={isCurrent}
                              className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-lg font-semibold transition ${
                                isCurrent
                                  ? 'bg-slate-800 text-slate-500 cursor-default'
                                  : 'bg-cyan-600 hover:bg-cyan-500 text-white shadow-sm'
                              }`}
                            >
                              <RotateCcw className="w-3 h-3" />
                              <span>{isCurrent ? 'Active' : 'Charger'}</span>
                            </button>
                          )}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </>
        )}
      </div>

      {/* Main Grid: Attack Vectors & Attacker Triage */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Left Column: Attack Vectors (MITRE ATT&CK) (2 cols) */}
        <div className="lg:col-span-2 space-y-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Target className="w-5 h-5 text-red-400" />
              <h3 className="text-base font-bold text-white">
                Vecteurs d'Attaques Identifiés ({analysis.attackVectors.length})
              </h3>
            </div>
            <span className="text-xs text-slate-400 font-mono">
              Mapping MITRE ATT&CK
            </span>
          </div>

          <div className="space-y-4">
            {analysis.attackVectors.map((vector, idx) => (
              <div
                key={idx}
                className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 hover:border-slate-700 shadow-xl space-y-4 transition"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2.5">
                    <span className="w-2.5 h-2.5 rounded-full bg-red-500 animate-ping" />
                    <h4 className="text-sm font-bold text-white">{vector.name}</h4>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-cyan-400 border border-slate-700">
                      {vector.mitreTechniqueId}
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-950 text-red-400 border border-red-800 font-bold">
                      {vector.severity}
                    </span>
                  </div>
                </div>

                <p className="text-xs text-slate-300 leading-relaxed">
                  {vector.description}
                </p>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2 text-xs font-mono">
                  <div className="p-2.5 rounded-xl bg-slate-950/70 border border-slate-800/80">
                    <span className="text-[10px] text-slate-500 uppercase block mb-1">
                      IPs Attaquantes Détectées
                    </span>
                    <div className="flex flex-wrap gap-1">
                      {vector.attackerIps.map((ip, i) => (
                        <span
                          key={i}
                          className="px-2 py-0.5 rounded bg-red-950/60 text-red-300 border border-red-900/80 font-bold"
                        >
                          {ip}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div className="p-2.5 rounded-xl bg-slate-950/70 border border-slate-800/80">
                    <span className="text-[10px] text-slate-500 uppercase block mb-1">
                      Cibles Internes Visées
                    </span>
                    <div className="flex flex-wrap gap-1">
                      {vector.targetAssets.map((asset, i) => (
                        <span
                          key={i}
                          className="px-2 py-0.5 rounded bg-slate-800 text-slate-200 border border-slate-700 font-bold"
                        >
                          {asset}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>

          {/* Category distribution */}
          <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-4">
            <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono">
              Répartition des Alertes par Module Nebula
            </h4>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              {Object.entries(categoryCounts).map(([cat, count]) => (
                <div key={cat} className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80">
                  <span className="text-[10px] font-mono text-slate-500 block truncate">{cat}</span>
                  <span className="text-lg font-bold font-mono text-white mt-1 block">{count} logs</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right Column: Top Attacker IPs & Fast Action (1 col) */}
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Globe className="w-5 h-5 text-amber-400" />
              <h3 className="text-base font-bold text-white">Top IPs Malveillantes</h3>
            </div>
            <span className="text-xs text-slate-400 font-mono">IOCs Actifs</span>
          </div>

          <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-3.5">
            {analysis.iocList
              .filter((ioc) => ioc.type === 'IP')
              .slice(0, 6)
              .map((ioc, idx) => {
                const blocked = isIpBlocked(ioc.value);
                const matchingAction = analysis.stopActions.find((a) => a.target === ioc.value);

                return (
                  <div
                    key={idx}
                    className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 hover:border-slate-700 transition space-y-2"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono font-bold text-white">{ioc.value}</span>
                        {ioc.country && (
                          <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-800 text-slate-300">
                            {ioc.country}
                          </span>
                        )}
                      </div>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded font-bold bg-red-950 text-red-400 border border-red-800">
                        {ioc.severity}
                      </span>
                    </div>

                    <p className="text-[11px] text-slate-400">{ioc.threat}</p>

                    <div className="flex items-center justify-between pt-1">
                      {blocked ? (
                        <span className="inline-flex items-center gap-1 text-[11px] font-mono text-emerald-400 font-bold">
                          <CheckCircle className="w-3.5 h-3.5" /> Bloqué sur Nebula WAN
                        </span>
                      ) : (
                        <button
                          onClick={() => {
                            if (matchingAction) {
                              onEnforceDefense(matchingAction);
                            } else {
                              onNavigateToCountermeasures();
                            }
                          }}
                          className="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg bg-red-600/90 hover:bg-red-500 text-white font-mono text-[11px] font-semibold transition"
                        >
                          <Lock className="w-3 h-3" /> Bloquer l'IP
                        </button>
                      )}
                    </div>
                  </div>
                );
              })}
          </div>

          {/* Internal Compromised Hosts */}
          <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-3.5">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Laptop className="w-5 h-5 text-purple-400" />
                <h3 className="text-sm font-bold text-white">Postes LAN Compromis</h3>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800">
                Nebula CDR
              </span>
            </div>

            {analysis.compromisedHosts.length === 0 ? (
              <p className="text-xs text-slate-500 text-center py-2">
                Aucun hôte interne compromis détecté.
              </p>
            ) : (
              analysis.compromisedHosts.map((host, idx) => (
                <div
                  key={idx}
                  className="p-3 rounded-xl bg-purple-950/20 border border-purple-900/50 space-y-2"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono font-bold text-purple-300">{host.ip}</span>
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-purple-900/50 text-purple-200">
                      {host.status}
                    </span>
                  </div>
                  {host.hostname && (
                    <p className="text-[11px] text-slate-300 font-mono">Hôte : {host.hostname}</p>
                  )}
                  <p className="text-[11px] text-slate-400">{host.evidence}</p>
                  {host.recommendedIsolation && (
                    <div className="pt-1">
                      <span className="text-[10px] font-mono text-amber-400 flex items-center gap-1 font-semibold">
                        <AlertTriangle className="w-3 h-3" /> Quarantaine VLAN recommandée
                      </span>
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
