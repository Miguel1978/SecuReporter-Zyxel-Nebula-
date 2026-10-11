import React, { useMemo, useState } from 'react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  ComposedChart,
  Bar,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ReferenceLine,
} from 'recharts';
import {
  TrendingUp,
  TrendingDown,
  ShieldAlert,
  ShieldCheck,
  Calendar,
  Activity,
  BarChart3,
  Layers,
  CheckCircle2,
  AlertTriangle,
} from 'lucide-react';
import {
  ThreatAnalysisResult,
  LogEntry,
  ActiveDefense,
  AnalysisHistoryItem,
} from '../types';

interface RiskScore7DaysChartProps {
  analysis: ThreatAnalysisResult;
  logs: LogEntry[];
  activeDefenses: ActiveDefense[];
  historyList?: AnalysisHistoryItem[];
  deviceName?: string;
}

export interface DailyRiskPoint {
  dayKey: string;
  label: string;
  fullDate: string;
  riskScore: number;
  residualScore: number;
  criticalAlerts: number;
  blockedAttacks: number;
  threatLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  dominantThreat: string;
  deltaPrevDay: number;
  isToday?: boolean;
}

const Custom7DaysTooltip = ({ active, payload }: any) => {
  if (!active || !payload || payload.length === 0) return null;
  const point: DailyRiskPoint = payload[0]?.payload;
  if (!point) return null;

  const badgeColor =
    point.riskScore >= 75
      ? 'text-red-400'
      : point.riskScore >= 50
      ? 'text-amber-400'
      : 'text-emerald-400';

  return (
    <div className="bg-slate-950/95 border border-slate-700 rounded-xl p-3.5 shadow-2xl backdrop-blur-md text-xs font-mono space-y-2 min-w-[250px]">
      <div className="flex items-center justify-between border-b border-slate-800 pb-1.5">
        <span className="font-bold text-white flex items-center gap-1.5">
          <Calendar className="w-3.5 h-3.5 text-cyan-400" />
          {point.fullDate}
        </span>
        <span className={`font-bold ${badgeColor}`}>
          {point.threatLevel} ({point.riskScore}/100)
        </span>
      </div>

      <div className="space-y-1">
        <div className="flex items-center justify-between text-[11px]">
          <span className="text-slate-400 flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-rose-500" />
            Score de Risque Brut :
          </span>
          <span className="font-bold text-white">{point.riskScore} / 100</span>
        </div>

        <div className="flex items-center justify-between text-[11px]">
          <span className="text-slate-400 flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-400" />
            Score Post-Riposte Nebula :
          </span>
          <span className="font-bold text-emerald-300">{point.residualScore} / 100</span>
        </div>

        <div className="flex items-center justify-between text-[11px]">
          <span className="text-slate-400 flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-amber-400" />
            Alertes Critiques :
          </span>
          <span className="font-bold text-amber-300">{point.criticalAlerts}</span>
        </div>

        <div className="flex items-center justify-between text-[11px]">
          <span className="text-slate-400 flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-cyan-400" />
            Attaques Bloquées WAN/CDR :
          </span>
          <span className="font-bold text-cyan-300">{point.blockedAttacks}</span>
        </div>
      </div>

      <div className="pt-1.5 border-t border-slate-800/90 text-[10px] text-slate-300">
        <span className="text-slate-500 block uppercase">Menace Dominante :</span>
        <span className="font-semibold text-cyan-200">{point.dominantThreat}</span>
      </div>
    </div>
  );
};

export const RiskScore7DaysChart: React.FC<RiskScore7DaysChartProps> = ({
  analysis,
  logs,
  activeDefenses,
  historyList = [],
  deviceName = 'Passerelle Zyxel Nebula ATP',
}) => {
  const [chartType, setChartType] = useState<'area' | 'composed'>('area');
  const [showResidualCurve, setShowResidualCurve] = useState<boolean>(true);
  const [selectedDayIndex, setSelectedDayIndex] = useState<number>(6);

  const activeDefenseCount = useMemo(
    () => activeDefenses.filter((d) => d.status === 'ACTIVE').length,
    [activeDefenses]
  );

  // Build realistic 7-day evolution series anchored to current analysis, logs, active defenses, and history
  const sevenDaysData: DailyRiskPoint[] = useMemo(() => {
    const now = new Date();
    const currentScore = Math.min(100, Math.max(10, analysis.riskScore || 85));
    const criticalLogsCount = logs.filter((l) => l.severity === 'CRITICAL').length;
    const blockedLogsCount = logs.filter(
      (l) => l.action === 'Blocked' || l.action === 'Dropped' || l.action === 'Quarantined'
    ).length;

    const primaryThreatName =
      analysis.attackVectors[0]?.name || ' Reconnaissance & Sondage Périmétrique WAN';

    // Deterministic daily offsets based on current score so the curve shows a realistic 7-day escalation/evolution
    const scoreOffsets = [-28, -22, -14, -19, -9, -4, 0];
    const defaultThreats = [
      'Scan de Ports WAN & Sondage SSH/Telnet',
      'Tentatives Brute Force SSL-VPN & Bad IP',
      'Filtrage DNS Dynamique & Phishing Ciblé',
      'Exploitation Vulnérabilité Web (IDP/IPS)',
      'Détection Signature Botnet & C2 Beaconing',
      'Mouvement Latéral SMB & Alerte CDR',
      primaryThreatName,
    ];

    const points: DailyRiskPoint[] = [];

    for (let i = 0; i < 7; i++) {
      const dayOffset = 6 - i;
      const dateObj = new Date(now);
      dateObj.setDate(now.getDate() - dayOffset);

      const dayKey = dateObj.toISOString().slice(0, 10);
      const shortDay = dateObj.toLocaleDateString('fr-FR', {
        weekday: 'short',
        day: '2-digit',
        month: '2-digit',
      });
      const fullDate = dateObj.toLocaleDateString('fr-FR', {
        weekday: 'long',
        day: '2-digit',
        month: 'long',
      });

      // Check if user has history items matching this calendar date
      const matchingHistory = historyList.filter(
        (h) => h.timestamp && h.timestamp.slice(0, 10) === dayKey
      );

      let dayScore: number;
      let dayCritical: number;
      let dayBlocked: number;
      let dominantThreat: string;

      if (i === 6) {
        // Today = live analysis
        dayScore = currentScore;
        dayCritical = Math.max(1, criticalLogsCount);
        dayBlocked = Math.max(2, blockedLogsCount + activeDefenseCount * 3);
        dominantThreat = primaryThreatName;
      } else if (matchingHistory.length > 0) {
        const avgHistScore = Math.round(
          matchingHistory.reduce((acc, item) => acc + item.riskScore, 0) / matchingHistory.length
        );
        dayScore = Math.min(100, Math.max(15, avgHistScore));
        dayCritical = Math.max(1, matchingHistory[0].attacksCount * 2);
        dayBlocked = Math.max(3, matchingHistory[0].logCount);
        dominantThreat =
          matchingHistory[0].analysis.attackVectors[0]?.name || defaultThreats[i];
      } else {
        const seedShift = ((currentScore + i * 7) % 9) - 4;
        dayScore = Math.min(98, Math.max(24, currentScore + scoreOffsets[i] + seedShift));
        dayCritical = Math.max(1, Math.round((dayScore / 100) * (criticalLogsCount + 3)));
        dayBlocked = Math.max(4, Math.round((dayScore / 100) * 14) + i * 2);
        dominantThreat = defaultThreats[i];
      }

      // Calculate post-mitigation residual score (shows impact of Zyxel Nebula rules)
      const defenseReduction =
        i === 6
          ? Math.min(45, activeDefenseCount * 9 + 12)
          : Math.min(35, Math.round(dayScore * 0.28));
      const residualScore = Math.max(12, dayScore - defenseReduction);

      const threatLevel: DailyRiskPoint['threatLevel'] =
        dayScore >= 75
          ? 'CRITICAL'
          : dayScore >= 50
          ? 'HIGH'
          : dayScore >= 30
          ? 'MEDIUM'
          : 'LOW';

      const prevScore = i > 0 ? points[i - 1].riskScore : dayScore;
      const deltaPrevDay = dayScore - prevScore;

      points.push({
        dayKey,
        label: i === 6 ? `${shortDay} (Auj.)` : shortDay,
        fullDate: i === 6 ? `${fullDate} (Aujourd'hui)` : fullDate,
        riskScore: dayScore,
        residualScore,
        criticalAlerts: dayCritical,
        blockedAttacks: dayBlocked,
        threatLevel,
        dominantThreat,
        deltaPrevDay,
        isToday: i === 6,
      });
    }

    return points;
  }, [analysis, logs, activeDefenseCount, historyList]);

  const stats = useMemo(() => {
    const scores = sevenDaysData.map((d) => d.riskScore);
    const avgScore = Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
    const maxPoint = sevenDaysData.reduce(
      (max, cur) => (cur.riskScore > max.riskScore ? cur : max),
      sevenDaysData[0]
    );
    const minPoint = sevenDaysData.reduce(
      (min, cur) => (cur.riskScore < min.riskScore ? cur : min),
      sevenDaysData[0]
    );
    const todayPoint = sevenDaysData[sevenDaysData.length - 1];
    const firstPoint = sevenDaysData[0];
    const sevenDayDelta = todayPoint.riskScore - firstPoint.riskScore;
    const mitigationGain = todayPoint.riskScore - todayPoint.residualScore;

    return {
      avgScore,
      maxPoint,
      minPoint,
      todayPoint,
      sevenDayDelta,
      mitigationGain,
    };
  }, [sevenDaysData]);

  const selectedDay = sevenDaysData[selectedDayIndex] || sevenDaysData[sevenDaysData.length - 1];

  return (
    <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-5">
      {/* Header & Interactive Controls */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div className="flex items-start gap-3">
          <div className="w-10 h-10 rounded-xl bg-rose-950/90 border border-rose-800/80 flex items-center justify-center text-rose-400 flex-shrink-0">
            <Activity className="w-5 h-5" />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="text-base font-bold text-white tracking-tight">
                Évolution du Score de Risque sur les 7 Derniers Jours
              </h3>
              <span className="text-xs font-mono text-slate-400">
                · {deviceName}
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              Suivi hebdomadaire de l'indice de menace SOC (0–100), seuil critique et réduction de risque après riposte Zyxel Nebula
            </p>
          </div>
        </div>

        {/* Chart Mode & Curve Toggles */}
        <div className="flex flex-wrap items-center gap-2 self-start lg:self-auto">
          <button
            onClick={() => setShowResidualCurve(!showResidualCurve)}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-semibold border transition ${
              showResidualCurve
                ? 'bg-emerald-950/80 text-emerald-300 border-emerald-700/70'
                : 'bg-slate-800/80 text-slate-400 border-slate-700 hover:text-slate-200'
            }`}
            title="Afficher ou masquer la courbe du score résiduel après application des règles de défense Nebula"
          >
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            <span>Score Post-Riposte</span>
          </button>

          <div className="flex items-center gap-1 p-1 rounded-lg bg-slate-950 border border-slate-800">
            <button
              onClick={() => setChartType('area')}
              className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-mono font-semibold transition ${
                chartType === 'area'
                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/80 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Layers className="w-3.5 h-3.5" />
              <span>Aire & Tendance</span>
            </button>
            <button
              onClick={() => setChartType('composed')}
              className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-mono font-semibold transition ${
                chartType === 'composed'
                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/80 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <BarChart3 className="w-3.5 h-3.5" />
              <span>Score + Alertes</span>
            </button>
          </div>
        </div>
      </div>

      {/* 4 Summary KPI Cards for the 7-Day Window */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3.5">
        <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800/90 flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400">
            <span>Score Aujourd'hui</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="my-1.5 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-white">
              {stats.todayPoint.riskScore}
              <span className="text-xs text-slate-500 font-normal">/100</span>
            </span>
            <span
              className={`text-xs font-mono font-bold flex items-center gap-0.5 ${
                stats.sevenDayDelta >= 0 ? 'text-rose-400' : 'text-emerald-400'
              }`}
            >
              {stats.sevenDayDelta >= 0 ? (
                <TrendingUp className="w-3.5 h-3.5" />
              ) : (
                <TrendingDown className="w-3.5 h-3.5" />
              )}
              {stats.sevenDayDelta >= 0 ? `+${stats.sevenDayDelta}` : stats.sevenDayDelta} pts (7j)
            </span>
          </div>
          <span className="text-[11px] font-mono text-slate-400">
            Niveau actuel : <strong className="text-rose-400">{stats.todayPoint.threatLevel}</strong>
          </span>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800/90 flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400">
            <span>Moyenne Hebdomadaire</span>
            <Activity className="w-4 h-4 text-amber-400" />
          </div>
          <div className="my-1.5 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-amber-300">
              {stats.avgScore}
              <span className="text-xs text-slate-500 font-normal">/100</span>
            </span>
          </div>
          <span className="text-[11px] font-mono text-slate-400">
            Min : {stats.minPoint.riskScore}/100 · Seuil critique : 75
          </span>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800/90 flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400">
            <span>Pic sur 7 Jours</span>
            <AlertTriangle className="w-4 h-4 text-red-400" />
          </div>
          <div className="my-1.5 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-red-400">
              {stats.maxPoint.riskScore}
              <span className="text-xs text-slate-500 font-normal">/100</span>
            </span>
          </div>
          <span className="text-[11px] font-mono text-slate-400 truncate">
            Atteint le {stats.maxPoint.label}
          </span>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-950/70 border border-emerald-900/50 flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs font-mono text-emerald-400">
            <span>Score Après Riposte</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="my-1.5 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-emerald-300">
              {stats.todayPoint.residualScore}
              <span className="text-xs text-slate-500 font-normal">/100</span>
            </span>
            <span className="text-xs font-mono font-bold text-emerald-400">
              -{stats.mitigationGain} pts
            </span>
          </div>
          <span className="text-[11px] font-mono text-slate-400">
            {activeDefenseCount} règle(s) Nebula active(s)
          </span>
        </div>
      </div>

      {/* Recharts 7-Day Visualization */}
      <div className="h-[290px] w-full pt-2">
        <ResponsiveContainer width="100%" height="100%">
          {chartType === 'area' ? (
            <AreaChart
              data={sevenDaysData}
              margin={{ top: 12, right: 18, left: -12, bottom: 5 }}
              onClick={(state: any) => {
                if (state && typeof state.activeTooltipIndex === 'number') {
                  setSelectedDayIndex(state.activeTooltipIndex);
                }
              }}
            >
              <defs>
                <linearGradient id="riskScoreGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.45} />
                  <stop offset="55%" stopColor="#f97316" stopOpacity={0.18} />
                  <stop offset="95%" stopColor="#f43f5e" stopOpacity={0.0} />
                </linearGradient>
                <linearGradient id="residualScoreGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#10b981" stopOpacity={0.35} />
                  <stop offset="95%" stopColor="#10b981" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
              <XAxis
                dataKey="label"
                stroke="#64748b"
                fontSize={11}
                tickLine={false}
                axisLine={{ stroke: '#334155' }}
              />
              <YAxis
                domain={[0, 100]}
                ticks={[0, 25, 50, 75, 100]}
                stroke="#64748b"
                fontSize={11}
                tickLine={false}
                axisLine={{ stroke: '#334155' }}
              />
              <Tooltip content={<Custom7DaysTooltip />} />
              <Legend
                verticalAlign="top"
                align="right"
                wrapperStyle={{
                  paddingBottom: '12px',
                  fontSize: '11px',
                  fontFamily: 'monospace',
                }}
              />
              <ReferenceLine
                y={75}
                stroke="#ef4444"
                strokeDasharray="4 4"
                label={{
                  value: 'Seuil Critique (75)',
                  position: 'insideTopRight',
                  fill: '#f87171',
                  fontSize: 10,
                }}
              />
              <ReferenceLine
                y={50}
                stroke="#f59e0b"
                strokeDasharray="3 3"
                strokeOpacity={0.6}
              />
              <Area
                type="monotone"
                dataKey="riskScore"
                name="Score de Risque Brut (/100)"
                stroke="#f43f5e"
                strokeWidth={3}
                fillOpacity={1}
                fill="url(#riskScoreGradient)"
                dot={{ fill: '#f43f5e', r: 4, strokeWidth: 1.5, stroke: '#4c0519' }}
                activeDot={{ r: 6, stroke: '#fecdd3', strokeWidth: 2 }}
              />
              {showResidualCurve && (
                <Area
                  type="monotone"
                  dataKey="residualScore"
                  name="Score Post-Riposte Nebula (/100)"
                  stroke="#10b981"
                  strokeWidth={2.5}
                  strokeDasharray="5 3"
                  fillOpacity={1}
                  fill="url(#residualScoreGradient)"
                  dot={{ fill: '#10b981', r: 3.5, strokeWidth: 1, stroke: '#064e3b' }}
                  activeDot={{ r: 5.5, stroke: '#a7f3d0', strokeWidth: 2 }}
                />
              )}
            </AreaChart>
          ) : (
            <ComposedChart
              data={sevenDaysData}
              margin={{ top: 12, right: 18, left: -12, bottom: 5 }}
              onClick={(state: any) => {
                if (state && typeof state.activeTooltipIndex === 'number') {
                  setSelectedDayIndex(state.activeTooltipIndex);
                }
              }}
            >
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
              <XAxis
                dataKey="label"
                stroke="#64748b"
                fontSize={11}
                tickLine={false}
                axisLine={{ stroke: '#334155' }}
              />
              <YAxis
                yAxisId="left"
                domain={[0, 100]}
                ticks={[0, 25, 50, 75, 100]}
                stroke="#64748b"
                fontSize={11}
                tickLine={false}
                axisLine={{ stroke: '#334155' }}
              />
              <YAxis
                yAxisId="right"
                orientation="right"
                stroke="#475569"
                fontSize={11}
                tickLine={false}
                axisLine={{ stroke: '#334155' }}
                allowDecimals={false}
              />
              <Tooltip content={<Custom7DaysTooltip />} />
              <Legend
                verticalAlign="top"
                align="right"
                wrapperStyle={{
                  paddingBottom: '12px',
                  fontSize: '11px',
                  fontFamily: 'monospace',
                }}
              />
              <ReferenceLine
                yAxisId="left"
                y={75}
                stroke="#ef4444"
                strokeDasharray="4 4"
              />
              <Bar
                yAxisId="right"
                dataKey="blockedAttacks"
                name="Attaques Bloquées WAN"
                fill="#06b6d4"
                fillOpacity={0.35}
                radius={[4, 4, 0, 0]}
                barSize={20}
              />
              <Bar
                yAxisId="right"
                dataKey="criticalAlerts"
                name="Alertes Critiques"
                fill="#f59e0b"
                fillOpacity={0.55}
                radius={[4, 4, 0, 0]}
                barSize={14}
              />
              <Line
                yAxisId="left"
                type="monotone"
                dataKey="riskScore"
                name="Score de Risque (/100)"
                stroke="#f43f5e"
                strokeWidth={3}
                dot={{ fill: '#f43f5e', r: 4 }}
                activeDot={{ r: 6, stroke: '#fecdd3', strokeWidth: 2 }}
              />
              {showResidualCurve && (
                <Line
                  yAxisId="left"
                  type="monotone"
                  dataKey="residualScore"
                  name="Score Post-Riposte (/100)"
                  stroke="#10b981"
                  strokeWidth={2}
                  strokeDasharray="5 3"
                  dot={{ fill: '#10b981', r: 3 }}
                />
              )}
            </ComposedChart>
          )}
        </ResponsiveContainer>
      </div>

      {/* Interactive 7-Day Selector Strip & Selected Day Details */}
      <div className="pt-3 border-t border-slate-800/80 space-y-3">
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2">
          {sevenDaysData.map((day, idx) => {
            const isSelected = idx === selectedDayIndex;
            const scoreColor =
              day.riskScore >= 75
                ? 'text-red-400'
                : day.riskScore >= 50
                ? 'text-amber-400'
                : 'text-emerald-400';

            return (
              <button
                key={day.dayKey}
                onClick={() => setSelectedDayIndex(idx)}
                className={`p-2.5 rounded-xl border text-left transition flex flex-col justify-between gap-1 ${
                  isSelected
                    ? 'bg-slate-950 border-cyan-600/80 ring-1 ring-cyan-500/30 shadow-md'
                    : 'bg-slate-950/50 border-slate-800/80 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between text-[10px] font-mono text-slate-400">
                  <span className="truncate font-semibold">{day.label}</span>
                  {day.isToday && (
                    <span className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-ping" />
                  )}
                </div>
                <div className="flex items-baseline justify-between">
                  <span className={`text-sm font-bold font-mono ${scoreColor}`}>
                    {day.riskScore}
                    <span className="text-[10px] text-slate-500 font-normal">/100</span>
                  </span>
                  <span
                    className={`text-[10px] font-mono ${
                      day.deltaPrevDay > 0
                        ? 'text-rose-400'
                        : day.deltaPrevDay < 0
                        ? 'text-emerald-400'
                        : 'text-slate-500'
                    }`}
                  >
                    {day.deltaPrevDay > 0 ? `+${day.deltaPrevDay}` : day.deltaPrevDay}
                  </span>
                </div>
              </button>
            );
          })}
        </div>

        {/* Selected Day Focus Bar */}
        {selectedDay && (
          <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono">
            <div className="space-y-0.5">
              <div className="flex items-center gap-2 text-slate-300">
                <Calendar className="w-3.5 h-3.5 text-cyan-400" />
                <span className="font-bold text-white capitalize">{selectedDay.fullDate}</span>
                <span className="text-slate-500">·</span>
                <span className="text-cyan-300 font-semibold">{selectedDay.dominantThreat}</span>
              </div>
              <p className="text-[11px] text-slate-400">
                Score brut : <strong className="text-white">{selectedDay.riskScore}/100</strong> · Score après riposte Nebula :{' '}
                <strong className="text-emerald-400">{selectedDay.residualScore}/100</strong> ·{' '}
                {selectedDay.criticalAlerts} alerte(s) critique(s) · {selectedDay.blockedAttacks} flux bloqués
              </p>
            </div>
            <div className="text-[11px] text-slate-400 self-start sm:self-center whitespace-nowrap">
              Cliquez sur un jour pour inspecter son détail
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
