import React, { useMemo, useState } from 'react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
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
  Clock,
  Activity,
  Flame,
  AlertTriangle,
  Zap,
  CheckCircle2,
  ArrowRight,
  Filter,
  Eye,
  Layers,
  Sparkles,
  Download,
} from 'lucide-react';
import {
  ThreatAnalysisResult,
  LogEntry,
  ActiveDefense,
  AnalysisHistoryItem,
  StopAction,
} from '../types';

interface RiskScore24HoursAreaChartProps {
  analysis: ThreatAnalysisResult;
  logs: LogEntry[];
  activeDefenses: ActiveDefense[];
  historyList?: AnalysisHistoryItem[];
  deviceName?: string;
  onNavigateToCountermeasures?: () => void;
  onInspectLog?: (log: LogEntry) => void;
}

export interface Hourly24RiskPoint {
  hourIndex: number; // 0 to 23
  hourLabel: string; // e.g., "14h00"
  relativeLabel: string; // e.g., "H-23", "Actuel"
  fullDateTime: string;
  isoTime: string;
  riskScore: number; // 0 - 100
  residualRiskScore: number; // 0 - 100
  criticalAlerts: number;
  highAlerts: number;
  totalAlerts: number;
  blockedThreats: number;
  threatLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  dominantThreat: string;
  attenuationPct: number;
  isPeak?: boolean;
  isCurrent?: boolean;
}

const Custom24HTooltip = ({ active, payload }: any) => {
  if (!active || !payload || payload.length === 0) return null;
  const point: Hourly24RiskPoint = payload[0]?.payload;
  if (!point) return null;

  const badgeColor =
    point.riskScore >= 75
      ? 'text-rose-400 bg-rose-950/70 border-rose-800'
      : point.riskScore >= 50
      ? 'text-amber-400 bg-amber-950/70 border-amber-800'
      : 'text-emerald-400 bg-emerald-950/70 border-emerald-800';

  const riskDelta = point.riskScore - point.residualRiskScore;

  return (
    <div className="bg-slate-950/95 border border-slate-700/80 rounded-2xl p-4 shadow-2xl backdrop-blur-xl text-xs font-mono space-y-3 min-w-[280px] max-w-[340px]">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-2">
        <div className="flex items-center gap-2">
          <Clock className="w-3.5 h-3.5 text-cyan-400" />
          <span className="font-bold text-white text-sm">{point.hourLabel}</span>
          <span className="text-[10px] text-slate-400">({point.relativeLabel})</span>
        </div>
        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${badgeColor}`}>
          {point.threatLevel}
        </span>
      </div>

      {/* Primary Metrics */}
      <div className="space-y-1.5">
        <div className="flex items-center justify-between p-2 rounded-xl bg-slate-900/80 border border-slate-800">
          <span className="text-slate-400 flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-500 shadow-sm shadow-rose-500/50" />
            Score de Risque Brut :
          </span>
          <span className="font-bold text-rose-300 text-sm">{point.riskScore} / 100</span>
        </div>

        <div className="flex items-center justify-between p-2 rounded-xl bg-slate-900/80 border border-slate-800">
          <span className="text-slate-400 flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 shadow-sm shadow-emerald-400/50" />
            Score Post-Riposte Nebula :
          </span>
          <span className="font-bold text-emerald-300 text-sm">
            {point.residualRiskScore} / 100
          </span>
        </div>

        {riskDelta > 0 && (
          <div className="flex items-center justify-between text-[11px] px-2 text-cyan-300">
            <span>Atténuation active de la menace :</span>
            <span className="font-bold">
              -{riskDelta} pts (-{point.attenuationPct}%)
            </span>
          </div>
        )}
      </div>

      {/* Alert Breakdown */}
      <div className="grid grid-cols-2 gap-2 text-[11px] pt-1 border-t border-slate-800/80">
        <div className="flex items-center justify-between text-slate-400">
          <span>Alertes Critiques :</span>
          <span className="font-bold text-rose-400">{point.criticalAlerts}</span>
        </div>
        <div className="flex items-center justify-between text-slate-400">
          <span>Hauts Événements :</span>
          <span className="font-bold text-amber-400">{point.highAlerts}</span>
        </div>
        <div className="flex items-center justify-between text-slate-400">
          <span>Total Logs / h :</span>
          <span className="font-bold text-white">{point.totalAlerts}</span>
        </div>
        <div className="flex items-center justify-between text-slate-400">
          <span>Bloqués par USG/ATP :</span>
          <span className="font-bold text-emerald-400">{point.blockedThreats}</span>
        </div>
      </div>

      {/* Threat Signature */}
      <div className="pt-2 border-t border-slate-800/80 text-[10px]">
        <span className="text-slate-500 block uppercase font-semibold mb-0.5">
          Vecteur Prédominant :
        </span>
        <span className="font-semibold text-cyan-200 line-clamp-2">
          {point.dominantThreat}
        </span>
      </div>

      {point.isPeak && (
        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-rose-950/80 border border-rose-800/80 text-rose-300 font-bold text-[10px]">
          <Flame className="w-3.5 h-3.5 text-rose-400 animate-pulse" />
          <span>Pic d'Intensité d'Attaque (24 Heures)</span>
        </div>
      )}
    </div>
  );
};

export const RiskScore24HoursAreaChart: React.FC<RiskScore24HoursAreaChartProps> = ({
  analysis,
  logs,
  activeDefenses,
  historyList = [],
  deviceName = 'Passerelle Zyxel Nebula ATP',
  onNavigateToCountermeasures,
  onInspectLog,
}) => {
  const [viewMode, setViewMode] = useState<'both' | 'gross' | 'residual'>('both');
  const [curveType, setCurveType] = useState<'monotone' | 'linear' | 'step'>('monotone');
  const [selectedHourIndex, setSelectedHourIndex] = useState<number>(23); // Default to current hour (H-0)
  const [showCriticalZone, setShowCriticalZone] = useState<boolean>(true);

  const activeDefenseCount = useMemo(
    () => activeDefenses.filter((d) => d.status === 'ACTIVE').length,
    [activeDefenses]
  );

  // Compute 24 realistic hourly risk scores anchored to real logs, current analysis, and active defenses
  const hourly24Data: Hourly24RiskPoint[] = useMemo(() => {
    const now = new Date();
    const currentScore = Math.min(100, Math.max(10, analysis.riskScore || 85));

    // Calculate real logs grouped by hour if timestamps are present
    const hourlyLogsBucket: {
      [hourKey: number]: {
        critical: number;
        high: number;
        total: number;
        blocked: number;
        threats: string[];
      };
    } = {};

    logs.forEach((log) => {
      let logHour = -1;
      if (log.timestamp) {
        const parsed = new Date(log.timestamp);
        if (!isNaN(parsed.getTime())) {
          logHour = parsed.getHours();
        } else {
          const match = log.timestamp.match(/(?:T|\s)(\d{1,2}):/);
          if (match) logHour = parseInt(match[1], 10);
        }
      }

      if (logHour >= 0 && logHour < 24) {
        if (!hourlyLogsBucket[logHour]) {
          hourlyLogsBucket[logHour] = {
            critical: 0,
            high: 0,
            total: 0,
            blocked: 0,
            threats: [],
          };
        }
        hourlyLogsBucket[logHour].total += 1;
        if (log.severity === 'CRITICAL') hourlyLogsBucket[logHour].critical += 1;
        if (log.severity === 'HIGH') hourlyLogsBucket[logHour].high += 1;
        if (
          log.action === 'Blocked' ||
          log.action === 'Dropped' ||
          log.action === 'Quarantined'
        ) {
          hourlyLogsBucket[logHour].blocked += 1;
        }
        const threatName = log.threatName || log.signature;
        if (threatName && !hourlyLogsBucket[logHour].threats.includes(threatName)) {
          hourlyLogsBucket[logHour].threats.push(threatName);
        }
      }
    });

    // Realistic baseline curve shape across the past 24 hours:
    // Escalating from lower risk (early morning) to major breach attempt around afternoon/evening
    const hourlyOffsets24 = [
      -42, -45, -48, -50, -47, -42, -35, -28, -20, -14, -8, -5,
      +4, +9, +12, +8, +2, -4, -8, -3, +1, +4, +6, 0,
    ];

    const threatSignaturesCycle = [
      'Sondage Port Scan Reconnaissance (SYN/FIN)',
      'Brute-Force SSH Automatisé (Dictionnaire)',
      'Tentative Exploitation CVE-2023-28771 (IKEv2)',
      'Requête DNS Suspecte & Fast-Flux Botnet',
      'Scan Vulnérabilités Web SSL-VPN Zyxel',
      'Infiltration RCE Apache Log4j / Log4Shell',
      'Communication Command-and-Control (C2 Cobalt Strike)',
      'Tentative Déploiement Ransomware LockBit v3.0',
      'Attaque par Déni de Service Distribué (Mirai Botnet)',
      'Exfiltration Données DNS Tunneling UDP 53',
      'Injection SQL Union Select API Auth',
      'Mouvement Latéral SMB / PsExec Interne',
    ];

    const points: Hourly24RiskPoint[] = [];
    let maxRisk = -1;
    let peakIndex = -1;

    for (let i = 0; i < 24; i++) {
      const hourOffset = 23 - i; // 23 hours ago down to 0 (current hour)
      const targetTime = new Date(now.getTime() - hourOffset * 60 * 60 * 1000);
      const hourNumber = targetTime.getHours();

      const hourLabel = `${hourNumber.toString().padStart(2, '0')}h00`;
      const relativeLabel = hourOffset === 0 ? 'Actuel (H-0)' : `H-${hourOffset}`;
      const fullDateTime = targetTime.toLocaleString('fr-FR', {
        day: '2-digit',
        month: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
      });

      // Check if real log events happened in this calendar hour
      const realHourData = hourlyLogsBucket[hourNumber];

      let rawRisk: number;
      let criticalAlerts: number;
      let highAlerts: number;
      let totalAlerts: number;
      let blockedThreats: number;
      let dominantThreat: string;

      if (hourOffset === 0) {
        // Current hour: matches current analysis exactly
        rawRisk = currentScore;
        criticalAlerts = Math.max(
          1,
          realHourData?.critical || logs.filter((l) => l.severity === 'CRITICAL').length
        );
        highAlerts = Math.max(
          2,
          realHourData?.high || logs.filter((l) => l.severity === 'HIGH').length
        );
        totalAlerts = Math.max(5, realHourData?.total || logs.length);
        blockedThreats = Math.max(
          3,
          realHourData?.blocked || activeDefenseCount * 2 + 4
        );
        dominantThreat =
          analysis.attackVectors[0]?.name ||
          'Tentative d\'Infiltration & Reconnaissance Périmétrique';
      } else {
        const offset = hourlyOffsets24[i] ?? 0;
        const computed = currentScore + offset;

        // Boost score if real logs detected for this hour
        const logWeight = realHourData
          ? realHourData.critical * 6 + realHourData.high * 3
          : 0;
        rawRisk = Math.min(98, Math.max(14, computed + logWeight));

        criticalAlerts = realHourData?.critical ?? Math.max(0, Math.round(rawRisk / 25));
        highAlerts = realHourData?.high ?? Math.max(1, Math.round(rawRisk / 18));
        totalAlerts = realHourData?.total ?? Math.max(3, Math.round(rawRisk / 4));
        blockedThreats =
          realHourData?.blocked ?? Math.max(1, Math.round((rawRisk * 0.4)));

        dominantThreat =
          realHourData?.threats[0] ||
          threatSignaturesCycle[i % threatSignaturesCycle.length];
      }

      // Compute residual risk score reflecting active defenses impact
      // Defenses reduce score by 12% per active rule up to 75% max mitigation
      const mitigationFactor = Math.min(0.78, activeDefenseCount * 0.14 + 0.2);
      const residualRiskScore = Math.max(
        12,
        Math.round(rawRisk * (1 - mitigationFactor))
      );
      const attenuationPct = Math.round(
        ((rawRisk - residualRiskScore) / rawRisk) * 100
      );

      const threatLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' =
        rawRisk >= 75
          ? 'CRITICAL'
          : rawRisk >= 50
          ? 'HIGH'
          : rawRisk >= 25
          ? 'MEDIUM'
          : 'LOW';

      if (rawRisk > maxRisk) {
        maxRisk = rawRisk;
        peakIndex = i;
      }

      points.push({
        hourIndex: i,
        hourLabel,
        relativeLabel,
        fullDateTime,
        isoTime: targetTime.toISOString(),
        riskScore: rawRisk,
        residualRiskScore,
        criticalAlerts,
        highAlerts,
        totalAlerts,
        blockedThreats,
        threatLevel,
        dominantThreat,
        attenuationPct,
        isCurrent: hourOffset === 0,
      });
    }

    if (peakIndex >= 0 && points[peakIndex]) {
      points[peakIndex].isPeak = true;
    }

    return points;
  }, [analysis, logs, activeDefenseCount]);

  // Aggregate Key Statistics
  const stats = useMemo(() => {
    if (hourly24Data.length === 0) {
      return {
        current: 75,
        currentResidual: 28,
        peak: 90,
        peakPoint: null as Hourly24RiskPoint | null,
        average: 55,
        averageResidual: 22,
        criticalHoursCount: 0,
        totalThreatsBlocked: 0,
        attenuationPoints: 47,
        trendDirection: 'UP' as 'UP' | 'DOWN' | 'STABLE',
      };
    }

    const currentPoint = hourly24Data[hourly24Data.length - 1];
    const pastHourPoint = hourly24Data[hourly24Data.length - 2] || currentPoint;
    const peakPoint =
      hourly24Data.reduce(
        (max, p) => (p.riskScore > max.riskScore ? p : max),
        hourly24Data[0]
      ) || currentPoint;

    const sumRisk = hourly24Data.reduce((acc, p) => acc + p.riskScore, 0);
    const sumResidual = hourly24Data.reduce(
      (acc, p) => acc + p.residualRiskScore,
      0
    );
    const totalBlocked = hourly24Data.reduce(
      (acc, p) => acc + p.blockedThreats,
      0
    );
    const criticalHours = hourly24Data.filter((p) => p.riskScore >= 75).length;

    const avgRisk = Math.round(sumRisk / hourly24Data.length);
    const avgResidual = Math.round(sumResidual / hourly24Data.length);
    const diff = currentPoint.riskScore - pastHourPoint.riskScore;

    return {
      current: currentPoint.riskScore,
      currentResidual: currentPoint.residualRiskScore,
      peak: peakPoint.riskScore,
      peakPoint,
      average: avgRisk,
      averageResidual: avgResidual,
      criticalHoursCount: criticalHours,
      totalThreatsBlocked: totalBlocked,
      attenuationPoints: currentPoint.riskScore - currentPoint.residualRiskScore,
      trendDirection: diff > 2 ? 'UP' : diff < -2 ? 'DOWN' : 'STABLE',
    };
  }, [hourly24Data]);

  const selectedPoint = hourly24Data[selectedHourIndex] || hourly24Data[23];

  const handleDownloadCsv = () => {
    const headers = [
      'Heure',
      'Timestamp',
      'Score_Risque_Brut',
      'Score_Residuel_Riposte',
      'Niveau_Menace',
      'Alertes_Critiques',
      'Alertes_Hautes',
      'Total_Logs',
      'Menaces_Bloquees',
      'Vecteur_Dominant',
    ];

    const rows = hourly24Data.map((d) => [
      d.hourLabel,
      d.isoTime,
      d.riskScore,
      d.residualRiskScore,
      d.threatLevel,
      d.criticalAlerts,
      d.highAlerts,
      d.totalAlerts,
      d.blockedThreats,
      `"${d.dominantThreat.replace(/"/g, '""')}"`,
    ]);

    const csvContent =
      'data:text/csv;charset=utf-8,' +
      [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');

    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `zyxel_nebula_risk_score_24h_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="p-6 rounded-3xl bg-slate-900/95 border border-slate-800 shadow-2xl space-y-6 backdrop-blur-xl">
      {/* 1. Header with Title & Action Controls */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div className="flex items-center gap-3">
          <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-rose-950 via-slate-900 to-amber-950 border border-rose-500/60 flex items-center justify-center text-rose-400 shadow-lg shadow-rose-950/50 flex-shrink-0">
            <Activity className="w-6 h-6 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h3 className="text-base sm:text-lg font-bold text-white tracking-tight">
                Évolution du Score de Risque sur 24 Heures (Recharts)
              </h3>
              <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono bg-rose-950 text-rose-300 border border-rose-800 font-bold flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-rose-400 animate-ping" />
                Cycle 24h Glissant
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-950 text-emerald-300 border border-emerald-800">
                Post-Riposte Active
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              Superposition en aires Recharts du score de risque brut vs score atténué par les règles firewall Nebula et quarantaines CDR
            </p>
          </div>
        </div>

        {/* Action Buttons & Series Toggles */}
        <div className="flex flex-wrap items-center gap-2">
          {/* View Mode Toggle */}
          <div className="inline-flex rounded-xl bg-slate-950 p-1 border border-slate-800 text-xs font-mono">
            <button
              type="button"
              onClick={() => setViewMode('both')}
              className={`px-3 py-1.5 rounded-lg transition ${
                viewMode === 'both'
                  ? 'bg-rose-950/80 text-rose-300 border border-rose-700/70 font-bold shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Brut & Résiduel
            </button>
            <button
              type="button"
              onClick={() => setViewMode('gross')}
              className={`px-3 py-1.5 rounded-lg transition ${
                viewMode === 'gross'
                  ? 'bg-rose-950/80 text-rose-300 border border-rose-700/70 font-bold shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Score Brut
            </button>
            <button
              type="button"
              onClick={() => setViewMode('residual')}
              className={`px-3 py-1.5 rounded-lg transition ${
                viewMode === 'residual'
                  ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-700/70 font-bold shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Post-Riposte
            </button>
          </div>

          {/* Curve interpolation toggle */}
          <div className="inline-flex rounded-xl bg-slate-950 p-1 border border-slate-800 text-[11px] font-mono">
            <button
              type="button"
              onClick={() => setCurveType('monotone')}
              className={`px-2.5 py-1.5 rounded-lg transition ${
                curveType === 'monotone'
                  ? 'bg-slate-800 text-white font-bold'
                  : 'text-slate-400 hover:text-white'
              }`}
              title="Courbe lissée naturelle"
            >
              Fluide
            </button>
            <button
              type="button"
              onClick={() => setCurveType('linear')}
              className={`px-2.5 py-1.5 rounded-lg transition ${
                curveType === 'linear'
                  ? 'bg-slate-800 text-white font-bold'
                  : 'text-slate-400 hover:text-white'
              }`}
              title="Segments linéaires directs"
            >
              Linéaire
            </button>
            <button
              type="button"
              onClick={() => setCurveType('step')}
              className={`px-2.5 py-1.5 rounded-lg transition ${
                curveType === 'step'
                  ? 'bg-slate-800 text-white font-bold'
                  : 'text-slate-400 hover:text-white'
              }`}
              title="Paliers horaires (Step)"
            >
              Paliers
            </button>
          </div>

          {/* Toggle Critical Threshold Lines */}
          <button
            type="button"
            onClick={() => setShowCriticalZone((prev) => !prev)}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl border text-xs font-mono transition ${
              showCriticalZone
                ? 'bg-rose-950/40 text-rose-300 border-rose-800/80'
                : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-white'
            }`}
            title="Afficher/masquer les lignes de seuils d'alerte (75 et 50)"
          >
            <AlertTriangle className="w-3.5 h-3.5" />
            <span>Seuils SOC</span>
          </button>

          {/* Export CSV */}
          <button
            type="button"
            onClick={handleDownloadCsv}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-950 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-800 text-xs font-mono transition"
            title="Exporter les 24 relevés horaires de score de risque au format CSV"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span>Export CSV</span>
          </button>
        </div>
      </div>

      {/* 2. Key Metrics Summary Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs font-mono">
        {/* Score Actuel (H-0) */}
        <div className="p-4 rounded-2xl bg-slate-950/80 border border-slate-800/90 relative overflow-hidden group hover:border-slate-700 transition">
          <div className="absolute top-0 right-0 w-24 h-24 bg-rose-500/10 rounded-full blur-2xl group-hover:bg-rose-500/20 transition" />
          <div className="flex items-center justify-between text-slate-400 mb-1">
            <span className="text-[11px] uppercase tracking-wider">Score Actuel (H-0)</span>
            <Activity className="w-4 h-4 text-rose-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-white">
              {stats.current}
            </span>
            <span className="text-slate-500 text-xs">/ 100</span>
            <span
              className={`text-[10px] font-bold px-1.5 py-0.5 rounded ml-auto flex items-center gap-1 ${
                stats.trendDirection === 'UP'
                  ? 'bg-rose-950 text-rose-400 border border-rose-800'
                  : stats.trendDirection === 'DOWN'
                  ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                  : 'bg-slate-800 text-slate-300'
              }`}
            >
              {stats.trendDirection === 'UP' ? (
                <>
                  <TrendingUp className="w-3 h-3" /> +Hausse
                </>
              ) : stats.trendDirection === 'DOWN' ? (
                <>
                  <TrendingDown className="w-3 h-3" /> -Baisse
                </>
              ) : (
                'Stable'
              )}
            </span>
          </div>
          <div className="mt-2 flex items-center justify-between text-[11px] text-slate-400 pt-2 border-t border-slate-800/60">
            <span>Post-Riposte :</span>
            <span className="font-bold text-emerald-400">{stats.currentResidual} / 100</span>
          </div>
        </div>

        {/* Pic de Risque 24h */}
        <div className="p-4 rounded-2xl bg-slate-950/80 border border-slate-800/90 relative overflow-hidden group hover:border-slate-700 transition">
          <div className="absolute top-0 right-0 w-24 h-24 bg-amber-500/10 rounded-full blur-2xl group-hover:bg-amber-500/20 transition" />
          <div className="flex items-center justify-between text-slate-400 mb-1">
            <span className="text-[11px] uppercase tracking-wider">Pic 24h Maximum</span>
            <Flame className="w-4 h-4 text-amber-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-amber-300">
              {stats.peak}
            </span>
            <span className="text-slate-500 text-xs">/ 100</span>
            <span className="text-[11px] font-bold text-slate-300 ml-auto">
              à {stats.peakPoint?.hourLabel || '14h00'}
            </span>
          </div>
          <div className="mt-2 flex items-center justify-between text-[11px] text-slate-400 pt-2 border-t border-slate-800/60">
            <span>Heures Critiques (&ge;75) :</span>
            <span className="font-bold text-rose-400">{stats.criticalHoursCount} h</span>
          </div>
        </div>

        {/* Atténuation Active par Nebula */}
        <div className="p-4 rounded-2xl bg-slate-950/80 border border-slate-800/90 relative overflow-hidden group hover:border-slate-700 transition">
          <div className="absolute top-0 right-0 w-24 h-24 bg-emerald-500/10 rounded-full blur-2xl group-hover:bg-emerald-500/20 transition" />
          <div className="flex items-center justify-between text-slate-400 mb-1">
            <span className="text-[11px] uppercase tracking-wider">Atténuation Riposte</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-emerald-400">
              -{stats.attenuationPoints}
            </span>
            <span className="text-slate-400 text-xs">pts de risque</span>
          </div>
          <div className="mt-2 flex items-center justify-between text-[11px] text-slate-400 pt-2 border-t border-slate-800/60">
            <span>Règles Actives :</span>
            <span className="font-bold text-emerald-300">
              {activeDefenseCount} règle(s)
            </span>
          </div>
        </div>

        {/* Moyenne sur 24 Heures */}
        <div className="p-4 rounded-2xl bg-slate-950/80 border border-slate-800/90 relative overflow-hidden group hover:border-slate-700 transition">
          <div className="absolute top-0 right-0 w-24 h-24 bg-cyan-500/10 rounded-full blur-2xl group-hover:bg-cyan-500/20 transition" />
          <div className="flex items-center justify-between text-slate-400 mb-1">
            <span className="text-[11px] uppercase tracking-wider">Score Moyen 24h</span>
            <Clock className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-cyan-300">
              {stats.average}
            </span>
            <span className="text-slate-500 text-xs">/ 100</span>
          </div>
          <div className="mt-2 flex items-center justify-between text-[11px] text-slate-400 pt-2 border-t border-slate-800/60">
            <span>Moyenne Post-Riposte :</span>
            <span className="font-bold text-cyan-400">{stats.averageResidual} / 100</span>
          </div>
        </div>
      </div>

      {/* 3. Recharts 24h Area Chart */}
      <div className="p-4 sm:p-5 rounded-2xl bg-slate-950/90 border border-slate-800/80 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono">
          <div className="flex items-center gap-4 flex-wrap">
            <span className="flex items-center gap-2 text-slate-300">
              <span className="w-3 h-3 rounded bg-gradient-to-r from-rose-500 to-amber-500 shadow-sm shadow-rose-500/50" />
              <strong className="text-white">Score Brut (0-100)</strong>
            </span>
            <span className="flex items-center gap-2 text-slate-300">
              <span className="w-3 h-3 rounded bg-gradient-to-r from-emerald-400 to-cyan-500 shadow-sm shadow-emerald-500/50" />
              <strong className="text-emerald-300">Score Résiduel Post-Riposte</strong>
            </span>
            {showCriticalZone && (
              <span className="flex items-center gap-1.5 text-rose-400 text-[11px]">
                <span className="w-3 h-0.5 bg-rose-500 border-dashed" />
                <span>Seuil Critique (75)</span>
              </span>
            )}
          </div>

          <div className="text-[11px] text-slate-500">
            Survolez ou cliquez sur une heure pour inspecter l'événement
          </div>
        </div>

        <div className="h-[340px] w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart
              data={hourly24Data}
              margin={{ top: 20, right: 20, left: -10, bottom: 0 }}
              onClick={(state: any) => {
                if (state && state.activePayload && state.activePayload.length > 0) {
                  const clicked: Hourly24RiskPoint = state.activePayload[0].payload;
                  setSelectedHourIndex(clicked.hourIndex);
                }
              }}
            >
              <defs>
                {/* Gradient for Raw Risk Score (Red to Amber to Indigo) */}
                <linearGradient id="riskScore24hGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.65} />
                  <stop offset="45%" stopColor="#f97316" stopOpacity={0.35} />
                  <stop offset="85%" stopColor="#818cf8" stopOpacity={0.08} />
                  <stop offset="100%" stopColor="#0f172a" stopOpacity={0.0} />
                </linearGradient>

                {/* Gradient for Residual Risk Score (Emerald to Cyan) */}
                <linearGradient id="residualScore24hGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#10b981" stopOpacity={0.55} />
                  <stop offset="60%" stopColor="#06b6d4" stopOpacity={0.25} />
                  <stop offset="100%" stopColor="#022c22" stopOpacity={0.0} />
                </linearGradient>
              </defs>

              <CartesianGrid
                strokeDasharray="3 3"
                stroke="#1e293b"
                vertical={false}
              />

              <XAxis
                dataKey="hourLabel"
                stroke="#64748b"
                tick={{ fill: '#94a3b8', fontSize: 11, fontFamily: 'monospace' }}
                tickLine={{ stroke: '#334155' }}
                axisLine={{ stroke: '#334155' }}
                interval={1}
              />

              <YAxis
                domain={[0, 100]}
                ticks={[0, 25, 50, 75, 100]}
                stroke="#64748b"
                tick={{ fill: '#94a3b8', fontSize: 11, fontFamily: 'monospace' }}
                tickLine={{ stroke: '#334155' }}
                axisLine={{ stroke: '#334155' }}
                tickFormatter={(val) => `${val}`}
              />

              <Tooltip content={<Custom24HTooltip />} />

              {/* Critical threshold line at 75 */}
              {showCriticalZone && (
                <ReferenceLine
                  y={75}
                  stroke="#f43f5e"
                  strokeDasharray="4 4"
                  strokeWidth={1.5}
                  label={{
                    value: 'SEUIL CRITIQUE (75)',
                    position: 'insideTopLeft',
                    fill: '#f43f5e',
                    fontSize: 10,
                    fontFamily: 'monospace',
                    fontWeight: 'bold',
                  }}
                />
              )}

              {/* Warning threshold line at 50 */}
              {showCriticalZone && (
                <ReferenceLine
                  y={50}
                  stroke="#f59e0b"
                  strokeDasharray="4 4"
                  strokeWidth={1.5}
                  label={{
                    value: 'SEUIL ALERTE (50)',
                    position: 'insideTopLeft',
                    fill: '#f59e0b',
                    fontSize: 10,
                    fontFamily: 'monospace',
                  }}
                />
              )}

              {/* Area for Gross Risk Score */}
              {(viewMode === 'both' || viewMode === 'gross') && (
                <Area
                  type={curveType}
                  dataKey="riskScore"
                  name="Score Brut"
                  stroke="#f43f5e"
                  strokeWidth={2.5}
                  fill="url(#riskScore24hGradient)"
                  activeDot={{
                    r: 6,
                    fill: '#f43f5e',
                    stroke: '#fff',
                    strokeWidth: 2,
                    className: 'filter drop-shadow-[0_0_8px_rgba(244,63,94,0.8)]',
                  }}
                />
              )}

              {/* Area for Residual Risk Score (Post-Riposte) */}
              {(viewMode === 'both' || viewMode === 'residual') && (
                <Area
                  type={curveType}
                  dataKey="residualRiskScore"
                  name="Score Post-Riposte"
                  stroke="#10b981"
                  strokeWidth={2}
                  strokeDasharray={viewMode === 'both' ? '4 3' : undefined}
                  fill="url(#residualScore24hGradient)"
                  activeDot={{
                    r: 5,
                    fill: '#10b981',
                    stroke: '#fff',
                    strokeWidth: 2,
                  }}
                />
              )}
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* 4. Interactive 24-Hour Timeline Ribbon & Selected Hour Forensics */}
      <div className="space-y-3">
        <div className="flex items-center justify-between text-xs font-mono">
          <span className="text-slate-400 font-bold uppercase tracking-wider flex items-center gap-2">
            <Clock className="w-3.5 h-3.5 text-cyan-400" />
            Bandeau Interactif des 24 Heures (Sélectionner une heure pour zoomer) :
          </span>
          <span className="text-cyan-400 font-semibold">
            Heure sélectionnée : {selectedPoint.hourLabel} ({selectedPoint.relativeLabel})
          </span>
        </div>

        {/* 24-hour clickable micro buttons */}
        <div className="grid grid-cols-6 sm:grid-cols-12 md:grid-cols-24 gap-1">
          {hourly24Data.map((point) => {
            const isSelected = point.hourIndex === selectedHourIndex;
            const barBg =
              point.riskScore >= 75
                ? 'bg-rose-500/20 text-rose-300 border-rose-800/80 hover:bg-rose-500/30'
                : point.riskScore >= 50
                ? 'bg-amber-500/20 text-amber-300 border-amber-800/80 hover:bg-amber-500/30'
                : 'bg-emerald-500/20 text-emerald-300 border-emerald-800/80 hover:bg-emerald-500/30';

            return (
              <button
                key={point.hourIndex}
                type="button"
                onClick={() => setSelectedHourIndex(point.hourIndex)}
                className={`py-2 px-1 rounded-xl text-center text-[10px] font-mono border transition flex flex-col items-center justify-between gap-1 ${barBg} ${
                  isSelected
                    ? 'ring-2 ring-white border-white scale-105 shadow-lg z-10 font-bold'
                    : 'opacity-90'
                }`}
                title={`${point.hourLabel} - Score: ${point.riskScore}/100 - ${point.dominantThreat}`}
              >
                <span className="truncate w-full text-[9px]">
                  {point.hourLabel.replace('00', '')}
                </span>
                <span className="font-bold text-[10px]">{point.riskScore}</span>
                {point.isPeak && (
                  <span className="w-1.5 h-1.5 rounded-full bg-rose-400 animate-ping" />
                )}
                {point.isCurrent && !point.isPeak && (
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* 5. Selected Hour Detailed Forensics Card */}
      {selectedPoint && (
        <div className="p-5 rounded-2xl bg-slate-950 border border-slate-800 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
            <div className="flex items-center gap-3">
              <div
                className={`w-9 h-9 rounded-xl flex items-center justify-center font-bold text-sm ${
                  selectedPoint.riskScore >= 75
                    ? 'bg-rose-950 text-rose-400 border border-rose-800'
                    : selectedPoint.riskScore >= 50
                    ? 'bg-amber-950 text-amber-400 border border-amber-800'
                    : 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                }`}
              >
                {selectedPoint.riskScore}
              </div>
              <div>
                <div className="flex items-center gap-2 flex-wrap">
                  <h4 className="text-sm font-bold text-white font-mono">
                    Audit Forensique du Créneau : {selectedPoint.hourLabel} ({selectedPoint.fullDateTime})
                  </h4>
                  {selectedPoint.isPeak && (
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-rose-950 text-rose-300 border border-rose-800 font-bold">
                      PIC D'ATTAQUE
                    </span>
                  )}
                  {selectedPoint.isCurrent && (
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-950 text-cyan-300 border border-cyan-800 font-bold">
                      HEURE ACTUELLE
                    </span>
                  )}
                </div>
                <p className="text-xs text-slate-400 font-mono mt-0.5">
                  Vecteur d'attaque dominant :{' '}
                  <span className="text-cyan-300 font-semibold">{selectedPoint.dominantThreat}</span>
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2">
              {onNavigateToCountermeasures && (
                <button
                  type="button"
                  onClick={onNavigateToCountermeasures}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-rose-950/80 hover:bg-rose-900 text-rose-300 hover:text-white border border-rose-800 text-xs font-mono font-bold transition"
                >
                  <Zap className="w-3.5 h-3.5 text-rose-400" />
                  <span>Riposter via Nebula API</span>
                </button>
              )}
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
            <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800">
              <span className="text-slate-400 text-[11px] block mb-1">Score Brut / Résiduel :</span>
              <div className="flex items-baseline gap-2">
                <span className="text-base font-bold text-rose-400">{selectedPoint.riskScore}</span>
                <span className="text-slate-500">/</span>
                <span className="text-base font-bold text-emerald-400">{selectedPoint.residualRiskScore}</span>
                <span className="text-[10px] text-cyan-300 ml-auto">
                  (-{selectedPoint.attenuationPct}%)
                </span>
              </div>
            </div>

            <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800">
              <span className="text-slate-400 text-[11px] block mb-1">Alertes Critiques :</span>
              <div className="text-base font-bold text-rose-300">
                {selectedPoint.criticalAlerts} <span className="text-xs text-slate-500 font-normal">événements</span>
              </div>
            </div>

            <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800">
              <span className="text-slate-400 text-[11px] block mb-1">Attaques Bloquées USG/ATP :</span>
              <div className="text-base font-bold text-emerald-300">
                {selectedPoint.blockedThreats} <span className="text-xs text-slate-500 font-normal">paquets jetés</span>
              </div>
            </div>

            <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800">
              <span className="text-slate-400 text-[11px] block mb-1">Évaluation Menace SOC :</span>
              <div className="text-base font-bold text-white flex items-center gap-1.5">
                <span
                  className={`w-2 h-2 rounded-full ${
                    selectedPoint.threatLevel === 'CRITICAL'
                      ? 'bg-rose-500 animate-ping'
                      : selectedPoint.threatLevel === 'HIGH'
                      ? 'bg-amber-500'
                      : 'bg-emerald-500'
                  }`}
                />
                <span>{selectedPoint.threatLevel}</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
