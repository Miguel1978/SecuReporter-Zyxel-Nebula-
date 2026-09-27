import React, { useState, useMemo } from 'react';
import {
  GitCompare,
  ArrowLeftRight,
  TrendingUp,
  TrendingDown,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Target,
  Laptop,
  Globe,
  CheckCircle2,
  XCircle,
  Clock,
  RotateCcw,
  Sparkles,
  Layers,
  ChevronDown,
  ChevronUp,
  Eye,
  Lock,
} from 'lucide-react';
import { ThreatAnalysisResult, AnalysisHistoryItem, SampleReport, SeverityLevel } from '../types';
import { SAMPLE_REPORTS } from '../data/sampleReports';

export interface ComparableReport {
  id: string;
  sourceType: 'CURRENT' | 'HISTORY' | 'BENCHMARK';
  title: string;
  deviceName: string;
  timestamp: string;
  riskScore: number;
  threatLevel: SeverityLevel;
  activeAttacksCount: number;
  iocsCount: number;
  compromisedHostsCount: number;
  analysis: ThreatAnalysisResult;
  rawLogs?: string;
}

interface ReportComparisonSectionProps {
  currentAnalysis: ThreatAnalysisResult;
  historyList: AnalysisHistoryItem[];
  currentDeviceName?: string;
  onRestoreAnalysis?: (item: AnalysisHistoryItem) => void;
  onClose?: () => void;
}

// Generate algorithmic analysis for a sample report if needed
function buildSampleAnalysis(sample: SampleReport): ThreatAnalysisResult {
  const isCritical = sample.severity === 'CRITICAL';
  const riskScore = sample.id === 'ransomware-c2-exfiltration' ? 94 : sample.id === 'log4shell-vpn-bruteforce' ? 88 : sample.id === 'mirai-synflood-recon' ? 68 : 62;

  return {
    summary: sample.description,
    riskScore,
    threatLevel: sample.severity,
    activeAttacksDetected: sample.logCount,
    attackVectors: [
      {
        name: sample.primaryThreat,
        description: sample.description,
        mitreTactic: isCritical ? 'Command and Control / Execution' : 'Reconnaissance / Credential Access',
        mitreTechniqueId: isCritical ? 'T1071 / T1059' : 'T1110 / T1595',
        severity: sample.severity,
        attackerIps: sample.id === 'ransomware-c2-exfiltration' ? ['91.240.118.172', '185.220.101.5'] : ['45.142.122.9', '193.106.191.66'],
        targetAssets: ['192.168.1.105', '192.168.1.20'],
      },
    ],
    iocList: [
      {
        type: 'IP',
        value: sample.id === 'ransomware-c2-exfiltration' ? '91.240.118.172' : '45.142.122.9',
        threat: sample.primaryThreat,
        severity: sample.severity,
        recommendedAction: 'BLOCK_WAN',
      },
    ],
    compromisedHosts: isCritical
      ? [
          {
            ip: '192.168.1.105',
            hostname: 'DESKTOP-FINANCE-04',
            status: 'Infected',
            recommendedIsolation: true,
            evidence: 'Activité malveillante corrélée dans les logs de la passerelle.',
          },
        ]
      : [],
    stopActions: [],
    incidentPlaybook: [],
    cisoBriefing: sample.description,
    analyzedAt: new Date().toISOString(),
  };
}

// Baseline clean audit scenario
const BASELINE_AUDIT_REPORT: ComparableReport = {
  id: 'baseline-clean-audit',
  sourceType: 'BENCHMARK',
  title: 'Audit de Référence (Post-Remédiation & Posture Saine)',
  deviceName: 'Passerelle Zyxel Nebula ATP (Baseline Certifiée)',
  timestamp: new Date(Date.now() - 86400000 * 7).toISOString(),
  riskScore: 12,
  threatLevel: 'LOW',
  activeAttacksCount: 0,
  iocsCount: 0,
  compromisedHostsCount: 0,
  analysis: {
    summary: 'Rapport de conformité post-remédiation. Aucune anomalie critique détectée, politiques de sécurité actives.',
    riskScore: 12,
    threatLevel: 'LOW',
    activeAttacksDetected: 0,
    attackVectors: [],
    iocList: [],
    compromisedHosts: [],
    stopActions: [],
    incidentPlaybook: [],
    cisoBriefing: 'Le périmètre réseau est conforme aux normes de sécurité requises. Aucun vecteur d\'attaque actif.',
    analyzedAt: new Date(Date.now() - 86400000 * 7).toISOString(),
  },
};

export const ReportComparisonSection: React.FC<ReportComparisonSectionProps> = ({
  currentAnalysis,
  historyList,
  currentDeviceName = 'Passerelle Zyxel Nebula',
  onRestoreAnalysis,
  onClose,
}) => {
  // Build available comparable pool
  const availableReports = useMemo<ComparableReport[]>(() => {
    const list: ComparableReport[] = [];

    // Current report
    list.push({
      id: 'current-active-report',
      sourceType: 'CURRENT',
      title: 'Rapport Actif en Cours (Temps Réel)',
      deviceName: currentDeviceName,
      timestamp: currentAnalysis.analyzedAt || new Date().toISOString(),
      riskScore: currentAnalysis.riskScore,
      threatLevel: currentAnalysis.threatLevel,
      activeAttacksCount: currentAnalysis.attackVectors.length,
      iocsCount: currentAnalysis.iocList.length,
      compromisedHostsCount: currentAnalysis.compromisedHosts.length,
      analysis: currentAnalysis,
    });

    // History items
    historyList.forEach((item) => {
      list.push({
        id: item.id,
        sourceType: 'HISTORY',
        title: item.title || `Analyse du ${new Date(item.timestamp).toLocaleTimeString('fr-FR')}`,
        deviceName: item.deviceName,
        timestamp: item.timestamp,
        riskScore: item.riskScore,
        threatLevel: item.threatLevel,
        activeAttacksCount: item.analysis.attackVectors.length,
        iocsCount: item.analysis.iocList.length,
        compromisedHostsCount: item.analysis.compromisedHosts.length,
        analysis: item.analysis,
        rawLogs: item.rawLogs,
      });
    });

    // Sample reports benchmarks
    SAMPLE_REPORTS.forEach((sample) => {
      const sampleAnalysis = buildSampleAnalysis(sample);
      list.push({
        id: `sample-${sample.id}`,
        sourceType: 'BENCHMARK',
        title: `Benchmark : ${sample.title}`,
        deviceName: sample.device,
        timestamp: new Date(Date.now() - 3600000 * 4).toISOString(),
        riskScore: sampleAnalysis.riskScore,
        threatLevel: sampleAnalysis.threatLevel,
        activeAttacksCount: sampleAnalysis.attackVectors.length,
        iocsCount: sampleAnalysis.iocList.length,
        compromisedHostsCount: sampleAnalysis.compromisedHosts.length,
        analysis: sampleAnalysis,
        rawLogs: sample.rawLogs,
      });
    });

    // Baseline clean report
    list.push(BASELINE_AUDIT_REPORT);

    return list;
  }, [currentAnalysis, historyList, currentDeviceName]);

  // Initial selection: Report A = Baseline / Previous, Report B = Current
  const [reportAId, setReportAId] = useState<string>(() => {
    if (historyList.length > 0) return historyList[0].id;
    return 'baseline-clean-audit';
  });

  const [reportBId, setReportBId] = useState<string>('current-active-report');
  const [activeTab, setActiveTab] = useState<'overview' | 'vectors' | 'hosts' | 'iocs'>('overview');

  const reportA = useMemo(
    () => availableReports.find((r) => r.id === reportAId) || availableReports[0],
    [availableReports, reportAId]
  );

  const reportB = useMemo(
    () => availableReports.find((r) => r.id === reportBId) || availableReports[0],
    [availableReports, reportBId]
  );

  // Invert A and B
  const handleSwapReports = () => {
    setReportAId(reportBId);
    setReportBId(reportAId);
  };

  // Deltas calculation (B minus A)
  const scoreDelta = reportB.riskScore - reportA.riskScore;
  const attacksDelta = reportB.activeAttacksCount - reportA.activeAttacksCount;
  const hostsDelta = reportB.compromisedHostsCount - reportA.compromisedHostsCount;
  const iocsDelta = reportB.iocsCount - reportA.iocsCount;

  // Identify new attack vectors in B absent from A (REGRESSION)
  const newVectorsInB = useMemo(() => {
    const aNames = new Set(reportA.analysis.attackVectors.map((v) => v.name.toLowerCase().trim()));
    return reportB.analysis.attackVectors.filter((v) => !aNames.has(v.name.toLowerCase().trim()));
  }, [reportA, reportB]);

  // Identify resolved attack vectors in A absent from B (IMPROVEMENT)
  const resolvedVectorsFromA = useMemo(() => {
    const bNames = new Set(reportB.analysis.attackVectors.map((v) => v.name.toLowerCase().trim()));
    return reportA.analysis.attackVectors.filter((v) => !bNames.has(v.name.toLowerCase().trim()));
  }, [reportA, reportB]);

  // Persistent attack vectors present in both
  const persistentVectors = useMemo(() => {
    const bNames = new Set(reportB.analysis.attackVectors.map((v) => v.name.toLowerCase().trim()));
    return reportA.analysis.attackVectors.filter((v) => bNames.has(v.name.toLowerCase().trim()));
  }, [reportA, reportB]);

  // Identify new compromised internal hosts in B
  const newCompromisedHostsInB = useMemo(() => {
    const aIps = new Set(reportA.analysis.compromisedHosts.map((h) => h.ip));
    return reportB.analysis.compromisedHosts.filter((h) => !aIps.has(h.ip));
  }, [reportA, reportB]);

  // Regression Diagnosis
  const regressionVerdict = useMemo(() => {
    if (scoreDelta >= 15 || reportB.threatLevel === 'CRITICAL' && reportA.threatLevel !== 'CRITICAL' || newCompromisedHostsInB.length > 0) {
      return {
        status: 'CRITICAL_REGRESSION',
        badge: 'RÉGRESSION DE SÉCURITÉ CRITIQUE',
        badgeClass: 'bg-red-950 text-red-300 border-red-700 animate-pulse',
        bannerClass: 'bg-red-950/40 border-red-800/80 text-red-200',
        icon: ShieldAlert,
        summary: `Dégradation majeure de la posture de sécurité : le score de risque augmente de +${scoreDelta} points (${reportA.riskScore} → ${reportB.riskScore}). ${newVectorsInB.length} nouveau(x) vecteur(s) d'attaques identifié(s) et ${newCompromisedHostsInB.length} nouvel(le) hôte LAN compromis.`,
      };
    }
    if (scoreDelta > 3 || newVectorsInB.length > 0) {
      return {
        status: 'MODERATE_REGRESSION',
        badge: 'VIGILANCE : RÉGRESSION DÉTECTÉE',
        badgeClass: 'bg-amber-950 text-amber-300 border-amber-700',
        bannerClass: 'bg-amber-950/40 border-amber-800/80 text-amber-200',
        icon: AlertTriangle,
        summary: `Augmentation modérée du risque (+${scoreDelta} pts). De nouvelles anomalies ou tentatives d'intrusion ont été enregistrées sur le périmètre.`,
      };
    }
    if (scoreDelta <= -5 || resolvedVectorsFromA.length > 0) {
      return {
        status: 'IMPROVEMENT',
        badge: 'AMÉLIORATION DE LA SÉCURITÉ',
        badgeClass: 'bg-emerald-950 text-emerald-300 border-emerald-700',
        bannerClass: 'bg-emerald-950/40 border-emerald-800/80 text-emerald-200',
        icon: ShieldCheck,
        summary: `Résorption des menaces : réduction du score de risque de ${Math.abs(scoreDelta)} points (${reportA.riskScore} → ${reportB.riskScore}). ${resolvedVectorsFromA.length} vecteur(s) d'attaque neutralisé(s).`,
      };
    }
    return {
      status: 'STABLE',
      badge: 'POSTURE ÉQUIVALENTE / STABLE',
      badgeClass: 'bg-slate-800 text-slate-300 border-slate-700',
      bannerClass: 'bg-slate-900/60 border-slate-800 text-slate-300',
      icon: CheckCircle2,
      summary: `Les deux rapports présentent un profil de sécurité comparable (Écart de score : ${scoreDelta >= 0 ? `+${scoreDelta}` : scoreDelta} pts).`,
    };
  }, [scoreDelta, reportA, reportB, newVectorsInB, resolvedVectorsFromA, newCompromisedHostsInB]);

  const VerdictIcon = regressionVerdict.icon;

  return (
    <div className="rounded-3xl bg-slate-900/95 border-2 border-cyan-800/60 shadow-2xl p-6 sm:p-8 space-y-6 animate-in fade-in slide-in-from-top-4 backdrop-blur-xl">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-2xl bg-cyan-950 border border-cyan-700 flex items-center justify-center text-cyan-400">
            <GitCompare className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-lg font-bold text-white">
                Comparateur d'Analyses & Détection des Régressions
              </h3>
              <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-cyan-950 text-cyan-300 border border-cyan-800">
                Mode Diff Côte-à-Côte
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono">
              Comparez deux rapports Nebula Secure Report pour isoler les régressions, nouvelles menaces et améliorations.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleSwapReports}
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono border border-slate-700 transition"
            title="Inverser les rapports A et B"
          >
            <ArrowLeftRight className="w-3.5 h-3.5 text-cyan-400" />
            <span>Inverser A ⇄ B</span>
          </button>

          {onClose && (
            <button
              onClick={onClose}
              className="px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono border border-slate-700 transition"
            >
              Fermer
            </button>
          )}
        </div>
      </div>

      {/* Selectors Bar */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 p-4 rounded-2xl bg-slate-950/80 border border-slate-800/80">
        {/* Report A Selector (Base / Reference) */}
        <div className="space-y-1.5">
          <label className="text-xs font-mono font-bold text-slate-400 flex items-center gap-2">
            <span className="w-5 h-5 rounded-md bg-slate-800 text-cyan-300 flex items-center justify-center text-[11px]">
              A
            </span>
            <span>Rapport Référence (Baseline / Antérieur)</span>
          </label>
          <select
            value={reportAId}
            onChange={(e) => setReportAId(e.target.value)}
            className="w-full bg-slate-900 border border-slate-700 text-xs text-slate-200 rounded-xl px-3 py-2.5 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono"
          >
            {availableReports.map((r) => (
              <option key={`a-${r.id}`} value={r.id}>
                [{r.threatLevel} | {r.riskScore}/100] {r.title} ({r.deviceName})
              </option>
            ))}
          </select>
        </div>

        {/* Report B Selector (Target / New) */}
        <div className="space-y-1.5">
          <label className="text-xs font-mono font-bold text-slate-400 flex items-center gap-2">
            <span className="w-5 h-5 rounded-md bg-cyan-950 text-cyan-400 border border-cyan-800 flex items-center justify-center text-[11px]">
              B
            </span>
            <span>Rapport Cible (Nouveau / Comparé)</span>
          </label>
          <select
            value={reportBId}
            onChange={(e) => setReportBId(e.target.value)}
            className="w-full bg-slate-900 border border-slate-700 text-xs text-slate-200 rounded-xl px-3 py-2.5 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono"
          >
            {availableReports.map((r) => (
              <option key={`b-${r.id}`} value={r.id}>
                [{r.threatLevel} | {r.riskScore}/100] {r.title} ({r.deviceName})
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Regression Verdict Banner */}
      <div className={`p-4 rounded-2xl border ${regressionVerdict.bannerClass} space-y-2`}>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <VerdictIcon className="w-5 h-5 flex-shrink-0" />
            <span className={`px-2.5 py-0.5 rounded-full text-xs font-mono font-bold border ${regressionVerdict.badgeClass}`}>
              {regressionVerdict.badge}
            </span>
          </div>

          <div className="flex items-center gap-3 text-xs font-mono font-bold">
            <span>Score : {reportA.riskScore} → {reportB.riskScore}</span>
            <span
              className={`px-2 py-0.5 rounded-lg ${
                scoreDelta > 0 ? 'bg-red-900/60 text-red-300' : scoreDelta < 0 ? 'bg-emerald-900/60 text-emerald-300' : 'bg-slate-800 text-slate-300'
              }`}
            >
              {scoreDelta > 0 ? `+${scoreDelta} pts (Régression)` : scoreDelta < 0 ? `${scoreDelta} pts (Amélioration)` : 'Identique'}
            </span>
          </div>
        </div>

        <p className="text-xs leading-relaxed font-sans">{regressionVerdict.summary}</p>
      </div>

      {/* Side-by-Side Comparison Columns (Côte à côte) */}
      <div className="grid grid-cols-1 md:grid-cols-11 gap-4 items-stretch">
        {/* Left Column: Report A (5 cols) */}
        <div className="md:col-span-5 p-5 rounded-2xl bg-slate-950/70 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <div>
              <span className="text-[10px] font-mono text-cyan-400 font-bold uppercase tracking-wider block">
                Rapport A (Référence)
              </span>
              <h4 className="text-sm font-bold text-white truncate max-w-[260px]">{reportA.title}</h4>
            </div>
            <span
              className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                reportA.threatLevel === 'CRITICAL'
                  ? 'bg-red-950 text-red-300 border border-red-800'
                  : reportA.threatLevel === 'HIGH'
                  ? 'bg-amber-950 text-amber-300 border border-amber-800'
                  : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
              }`}
            >
              {reportA.threatLevel}
            </span>
          </div>

          {/* Key Metrics */}
          <div className="grid grid-cols-2 gap-3 text-xs font-mono">
            <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase block">Score de Risque</span>
              <span className="text-xl font-extrabold text-white mt-0.5 block">{reportA.riskScore} / 100</span>
            </div>

            <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase block">Attaques Actives</span>
              <span className="text-xl font-extrabold text-cyan-400 mt-0.5 block">{reportA.activeAttacksCount}</span>
            </div>

            <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase block">IOCs Signalés</span>
              <span className="text-xl font-extrabold text-amber-400 mt-0.5 block">{reportA.iocsCount}</span>
            </div>

            <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase block">Hôtes LAN Compromis</span>
              <span className="text-xl font-extrabold text-purple-400 mt-0.5 block">{reportA.compromisedHostsCount}</span>
            </div>
          </div>

          <div className="text-[11px] font-mono text-slate-400 space-y-1 pt-1">
            <div>Équipement : <span className="text-slate-200">{reportA.deviceName}</span></div>
            <div>Date : <span className="text-slate-300">{new Date(reportA.timestamp).toLocaleString('fr-FR')}</span></div>
          </div>
        </div>

        {/* Center Column: Diff Deltas (1 col) */}
        <div className="md:col-span-1 flex md:flex-col items-center justify-around p-3 rounded-2xl bg-slate-950/40 border border-slate-800/60 font-mono text-xs text-center">
          <div className="space-y-1">
            <span className="text-[9px] text-slate-500 uppercase block">Δ Score</span>
            <span
              className={`px-2 py-0.5 rounded font-bold block ${
                scoreDelta > 0 ? 'bg-red-950 text-red-400' : scoreDelta < 0 ? 'bg-emerald-950 text-emerald-400' : 'bg-slate-800 text-slate-400'
              }`}
            >
              {scoreDelta > 0 ? `+${scoreDelta}` : scoreDelta}
            </span>
          </div>

          <div className="space-y-1">
            <span className="text-[9px] text-slate-500 uppercase block">Δ Attaques</span>
            <span
              className={`px-2 py-0.5 rounded font-bold block ${
                attacksDelta > 0 ? 'bg-red-950 text-red-400' : attacksDelta < 0 ? 'bg-emerald-950 text-emerald-400' : 'bg-slate-800 text-slate-400'
              }`}
            >
              {attacksDelta > 0 ? `+${attacksDelta}` : attacksDelta}
            </span>
          </div>

          <div className="space-y-1">
            <span className="text-[9px] text-slate-500 uppercase block">Δ Hôtes</span>
            <span
              className={`px-2 py-0.5 rounded font-bold block ${
                hostsDelta > 0 ? 'bg-purple-950 text-purple-300' : hostsDelta < 0 ? 'bg-emerald-950 text-emerald-400' : 'bg-slate-800 text-slate-400'
              }`}
            >
              {hostsDelta > 0 ? `+${hostsDelta}` : hostsDelta}
            </span>
          </div>
        </div>

        {/* Right Column: Report B (5 cols) */}
        <div className="md:col-span-5 p-5 rounded-2xl bg-slate-950/70 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <div>
              <span className="text-[10px] font-mono text-cyan-400 font-bold uppercase tracking-wider block">
                Rapport B (Cible / Nouveau)
              </span>
              <h4 className="text-sm font-bold text-white truncate max-w-[260px]">{reportB.title}</h4>
            </div>
            <span
              className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                reportB.threatLevel === 'CRITICAL'
                  ? 'bg-red-950 text-red-300 border border-red-800'
                  : reportB.threatLevel === 'HIGH'
                  ? 'bg-amber-950 text-amber-300 border border-amber-800'
                  : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
              }`}
            >
              {reportB.threatLevel}
            </span>
          </div>

          {/* Key Metrics */}
          <div className="grid grid-cols-2 gap-3 text-xs font-mono">
            <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase block">Score de Risque</span>
              <span className="text-xl font-extrabold text-white mt-0.5 block">{reportB.riskScore} / 100</span>
            </div>

            <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase block">Attaques Actives</span>
              <span className="text-xl font-extrabold text-cyan-400 mt-0.5 block">{reportB.activeAttacksCount}</span>
            </div>

            <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase block">IOCs Signalés</span>
              <span className="text-xl font-extrabold text-amber-400 mt-0.5 block">{reportB.iocsCount}</span>
            </div>

            <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase block">Hôtes LAN Compromis</span>
              <span className="text-xl font-extrabold text-purple-400 mt-0.5 block">{reportB.compromisedHostsCount}</span>
            </div>
          </div>

          <div className="text-[11px] font-mono text-slate-400 space-y-1 pt-1">
            <div>Équipement : <span className="text-slate-200">{reportB.deviceName}</span></div>
            <div>Date : <span className="text-slate-300">{new Date(reportB.timestamp).toLocaleString('fr-FR')}</span></div>
          </div>
        </div>
      </div>

      {/* Detailed Diff Breakdown Tabs */}
      <div className="space-y-4 pt-2">
        <div className="flex items-center gap-2 border-b border-slate-800 pb-2 overflow-x-auto no-scrollbar">
          <button
            onClick={() => setActiveTab('overview')}
            className={`px-3 py-1.5 rounded-xl text-xs font-mono font-semibold transition whitespace-nowrap ${
              activeTab === 'overview'
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Vue Synthétique & Régressions
          </button>
          <button
            onClick={() => setActiveTab('vectors')}
            className={`px-3 py-1.5 rounded-xl text-xs font-mono font-semibold transition whitespace-nowrap ${
              activeTab === 'vectors'
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Vecteurs d'Attaques Diff ({newVectorsInB.length} nouveaux, {resolvedVectorsFromA.length} résolus)
          </button>
          <button
            onClick={() => setActiveTab('hosts')}
            className={`px-3 py-1.5 rounded-xl text-xs font-mono font-semibold transition whitespace-nowrap ${
              activeTab === 'hosts'
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Hôtes LAN Infectés ({newCompromisedHostsInB.length} nouveaux)
          </button>
          <button
            onClick={() => setActiveTab('iocs')}
            className={`px-3 py-1.5 rounded-xl text-xs font-mono font-semibold transition whitespace-nowrap ${
              activeTab === 'iocs'
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            IOCs & Signatures
          </button>
        </div>

        {/* Tab 1: Overview Matrix */}
        {activeTab === 'overview' && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* New Threats (Regression) */}
              <div className="p-4 rounded-2xl bg-red-950/20 border border-red-900/50 space-y-2">
                <div className="flex items-center gap-2 text-xs font-mono font-bold text-red-400">
                  <XCircle className="w-4 h-4 text-red-500" />
                  <span>Nouvelles Menaces Apparues ({newVectorsInB.length})</span>
                </div>
                {newVectorsInB.length === 0 ? (
                  <p className="text-xs text-slate-500 font-sans">Aucun nouveau vecteur d'attaque introduit.</p>
                ) : (
                  <ul className="space-y-1.5 text-xs font-mono">
                    {newVectorsInB.map((v, i) => (
                      <li key={i} className="p-2 rounded-lg bg-red-950/40 border border-red-800/60 text-red-200">
                        <div className="font-bold">{v.name}</div>
                        <div className="text-[10px] text-red-400 font-sans mt-0.5">{v.mitreTechniqueId} • {v.mitreTactic}</div>
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              {/* Neutralized Threats (Improvement) */}
              <div className="p-4 rounded-2xl bg-emerald-950/20 border border-emerald-900/50 space-y-2">
                <div className="flex items-center gap-2 text-xs font-mono font-bold text-emerald-400">
                  <CheckCircle2 className="w-4 h-4 text-emerald-500" />
                  <span>Menaces Résolues / Neutralisées ({resolvedVectorsFromA.length})</span>
                </div>
                {resolvedVectorsFromA.length === 0 ? (
                  <p className="text-xs text-slate-500 font-sans">Aucune menace clôturée entre ces deux rapports.</p>
                ) : (
                  <ul className="space-y-1.5 text-xs font-mono">
                    {resolvedVectorsFromA.map((v, i) => (
                      <li key={i} className="p-2 rounded-lg bg-emerald-950/40 border border-emerald-800/60 text-emerald-200">
                        <div className="font-bold">{v.name}</div>
                        <div className="text-[10px] text-emerald-400 font-sans mt-0.5">{v.mitreTechniqueId}</div>
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              {/* Persistent Threats */}
              <div className="p-4 rounded-2xl bg-amber-950/20 border border-amber-900/50 space-y-2">
                <div className="flex items-center gap-2 text-xs font-mono font-bold text-amber-400">
                  <AlertTriangle className="w-4 h-4 text-amber-500" />
                  <span>Menaces Persistantes ({persistentVectors.length})</span>
                </div>
                {persistentVectors.length === 0 ? (
                  <p className="text-xs text-slate-500 font-sans">Aucun vecteur commun.</p>
                ) : (
                  <ul className="space-y-1.5 text-xs font-mono">
                    {persistentVectors.map((v, i) => (
                      <li key={i} className="p-2 rounded-lg bg-amber-950/40 border border-amber-800/60 text-amber-200">
                        <div className="font-bold">{v.name}</div>
                        <div className="text-[10px] text-amber-400 font-sans mt-0.5">{v.mitreTechniqueId}</div>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Tab 2: Attack Vectors Diff */}
        {activeTab === 'vectors' && (
          <div className="space-y-3">
            <h5 className="text-xs font-mono font-bold text-slate-300 uppercase">
              Analyse Comparative Détaillée des Vecteurs MITRE ATT&CK
            </h5>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <span className="text-xs font-mono font-bold text-slate-400 block">Vecteurs dans Rapport A :</span>
                {reportA.analysis.attackVectors.length === 0 ? (
                  <p className="text-xs text-slate-500">Aucun vecteur répertorié.</p>
                ) : (
                  reportA.analysis.attackVectors.map((v, idx) => (
                    <div key={idx} className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-white">{v.name}</span>
                        <span className="text-[10px] text-cyan-400">{v.mitreTechniqueId}</span>
                      </div>
                      <p className="text-[11px] text-slate-400 font-sans">{v.description}</p>
                    </div>
                  ))
                )}
              </div>

              <div className="space-y-2">
                <span className="text-xs font-mono font-bold text-slate-400 block">Vecteurs dans Rapport B :</span>
                {reportB.analysis.attackVectors.length === 0 ? (
                  <p className="text-xs text-slate-500">Aucun vecteur répertorié.</p>
                ) : (
                  reportB.analysis.attackVectors.map((v, idx) => {
                    const isNew = newVectorsInB.some((nv) => nv.name === v.name);
                    return (
                      <div
                        key={idx}
                        className={`p-3 rounded-xl text-xs font-mono space-y-1 border ${
                          isNew ? 'bg-red-950/40 border-red-700 text-red-200' : 'bg-slate-950 border-slate-800 text-slate-200'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-white flex items-center gap-1.5">
                            {isNew && <span className="px-1.5 py-0.2 rounded text-[9px] bg-red-600 text-white font-bold">NOUVEAU</span>}
                            {v.name}
                          </span>
                          <span className="text-[10px] text-cyan-400">{v.mitreTechniqueId}</span>
                        </div>
                        <p className="text-[11px] text-slate-400 font-sans">{v.description}</p>
                      </div>
                    );
                  })
                )}
              </div>
            </div>
          </div>
        )}

        {/* Tab 3: Hosts Diff */}
        {activeTab === 'hosts' && (
          <div className="space-y-3">
            <h5 className="text-xs font-mono font-bold text-slate-300 uppercase">
              Différentiel des Postes Internes & Confinement CDR
            </h5>
            {newCompromisedHostsInB.length > 0 && (
              <div className="p-3 rounded-xl bg-red-950/40 border border-red-800 text-xs font-mono text-red-300 space-y-1">
                <div className="font-bold flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-red-400" />
                  <span>RÉGRESSION : Nouveaux hôtes LAN infectés dans le Rapport B :</span>
                </div>
                {newCompromisedHostsInB.map((h, i) => (
                  <div key={i} className="pl-6">
                    • <strong>{h.ip}</strong> {h.hostname ? `(${h.hostname})` : ''} - {h.evidence}
                  </div>
                ))}
              </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2 text-xs font-mono">
                <span className="font-bold text-slate-400 block">Hôtes Rapport A :</span>
                {reportA.analysis.compromisedHosts.length === 0 ? (
                  <span className="text-slate-500">Aucun poste compromis</span>
                ) : (
                  reportA.analysis.compromisedHosts.map((h, i) => (
                    <div key={i} className="p-2 rounded bg-slate-900 border border-slate-800">
                      <span className="text-white font-bold">{h.ip}</span> - {h.status}
                    </div>
                  ))
                )}
              </div>

              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2 text-xs font-mono">
                <span className="font-bold text-slate-400 block">Hôtes Rapport B :</span>
                {reportB.analysis.compromisedHosts.length === 0 ? (
                  <span className="text-slate-500">Aucun poste compromis</span>
                ) : (
                  reportB.analysis.compromisedHosts.map((h, i) => (
                    <div key={i} className="p-2 rounded bg-slate-900 border border-slate-800">
                      <span className="text-white font-bold">{h.ip}</span> - {h.status}
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        )}

        {/* Tab 4: IOCs Diff */}
        {activeTab === 'iocs' && (
          <div className="space-y-3">
            <h5 className="text-xs font-mono font-bold text-slate-300 uppercase">
              Indicateurs de Compromission Relevés
            </h5>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2 text-xs font-mono">
                <span className="font-bold text-slate-400 block">IOCs Rapport A ({reportA.analysis.iocList.length}) :</span>
                <div className="space-y-1.5 max-h-48 overflow-y-auto">
                  {reportA.analysis.iocList.map((ioc, i) => (
                    <div key={i} className="p-2 rounded bg-slate-900 border border-slate-800 flex items-center justify-between">
                      <span className="text-white font-bold">{ioc.value}</span>
                      <span className="text-[10px] text-cyan-400">{ioc.type}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2 text-xs font-mono">
                <span className="font-bold text-slate-400 block">IOCs Rapport B ({reportB.analysis.iocList.length}) :</span>
                <div className="space-y-1.5 max-h-48 overflow-y-auto">
                  {reportB.analysis.iocList.map((ioc, i) => (
                    <div key={i} className="p-2 rounded bg-slate-900 border border-slate-800 flex items-center justify-between">
                      <span className="text-white font-bold">{ioc.value}</span>
                      <span className="text-[10px] text-cyan-400">{ioc.type}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
