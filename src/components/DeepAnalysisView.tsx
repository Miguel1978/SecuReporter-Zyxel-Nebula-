import React, { useState, useMemo } from 'react';
import {
  ShieldAlert,
  Target,
  ListOrdered,
  FileText,
  Copy,
  Check,
  ExternalLink,
  ChevronRight,
  ShieldCheck,
  AlertTriangle,
  Lock,
  Download,
  Search,
  Filter,
  Zap,
} from 'lucide-react';
import { ThreatAnalysisResult, StopAction, ActiveDefense } from '../types';

interface DeepAnalysisViewProps {
  analysis: ThreatAnalysisResult;
  onEnforceDefense?: (action: StopAction) => Promise<void>;
  onNavigateToCountermeasures?: () => void;
  activeDefenses?: ActiveDefense[];
}

export const DeepAnalysisView: React.FC<DeepAnalysisViewProps> = ({
  analysis,
  onEnforceDefense,
  onNavigateToCountermeasures,
  activeDefenses = [],
}) => {
  const [copiedIoc, setCopiedIoc] = useState<string | null>(null);
  const [iocSearch, setIocSearch] = useState<string>('');
  const [selectedMitreTactic, setSelectedMitreTactic] = useState<string>('ALL');

  const handleCopy = (val: string) => {
    navigator.clipboard.writeText(val);
    setCopiedIoc(val);
    setTimeout(() => setCopiedIoc(null), 2000);
  };

  const isIpBlocked = (ip: string) => {
    return activeDefenses.some((d) => d.target === ip && d.status === 'ACTIVE');
  };

  // Unique MITRE tactics
  const uniqueTactics = useMemo(() => {
    const set = new Set<string>();
    analysis.attackVectors.forEach((v) => {
      if (v.mitreTactic) set.add(v.mitreTactic);
    });
    return Array.from(set);
  }, [analysis.attackVectors]);

  // Filtered attack vectors
  const filteredAttackVectors = useMemo(() => {
    if (selectedMitreTactic === 'ALL') return analysis.attackVectors;
    return analysis.attackVectors.filter((v) => v.mitreTactic === selectedMitreTactic);
  }, [analysis.attackVectors, selectedMitreTactic]);

  // Filtered IOCs
  const filteredIocs = useMemo(() => {
    if (!iocSearch.trim()) return analysis.iocList;
    const q = iocSearch.toLowerCase().trim();
    return analysis.iocList.filter(
      (ioc) =>
        ioc.value.toLowerCase().includes(q) ||
        ioc.threat.toLowerCase().includes(q) ||
        ioc.type.toLowerCase().includes(q) ||
        ioc.severity.toLowerCase().includes(q)
    );
  }, [analysis.iocList, iocSearch]);

  // Export IOCs as CSV
  const handleExportCsv = () => {
    const headers = ['Type', 'Valeur', 'Menace_Contexte', 'Severite', 'Action_Recommandee'];
    const rows = filteredIocs.map((ioc) => [
      ioc.type,
      ioc.value,
      `"${ioc.threat.replace(/"/g, '""')}"`,
      ioc.severity,
      ioc.recommendedAction,
    ]);
    const csvContent =
      'data:text/csv;charset=utf-8,' +
      [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const link = document.createElement('a');
    link.href = encodeURI(csvContent);
    link.download = `nebula_iocs_${Date.now()}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Export IOCs as JSON
  const handleExportJson = () => {
    const dataStr =
      'data:text/json;charset=utf-8,' +
      encodeURIComponent(JSON.stringify(analysis.iocList, null, 2));
    const link = document.createElement('a');
    link.href = dataStr;
    link.download = `nebula_iocs_threat_intel_${Date.now()}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="space-y-8">
      {/* CISO Executive Briefing */}
      <div className="p-6 rounded-3xl bg-slate-900/95 border border-slate-800 shadow-2xl space-y-4 backdrop-blur-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2.5">
            <div className="w-10 h-10 rounded-xl bg-cyan-950/80 border border-cyan-800 flex items-center justify-center text-cyan-400">
              <FileText className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white tracking-tight">
                Synthèse Exécutive & Briefing Direction Sécurité (CISO / RSSI)
              </h3>
              <p className="text-xs text-slate-400 font-mono">
                Post-mortem automatique et recommandations stratégiques pour le comité de direction
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <span
              className={`px-3 py-1 rounded-xl text-xs font-mono font-bold border ${
                analysis.threatLevel === 'CRITICAL'
                  ? 'bg-rose-950 text-rose-300 border-rose-800'
                  : analysis.threatLevel === 'HIGH'
                  ? 'bg-amber-950 text-amber-300 border-amber-800'
                  : 'bg-emerald-950 text-emerald-300 border-emerald-800'
              }`}
            >
              Niveau : {analysis.threatLevel} ({analysis.riskScore}/100)
            </span>
          </div>
        </div>

        <p className="text-sm text-slate-300 leading-relaxed font-sans bg-slate-950/60 p-5 rounded-2xl border border-slate-800/80">
          {analysis.cisoBriefing}
        </p>
      </div>

      {/* MITRE ATT&CK Matrix Breakdown */}
      <div className="p-6 rounded-3xl bg-slate-900/95 border border-slate-800 shadow-2xl space-y-6 backdrop-blur-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-rose-950/80 border border-rose-800 flex items-center justify-center text-rose-400">
              <Target className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white tracking-tight">
                Cartographie MITRE ATT&CK Enterprise
              </h3>
              <p className="text-xs text-slate-400 font-mono">
                Corrélation des alertes IDP/IPS, réputation IP et signatures de passerelle Zyxel
              </p>
            </div>
          </div>

          {/* MITRE Tactic Filters */}
          {uniqueTactics.length > 0 && (
            <div className="flex items-center gap-1.5 flex-wrap">
              <button
                type="button"
                onClick={() => setSelectedMitreTactic('ALL')}
                className={`px-3 py-1.5 rounded-xl text-xs font-mono transition ${
                  selectedMitreTactic === 'ALL'
                    ? 'bg-cyan-950 text-cyan-300 border border-cyan-700 font-bold'
                    : 'bg-slate-950 text-slate-400 border border-slate-800 hover:text-white'
                }`}
              >
                Toutes ({analysis.attackVectors.length})
              </button>
              {uniqueTactics.map((tac) => (
                <button
                  key={tac}
                  type="button"
                  onClick={() => setSelectedMitreTactic(tac)}
                  className={`px-3 py-1.5 rounded-xl text-xs font-mono transition ${
                    selectedMitreTactic === tac
                      ? 'bg-cyan-950 text-cyan-300 border border-cyan-700 font-bold'
                      : 'bg-slate-950 text-slate-400 border border-slate-800 hover:text-white'
                  }`}
                >
                  {tac.split('/')[0].trim()}
                </button>
              ))}
            </div>
          )}
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filteredAttackVectors.map((vec, idx) => (
            <div
              key={idx}
              className="p-5 rounded-2xl bg-slate-950/80 border border-slate-800/80 hover:border-slate-700 transition flex flex-col justify-between space-y-4"
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[11px] font-mono font-bold px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                    {vec.mitreTechniqueId}
                  </span>
                  <span className="text-[11px] font-mono px-2 py-0.5 rounded font-bold bg-rose-950 text-rose-300 border border-rose-800">
                    {vec.severity}
                  </span>
                </div>
                <h4 className="text-sm font-bold text-white mb-1">{vec.name}</h4>
                <p className="text-[11px] text-slate-400 font-mono mb-2">
                  Tactique : <span className="text-slate-300">{vec.mitreTactic}</span>
                </p>
                <p className="text-xs text-slate-300 leading-relaxed">{vec.description}</p>
              </div>

              <div className="pt-3 border-t border-slate-800 text-xs font-mono text-slate-400 flex items-center justify-between">
                <span>Cibles : {vec.targetAssets.join(', ') || 'Périmètre'}</span>
                <span className="text-rose-400 font-bold">{vec.attackerIps.length} Attaquant(s)</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Incident Response Playbook */}
      <div className="p-6 rounded-3xl bg-slate-900/95 border border-slate-800 shadow-2xl space-y-6 backdrop-blur-xl">
        <div className="flex items-center gap-3 border-b border-slate-800 pb-4">
          <div className="w-10 h-10 rounded-xl bg-emerald-950/80 border border-emerald-800 flex items-center justify-center text-emerald-400">
            <ListOrdered className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white tracking-tight">
              Playbook d'Intervention Rapide (Étapes Chronologiques)
            </h3>
            <p className="text-xs text-slate-400 font-mono">
              Guide tactique pour l'analyste SOC et l'administrateur réseau Zyxel
            </p>
          </div>
        </div>

        <div className="space-y-3.5">
          {analysis.incidentPlaybook.map((step, idx) => (
            <div
              key={idx}
              className="p-4 rounded-2xl bg-slate-950/70 border border-slate-800/80 flex items-start gap-4 hover:border-slate-700 transition"
            >
              <div className="w-8 h-8 rounded-xl bg-emerald-950 text-emerald-400 border border-emerald-800 flex items-center justify-center font-mono font-bold text-sm flex-shrink-0">
                {step.step || idx + 1}
              </div>
              <div className="space-y-1 flex-1">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                  <h4 className="text-sm font-bold text-white">{step.action}</h4>
                  <span className="text-xs font-mono text-cyan-400 px-2 py-0.5 rounded bg-slate-900 border border-slate-800">
                    Cible : {step.target}
                  </span>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed pt-1">{step.details}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Complete Indicators of Compromise (IOC) Table */}
      <div className="p-6 rounded-3xl bg-slate-900/95 border border-slate-800 shadow-2xl space-y-5 backdrop-blur-xl">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-amber-950/80 border border-amber-800 flex items-center justify-center text-amber-400">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-white tracking-tight">
                  Indicateurs de Compromission Identifiés (IOCs)
                </h3>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-950 text-cyan-300 border border-cyan-800 font-bold">
                  {filteredIocs.length} / {analysis.iocList.length}
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono">
                Liste certifiée des serveurs C2, scanners hostiles et cibles internes
              </p>
            </div>
          </div>

          {/* IOC Search & Export Toolbar */}
          <div className="flex flex-wrap items-center gap-2.5">
            <div className="relative min-w-[200px] sm:min-w-[260px]">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={iocSearch}
                onChange={(e) => setIocSearch(e.target.value)}
                placeholder="Filtrer par IP, menace, sévérité..."
                className="w-full bg-slate-950 border border-slate-700 rounded-xl pl-9 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono"
              />
            </div>

            <button
              type="button"
              onClick={handleExportCsv}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-950 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-700 text-xs font-mono transition"
              title="Exporter les IOCs filtrés au format CSV"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" />
              <span>Export CSV</span>
            </button>

            <button
              type="button"
              onClick={handleExportJson}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-950 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-700 text-xs font-mono transition"
              title="Exporter les IOCs au format JSON STIX"
            >
              <Download className="w-3.5 h-3.5 text-emerald-400" />
              <span>Export JSON</span>
            </button>
          </div>
        </div>

        <div className="overflow-x-auto rounded-2xl border border-slate-800">
          <table className="w-full text-left font-mono text-xs">
            <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
              <tr>
                <th className="p-3">Type</th>
                <th className="p-3">Valeur de l'IOC</th>
                <th className="p-3">Menace & Contexte</th>
                <th className="p-3">Niveau</th>
                <th className="p-3">Action Recommandée</th>
                <th className="p-3">Statut Riposte Nebula</th>
                <th className="p-3 text-right">Copier</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80 bg-slate-900/40">
              {filteredIocs.map((ioc, idx) => {
                const blocked = isIpBlocked(ioc.value);
                const matchingAction = analysis.stopActions.find((a) => a.target === ioc.value);

                return (
                  <tr key={idx} className="hover:bg-slate-800/40 transition">
                    <td className="p-3">
                      <span className="px-2 py-0.5 rounded-lg bg-slate-800 text-cyan-300 text-[10px] font-bold">
                        {ioc.type}
                      </span>
                    </td>
                    <td className="p-3 font-bold text-white select-all">{ioc.value}</td>
                    <td className="p-3 text-slate-300 font-sans">{ioc.threat}</td>
                    <td className="p-3">
                      <span
                        className={`px-2 py-0.5 rounded-lg text-[10px] font-bold border ${
                          ioc.severity === 'CRITICAL'
                            ? 'bg-rose-950 text-rose-300 border-rose-800'
                            : ioc.severity === 'HIGH'
                            ? 'bg-amber-950 text-amber-300 border-amber-800'
                            : 'bg-slate-800 text-slate-300 border-slate-700'
                        }`}
                      >
                        {ioc.severity}
                      </span>
                    </td>
                    <td className="p-3 text-cyan-400 font-semibold">{ioc.recommendedAction}</td>
                    <td className="p-3">
                      {blocked ? (
                        <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-emerald-950/70 border border-emerald-800 text-emerald-300 text-[11px] font-bold">
                          <ShieldCheck className="w-3.5 h-3.5" />
                          <span>Bloqué sur Nebula</span>
                        </span>
                      ) : (
                        <button
                          type="button"
                          onClick={() => {
                            if (matchingAction && onEnforceDefense) {
                              onEnforceDefense(matchingAction);
                            } else if (onNavigateToCountermeasures) {
                              onNavigateToCountermeasures();
                            }
                          }}
                          className="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg bg-rose-600/90 hover:bg-rose-500 text-white font-mono text-[11px] font-semibold transition shadow-sm"
                          title="Bloquer immédiatement cette IP sur la passerelle Zyxel Nebula"
                        >
                          <Lock className="w-3 h-3" />
                          <span>Bloquer l'IP</span>
                        </button>
                      )}
                    </td>
                    <td className="p-3 text-right">
                      <button
                        onClick={() => handleCopy(ioc.value)}
                        className="p-1.5 rounded-lg hover:bg-slate-700 text-slate-400 hover:text-white transition"
                        title="Copier la valeur"
                      >
                        {copiedIoc === ioc.value ? (
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
