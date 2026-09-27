import React, { useState } from 'react';
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
} from 'lucide-react';
import { ThreatAnalysisResult } from '../types';

interface DeepAnalysisViewProps {
  analysis: ThreatAnalysisResult;
}

export const DeepAnalysisView: React.FC<DeepAnalysisViewProps> = ({ analysis }) => {
  const [copiedIoc, setCopiedIoc] = useState<string | null>(null);

  const handleCopy = (val: string) => {
    navigator.clipboard.writeText(val);
    setCopiedIoc(val);
    setTimeout(() => setCopiedIoc(null), 2000);
  };

  return (
    <div className="space-y-8">
      {/* CISO Executive Briefing */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 border border-slate-700/80 shadow-xl space-y-4">
        <div className="flex items-center gap-2.5">
          <FileText className="w-5 h-5 text-cyan-400" />
          <h3 className="text-base font-bold text-white tracking-tight">
            Synthèse Exécutive & Briefing Direction Sécurité (CISO / RSSI)
          </h3>
        </div>
        <p className="text-sm text-slate-300 leading-relaxed font-sans bg-slate-950/60 p-4 rounded-xl border border-slate-800">
          {analysis.cisoBriefing}
        </p>
      </div>

      {/* MITRE ATT&CK Matrix Breakdown */}
      <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <Target className="w-5 h-5 text-red-400" />
            <h3 className="text-base font-bold text-white">
              Cartographie MITRE ATT&CK Enterprise
            </h3>
          </div>
          <span className="text-xs font-mono text-slate-400">
            Corrélation des alertes IDP & Réputation Nebula
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {analysis.attackVectors.map((vec, idx) => (
            <div
              key={idx}
              className="p-4 rounded-xl bg-slate-950/80 border border-slate-800/80 hover:border-slate-700 transition flex flex-col justify-between space-y-3"
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                    {vec.mitreTechniqueId}
                  </span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded font-bold bg-red-950 text-red-400 border border-red-800">
                    {vec.severity}
                  </span>
                </div>
                <h4 className="text-xs font-bold text-white mb-1">{vec.name}</h4>
                <p className="text-[11px] text-slate-400 font-mono mb-2">
                  Tactique : <span className="text-slate-300">{vec.mitreTactic}</span>
                </p>
                <p className="text-xs text-slate-300 leading-relaxed">{vec.description}</p>
              </div>

              <div className="pt-2 border-t border-slate-800 text-[10px] font-mono text-slate-400 flex items-center justify-between">
                <span>Cibles : {vec.targetAssets.join(', ') || 'Périmètre'}</span>
                <span className="text-red-400 font-bold">{vec.attackerIps.length} Attaquant(s)</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Incident Response Playbook */}
      <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-6">
        <div className="flex items-center gap-2.5">
          <ListOrdered className="w-5 h-5 text-emerald-400" />
          <div>
            <h3 className="text-base font-bold text-white">
              Playbook d'Intervention Rapide (Étapes Chronologiques)
            </h3>
            <p className="text-xs text-slate-400 font-mono">
              Guide tactique pour l'analyste SOC et l'administrateur réseau
            </p>
          </div>
        </div>

        <div className="space-y-4">
          {analysis.incidentPlaybook.map((step, idx) => (
            <div
              key={idx}
              className="p-4 rounded-xl bg-slate-950/70 border border-slate-800/80 flex items-start gap-4"
            >
              <div className="w-8 h-8 rounded-full bg-emerald-950 text-emerald-400 border border-emerald-800 flex items-center justify-center font-mono font-bold text-sm flex-shrink-0">
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
      <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <ShieldAlert className="w-5 h-5 text-amber-400" />
            <h3 className="text-base font-bold text-white">
              Indicateurs de Compromission Identifiés (IOCs)
            </h3>
          </div>
          <span className="text-xs font-mono text-slate-400">
            {analysis.iocList.length} indicateurs répertoriés
          </span>
        </div>

        <div className="overflow-x-auto rounded-xl border border-slate-800">
          <table className="w-full text-left font-mono text-xs">
            <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
              <tr>
                <th className="p-3">Type</th>
                <th className="p-3">Valeur de l'IOC</th>
                <th className="p-3">Menace & Contexte</th>
                <th className="p-3">Niveau</th>
                <th className="p-3">Action Recommandée</th>
                <th className="p-3 text-right">Copier</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80 bg-slate-900/40">
              {analysis.iocList.map((ioc, idx) => (
                <tr key={idx} className="hover:bg-slate-800/40 transition">
                  <td className="p-3">
                    <span className="px-1.5 py-0.5 rounded bg-slate-800 text-cyan-300 text-[10px] font-bold">
                      {ioc.type}
                    </span>
                  </td>
                  <td className="p-3 font-bold text-white select-all">{ioc.value}</td>
                  <td className="p-3 text-slate-300 font-sans">{ioc.threat}</td>
                  <td className="p-3">
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-red-950 text-red-400 border border-red-800">
                      {ioc.severity}
                    </span>
                  </td>
                  <td className="p-3 text-cyan-400">{ioc.recommendedAction}</td>
                  <td className="p-3 text-right">
                    <button
                      onClick={() => handleCopy(ioc.value)}
                      className="p-1.5 rounded hover:bg-slate-700 text-slate-400 hover:text-white transition"
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
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
