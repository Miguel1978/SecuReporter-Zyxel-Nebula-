import React from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Zap,
  Upload,
  RefreshCw,
  FolderOpen,
  Wifi,
  ExternalLink,
  Bell,
} from 'lucide-react';
import { SAMPLE_REPORTS } from '../data/sampleReports';
import { SampleReport, SeverityLevel } from '../types';

interface HeaderProps {
  currentScenario: SampleReport | null;
  onSelectScenario: (scenario: SampleReport) => void;
  onOpenUpload: () => void;
  onAnalyze: () => void;
  isAnalyzing: boolean;
  threatLevel?: SeverityLevel;
  activeDefensesCount: number;
  onTestNotification?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  currentScenario,
  onSelectScenario,
  onOpenUpload,
  onAnalyze,
  isAnalyzing,
  threatLevel = 'HIGH',
  activeDefensesCount,
  onTestNotification,
}) => {
  const getSeverityBadge = () => {
    switch (threatLevel) {
      case 'CRITICAL':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-red-950/80 text-red-400 border border-red-800 animate-pulse">
            <span className="w-2 h-2 rounded-full bg-red-500"></span>
            MENACE CRITIQUE DÉTECTÉE
          </span>
        );
      case 'HIGH':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-amber-950/80 text-amber-400 border border-amber-800">
            <span className="w-2 h-2 rounded-full bg-amber-500"></span>
            MENACE ÉLEVÉE
          </span>
        );
      case 'MEDIUM':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-yellow-950/80 text-yellow-400 border border-yellow-800">
            <span className="w-2 h-2 rounded-full bg-yellow-500"></span>
            RISQUE MODÉRÉ
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-950/80 text-emerald-400 border border-emerald-800">
            <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
            PÉRIMÈTRE PROTÉGÉ
          </span>
        );
    }
  };

  return (
    <header className="bg-slate-900/90 border-b border-slate-800 sticky top-0 z-40 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-3.5">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          {/* Logo & Brand */}
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-600 via-blue-600 to-indigo-600 flex items-center justify-center shadow-lg shadow-cyan-500/20 border border-cyan-400/30">
              <ShieldAlert className="w-6 h-6 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
                  NebulaGuard <span className="text-cyan-400 font-mono text-sm px-1.5 py-0.5 rounded bg-cyan-950 border border-cyan-800">AI SOC</span>
                </h1>
                <span className="hidden sm:inline-block text-xs font-mono text-slate-400 px-2 py-0.5 rounded bg-slate-800 border border-slate-700">
                  v2.6 Secure Reporter
                </span>
              </div>
              <p className="text-xs text-slate-400 flex items-center gap-2 mt-0.5">
                <span className="inline-flex items-center gap-1 text-emerald-400 font-mono">
                  <Wifi className="w-3 h-3 animate-pulse" /> Nebula Cloud Gateway Synced
                </span>
                <span className="text-slate-600">•</span>
                <span>Analyseur d'attaques & Riposte automatisée</span>
              </p>
            </div>
          </div>

          {/* Quick Actions & Scenario Loader */}
          <div className="flex flex-wrap items-center gap-2.5">
            {getSeverityBadge()}

            {/* Defense counter */}
            <div className="hidden sm:flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800/80 border border-slate-700 text-xs font-mono text-slate-300">
              <ShieldCheck className="w-4 h-4 text-cyan-400" />
              <span>Défenses Actives :</span>
              <span className="font-bold text-white px-1.5 py-0.2 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                {activeDefensesCount}
              </span>
            </div>

            {/* Scenario dropdown selector */}
            <div className="relative">
              <select
                value={currentScenario?.id || ''}
                onChange={(e) => {
                  const found = SAMPLE_REPORTS.find((s) => s.id === e.target.value);
                  if (found) onSelectScenario(found);
                }}
                className="bg-slate-800 text-slate-200 text-xs rounded-lg px-3 py-2 border border-slate-700 hover:border-slate-600 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-medium cursor-pointer max-w-[200px] sm:max-w-none truncate"
              >
                <option value="" disabled>
                  Charger un rapport Nebula...
                </option>
                {SAMPLE_REPORTS.map((sc) => (
                  <option key={sc.id} value={sc.id}>
                    [{sc.severity}] {sc.title}
                  </option>
                ))}
              </select>
            </div>

            {/* Upload Button */}
            <button
              onClick={onOpenUpload}
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition"
              title="Importer des logs personnalisés (CSV, Syslog, JSON)"
            >
              <Upload className="w-3.5 h-3.5 text-cyan-400" />
              <span>Importer Logs</span>
            </button>

            {/* Notification Simulation Trigger */}
            {onTestNotification && (
              <button
                onClick={onTestNotification}
                className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-red-950/40 hover:bg-red-900/60 text-red-300 text-xs font-medium border border-red-800/60 hover:border-red-700 transition"
                title="Déclencher la simulation d'alerte système CRITICAL (Web Notifications API)"
              >
                <Bell className="w-3.5 h-3.5 text-red-400 animate-pulse" />
                <span className="hidden sm:inline">Alerte Système</span>
              </button>
            )}

            {/* Re-analyze button */}
            <button
              onClick={onAnalyze}
              disabled={isAnalyzing}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-semibold shadow-md shadow-cyan-600/20 border border-cyan-400/40 transition disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isAnalyzing ? 'animate-spin' : ''}`} />
              <span>{isAnalyzing ? 'Analyse IA...' : 'Analyser avec IA'}</span>
            </button>
          </div>
        </div>
      </div>
    </header>
  );
};
