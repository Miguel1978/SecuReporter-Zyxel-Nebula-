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
  Search,
  Command,
  ChevronDown,
  Activity,
  Layers,
} from 'lucide-react';
import { SAMPLE_REPORTS } from '../data/sampleReports';
import { SampleReport, SeverityLevel } from '../types';
import { AutoRefreshNavbarSwitch } from './AutoRefreshNavbarSwitch';

interface HeaderProps {
  currentScenario: SampleReport | null;
  onSelectScenario: (scenario: SampleReport) => void;
  onOpenUpload: () => void;
  onAnalyze: () => void;
  isAnalyzing: boolean;
  threatLevel?: SeverityLevel;
  activeDefensesCount: number;
  onTestNotification?: () => void;
  onOpenNebulaApi?: () => void;
  onOpenCommandPalette?: () => void;
  isAutoRefreshEnabled?: boolean;
  onToggleAutoRefresh?: (enabled: boolean) => void;
  autoRefreshCountdown?: number;
  isAutoRefreshing?: boolean;
  onManualRefresh?: () => void;
  lastAutoRefreshTime?: Date | null;
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
  onOpenNebulaApi,
  onOpenCommandPalette,
  isAutoRefreshEnabled,
  onToggleAutoRefresh,
  autoRefreshCountdown = 30,
  isAutoRefreshing = false,
  onManualRefresh,
  lastAutoRefreshTime,
}) => {
  const getSeverityBadge = () => {
    switch (threatLevel) {
      case 'CRITICAL':
        return (
          <div className="flex items-center gap-2 px-3 py-1 rounded-xl bg-red-950/80 border border-red-800 text-red-300 font-mono text-xs font-bold animate-pulse shadow-sm shadow-red-950">
            <span className="w-2 h-2 rounded-full bg-red-500 animate-ping" />
            <span>MENACE CRITIQUE DÉTECTÉE</span>
          </div>
        );
      case 'HIGH':
        return (
          <div className="flex items-center gap-2 px-3 py-1 rounded-xl bg-amber-950/80 border border-amber-800 text-amber-300 font-mono text-xs font-bold">
            <span className="w-2 h-2 rounded-full bg-amber-400" />
            <span>MENACE ÉLEVÉE</span>
          </div>
        );
      case 'MEDIUM':
        return (
          <div className="flex items-center gap-2 px-3 py-1 rounded-xl bg-yellow-950/80 border border-yellow-800 text-yellow-300 font-mono text-xs font-bold">
            <span className="w-2 h-2 rounded-full bg-yellow-400" />
            <span>RISQUE MODÉRÉ</span>
          </div>
        );
      default:
        return (
          <div className="flex items-center gap-2 px-3 py-1 rounded-xl bg-emerald-950/80 border border-emerald-800 text-emerald-300 font-mono text-xs font-bold">
            <span className="w-2 h-2 rounded-full bg-emerald-400" />
            <span>PÉRIMÈTRE PROTÉGÉ</span>
          </div>
        );
    }
  };

  return (
    <header className="bg-slate-900/95 border-b border-slate-800 sticky top-0 z-40 backdrop-blur-md shadow-lg shadow-black/20">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-3">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-3">
          {/* Left: Brand Identity & Connectivity */}
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-600 via-blue-600 to-indigo-600 flex items-center justify-center shadow-lg shadow-cyan-500/25 border border-cyan-400/40 flex-shrink-0">
              <ShieldAlert className="w-5 h-5 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-lg font-bold tracking-tight text-white flex items-center gap-2">
                  NebulaGuard{' '}
                  <span className="text-cyan-400 font-mono text-xs px-2 py-0.5 rounded-lg bg-cyan-950 border border-cyan-800 font-bold">
                    AI SOC ENTERPRISE
                  </span>
                </h1>
                <span className="hidden xl:inline-block text-[11px] font-mono text-slate-400 px-2 py-0.5 rounded-lg bg-slate-800/80 border border-slate-700">
                  SecuReporter v2.6
                </span>
              </div>
              <p className="text-xs text-slate-400 flex items-center gap-2 mt-0.5 font-mono">
                <button
                  type="button"
                  onClick={onOpenNebulaApi}
                  className="inline-flex items-center gap-1.5 text-emerald-400 hover:text-emerald-300 underline-offset-2 hover:underline transition"
                  title="Ouvrir le connecteur Zyxel Nebula Control Center API"
                >
                  <Wifi className="w-3 h-3 animate-pulse" />
                  <span>Passerelle Zyxel ATP Connectée</span>
                </button>
                <span className="text-slate-600">•</span>
                <span className="text-slate-400 hidden sm:inline">Détection & Riposte Automatisée</span>
              </p>
            </div>
          </div>

          {/* Middle: Command Palette Search Bar Trigger */}
          {onOpenCommandPalette && (
            <button
              onClick={onOpenCommandPalette}
              className="hidden md:flex items-center gap-3 px-3.5 py-1.5 rounded-xl bg-slate-950/80 hover:bg-slate-800/80 border border-slate-700/80 hover:border-cyan-500/50 text-slate-400 hover:text-slate-200 transition text-xs font-mono shadow-inner group min-w-[260px] max-w-sm justify-between"
              title="Ouvrir la palette de commandes globale (Ctrl + K)"
            >
              <div className="flex items-center gap-2">
                <Search className="w-3.5 h-3.5 text-slate-400 group-hover:text-cyan-400 transition" />
                <span className="truncate">Rechercher IP, scénario, vue...</span>
              </div>
              <kbd className="px-1.5 py-0.5 rounded bg-slate-800 text-[10px] text-slate-400 border border-slate-700 group-hover:text-cyan-300">
                Ctrl+K
              </kbd>
            </button>
          )}

          {/* Right: Quick Actions, Scenarios & Re-analyze */}
          <div className="flex flex-wrap items-center gap-2.5">
            {getSeverityBadge()}

            {/* Defense counter */}
            <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-xl bg-slate-800/80 border border-slate-700 text-xs font-mono text-slate-300">
              <ShieldCheck className="w-4 h-4 text-cyan-400" />
              <span>Défenses :</span>
              <span className="font-bold text-white px-1.5 py-0.2 rounded-md bg-cyan-950 text-cyan-300 border border-cyan-800">
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
                className="bg-slate-800/90 text-slate-200 text-xs rounded-xl px-3 py-2 border border-slate-700 hover:border-slate-600 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-medium cursor-pointer max-w-[210px] sm:max-w-none truncate font-mono"
                title="Charger un jeu d'attaques SecuReporter certifié"
              >
                <option value="" disabled>
                  Charger un scénario d'attaque...
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
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl bg-slate-800/90 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition"
              title="Importer des logs personnalisés (CSV, Syslog, JSON)"
            >
              <Upload className="w-3.5 h-3.5 text-cyan-400" />
              <span className="hidden sm:inline">Importer Logs</span>
            </button>

            {/* Notification Simulation Trigger */}
            {onTestNotification && (
              <button
                onClick={onTestNotification}
                className="inline-flex items-center gap-1.5 px-2.5 py-2 rounded-xl bg-red-950/40 hover:bg-red-900/60 text-red-300 text-xs font-medium border border-red-800/60 hover:border-red-700 transition"
                title="Déclencher la simulation d'alerte système CRITICAL (Web Notifications API)"
              >
                <Bell className="w-3.5 h-3.5 text-red-400 animate-pulse" />
                <span className="hidden md:inline">Alerte</span>
              </button>
            )}

            {/* Auto-Refresh Toggle Switch (Nebula API 30s) */}
            {onToggleAutoRefresh && (
              <AutoRefreshNavbarSwitch
                isEnabled={Boolean(isAutoRefreshEnabled)}
                onToggle={onToggleAutoRefresh}
                secondsRemaining={autoRefreshCountdown}
                isRefreshing={isAutoRefreshing}
                onManualRefresh={onManualRefresh || onAnalyze}
                lastRefreshedAt={lastAutoRefreshTime}
                targetSiteName={currentScenario?.device || 'Passerelle Nebula ATP'}
                compact={true}
              />
            )}

            {/* Re-analyze button */}
            <button
              onClick={onAnalyze}
              disabled={isAnalyzing}
              className="inline-flex items-center gap-2 px-3.5 py-2 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-semibold shadow-md shadow-cyan-600/20 border border-cyan-400/40 transition disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isAnalyzing ? 'animate-spin' : ''}`} />
              <span>{isAnalyzing ? 'Analyse...' : 'Analyser IA'}</span>
            </button>
          </div>
        </div>
      </div>
    </header>
  );
};
