import React, { useState } from 'react';
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
  Copy,
  Check,
  Radio,
  SlidersHorizontal,
  Flame,
  Sparkles,
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
  onOpenKnownAttacks?: () => void;
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
  onOpenKnownAttacks,
  onOpenCommandPalette,
  isAutoRefreshEnabled,
  onToggleAutoRefresh,
  autoRefreshCountdown = 30,
  isAutoRefreshing = false,
  onManualRefresh,
  lastAutoRefreshTime,
}) => {
  const [isScenarioMenuOpen, setIsScenarioMenuOpen] = useState(false);
  const [copiedSummary, setCopiedSummary] = useState(false);

  const handleCopySocSummary = () => {
    const summary = `[NEBULAGUARD AI SOC - RAPPORT FLASH]\nScénario: ${currentScenario?.title || 'Non spécifié'}\nPasserelle: ${currentScenario?.device || 'Zyxel ATP700'}\nNiveau de Menace: ${threatLevel}\nContre-mesures actives: ${activeDefensesCount}\nÉvénements analysés: ${currentScenario?.logCount || 0}\nHorodatage: ${new Date().toISOString()}`;
    navigator.clipboard.writeText(summary);
    setCopiedSummary(true);
    setTimeout(() => setCopiedSummary(false), 2000);
  };

  const getSeverityBadge = () => {
    switch (threatLevel) {
      case 'CRITICAL':
        return (
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-rose-950/90 border border-rose-500/70 text-rose-300 font-mono text-xs font-bold animate-pulse shadow-md shadow-rose-950/60">
            <span className="w-2 h-2 rounded-full bg-rose-500 animate-ping" />
            <span>MENACE CRITIQUE</span>
          </div>
        );
      case 'HIGH':
        return (
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-amber-950/80 border border-amber-600/60 text-amber-300 font-mono text-xs font-bold shadow-md shadow-amber-950/40">
            <span className="w-2 h-2 rounded-full bg-amber-400" />
            <span>MENACE ÉLEVÉE</span>
          </div>
        );
      case 'MEDIUM':
        return (
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-yellow-950/80 border border-yellow-700/60 text-yellow-300 font-mono text-xs font-bold">
            <span className="w-2 h-2 rounded-full bg-yellow-400" />
            <span>RISQUE MODÉRÉ</span>
          </div>
        );
      default:
        return (
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-emerald-950/80 border border-emerald-600/60 text-emerald-300 font-mono text-xs font-bold shadow-md shadow-emerald-950/30">
            <span className="w-2 h-2 rounded-full bg-emerald-400" />
            <span>PÉRIMÈTRE PROTÉGÉ</span>
          </div>
        );
    }
  };

  return (
    <header className="bg-slate-900/95 border-b border-slate-800/90 sticky top-0 z-40 backdrop-blur-md shadow-lg shadow-black/20">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-2.5">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-3">
          {/* Left: Brand Identity & Connectivity */}
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-600 via-blue-600 to-indigo-600 flex items-center justify-center shadow-lg shadow-cyan-500/25 border border-cyan-400/40 flex-shrink-0">
              <ShieldAlert className="w-5 h-5 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <h1 className="text-lg font-bold tracking-tight text-white flex items-center gap-2">
                  NebulaGuard{' '}
                  <span className="text-cyan-400 font-mono text-xs px-2 py-0.5 rounded-lg bg-cyan-950/90 border border-cyan-800 font-bold">
                    AI SOC ENTERPRISE
                  </span>
                </h1>
                <span className="hidden xl:inline-block text-[11px] font-mono text-slate-400 px-2 py-0.5 rounded-lg bg-slate-800/80 border border-slate-700">
                  SecuReporter v2.6
                </span>
                <span className="hidden sm:inline-flex items-center gap-1.5 text-[10px] font-mono text-emerald-400 bg-emerald-950/50 border border-emerald-800/70 px-2 py-0.5 rounded-lg">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  <span>14ms • En ligne</span>
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
          <div className="flex flex-wrap items-center gap-2">
            {getSeverityBadge()}

            {/* Defense counter */}
            <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-xl bg-slate-800/80 border border-slate-700 text-xs font-mono text-slate-300">
              <ShieldCheck className="w-4 h-4 text-cyan-400" />
              <span>Défenses :</span>
              <span className="font-bold text-white px-1.5 py-0.2 rounded-md bg-cyan-950 text-cyan-300 border border-cyan-800">
                {activeDefensesCount}
              </span>
            </div>

            {/* Scenario Selector with Popover / Modal option */}
            <div className="relative">
              <button
                type="button"
                onClick={() => setIsScenarioMenuOpen(!isScenarioMenuOpen)}
                className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl bg-slate-800/90 hover:bg-slate-750 text-slate-200 text-xs font-mono border border-slate-700 hover:border-cyan-500/50 transition cursor-pointer max-w-[220px] truncate"
                title="Choisir un scénario d'attaque certifié SecuReporter"
              >
                <Layers className="w-3.5 h-3.5 text-cyan-400 flex-shrink-0" />
                <span className="truncate">{currentScenario ? currentScenario.title.slice(0, 22) + '...' : 'Scénario...'}</span>
                <ChevronDown className={`w-3.5 h-3.5 text-slate-400 transition-transform ${isScenarioMenuOpen ? 'rotate-180' : ''}`} />
              </button>

              {isScenarioMenuOpen && (
                <>
                  <div
                    className="fixed inset-0 z-40"
                    onClick={() => setIsScenarioMenuOpen(false)}
                  />
                  <div className="absolute right-0 mt-2 w-80 sm:w-96 rounded-2xl bg-slate-900 border border-slate-700 shadow-2xl z-50 p-3 space-y-2 animate-in fade-in slide-in-from-top-2">
                    <div className="flex items-center justify-between px-2 pb-2 border-b border-slate-800">
                      <span className="text-xs font-mono font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
                        <Flame className="w-3.5 h-3.5 text-rose-400" />
                        Scénarios d'Attaque SecuReporter
                      </span>
                      <span className="text-[10px] font-mono text-slate-400">
                        {SAMPLE_REPORTS.length} scénarios
                      </span>
                    </div>

                    <div className="space-y-1.5 max-h-80 overflow-y-auto">
                      {SAMPLE_REPORTS.map((sc) => {
                        const isCurrent = currentScenario?.id === sc.id;
                        return (
                          <button
                            key={sc.id}
                            type="button"
                            onClick={() => {
                              onSelectScenario(sc);
                              setIsScenarioMenuOpen(false);
                            }}
                            className={`w-full text-left p-2.5 rounded-xl border transition flex flex-col gap-1 ${
                              isCurrent
                                ? 'bg-cyan-950/80 border-cyan-600/70 shadow-sm shadow-cyan-950'
                                : 'bg-slate-800/40 hover:bg-slate-800 border-slate-800 hover:border-slate-700'
                            }`}
                          >
                            <div className="flex items-center justify-between gap-2">
                              <span className="text-xs font-semibold text-white truncate">
                                {sc.title}
                              </span>
                              <span
                                className={`text-[10px] font-mono px-1.5 py-0.5 rounded font-bold uppercase flex-shrink-0 ${
                                  sc.severity === 'CRITICAL'
                                    ? 'bg-rose-950 text-rose-300 border border-rose-800'
                                    : 'bg-amber-950 text-amber-300 border border-amber-800'
                                }`}
                              >
                                {sc.severity}
                              </span>
                            </div>
                            <p className="text-[11px] text-slate-400 line-clamp-1">
                              {sc.description}
                            </p>
                            <div className="flex items-center justify-between text-[10px] font-mono text-slate-500 pt-1">
                              <span>{sc.device}</span>
                              <span className="text-cyan-400 font-bold">{sc.logCount} logs</span>
                            </div>
                          </button>
                        );
                      })}
                    </div>
                  </div>
                </>
              )}
            </div>

            {/* Known Attacks AI Repository Button */}
            {onOpenKnownAttacks && (
              <button
                onClick={onOpenKnownAttacks}
                className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl bg-gradient-to-r from-cyan-950/90 to-indigo-950/90 hover:from-cyan-900 hover:to-indigo-900 text-cyan-300 text-xs font-mono font-bold border border-cyan-700/80 hover:border-cyan-500 shadow-sm transition"
                title="Consulter et mettre à jour le référentiel des attaques avec l'IA (Raccourci: 0)"
              >
                <Sparkles className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
                <span className="hidden sm:inline">Attaques IA</span>
              </button>
            )}

            {/* Copy SOC Summary Button */}
            <button
              onClick={handleCopySocSummary}
              className="inline-flex items-center gap-1.5 px-2.5 py-2 rounded-xl bg-slate-800/90 hover:bg-slate-750 text-slate-300 text-xs font-mono border border-slate-700 transition"
              title="Copier le résumé Flash du SOC pour documentation ou SIEM"
            >
              {copiedSummary ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                  <span className="hidden md:inline text-emerald-400 font-bold">Copié</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5 text-slate-400" />
                  <span className="hidden md:inline">Résumé</span>
                </>
              )}
            </button>

            {/* Upload Button */}
            <button
              onClick={onOpenUpload}
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl bg-slate-800/90 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition"
              title="Importer des logs personnalisés (CSV, Syslog, JSON)"
            >
              <Upload className="w-3.5 h-3.5 text-cyan-400" />
              <span className="hidden sm:inline">Importer</span>
            </button>

            {/* Notification Simulation Trigger */}
            {onTestNotification && (
              <button
                onClick={onTestNotification}
                className="inline-flex items-center gap-1.5 px-2.5 py-2 rounded-xl bg-red-950/40 hover:bg-red-900/60 text-red-300 text-xs font-medium border border-red-800/60 hover:border-red-700 transition"
                title="Déclencher la simulation d'alerte système CRITICAL (Web Notifications API)"
              >
                <Bell className="w-3.5 h-3.5 text-red-400 animate-pulse" />
                <span className="hidden lg:inline">Alerte</span>
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
