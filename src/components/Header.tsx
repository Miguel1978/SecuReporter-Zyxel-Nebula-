import React, { useState, useRef, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Zap,
  Upload,
  RefreshCw,
  Search,
  ChevronDown,
  Layers,
  Copy,
  Check,
  Radio,
  Flame,
  Sparkles,
  Bell,
  MoreHorizontal,
  Wifi,
  ExternalLink,
  HelpCircle,
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
  onOpenHelpGuide?: () => void;
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
  onOpenHelpGuide,
  isAutoRefreshEnabled,
  onToggleAutoRefresh,
  autoRefreshCountdown = 30,
  isAutoRefreshing = false,
  onManualRefresh,
  lastAutoRefreshTime,
}) => {
  const [isScenarioMenuOpen, setIsScenarioMenuOpen] = useState(false);
  const [isMoreMenuOpen, setIsMoreMenuOpen] = useState(false);
  const [copiedSummary, setCopiedSummary] = useState(false);

  const scenarioRef = useRef<HTMLDivElement>(null);
  const moreRef = useRef<HTMLDivElement>(null);

  // Close menus when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (scenarioRef.current && !scenarioRef.current.contains(event.target as Node)) {
        setIsScenarioMenuOpen(false);
      }
      if (moreRef.current && !moreRef.current.contains(event.target as Node)) {
        setIsMoreMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleCopySocSummary = () => {
    const summary = `[NEBULAGUARD SOC - RAPPORT FLASH]\nScénario: ${currentScenario?.title || 'Non spécifié'}\nPasserelle: ${currentScenario?.device || 'Zyxel ATP700'}\nNiveau de Menace: ${threatLevel}\nContre-mesures actives: ${activeDefensesCount}\nÉvénements analysés: ${currentScenario?.logCount || 0}\nHorodatage: ${new Date().toISOString()}`;
    navigator.clipboard.writeText(summary);
    setCopiedSummary(true);
    setTimeout(() => setCopiedSummary(false), 2000);
  };

  const getThreatStatus = () => {
    switch (threatLevel) {
      case 'CRITICAL':
        return {
          label: 'Alerte Critique',
          dotClass: 'bg-rose-500 animate-pulse',
          badgeClass: 'text-rose-400 bg-rose-950/80 border-rose-800/80',
        };
      case 'HIGH':
        return {
          label: 'Menace Élevée',
          dotClass: 'bg-amber-400',
          badgeClass: 'text-amber-400 bg-amber-950/80 border-amber-800/80',
        };
      case 'MEDIUM':
        return {
          label: 'Risque Modéré',
          dotClass: 'bg-yellow-400',
          badgeClass: 'text-yellow-400 bg-yellow-950/80 border-yellow-800/80',
        };
      default:
        return {
          label: 'Périmètre Sécurisé',
          dotClass: 'bg-emerald-400',
          badgeClass: 'text-emerald-400 bg-emerald-950/80 border-emerald-800/80',
        };
    }
  };

  const threatStatus = getThreatStatus();

  return (
    <header className="bg-slate-900/95 border-b border-slate-800/90 sticky top-0 z-40 backdrop-blur-md shadow-lg shadow-black/20">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-2.5">
        <div className="flex items-center justify-between gap-4">
          
          {/* Left: Brand & Clean Connectivity Info */}
          <div className="flex items-center gap-3 min-w-0 flex-shrink-0">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-600 via-blue-600 to-indigo-600 flex items-center justify-center shadow-md shadow-cyan-500/20 border border-cyan-400/30 flex-shrink-0">
              <ShieldAlert className="w-5 h-5 text-white" />
            </div>
            
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <span className="text-base font-bold tracking-tight text-white">
                  NebulaGuard
                </span>
                <span className="text-xs font-semibold px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800/80 font-mono">
                  SOC
                </span>
              </div>
              
              <div className="flex items-center gap-2 text-[11px] text-slate-400 font-mono">
                <span className="flex items-center gap-1.5 text-emerald-400">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  <span>{currentScenario?.device || 'Passerelle Zyxel ATP'}</span>
                </span>
                <span className="text-slate-600 hidden sm:inline">·</span>
                <span className="text-slate-400 hidden sm:inline">En ligne (14ms)</span>
              </div>
            </div>
          </div>

          {/* Middle: Command Palette Quick Search (Ctrl+K) */}
          {onOpenCommandPalette && (
            <div className="hidden lg:flex flex-1 max-w-md mx-2">
              <button
                type="button"
                onClick={onOpenCommandPalette}
                className="w-full flex items-center justify-between gap-3 px-3.5 py-1.5 rounded-xl bg-slate-950/80 hover:bg-slate-800/90 border border-slate-800 hover:border-cyan-500/50 text-slate-400 hover:text-slate-200 transition text-xs font-mono shadow-inner group"
                title="Ouvrir la palette de commandes globale (Ctrl + K)"
              >
                <div className="flex items-center gap-2 truncate">
                  <Search className="w-3.5 h-3.5 text-slate-500 group-hover:text-cyan-400 transition flex-shrink-0" />
                  <span className="truncate">Rechercher une IP, menace, vue...</span>
                </div>
                <kbd className="px-1.5 py-0.5 rounded bg-slate-800 text-[10px] text-slate-400 border border-slate-700 group-hover:text-cyan-300 flex-shrink-0">
                  Ctrl+K
                </kbd>
              </button>
            </div>
          )}

          {/* Right: Actions, Scenarios & Re-analyze */}
          <div className="flex items-center gap-2 flex-shrink-0">
            
            {/* Threat Status Pill */}
            <div className={`hidden sm:flex items-center gap-2 px-2.5 py-1.5 rounded-xl border text-xs font-mono font-medium ${threatStatus.badgeClass}`}>
              <span className={`w-2 h-2 rounded-full ${threatStatus.dotClass}`} />
              <span>{threatStatus.label}</span>
            </div>

            {/* Active Defenses counter */}
            {activeDefensesCount > 0 && (
              <div
                className="hidden xl:flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl bg-slate-800/80 border border-slate-700 text-xs font-mono text-slate-300"
                title={`${activeDefensesCount} règle(s) de riposte active(s) sur le pare-feu`}
              >
                <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
                <span>{activeDefensesCount} riposte{activeDefensesCount > 1 ? 's' : ''}</span>
              </div>
            )}

            {/* Scenario Selector Dropdown */}
            <div className="relative" ref={scenarioRef}>
              <button
                type="button"
                onClick={() => setIsScenarioMenuOpen(!isScenarioMenuOpen)}
                className="inline-flex items-center gap-2 px-3 py-1.5 rounded-xl bg-slate-800/90 hover:bg-slate-750 text-slate-200 text-xs font-medium border border-slate-700 hover:border-cyan-500/50 transition cursor-pointer max-w-[200px] sm:max-w-[240px] truncate"
                title="Choisir un scénario d'attaque SecuReporter certifié"
              >
                <Layers className="w-3.5 h-3.5 text-cyan-400 flex-shrink-0" />
                <span className="truncate text-left">
                  {currentScenario ? currentScenario.title : 'Scénario...'}
                </span>
                <ChevronDown className={`w-3.5 h-3.5 text-slate-400 transition-transform flex-shrink-0 ${isScenarioMenuOpen ? 'rotate-180' : ''}`} />
              </button>

              {isScenarioMenuOpen && (
                <div className="absolute right-0 mt-2 w-80 sm:w-96 rounded-2xl bg-slate-900 border border-slate-700 shadow-2xl z-50 p-3 space-y-2 animate-in fade-in slide-in-from-top-2">
                  <div className="flex items-center justify-between px-2 pb-2 border-b border-slate-800">
                    <span className="text-xs font-mono font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
                      <Flame className="w-3.5 h-3.5 text-rose-400" />
                      Scénarios SecuReporter Disponibles
                    </span>
                    <span className="text-[10px] font-mono text-slate-500">
                      {SAMPLE_REPORTS.length} scénarios
                    </span>
                  </div>

                  <div className="space-y-1.5 max-h-80 overflow-y-auto pr-1">
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
                              ? 'bg-cyan-950/80 border-cyan-500/70 shadow-sm'
                              : 'bg-slate-800/40 hover:bg-slate-800 border-slate-800 hover:border-slate-700'
                          }`}
                        >
                          <div className="flex items-center justify-between gap-2">
                            <span className="text-xs font-semibold text-white truncate">
                              {sc.title}
                            </span>
                            <span
                              className={`text-[9px] font-mono px-1.5 py-0.2 rounded font-bold uppercase flex-shrink-0 ${
                                sc.severity === 'CRITICAL'
                                  ? 'bg-rose-950 text-rose-300 border border-rose-800'
                                  : 'bg-amber-950 text-amber-300 border border-amber-800'
                              }`}
                            >
                              {sc.severity}
                            </span>
                          </div>
                          <p className="text-[11px] text-slate-400 line-clamp-1 font-sans">
                            {sc.description}
                          </p>
                          <div className="flex items-center justify-between text-[10px] font-mono text-slate-500 pt-1">
                            <span>{sc.device}</span>
                            <span className="text-cyan-400 font-bold">{sc.logCount} événements</span>
                          </div>
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>

            {/* Auto-Refresh Toggle Switch (30s) */}
            {onToggleAutoRefresh && (
              <div className="hidden sm:block">
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
              </div>
            )}

            {/* Quick Interactive Guide Button */}
            {onOpenHelpGuide && (
              <button
                type="button"
                onClick={onOpenHelpGuide}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-cyan-950/70 hover:bg-cyan-900/80 text-cyan-300 text-xs font-semibold border border-cyan-800/80 hover:border-cyan-500/50 transition shadow-sm"
                title="Ouvrir le guide d'utilisation et prise en main rapide"
              >
                <HelpCircle className="w-3.5 h-3.5 text-cyan-400" />
                <span className="hidden sm:inline">Guide</span>
              </button>
            )}

            {/* Import Custom Logs Button */}
            <button
              type="button"
              onClick={onOpenUpload}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition"
              title="Importer des logs personnalisés (CSV, Syslog, JSON)"
            >
              <Upload className="w-3.5 h-3.5 text-cyan-400" />
              <span className="hidden md:inline">Importer</span>
            </button>

            {/* Primary Action: Re-analyze Logs */}
            <button
              type="button"
              onClick={onAnalyze}
              disabled={isAnalyzing}
              className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-semibold shadow-md shadow-cyan-600/20 border border-cyan-400/40 transition disabled:opacity-50"
              title="Relancer l'analyse complète des logs avec l'IA SOC"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isAnalyzing ? 'animate-spin' : ''}`} />
              <span>{isAnalyzing ? 'Analyse...' : 'Analyser'}</span>
            </button>

            {/* More Menu Dropdown (...) */}
            <div className="relative" ref={moreRef}>
              <button
                type="button"
                onClick={() => setIsMoreMenuOpen(!isMoreMenuOpen)}
                className="p-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white border border-slate-700 transition"
                title="Options supplémentaires et utilitaires"
              >
                <MoreHorizontal className="w-4 h-4" />
              </button>

              {isMoreMenuOpen && (
                <div className="absolute right-0 mt-2 w-56 rounded-2xl bg-slate-900 border border-slate-700 shadow-2xl z-50 p-2 space-y-1 animate-in fade-in slide-in-from-top-2 text-xs font-mono">
                  <button
                    type="button"
                    onClick={() => {
                      handleCopySocSummary();
                      setIsMoreMenuOpen(false);
                    }}
                    className="w-full text-left px-3 py-2 rounded-xl hover:bg-slate-800 text-slate-200 hover:text-white transition flex items-center justify-between"
                  >
                    <span className="flex items-center gap-2">
                      <Copy className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Copier Résumé Flash</span>
                    </span>
                    {copiedSummary && <Check className="w-3 h-3 text-emerald-400" />}
                  </button>

                  {onTestNotification && (
                    <button
                      type="button"
                      onClick={() => {
                        onTestNotification();
                        setIsMoreMenuOpen(false);
                      }}
                      className="w-full text-left px-3 py-2 rounded-xl hover:bg-slate-800 text-slate-200 hover:text-white transition flex items-center gap-2"
                    >
                      <Bell className="w-3.5 h-3.5 text-rose-400" />
                      <span>Simuler Alerte Système</span>
                    </button>
                  )}

                  {onOpenNebulaApi && (
                    <button
                      type="button"
                      onClick={() => {
                        onOpenNebulaApi();
                        setIsMoreMenuOpen(false);
                      }}
                      className="w-full text-left px-3 py-2 rounded-xl hover:bg-slate-800 text-slate-200 hover:text-white transition flex items-center gap-2"
                    >
                      <Wifi className="w-3.5 h-3.5 text-emerald-400" />
                      <span>API Nebula Cloud</span>
                    </button>
                  )}

                  {onOpenCommandPalette && (
                    <button
                      type="button"
                      onClick={() => {
                        onOpenCommandPalette();
                        setIsMoreMenuOpen(false);
                      }}
                      className="w-full text-left px-3 py-2 rounded-xl hover:bg-slate-800 text-slate-200 hover:text-white transition flex items-center justify-between"
                    >
                      <span className="flex items-center gap-2">
                        <Search className="w-3.5 h-3.5 text-slate-400" />
                        <span>Palette de commandes</span>
                      </span>
                      <kbd className="text-[10px] text-slate-500">Ctrl+K</kbd>
                    </button>
                  )}
                </div>
              )}
            </div>

          </div>
        </div>
      </div>
    </header>
  );
};
