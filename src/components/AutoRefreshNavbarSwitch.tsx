import React, { useState } from 'react';
import {
  RefreshCw,
  Cloud,
  Wifi,
  Clock,
  Sparkles,
  Zap,
  CheckCircle2,
  ChevronDown,
} from 'lucide-react';

interface AutoRefreshNavbarSwitchProps {
  isEnabled: boolean;
  onToggle: (enabled: boolean) => void;
  secondsRemaining: number;
  isRefreshing: boolean;
  onManualRefresh: () => void;
  lastRefreshedAt?: Date | null;
  targetSiteName?: string;
  compact?: boolean;
}

export const AutoRefreshNavbarSwitch: React.FC<AutoRefreshNavbarSwitchProps> = ({
  isEnabled,
  onToggle,
  secondsRemaining,
  isRefreshing,
  onManualRefresh,
  lastRefreshedAt,
  targetSiteName = 'Passerelle Nebula ATP',
  compact = false,
}) => {
  const [showDetails, setShowDetails] = useState<boolean>(false);

  return (
    <div className="relative inline-flex items-center">
      <div
        className={`inline-flex items-center gap-2 px-2.5 py-1.5 rounded-xl border transition-all duration-300 ${
          isEnabled
            ? 'bg-emerald-950/70 border-emerald-500/60 shadow-sm shadow-emerald-500/20 text-emerald-200'
            : 'bg-slate-900/90 border-slate-700/80 text-slate-400 hover:border-slate-600'
        }`}
      >
        {/* Cloud / Sync Icon */}
        <div className="relative flex items-center justify-center">
          <Cloud
            className={`w-3.5 h-3.5 transition-colors ${
              isEnabled ? 'text-emerald-400' : 'text-slate-500'
            }`}
          />
          {isEnabled && (
            <span className="absolute -top-1 -right-1 flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-400" />
            </span>
          )}
        </div>

        {/* Text Label & Badge */}
        <div className="flex items-center gap-1.5">
          <span className="text-xs font-semibold whitespace-nowrap tracking-tight select-none">
            {compact ? 'Auto-sync' : 'Auto-rafraîchissement'}
          </span>

          {/* 30s Countdown / Status Pill */}
          <span
            className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded-md border flex items-center gap-1 transition-all ${
              isEnabled
                ? 'bg-emerald-900/80 border-emerald-700 text-emerald-300'
                : 'bg-slate-800 border-slate-700 text-slate-400'
            }`}
            title={
              isEnabled
                ? `Prochaine mise à jour automatique via l'API Nebula dans ${secondsRemaining}s`
                : 'Auto-rafraîchissement désactivé (intervalle de 30s via Nebula API)'
            }
          >
            {isRefreshing ? (
              <RefreshCw className="w-2.5 h-2.5 animate-spin text-cyan-300" />
            ) : isEnabled ? (
              <Clock className="w-2.5 h-2.5 text-emerald-400" />
            ) : null}
            <span>{isEnabled ? `${secondsRemaining}s` : '30s'}</span>
          </span>
        </div>

        {/* The Interactive Switch Toggle */}
        <button
          type="button"
          role="switch"
          aria-checked={isEnabled}
          onClick={() => onToggle(!isEnabled)}
          className={`relative inline-flex h-5 w-9 flex-shrink-0 cursor-pointer rounded-full border-2 transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:ring-offset-1 focus:ring-offset-slate-900 ${
            isEnabled
              ? 'bg-emerald-500 border-emerald-400'
              : 'bg-slate-700 border-slate-600'
          }`}
          title={
            isEnabled
              ? "Désactiver l'auto-rafraîchissement des logs toutes les 30s"
              : "Activer la mise à jour automatique des logs toutes les 30 secondes via l'API Nebula"
          }
        >
          <span className="sr-only">Auto-rafraîchissement Nebula API (30s)</span>
          <span
            aria-hidden="true"
            className={`pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow-md ring-0 transition duration-200 ease-in-out ${
              isEnabled ? 'translate-x-4 bg-white' : 'translate-x-0 bg-slate-300'
            }`}
          />
        </button>

        {/* Quick Trigger / Dropdown button */}
        <button
          type="button"
          onClick={() => onManualRefresh()}
          disabled={isRefreshing}
          className={`p-1 rounded-lg transition-colors hover:bg-slate-800 disabled:opacity-50 ${
            isEnabled ? 'text-emerald-300 hover:text-white' : 'text-slate-400 hover:text-slate-200'
          }`}
          title="Forcer la synchronisation immédiate des logs via l'API Nebula"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-cyan-400' : ''}`} />
        </button>

        {/* Details Toggle */}
        <button
          type="button"
          onClick={() => setShowDetails(!showDetails)}
          className="p-0.5 rounded text-slate-500 hover:text-slate-300"
          title="Afficher les détails de la synchronisation Nebula"
        >
          <ChevronDown className={`w-3 h-3 transition-transform ${showDetails ? 'rotate-180' : ''}`} />
        </button>
      </div>

      {/* Floating Info Popover */}
      {showDetails && (
        <div className="absolute right-0 top-full mt-2 z-50 w-72 rounded-2xl bg-slate-900/95 border border-slate-700 p-3.5 shadow-2xl backdrop-blur-xl text-xs font-sans text-slate-300 animate-in fade-in slide-in-from-top-2">
          <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-800">
            <span className="font-semibold text-white flex items-center gap-1.5">
              <Cloud className="w-3.5 h-3.5 text-cyan-400" />
              API Nebula Control Center
            </span>
            <span
              className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold ${
                isEnabled
                  ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                  : 'bg-slate-800 text-slate-400 border border-slate-700'
              }`}
            >
              {isEnabled ? 'ACTIF (30s)' : 'INACTIF'}
            </span>
          </div>

          <div className="space-y-1.5 text-[11px] font-mono">
            <div className="flex items-center justify-between text-slate-400">
              <span>Passerelle cible :</span>
              <span className="text-white font-semibold truncate max-w-[140px]">
                {targetSiteName}
              </span>
            </div>

            <div className="flex items-center justify-between text-slate-400">
              <span>Intervalle :</span>
              <span className="text-cyan-300 font-semibold">Toutes les 30 secondes</span>
            </div>

            <div className="flex items-center justify-between text-slate-400">
              <span>Prochain tick :</span>
              <span className="text-emerald-400 font-bold">
                {isEnabled ? `${secondsRemaining} seconde(s)` : 'En pause'}
              </span>
            </div>

            {lastRefreshedAt && (
              <div className="flex items-center justify-between text-slate-400">
                <span>Dernière synchro :</span>
                <span className="text-slate-300">
                  {lastRefreshedAt.toLocaleTimeString('fr-FR', {
                    hour: '2-digit',
                    minute: '2-digit',
                    second: '2-digit',
                  })}
                </span>
              </div>
            )}
          </div>

          <div className="mt-3 pt-2 border-t border-slate-800/80 flex items-center justify-between gap-2">
            <button
              type="button"
              onClick={() => {
                onToggle(!isEnabled);
              }}
              className={`w-full py-1.5 px-2.5 rounded-xl text-center text-xs font-semibold transition ${
                isEnabled
                  ? 'bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700'
                  : 'bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white shadow-md shadow-emerald-950 border border-emerald-400/30'
              }`}
            >
              {isEnabled ? 'Désactiver le rafraîchissement' : 'Activer (30s)'}
            </button>

            <button
              type="button"
              onClick={() => {
                onManualRefresh();
                setShowDetails(false);
              }}
              disabled={isRefreshing}
              className="py-1.5 px-2.5 rounded-xl bg-cyan-950 hover:bg-cyan-900 border border-cyan-800 text-cyan-200 text-xs font-semibold whitespace-nowrap transition disabled:opacity-50"
            >
              {isRefreshing ? 'Actualisation...' : 'Actualiser'}
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
