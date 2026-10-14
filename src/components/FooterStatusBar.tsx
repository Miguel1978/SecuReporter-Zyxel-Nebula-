import React from 'react';
import {
  Wifi,
  ShieldCheck,
  ShieldAlert,
  Activity,
  Cpu,
  Clock,
  Terminal,
  Layers,
  Sparkles,
  Command,
} from 'lucide-react';
import { SeverityLevel } from '../types';

interface FooterStatusBarProps {
  deviceName?: string;
  logCount: number;
  activeDefensesCount: number;
  threatLevel?: SeverityLevel;
  onOpenCommandPalette: () => void;
  onOpenNebulaApi: () => void;
  isAnalyzing?: boolean;
}

export const FooterStatusBar: React.FC<FooterStatusBarProps> = ({
  deviceName = 'Passerelle Zyxel Nebula ATP',
  logCount,
  activeDefensesCount,
  threatLevel = 'HIGH',
  onOpenCommandPalette,
  onOpenNebulaApi,
  isAnalyzing = false,
}) => {
  return (
    <footer className="fixed bottom-0 left-0 right-0 z-40 bg-slate-950/95 border-t border-slate-800/90 backdrop-blur-md text-[11px] font-mono text-slate-400 select-none">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-2 flex flex-wrap items-center justify-between gap-3">
        {/* Left: Device & Cloud Status */}
        <div className="flex items-center gap-4">
          <button
            onClick={onOpenNebulaApi}
            className="flex items-center gap-2 hover:text-white transition group"
            title="Ouvrir la console Zyxel Nebula API"
          >
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
            <span className="font-bold text-slate-200 group-hover:text-cyan-300">
              {deviceName}
            </span>
            <span className="text-slate-600 hidden sm:inline">•</span>
            <span className="text-emerald-400 hidden sm:inline">Nebula Cloud Online (22ms)</span>
          </button>

          <div className="hidden md:flex items-center gap-2 text-slate-500">
            <span>•</span>
            <span className="text-slate-400">IDP/IPS Signature v3.38</span>
            <span>•</span>
            <span className="text-cyan-400">CDR Armé</span>
          </div>
        </div>

        {/* Center: Live Analysis or Status */}
        <div className="flex items-center gap-3">
          {isAnalyzing ? (
            <div className="flex items-center gap-1.5 text-cyan-400 font-bold animate-pulse">
              <Activity className="w-3.5 h-3.5 animate-spin" />
              <span>Analyse Heuristique & MITRE en cours...</span>
            </div>
          ) : (
            <div className="flex items-center gap-3 text-slate-400">
              <span>
                Logs surveillés : <strong className="text-white">{logCount}</strong>
              </span>
              <span>•</span>
              <span className="flex items-center gap-1">
                <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
                Ripostes actives : <strong className="text-cyan-300">{activeDefensesCount}</strong>
              </span>
            </div>
          )}
        </div>

        {/* Right: Quick Command Palette Trigger */}
        <div className="flex items-center gap-3">
          <button
            onClick={onOpenCommandPalette}
            className="flex items-center gap-1.5 px-2 py-0.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-700/80 transition"
            title="Ouvrir la palette de commandes globale"
          >
            <Command className="w-3 h-3 text-cyan-400" />
            <span className="hidden sm:inline">Palette rapide</span>
            <kbd className="px-1 rounded bg-slate-950 text-[10px] text-slate-400 border border-slate-800">
              Ctrl+K
            </kbd>
          </button>

          <span className="text-slate-600 hidden lg:inline">|</span>
          <span className="text-slate-500 text-[10px] hidden lg:inline">
            NebulaGuard Enterprise SOC v2.6
          </span>
        </div>
      </div>
    </footer>
  );
};
