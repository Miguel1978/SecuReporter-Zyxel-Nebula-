import React from 'react';
import {
  X,
  Compass,
  LayoutDashboard,
  MapPin,
  Flame,
  Zap,
  ShieldCheck,
  Search,
  MessageSquare,
  FileCheck,
  Keyboard,
  ArrowRight,
  ShieldAlert,
} from 'lucide-react';

interface HelpGuideModalProps {
  isOpen: boolean;
  onClose: () => void;
  onNavigateToTab: (tab: string) => void;
  onLoadScenario?: (scenarioId?: string) => void;
}

export const HelpGuideModal: React.FC<HelpGuideModalProps> = ({
  isOpen,
  onClose,
  onNavigateToTab,
  onLoadScenario,
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 bg-slate-950/80 backdrop-blur-md animate-in fade-in duration-200">
      <div className="relative w-full max-w-3xl rounded-2xl bg-slate-900 border border-slate-700/80 shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-900/90">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-cyan-950 border border-cyan-700/70 flex items-center justify-center text-cyan-400">
              <Compass className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white tracking-tight flex items-center gap-2">
                Guide d'Utilisation NebulaGuard SOC
                <span className="text-[10px] font-mono font-medium px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                  Prise en main rapide
                </span>
              </h2>
              <p className="text-xs text-slate-400">
                Maîtrisez en 3 étapes les flux d'analyse de menaces et de riposte pare-feu Zyxel Nebula
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
            title="Fermer le guide"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 overflow-y-auto space-y-6 text-slate-200 text-sm">
          {/* 3-Step Core Workflow */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Step 1 */}
            <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 space-y-2.5">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono font-bold text-cyan-400 uppercase tracking-wider">
                  Étape 1
                </span>
                <span className="w-6 h-6 rounded-full bg-cyan-950 text-cyan-300 text-xs font-mono font-bold flex items-center justify-center border border-cyan-800">
                  1
                </span>
              </div>
              <h3 className="font-semibold text-white text-sm">Choisir un Scénario</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Sélectionnez un scénario (Ransomware LockBit, DDoS SYN Flood, Brute Force SSH) dans la barre supérieure ou importez vos propres logs SecuReporter.
              </p>
            </div>

            {/* Step 2 */}
            <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 space-y-2.5">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono font-bold text-cyan-400 uppercase tracking-wider">
                  Étape 2
                </span>
                <span className="w-6 h-6 rounded-full bg-cyan-950 text-cyan-300 text-xs font-mono font-bold flex items-center justify-center border border-cyan-800">
                  2
                </span>
              </div>
              <h3 className="font-semibold text-white text-sm">Analyser la Cartographie</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Visualisez la <strong>Carte Leaflet/D3</strong> pour repérer l'origine des attaquants et la <strong>Heatmap 24h</strong> pour identifier les créneaux horaires critiques.
              </p>
            </div>

            {/* Step 3 */}
            <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 space-y-2.5">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono font-bold text-emerald-400 uppercase tracking-wider">
                  Étape 3
                </span>
                <span className="w-6 h-6 rounded-full bg-emerald-950 text-emerald-300 text-xs font-mono font-bold flex items-center justify-center border border-emerald-800">
                  3
                </span>
              </div>
              <h3 className="font-semibold text-white text-sm">Déployer la Riposte</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Appliquez en 1 clic les règles de blocage pare-feu WAN et d'isolation CDR sur la passerelle Zyxel Nebula pour neutraliser l'attaque.
              </p>
            </div>
          </div>

          {/* Key Views Guide */}
          <div className="space-y-3">
            <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400">
              Vues & Fonctionnalités Clés
            </h4>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
              <button
                type="button"
                onClick={() => {
                  onNavigateToTab('dashboard');
                  onClose();
                }}
                className="p-3 rounded-xl bg-slate-800/50 hover:bg-slate-800 border border-slate-800 hover:border-cyan-500/50 text-left transition flex items-start gap-3 group"
              >
                <div className="p-2 rounded-lg bg-cyan-950 text-cyan-400 border border-cyan-800/80 flex-shrink-0">
                  <LayoutDashboard className="w-4 h-4" />
                </div>
                <div>
                  <div className="font-semibold text-white group-hover:text-cyan-300 transition">
                    Tableau de Bord SOC
                  </div>
                  <div className="text-slate-400 text-[11px] mt-0.5">
                    Vue synthétique avec KPIs, Carte Leaflet, Heatmap 24h et Topologie D3.
                  </div>
                </div>
              </button>

              <button
                type="button"
                onClick={() => {
                  onNavigateToTab('countermeasures');
                  onClose();
                }}
                className="p-3 rounded-xl bg-slate-800/50 hover:bg-slate-800 border border-slate-800 hover:border-red-500/50 text-left transition flex items-start gap-3 group"
              >
                <div className="p-2 rounded-lg bg-red-950 text-red-400 border border-red-800/80 flex-shrink-0">
                  <Zap className="w-4 h-4" />
                </div>
                <div>
                  <div className="font-semibold text-white group-hover:text-red-300 transition">
                    Centre de Riposte
                  </div>
                  <div className="text-slate-400 text-[11px] mt-0.5">
                    Génération et exécution immédiate des règles Zyxel CLI et API Nebula.
                  </div>
                </div>
              </button>

              <button
                type="button"
                onClick={() => {
                  onNavigateToTab('deep-analysis');
                  onClose();
                }}
                className="p-3 rounded-xl bg-slate-800/50 hover:bg-slate-800 border border-slate-800 hover:border-cyan-500/50 text-left transition flex items-start gap-3 group"
              >
                <div className="p-2 rounded-lg bg-purple-950 text-purple-400 border border-purple-800/80 flex-shrink-0">
                  <ShieldAlert className="w-4 h-4" />
                </div>
                <div>
                  <div className="font-semibold text-white group-hover:text-purple-300 transition">
                    Analyse MITRE ATT&CK
                  </div>
                  <div className="text-slate-400 text-[11px] mt-0.5">
                    Décomposition granulaire des tactiques, techniques et indicateurs IOCs.
                  </div>
                </div>
              </button>

              <button
                type="button"
                onClick={() => {
                  onNavigateToTab('copilot');
                  onClose();
                }}
                className="p-3 rounded-xl bg-slate-800/50 hover:bg-slate-800 border border-slate-800 hover:border-cyan-500/50 text-left transition flex items-start gap-3 group"
              >
                <div className="p-2 rounded-lg bg-emerald-950 text-emerald-400 border border-emerald-800/80 flex-shrink-0">
                  <MessageSquare className="w-4 h-4" />
                </div>
                <div>
                  <div className="font-semibold text-white group-hover:text-emerald-300 transition">
                    Copilote IA SOC
                  </div>
                  <div className="text-slate-400 text-[11px] mt-0.5">
                    Posez vos questions d'investigation en langage naturel sur chaque événement.
                  </div>
                </div>
              </button>
            </div>
          </div>

          {/* Keyboard Shortcuts */}
          <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-2">
              <Keyboard className="w-4 h-4 text-cyan-400" />
              <span className="text-xs font-mono font-bold text-slate-300">
                Raccourcis Clavier Rapides :
              </span>
            </div>
            <div className="flex flex-wrap items-center gap-3 text-xs font-mono text-slate-400">
              <span className="flex items-center gap-1.5">
                <kbd className="px-1.5 py-0.5 rounded bg-slate-800 text-cyan-300 border border-slate-700 text-[11px]">
                  Ctrl+K
                </kbd>
                <span>Recherche globale</span>
              </span>
              <span className="flex items-center gap-1.5">
                <kbd className="px-1.5 py-0.5 rounded bg-slate-800 text-cyan-300 border border-slate-700 text-[11px]">
                  1 - 7
                </kbd>
                <span>Changer d'onglet</span>
              </span>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between px-6 py-4 border-t border-slate-800 bg-slate-900/90">
          <span className="text-xs text-slate-500 font-mono">
            NebulaGuard SOC · Surveillance Zyxel ATP / USG FLEX
          </span>
          <button
            type="button"
            onClick={onClose}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-semibold shadow-md transition"
          >
            <span>Commencer l'exploration</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </div>
  );
};
