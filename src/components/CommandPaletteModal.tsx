import React, { useState, useEffect, useMemo, useRef } from 'react';
import {
  Search,
  LayoutDashboard,
  Zap,
  ShieldAlert,
  FileSearch,
  MessageSquare,
  FileCheck,
  Cloud,
  CalendarClock,
  ArrowRight,
  Sparkles,
  RefreshCw,
  Bell,
  Lock,
  Globe,
  Upload,
  X,
  Laptop,
  CheckCircle2,
  Terminal,
  Radio,
} from 'lucide-react';
import { SAMPLE_REPORTS } from '../data/sampleReports';
import { SampleReport, ThreatAnalysisResult, LogEntry, StopAction } from '../types';

interface CommandPaletteModalProps {
  isOpen: boolean;
  onClose: () => void;
  onNavigateTab: (tab: any) => void;
  onSelectScenario: (scenario: SampleReport) => void;
  onAnalyze: () => void;
  onOpenUpload: () => void;
  onTestNotification?: () => void;
  onInspectIp?: (ip: string) => void;
  analysis?: ThreatAnalysisResult | null;
  logs?: LogEntry[];
  activeDefensesCount: number;
  isAutoRefreshEnabled?: boolean;
  onToggleAutoRefresh?: (enabled: boolean) => void;
}

export const CommandPaletteModal: React.FC<CommandPaletteModalProps> = ({
  isOpen,
  onClose,
  onNavigateTab,
  onSelectScenario,
  onAnalyze,
  onOpenUpload,
  onTestNotification,
  onInspectIp,
  analysis,
  logs = [],
  activeDefensesCount,
  isAutoRefreshEnabled,
  onToggleAutoRefresh,
}) => {
  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (isOpen) {
      setQuery('');
      setSelectedIndex(0);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [isOpen]);

  // Extract unique attacker and target IPs from logs and IOCs
  const availableIps = useMemo(() => {
    const set = new Set<string>();
    logs.forEach((l) => {
      if (l.srcIp && l.srcIp !== '0.0.0.0') set.add(l.srcIp);
      if (l.dstIp && l.dstIp !== '0.0.0.0') set.add(l.dstIp);
    });
    analysis?.iocList?.forEach((ioc) => {
      if (ioc.type === 'IP') set.add(ioc.value);
    });
    return Array.from(set).slice(0, 10);
  }, [logs, analysis]);

  // All actionable commands
  const allCommands = useMemo(() => {
    const list: Array<{
      id: string;
      category: 'Navigation SOC' | 'Scénarios d’Attaque' | 'Actions Rapides' | 'Adresses IP & IOCs';
      title: string;
      description: string;
      icon: React.ReactNode;
      action: () => void;
      shortcut?: string;
    }> = [
      // Navigation
      {
        id: 'nav-dashboard',
        category: 'Navigation SOC',
        title: 'Aller au Tableau de Bord SOC',
        description: 'Vue d’ensemble des KPIs, topologie D3, heatmaps géographiques et 7 jours',
        icon: <LayoutDashboard className="w-4 h-4 text-cyan-400" />,
        action: () => {
          onNavigateTab('dashboard');
          onClose();
        },
        shortcut: '1',
      },
      {
        id: 'nav-scheduler',
        category: 'Navigation SOC',
        title: 'Planificateur d’Analyses & Tâches Continues',
        description: 'Programmation récurrente (horaire, quotidienne) et alertes automatiques 24/7',
        icon: <CalendarClock className="w-4 h-4 text-cyan-400" />,
        action: () => {
          onNavigateTab('scheduler');
          onClose();
        },
        shortcut: '2',
      },
      {
        id: 'nav-countermeasures',
        category: 'Navigation SOC',
        title: 'Centre de Riposte & Contre-Mesures',
        description: 'Déploiement des règles de blocage WAN, quarantaine CDR et scripts CLI Zyxel',
        icon: <Zap className="w-4 h-4 text-red-400" />,
        action: () => {
          onNavigateTab('countermeasures');
          onClose();
        },
        shortcut: '3',
      },
      {
        id: 'nav-deep-analysis',
        category: 'Navigation SOC',
        title: 'Analyse Détaillée IA & MITRE ATT&CK',
        description: 'Chaîne de compromission, matrice MITRE, IOCs identifiés et briefing CISO',
        icon: <ShieldAlert className="w-4 h-4 text-cyan-400" />,
        action: () => {
          onNavigateTab('deep-analysis');
          onClose();
        },
        shortcut: '4',
      },
      {
        id: 'nav-logs',
        category: 'Navigation SOC',
        title: 'Explorateur de Logs & Filtres Rapides IP',
        description: 'Investigation granulaire des paquets, filtre par IP source/destination et export',
        icon: <FileSearch className="w-4 h-4 text-cyan-400" />,
        action: () => {
          onNavigateTab('logs');
          onClose();
        },
        shortcut: '5',
      },
      {
        id: 'nav-copilot',
        category: 'Navigation SOC',
        title: 'Copilote IA SOC',
        description: 'Assistant interactif spécialisé dans la cybersécurité Zyxel Nebula et l’investigation',
        icon: <MessageSquare className="w-4 h-4 text-purple-400" />,
        action: () => {
          onNavigateTab('copilot');
          onClose();
        },
        shortcut: '6',
      },
      {
        id: 'nav-report',
        category: 'Navigation SOC',
        title: 'Rapport d’Incident Certifié',
        description: 'Génération du livrable officiel SOC avec export PDF certifié conforme',
        icon: <FileCheck className="w-4 h-4 text-emerald-400" />,
        action: () => {
          onNavigateTab('report');
          onClose();
        },
        shortcut: '7',
      },
      {
        id: 'nav-syslog-server',
        category: 'Navigation SOC',
        title: 'Serveur Récepteur Syslog UDP (Port 514)',
        description: 'Écoute directe des paquets UDP, guide rsyslog.conf, syslog-ng et injection IA',
        icon: <Radio className="w-4 h-4 text-cyan-400" />,
        action: () => {
          onNavigateTab('syslog-server');
          onClose();
        },
        shortcut: '8',
      },
      {
        id: 'nav-nebula-api',
        category: 'Navigation SOC',
        title: 'Connexion API Nebula Zyxel Control Center',
        description: 'Configuration du connecteur API, test de liaison passerelle et synchronisation',
        icon: <Cloud className="w-4 h-4 text-emerald-400" />,
        action: () => {
          onNavigateTab('nebula-api');
          onClose();
        },
        shortcut: '9',
      },

      // Quick Actions
      {
        id: 'action-analyze',
        category: 'Actions Rapides',
        title: 'Relancer l’Analyse IA Complète',
        description: 'Analyser immédiatement le flux de logs actif avec le moteur Gemini',
        icon: <RefreshCw className="w-4 h-4 text-cyan-400" />,
        action: () => {
          onAnalyze();
          onClose();
        },
      },
      {
        id: 'action-upload',
        category: 'Actions Rapides',
        title: 'Importer des Logs Personnalisés (Syslog, CSV, CEF)',
        description: 'Ouvrir le module d’import de fichiers bruts pour analyse immédiate',
        icon: <Upload className="w-4 h-4 text-cyan-400" />,
        action: () => {
          onOpenUpload();
          onClose();
        },
      },
      {
        id: 'action-test-notif',
        category: 'Actions Rapides',
        title: 'Tester la Notification Système (Web Notifications)',
        description: 'Simuler une alerte système critique de niveau 1 sur le poste de l’analyste',
        icon: <Bell className="w-4 h-4 text-red-400" />,
        action: () => {
          onTestNotification?.();
          onClose();
        },
      },
      {
        id: 'action-toggle-autorefresh',
        category: 'Actions Rapides',
        title: isAutoRefreshEnabled
          ? 'Désactiver l’Auto-rafraîchissement des Logs (Nebula)'
          : 'Activer l’Auto-rafraîchissement des Logs (30s via Nebula API)',
        description: isAutoRefreshEnabled
          ? 'Mettre en pause la synchronisation périodique de 30 secondes'
          : 'Mettre à jour et ré-analyser automatiquement les flux de logs toutes les 30 secondes',
        icon: <Cloud className="w-4 h-4 text-emerald-400" />,
        action: () => {
          onToggleAutoRefresh?.(!isAutoRefreshEnabled);
          onClose();
        },
      },

      // Scenarios
      ...SAMPLE_REPORTS.map((sc) => ({
        id: `sc-${sc.id}`,
        category: 'Scénarios d’Attaque' as const,
        title: `Charger : ${sc.title}`,
        description: `${sc.device} • ${sc.primaryThreat} • ${sc.logCount} événements`,
        icon: <ShieldAlert className="w-4 h-4 text-amber-400" />,
        action: () => {
          onSelectScenario(sc);
          onClose();
        },
      })),

      // IPs / IOCs
      ...availableIps.map((ip) => {
        const isPrivate =
          ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.');
        return {
          id: `ip-${ip}`,
          category: 'Adresses IP & IOCs' as const,
          title: `Inspecter l'adresse IP ${ip}`,
          description: isPrivate ? 'Hôte interne LAN compromis / cible' : 'IP externe attaquante WAN (IOC)',
          icon: isPrivate ? (
            <Laptop className="w-4 h-4 text-purple-400" />
          ) : (
            <Globe className="w-4 h-4 text-rose-400" />
          ),
          action: () => {
            onInspectIp?.(ip);
            onNavigateTab('logs');
            onClose();
          },
        };
      }),
    ];

    return list;
  }, [onNavigateTab, onSelectScenario, onAnalyze, onOpenUpload, onTestNotification, onInspectIp, onClose, availableIps]);

  // Filter commands by search query
  const filteredCommands = useMemo(() => {
    if (!query.trim()) return allCommands;
    const q = query.toLowerCase().trim();
    return allCommands.filter(
      (c) =>
        c.title.toLowerCase().includes(q) ||
        c.description.toLowerCase().includes(q) ||
        c.category.toLowerCase().includes(q)
    );
  }, [allCommands, query]);

  // Keyboard navigation within palette
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIndex((prev) => (prev + 1) % Math.max(1, filteredCommands.length));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedIndex((prev) => (prev - 1 + filteredCommands.length) % Math.max(1, filteredCommands.length));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (filteredCommands[selectedIndex]) {
        filteredCommands[selectedIndex].action();
      }
    } else if (e.key === 'Escape') {
      e.preventDefault();
      onClose();
    }
  };

  if (!isOpen) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-16 sm:pt-24 px-4 bg-slate-950/80 backdrop-blur-md"
      onClick={onClose}
    >
      <div
        className="w-full max-w-2xl bg-slate-900 border border-slate-700/80 rounded-2xl shadow-2xl shadow-cyan-950/40 overflow-hidden flex flex-col max-h-[80vh] animate-in fade-in zoom-in-95 duration-150"
        onClick={(e) => e.stopPropagation()}
        onKeyDown={handleKeyDown}
      >
        {/* Search Input Bar */}
        <div className="flex items-center gap-3 px-4 py-3.5 border-b border-slate-800 bg-slate-950/60">
          <Search className="w-5 h-5 text-cyan-400 flex-shrink-0" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setSelectedIndex(0);
            }}
            placeholder="Rechercher une commande, une vue, une adresse IP ou un scénario... (Échap pour fermer)"
            className="flex-1 bg-transparent text-sm text-slate-100 placeholder-slate-500 focus:outline-none font-mono"
          />
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-slate-500 hover:text-slate-300 hover:bg-slate-800 transition"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Command list */}
        <div className="flex-1 overflow-y-auto p-2 space-y-4">
          {filteredCommands.length === 0 ? (
            <div className="py-12 text-center text-slate-500 text-xs font-mono space-y-2">
              <Search className="w-8 h-8 text-slate-600 mx-auto opacity-40" />
              <p>Aucun résultat correspondant à "{query}"</p>
              <p className="text-[11px] text-slate-600">
                Essayez "LockBit", "RCE", "192.168.1.105", "Riposte" ou "Logs"
              </p>
            </div>
          ) : (
            <div className="space-y-1">
              {filteredCommands.map((cmd, idx) => {
                const isSelected = idx === selectedIndex;
                return (
                  <button
                    key={cmd.id}
                    onClick={cmd.action}
                    onMouseEnter={() => setSelectedIndex(idx)}
                    className={`w-full flex items-center justify-between gap-3 p-3 rounded-xl text-left transition font-mono ${
                      isSelected
                        ? 'bg-cyan-950/80 border border-cyan-700/80 shadow-md text-white'
                        : 'hover:bg-slate-800/60 border border-transparent text-slate-300'
                    }`}
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <div
                        className={`p-2 rounded-lg ${
                          isSelected ? 'bg-cyan-900/60 text-cyan-300' : 'bg-slate-800 text-slate-400'
                        }`}
                      >
                        {cmd.icon}
                      </div>
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-bold truncate text-slate-100">
                            {cmd.title}
                          </span>
                          <span className="text-[10px] text-slate-500 px-1.5 py-0.2 rounded bg-slate-800/80">
                            {cmd.category}
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-400 truncate mt-0.5">
                          {cmd.description}
                        </p>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 flex-shrink-0">
                      {cmd.shortcut && (
                        <kbd className="hidden sm:inline-block px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-[10px] text-slate-400">
                          {cmd.shortcut}
                        </kbd>
                      )}
                      <ArrowRight
                        className={`w-4 h-4 transition ${
                          isSelected ? 'text-cyan-400 translate-x-0.5' : 'text-slate-600'
                        }`}
                      />
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </div>

        {/* Footer info bar */}
        <div className="px-4 py-2.5 bg-slate-950/90 border-t border-slate-800/90 flex items-center justify-between text-[11px] font-mono text-slate-500">
          <div className="flex items-center gap-3">
            <span>↑↓ Naviguer</span>
            <span>↵ Exécuter</span>
            <span>Échap Fermer</span>
          </div>
          <span className="text-cyan-400 font-bold">
            NebulaGuard SOC Command Engine
          </span>
        </div>
      </div>
    </div>
  );
};
