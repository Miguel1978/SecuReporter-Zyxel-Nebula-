import React, { useMemo, useState, useEffect } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  Activity,
  Globe,
  Lock,
  ArrowRight,
  Zap,
  Target,
  Laptop,
  CheckCircle,
  PieChart as PieChartIcon,
  TrendingUp,
  Clock,
  History,
  RotateCcw,
  Trash2,
  Archive,
  ChevronDown,
  ChevronUp,
  GitCompare,
  LayoutGrid,
  GripVertical,
  Eye,
  EyeOff,
  ArrowUp,
  ArrowDown,
  Maximize2,
  Minimize2,
  SlidersHorizontal,
  Sparkles,
  Calendar,
  Volume2,
  Building2,
  BarChart3,
  CalendarClock,
  Network,
  Radio,
  RefreshCw,
  Flame,
} from 'lucide-react';
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Legend,
} from 'recharts';
import { ThreatScoreGauge } from './ThreatScoreGauge';
import { LogEntry, StopAction, ThreatAnalysisResult, ActiveDefense, AnalysisHistoryItem } from '../types';
import { ReportComparisonSection } from './ReportComparisonSection';
import { ThreatAudioBriefing } from './ThreatAudioBriefing';
import { PredictiveAttackVectors } from './PredictiveAttackVectors';
import { IncidentCalendarView } from './IncidentCalendarView';
import { MultiOrgSiteManager } from './MultiOrgSiteManager';
import { RiskScore7DaysChart } from './RiskScore7DaysChart';
import { ScheduledAnalysisManager } from './ScheduledAnalysisManager';
import { ThreatTopologyD3Graph } from './ThreatTopologyD3Graph';
import { AttackHeatmapVisualizer } from './AttackHeatmapVisualizer';
import { AttackVolume7DaysTrendChart } from './AttackVolume7DaysTrendChart';
import { GeographicalAttackHeatmap } from './GeographicalAttackHeatmap';
import { NebulaLiveStreamConsole } from './NebulaLiveStreamConsole';
import { SecurityAlertsHourlyChart } from './SecurityAlertsHourlyChart';
import { RiskScore24HoursAreaChart } from './RiskScore24HoursAreaChart';
import { HourlyAttackHeatmap } from './HourlyAttackHeatmap';

interface DashboardViewProps {
  analysis: ThreatAnalysisResult;
  logs: LogEntry[];
  activeDefenses: ActiveDefense[];
  onNavigateToCountermeasures: () => void;
  onEnforceDefense: (action: StopAction) => Promise<void>;
  onInspectLog: (log: LogEntry) => void;
  historyList?: AnalysisHistoryItem[];
  onRestoreAnalysis?: (item: AnalysisHistoryItem) => void;
  onDeleteHistoryItem?: (id: string) => void;
  onClearHistory?: () => void;
  deviceName?: string;
  onSelectSiteLogs?: (rawLogs: string, siteLabel: string) => void;
  onAppendLiveLog?: (rawLine: string) => void;
  onNavigateToTab?: (tab: any) => void;
}

export type DashboardWidgetId =
  | 'kpi_score_metrics'
  | 'risk_score_24hours'
  | 'hourly_attacks_heatmap'
  | 'nebula_live_stream'
  | 'threat_topology_d3'
  | 'geographical_attack_heatmap'
  | 'attack_sources_heatmap'
  | 'attack_volume_7days_trend'
  | 'risk_score_7days'
  | 'scheduled_log_analysis'
  | 'multi_org_sites'
  | 'countermeasures_banner'
  | 'attack_timeline'
  | 'threat_distribution'
  | 'mitre_attack_vectors'
  | 'malicious_ips_hosts'
  | 'predictive_vectors'
  | 'incident_calendar'
  | 'audio_briefing'
  | 'analysis_history';

export type WidgetColSpan = 12 | 8 | 6 | 4;

export interface DashboardWidgetConfig {
  id: DashboardWidgetId;
  title: string;
  description: string;
  category: 'Posture & KPIs' | 'Opérations Live' | 'Analytique & Graphiques' | 'Threat Intel & IA';
  visible: boolean;
  collapsed: boolean;
  colSpan: WidgetColSpan;
}

const WIDGET_STORAGE_KEY = 'zyxel_soc_dashboard_widgets_v12_pro';

const DEFAULT_WIDGETS: DashboardWidgetConfig[] = [
  {
    id: 'kpi_score_metrics',
    title: 'Score de Menace & Indicateurs Clés (KPIs)',
    description: 'Jauge de risque global et compteurs d’attaques critiques, IPs malveillantes, hôtes LAN et ripostes',
    category: 'Posture & KPIs',
    visible: true,
    collapsed: false,
    colSpan: 12,
  },
  {
    id: 'geographical_attack_heatmap',
    title: 'Carte Thermique Géographique des Cyberattaques (Leaflet & D3)',
    description: 'Cartographie mondiale interactive Leaflet avec tuiles sombres, projection D3 et origine géographique WAN des attaquants',
    category: 'Analytique & Graphiques',
    visible: true,
    collapsed: false,
    colSpan: 12,
  },
  {
    id: 'hourly_attacks_heatmap',
    title: 'Heatmap des Attaques par Heure (Créneaux Horaires Critiques 24h)',
    description: 'Visualisation thermique interactive montrant la fréquence et la criticité des attaques par heure de la journée (00h-23h)',
    category: 'Analytique & Graphiques',
    visible: true,
    collapsed: false,
    colSpan: 12,
  },
  {
    id: 'countermeasures_banner',
    title: 'Alerte Contre-Mesures & Riposte Rapide Pare-Feu',
    description: 'Bannière d’accès rapide au déploiement des règles de filtrage WAN et quarantaine CDR Zyxel',
    category: 'Opérations Live',
    visible: true,
    collapsed: false,
    colSpan: 12,
  },
  {
    id: 'threat_topology_d3',
    title: 'Topologie Interactive des Menaces (D3.js)',
    description: 'Graphe interactif D3.js des flux d’attaques entre IPs externes malveillantes, passerelle Zyxel et cibles LAN',
    category: 'Analytique & Graphiques',
    visible: true,
    collapsed: false,
    colSpan: 6,
  },
  {
    id: 'threat_distribution',
    title: 'Répartition des Types de Menaces',
    description: 'Distribution par vecteur (Malwares, Brute Force, DDoS, C2/Botnet, Exploits, Phishing)',
    category: 'Analytique & Graphiques',
    visible: true,
    collapsed: false,
    colSpan: 6,
  },
  {
    id: 'malicious_ips_hosts',
    title: 'Top IPs Malveillantes (IOCs) & Riposte 1-Clic',
    description: 'Liste des adresses IP hostiles avec blocage en 1 clic et état des machines internes compromises',
    category: 'Opérations Live',
    visible: true,
    collapsed: false,
    colSpan: 6,
  },
  {
    id: 'risk_score_24hours',
    title: 'Évolution du Score de Risque sur 24 Heures (Recharts)',
    description: 'Graphique en aires Recharts mesurant l’évolution horaire du score de risque brut vs score résiduel post-riposte Nebula',
    category: 'Analytique & Graphiques',
    visible: true,
    collapsed: false,
    colSpan: 6,
  },
  {
    id: 'mitre_attack_vectors',
    title: 'Vecteurs MITRE ATT&CK & Modules Nebula',
    description: 'Cartographie détaillée des tactiques d’attaque identifiées et volume par module de sécurité',
    category: 'Threat Intel & IA',
    visible: false,
    collapsed: false,
    colSpan: 8,
  },
  {
    id: 'predictive_vectors',
    title: 'Prédiction IA des Vecteurs d’Attaques Probables',
    description: 'Anticipe les prochaines étapes d’intrusion selon la chaîne de compromission observée',
    category: 'Threat Intel & IA',
    visible: false,
    collapsed: false,
    colSpan: 12,
  },
  {
    id: 'attack_volume_7days_trend',
    title: 'Tendances de Volume d’Attaques sur 7 Jours (Recharts)',
    description: 'Graphique linéaire Recharts mesurant l’évolution du volume d’attaques sur 7 jours et prévoyant les vagues',
    category: 'Analytique & Graphiques',
    visible: false,
    collapsed: false,
    colSpan: 12,
  },
  {
    id: 'risk_score_7days',
    title: 'Évolution du Score de Risque (7 Derniers Jours)',
    description: 'Courbe Recharts comparative du score de risque brut vs score résiduel post-riposte sur 7 jours glissants',
    category: 'Analytique & Graphiques',
    visible: false,
    collapsed: false,
    colSpan: 12,
  },
  {
    id: 'incident_calendar',
    title: 'Calendrier des Incidents & Tendances',
    description: 'Vue mensuelle et hebdomadaire de l’intensité des incidents de sécurité',
    category: 'Analytique & Graphiques',
    visible: false,
    collapsed: false,
    colSpan: 12,
  },
  {
    id: 'attack_sources_heatmap',
    title: 'Heatmap des Sources d’Attaque (Recharts)',
    description: 'Matrice thermique Recharts visualisant la densité des attaques par heure et par localisation',
    category: 'Analytique & Graphiques',
    visible: false,
    collapsed: false,
    colSpan: 12,
  },
  {
    id: 'attack_timeline',
    title: 'Volume des Alertes de Sécurité par Heure',
    description: 'Graphique temporel Recharts agrégeant les alertes par créneau horaire avec détection des pics',
    category: 'Analytique & Graphiques',
    visible: false,
    collapsed: false,
    colSpan: 12,
  },
  {
    id: 'nebula_live_stream',
    title: 'Flux de Logs en Direct (Zyxel Nebula Stream)',
    description: 'Flux streaming continu de paquets SecuReporter OpenAPI et inspection en temps réel',
    category: 'Opérations Live',
    visible: false,
    collapsed: false,
    colSpan: 12,
  },
  {
    id: 'multi_org_sites',
    title: 'Organisations & Sites Nebula NCC',
    description: 'Variables d’environnement API, gestion multi-organisations/sites et flux live',
    category: 'Opérations Live',
    visible: false,
    collapsed: false,
    colSpan: 12,
  },
  {
    id: 'scheduled_log_analysis',
    title: 'Planificateur d’Analyses Automatiques (24/7)',
    description: 'Programmation d’analyses régulières (horaire, quotidien, 15 min)',
    category: 'Opérations Live',
    visible: false,
    collapsed: false,
    colSpan: 12,
  },
  {
    id: 'audio_briefing',
    title: 'Briefing Audio Vocal SOC (TTS)',
    description: 'Synthèse vocale de la posture de sécurité pour les analystes SOC',
    category: 'Posture & KPIs',
    visible: false,
    collapsed: false,
    colSpan: 12,
  },
  {
    id: 'analysis_history',
    title: 'Historique des Analyses Récentes',
    description: 'Sauvegarde persistante et rechargement des 10 derniers rapports de sécurité',
    category: 'Posture & KPIs',
    visible: false,
    collapsed: false,
    colSpan: 12,
  },
];

const THREAT_COLORS: Record<string, string> = {
  'Malwares & Ransomware': '#ef4444',
  'Brute Force & Auth': '#f97316',
  'DDoS & Floods': '#eab308',
  'C2 & Botnets': '#a855f7',
  'Exploits Web & RCE': '#06b6d4',
  'Phishing & DNS Tunneling': '#10b981',
  'Autres Menaces': '#64748b',
};

const classifyThreat = (log: LogEntry): string => {
  const text = `${log.threatName} ${log.category} ${log.raw}`.toLowerCase();
  if (
    text.includes('brute') ||
    text.includes('password') ||
    text.includes('auth') ||
    text.includes('login') ||
    text.includes('credential') ||
    text.includes('psk') ||
    text.includes('dictionary')
  ) {
    return 'Brute Force & Auth';
  }
  if (
    text.includes('syn_flood') ||
    text.includes('flood') ||
    text.includes('ddos') ||
    text.includes('port_scan') ||
    text.includes('anomaly') ||
    text.includes('dos') ||
    text.includes('packets_sec')
  ) {
    return 'DDoS & Floods';
  }
  if (
    text.includes('malware') ||
    text.includes('ransomware') ||
    text.includes('lockbit') ||
    text.includes('trojan') ||
    text.includes('virus') ||
    text.includes('stealer') ||
    text.includes('mimikatz')
  ) {
    return 'Malwares & Ransomware';
  }
  if (
    text.includes('c2') ||
    text.includes('botnet') ||
    text.includes('beacon') ||
    text.includes('cobalt') ||
    text.includes('tor_exit') ||
    text.includes('mirai')
  ) {
    return 'C2 & Botnets';
  }
  if (
    text.includes('log4j') ||
    text.includes('rce') ||
    text.includes('cve') ||
    text.includes('shell') ||
    text.includes('traversal') ||
    text.includes('idp') ||
    text.includes('exploit') ||
    text.includes('psexec')
  ) {
    return 'Exploits Web & RCE';
  }
  if (
    text.includes('phishing') ||
    text.includes('domain') ||
    text.includes('dns') ||
    text.includes('content_filter')
  ) {
    return 'Phishing & DNS Tunneling';
  }
  return 'Autres Menaces';
};

const CustomTooltip = ({ active, payload }: any) => {
  if (active && payload && payload.length) {
    const data = payload[0].payload;
    return (
      <div className="bg-slate-900 border border-slate-700 rounded-xl p-3 shadow-2xl backdrop-blur-md text-xs font-mono">
        <div className="flex items-center gap-2 mb-1">
          <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: data.color }} />
          <span className="font-bold text-white">{data.name}</span>
        </div>
        <div className="text-slate-300">
          Occurrences : <strong className="text-cyan-400">{data.value}</strong> alertes
        </div>
        <div className="text-slate-400 text-[11px]">
          Part du total : <strong className="text-white">{data.percentage}%</strong>
        </div>
      </div>
    );
  }
  return null;
};

const CustomLineTooltip = ({ active, payload, label }: any) => {
  if (active && payload && payload.length) {
    return (
      <div className="bg-slate-900 border border-slate-700 rounded-xl p-3 shadow-2xl backdrop-blur-md text-xs font-mono space-y-1.5 min-w-[200px]">
        <div className="text-white font-bold border-b border-slate-800 pb-1 flex items-center justify-between">
          <span className="flex items-center gap-1.5 text-cyan-400">
            <Clock className="w-3.5 h-3.5" /> {label}
          </span>
          <span className="text-[10px] text-slate-500 uppercase">Horodatage</span>
        </div>
        {payload.map((entry: any, i: number) => (
          <div key={i} className="flex items-center justify-between gap-4 text-[11px]">
            <span className="flex items-center gap-1.5" style={{ color: entry.color }}>
              <span className="w-2 h-2 rounded-full" style={{ backgroundColor: entry.color }} />
              {entry.name} :
            </span>
            <span className="font-bold text-white font-mono">{entry.value}</span>
          </div>
        ))}
      </div>
    );
  }
  return null;
};

const getColSpanClass = (colSpan: WidgetColSpan): string => {
  switch (colSpan) {
    case 12:
      return 'col-span-12';
    case 8:
      return 'col-span-12 xl:col-span-8';
    case 6:
      return 'col-span-12 xl:col-span-6';
    case 4:
      return 'col-span-12 xl:col-span-4';
    default:
      return 'col-span-12';
  }
};

const getWidgetIcon = (id: DashboardWidgetId) => {
  switch (id) {
    case 'kpi_score_metrics':
      return <Activity className="w-4 h-4 text-cyan-400" />;
    case 'risk_score_24hours':
      return <Activity className="w-4 h-4 text-rose-400" />;
    case 'hourly_attacks_heatmap':
      return <Flame className="w-4 h-4 text-rose-500 animate-pulse" />;
    case 'nebula_live_stream':
      return <Radio className="w-4 h-4 text-emerald-400 animate-pulse" />;
    case 'threat_topology_d3':
      return <Network className="w-4 h-4 text-cyan-400" />;
    case 'geographical_attack_heatmap':
      return <Globe className="w-4 h-4 text-cyan-400" />;
    case 'attack_sources_heatmap':
      return <Flame className="w-4 h-4 text-rose-400" />;
    case 'attack_volume_7days_trend':
      return <TrendingUp className="w-4 h-4 text-indigo-400" />;
    case 'risk_score_7days':
      return <BarChart3 className="w-4 h-4 text-rose-400" />;
    case 'scheduled_log_analysis':
      return <CalendarClock className="w-4 h-4 text-cyan-400" />;
    case 'multi_org_sites':
      return <Building2 className="w-4 h-4 text-cyan-400" />;
    case 'countermeasures_banner':
      return <ShieldAlert className="w-4 h-4 text-red-400" />;
    case 'attack_timeline':
      return <TrendingUp className="w-4 h-4 text-cyan-400" />;
    case 'threat_distribution':
      return <PieChartIcon className="w-4 h-4 text-cyan-400" />;
    case 'mitre_attack_vectors':
      return <Target className="w-4 h-4 text-red-400" />;
    case 'malicious_ips_hosts':
      return <Globe className="w-4 h-4 text-amber-400" />;
    case 'predictive_vectors':
      return <Sparkles className="w-4 h-4 text-purple-400" />;
    case 'incident_calendar':
      return <Calendar className="w-4 h-4 text-emerald-400" />;
    case 'audio_briefing':
      return <Volume2 className="w-4 h-4 text-cyan-400" />;
    case 'analysis_history':
      return <History className="w-4 h-4 text-indigo-400" />;
  }
};

export const DashboardView: React.FC<DashboardViewProps> = ({
  analysis,
  logs,
  activeDefenses,
  onNavigateToCountermeasures,
  onEnforceDefense,
  onInspectLog,
  historyList = [],
  onRestoreAnalysis,
  onDeleteHistoryItem,
  onClearHistory,
  deviceName = 'Passerelle Zyxel Nebula ATP',
  onSelectSiteLogs,
  onAppendLiveLog,
  onNavigateToTab,
}) => {
  const [isHistoryOpen, setIsHistoryOpen] = useState(true);
  const [isComparisonOpen, setIsComparisonOpen] = useState(false);

  // Active Site Attack Surveillance State
  const [activeMonitoredSite, setActiveMonitoredSite] = useState<string>('SITE-PARIS-ATP700');
  const [isSyncingSite, setIsSyncingSite] = useState<boolean>(false);
  const [syncStatusMsg, setSyncStatusMsg] = useState<string | null>(null);

  const handleQuickSyncSite = async (targetSiteId: string) => {
    setActiveMonitoredSite(targetSiteId);
    setIsSyncingSite(true);
    try {
      const res = await fetch('/api/nebula/pull-logs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ siteId: targetSiteId }),
      });
      if (res.ok) {
        const data = await res.json();
        const siteLabel = `${data.site?.gatewayModel || 'Passerelle'} (${data.site?.siteName || targetSiteId})`;
        setSyncStatusMsg(`Logs synchronisés avec ${siteLabel} — ${data.rawLogs?.split('\n').length || 0} événements analysés pour la surveillance des attaques.`);
        onSelectSiteLogs?.(data.rawLogs, siteLabel);
      }
    } catch (e) {
      console.warn('Sync failed:', e);
    } finally {
      setIsSyncingSite(false);
    }
  };

  // Customizable Widget Grid State
  const [widgets, setWidgets] = useState<DashboardWidgetConfig[]>(() => {
    try {
      const saved = localStorage.getItem(WIDGET_STORAGE_KEY);
      if (saved) {
        const parsed = JSON.parse(saved) as DashboardWidgetConfig[];
        if (Array.isArray(parsed) && parsed.length > 0) {
          // Merge with DEFAULT_WIDGETS to ensure any newly added widget IDs exist
          const existingIds = new Set(parsed.map((w) => w.id));
          const merged = [
            ...parsed.map((savedWidget) => {
              const def = DEFAULT_WIDGETS.find((d) => d.id === savedWidget.id);
              return def ? { ...def, ...savedWidget } : savedWidget;
            }),
            ...DEFAULT_WIDGETS.filter((d) => !existingIds.has(d.id)),
          ];
          return merged;
        }
      }
    } catch {
      // Ignore storage error and use default
    }
    return DEFAULT_WIDGETS;
  });

  const [isCustomizingGrid, setIsCustomizingGrid] = useState(false);
  const [draggedWidgetId, setDraggedWidgetId] = useState<DashboardWidgetId | null>(null);
  const [dragOverWidgetId, setDragOverWidgetId] = useState<DashboardWidgetId | null>(null);

  useEffect(() => {
    try {
      localStorage.setItem(WIDGET_STORAGE_KEY, JSON.stringify(widgets));
    } catch {
      // Ignore localStorage quota errors
    }
  }, [widgets]);

  // Widget manipulation helpers
  const toggleWidgetVisibility = (id: DashboardWidgetId) => {
    setWidgets((prev) =>
      prev.map((w) => (w.id === id ? { ...w, visible: !w.visible } : w))
    );
  };

  const toggleWidgetCollapse = (id: DashboardWidgetId) => {
    setWidgets((prev) =>
      prev.map((w) => (w.id === id ? { ...w, collapsed: !w.collapsed } : w))
    );
  };

  const changeWidgetColSpan = (id: DashboardWidgetId, colSpan: WidgetColSpan) => {
    setWidgets((prev) =>
      prev.map((w) => (w.id === id ? { ...w, colSpan } : w))
    );
  };

  const cycleWidgetWidth = (id: DashboardWidgetId) => {
    setWidgets((prev) =>
      prev.map((w) => {
        if (w.id !== id) return w;
        const nextSpan: WidgetColSpan = w.colSpan === 12 ? 6 : 12;
        return { ...w, colSpan: nextSpan };
      })
    );
  };

  const moveWidget = (id: DashboardWidgetId, direction: 'up' | 'down') => {
    setWidgets((prev) => {
      const idx = prev.findIndex((w) => w.id === id);
      if (idx === -1) return prev;
      const targetIdx = direction === 'up' ? idx - 1 : idx + 1;
      if (targetIdx < 0 || targetIdx >= prev.length) return prev;
      const copy = [...prev];
      const [removed] = copy.splice(idx, 1);
      copy.splice(targetIdx, 0, removed);
      return copy;
    });
  };

  const reorderWidgetsByDrag = (sourceId: DashboardWidgetId, targetId: DashboardWidgetId) => {
    if (sourceId === targetId) return;
    setWidgets((prev) => {
      const sourceIdx = prev.findIndex((w) => w.id === sourceId);
      const targetIdx = prev.findIndex((w) => w.id === targetId);
      if (sourceIdx === -1 || targetIdx === -1) return prev;
      const copy = [...prev];
      const [moved] = copy.splice(sourceIdx, 1);
      copy.splice(targetIdx, 0, moved);
      return copy;
    });
  };

  const resetDefaultLayout = () => {
    setWidgets(DEFAULT_WIDGETS);
  };

  const applyPresetLayout = (preset: 'full' | 'executive' | 'hunting' | 'predictive' | 'geo_time') => {
    if (preset === 'full') {
      setWidgets((prev) => prev.map((w) => ({ ...w, visible: true, collapsed: false })));
      return;
    }

    const visibleMap: Record<'executive' | 'hunting' | 'predictive' | 'geo_time', DashboardWidgetId[]> = {
      executive: [
        'kpi_score_metrics',
        'geographical_attack_heatmap',
        'hourly_attacks_heatmap',
        'countermeasures_banner',
        'threat_topology_d3',
        'threat_distribution',
        'malicious_ips_hosts',
        'risk_score_24hours',
      ],
      geo_time: [
        'geographical_attack_heatmap',
        'hourly_attacks_heatmap',
        'threat_topology_d3',
        'malicious_ips_hosts',
        'countermeasures_banner',
      ],
      hunting: [
        'countermeasures_banner',
        'geographical_attack_heatmap',
        'hourly_attacks_heatmap',
        'threat_topology_d3',
        'mitre_attack_vectors',
        'malicious_ips_hosts',
      ],
      predictive: [
        'kpi_score_metrics',
        'risk_score_24hours',
        'attack_volume_7days_trend',
        'risk_score_7days',
        'predictive_vectors',
        'incident_calendar',
        'threat_distribution',
        'analysis_history',
      ],
    };

    const allowed = new Set(visibleMap[preset]);
    const priorityOrder = visibleMap[preset];

    setWidgets((prev) => {
      const updated = prev.map((w) => {
        const isVis = allowed.has(w.id);
        let colSpan = w.colSpan;
        if (preset === 'geo_time' && (w.id === 'geographical_attack_heatmap' || w.id === 'hourly_attacks_heatmap')) {
          colSpan = 12;
        }
        return {
          ...w,
          visible: isVis,
          collapsed: false,
          colSpan,
        };
      });
      return updated.sort((a, b) => {
        const idxA = priorityOrder.indexOf(a.id);
        const idxB = priorityOrder.indexOf(b.id);
        if (idxA !== -1 && idxB !== -1) return idxA - idxB;
        if (idxA !== -1) return -1;
        if (idxB !== -1) return 1;
        return 0;
      });
    });
  };

  // Aggregate log statistics
  const criticalLogs = logs.filter((l) => l.severity === 'CRITICAL');
  const blockedLogs = logs.filter(
    (l) => l.action === 'Blocked' || l.action === 'Dropped' || l.action === 'Quarantined'
  );

  // Category counts
  const categoryCounts: Record<string, number> = {};
  logs.forEach((l) => {
    categoryCounts[l.category] = (categoryCounts[l.category] || 0) + 1;
  });

  // Threat type pie data calculation
  const pieData = useMemo(() => {
    const counts: Record<string, number> = {};
    logs.forEach((log) => {
      const type = classifyThreat(log);
      counts[type] = (counts[type] || 0) + 1;
    });

    const total = logs.length || 1;
    return Object.entries(counts)
      .map(([name, count]) => ({
        name,
        value: count,
        color: THREAT_COLORS[name] || '#64748b',
        percentage: Math.round((count / total) * 100),
      }))
      .sort((a, b) => b.value - a.value);
  }, [logs]);

  // Chronological timeline data calculation for LineChart
  const timelineData = useMemo(() => {
    if (!logs || logs.length === 0) return [];

    const sorted = [...logs].sort((a, b) => {
      const timeA = new Date(a.timestamp).getTime();
      const timeB = new Date(b.timestamp).getTime();
      return (isNaN(timeA) ? 0 : timeA) - (isNaN(timeB) ? 0 : timeB);
    });

    const timeMap: Record<
      string,
      { time: string; total: number; critical: number; blocked: number }
    > = {};

    sorted.forEach((log) => {
      let timeKey = log.timestamp;
      try {
        const d = new Date(log.timestamp);
        if (!isNaN(d.getTime())) {
          timeKey = d.toLocaleTimeString('fr-FR', {
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
          });
        } else {
          const match = log.timestamp.match(/\d{2}:\d{2}(:\d{2})?/);
          if (match) timeKey = match[0];
        }
      } catch {
        timeKey = log.timestamp.slice(11, 19) || log.timestamp;
      }

      if (!timeMap[timeKey]) {
        timeMap[timeKey] = {
          time: timeKey,
          total: 0,
          critical: 0,
          blocked: 0,
        };
      }

      timeMap[timeKey].total += 1;
      if (log.severity === 'CRITICAL') {
        timeMap[timeKey].critical += 1;
      }
      if (log.action === 'Blocked' || log.action === 'Dropped' || log.action === 'Quarantined') {
        timeMap[timeKey].blocked += 1;
      }
    });

    return Object.values(timeMap);
  }, [logs]);

  const peakAttack = useMemo(() => {
    if (timelineData.length === 0) return null;
    return timelineData.reduce((max, cur) => (cur.total > max.total ? cur : max), timelineData[0]);
  }, [timelineData]);

  const isIpBlocked = (ip: string) => {
    return activeDefenses.some((d) => d.target === ip && d.status === 'ACTIVE');
  };

  const visibleWidgets = widgets.filter((w) => w.visible);
  const hiddenWidgets = widgets.filter((w) => !w.visible);

  // Render content for a given widget ID
  const renderWidgetBody = (widgetId: DashboardWidgetId) => {
    switch (widgetId) {
      case 'kpi_score_metrics':
        return (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Threat Gauge */}
            <div className="lg:col-span-1">
              <ThreatScoreGauge
                score={analysis.riskScore}
                threatLevel={analysis.threatLevel}
                activeAttacks={analysis.attackVectors.length}
              />
            </div>

            {/* 4 Metric Cards */}
            <div className="lg:col-span-2 grid grid-cols-2 sm:grid-cols-4 gap-4">
              {/* Card 1 */}
              <div className="p-4 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl flex flex-col justify-between">
                <div className="flex items-center justify-between text-slate-400">
                  <span className="text-xs font-mono">Attaques Détectées</span>
                  <AlertTriangle className="w-4 h-4 text-red-400" />
                </div>
                <div className="my-2">
                  <span className="text-2xl sm:text-3xl font-bold font-mono text-white">
                    {analysis.activeAttacksDetected}
                  </span>
                </div>
                <span className="text-[11px] text-red-400 font-mono flex items-center gap-1">
                  {criticalLogs.length} événements critiques
                </span>
              </div>

              {/* Card 2 */}
              <div className="p-4 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl flex flex-col justify-between">
                <div className="flex items-center justify-between text-slate-400">
                  <span className="text-xs font-mono">IPs Malveillantes</span>
                  <Globe className="w-4 h-4 text-amber-400" />
                </div>
                <div className="my-2">
                  <span className="text-2xl sm:text-3xl font-bold font-mono text-white">
                    {analysis.iocList.filter((i) => i.type === 'IP').length}
                  </span>
                </div>
                <span className="text-[11px] text-amber-400 font-mono">
                  Serveurs C2 & Scanners
                </span>
              </div>

              {/* Card 3 */}
              <div className="p-4 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl flex flex-col justify-between">
                <div className="flex items-center justify-between text-slate-400">
                  <span className="text-xs font-mono">Hôtes LAN Menacés</span>
                  <Laptop className="w-4 h-4 text-purple-400" />
                </div>
                <div className="my-2">
                  <span className="text-2xl sm:text-3xl font-bold font-mono text-white">
                    {analysis.compromisedHosts.length}
                  </span>
                </div>
                <span className="text-[11px] text-purple-400 font-mono">
                  Quarantaine CDR prête
                </span>
              </div>

              {/* Card 4 */}
              <div className="p-4 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl flex flex-col justify-between">
                <div className="flex items-center justify-between text-slate-400">
                  <span className="text-xs font-mono">Règles de Riposte</span>
                  <Zap className="w-4 h-4 text-cyan-400" />
                </div>
                <div className="my-2">
                  <span className="text-2xl sm:text-3xl font-bold font-mono text-cyan-300">
                    {analysis.stopActions.length}
                  </span>
                </div>
                <span className="text-[11px] text-cyan-400 font-mono">
                  1-Clic Déploiement
                </span>
              </div>
            </div>
          </div>
        );

      case 'hourly_attacks_heatmap':
        return (
          <HourlyAttackHeatmap
            logs={logs}
            analysis={analysis}
            onInspectLog={onInspectLog}
            onEnforceDefense={onEnforceDefense}
            onNavigateToCountermeasures={onNavigateToCountermeasures}
            deviceName={deviceName}
          />
        );

      case 'nebula_live_stream':
        return (
          <NebulaLiveStreamConsole
            activeDefenses={activeDefenses}
            onEnforceDefense={onEnforceDefense}
            onSyncWithApp={(rawLogsText, siteLabel) => {
              if (onSelectSiteLogs) {
                onSelectSiteLogs(rawLogsText, siteLabel);
              }
            }}
            onNavigateToDashboard={() => onNavigateToTab?.('dashboard')}
          />
        );

      case 'threat_topology_d3':
        return (
          <ThreatTopologyD3Graph
            logs={logs}
            analysis={analysis}
            activeDefenses={activeDefenses}
            deviceName={deviceName}
            onEnforceDefense={onEnforceDefense}
            onInspectLog={onInspectLog}
            onNavigateToCountermeasures={onNavigateToCountermeasures}
          />
        );

      case 'geographical_attack_heatmap':
        return (
          <GeographicalAttackHeatmap
            logs={logs}
            analysis={analysis}
            onInspectLog={onInspectLog}
            onEnforceDefense={onEnforceDefense}
            deviceName={deviceName}
          />
        );

      case 'attack_sources_heatmap':
        return (
          <AttackHeatmapVisualizer
            logs={logs}
            analysis={analysis}
            onInspectLog={onInspectLog}
            onEnforceDefense={onEnforceDefense}
            deviceName={deviceName}
          />
        );

      case 'attack_volume_7days_trend':
        return (
          <AttackVolume7DaysTrendChart
            analysis={analysis}
            logs={logs}
            activeDefenses={activeDefenses}
            historyList={historyList}
            deviceName={deviceName}
            onNavigateToCountermeasures={onNavigateToCountermeasures}
          />
        );

      case 'risk_score_24hours':
        return (
          <RiskScore24HoursAreaChart
            analysis={analysis}
            logs={logs}
            activeDefenses={activeDefenses}
            historyList={historyList}
            deviceName={deviceName}
            onNavigateToCountermeasures={onNavigateToCountermeasures}
            onInspectLog={onInspectLog}
          />
        );

      case 'risk_score_7days':
        return (
          <RiskScore7DaysChart
            analysis={analysis}
            logs={logs}
            activeDefenses={activeDefenses}
            historyList={historyList}
            deviceName={deviceName}
          />
        );

      case 'scheduled_log_analysis':
        return (
          <ScheduledAnalysisManager
            onSelectSiteLogs={onSelectSiteLogs}
          />
        );

      case 'multi_org_sites':
        return (
          <MultiOrgSiteManager
            currentDeviceName={deviceName}
            activeDefenses={activeDefenses}
            onEnforceDefense={onEnforceDefense}
            onAppendLiveLog={onAppendLiveLog}
            onSelectAndMonitorSite={(pulledLogs, siteContextLabel) => {
              onSelectSiteLogs?.(pulledLogs, siteContextLabel);
            }}
          />
        );

      case 'countermeasures_banner':
        return (
          <div className="p-5 rounded-2xl bg-gradient-to-r from-red-950/60 via-slate-900 to-slate-900 border border-red-800/50 shadow-xl flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-red-600/20 border border-red-500/40 flex items-center justify-center text-red-400 flex-shrink-0">
                <ShieldAlert className="w-6 h-6 animate-pulse" />
              </div>
              <div>
                <h4 className="text-sm font-bold text-white">
                  {analysis.stopActions.length} Contre-mesures prêtes pour neutraliser les attaques en cours
                </h4>
                <p className="text-xs text-slate-400">
                  Générez instantanément les règles de filtrage WAN Zyxel Nebula Cloud & isolez les machines infectées.
                </p>
              </div>
            </div>

            <button
              onClick={onNavigateToCountermeasures}
              className="inline-flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 text-white font-bold text-xs shadow-lg shadow-red-900/40 transition whitespace-nowrap"
            >
              <span>Accéder au Centre de Riposte</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        );

      case 'attack_timeline':
        return (
          <SecurityAlertsHourlyChart
            logs={logs}
            analysis={analysis}
            onInspectLog={onInspectLog}
            onEnforceDefense={onEnforceDefense}
            onNavigateToCountermeasures={onNavigateToCountermeasures}
            deviceName={deviceName}
          />
        );

      case 'threat_distribution':
        return (
          <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-5 h-full flex flex-col justify-between">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/80 pb-4">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-lg bg-cyan-950 text-cyan-400 border border-cyan-800 flex items-center justify-center">
                  <PieChartIcon className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white tracking-tight">
                    Répartition des Types de Menaces Détectées
                  </h3>
                  <p className="text-xs text-slate-400 font-mono">
                    Visualisation par vecteur d'attaque (Malwares, Brute Force, DDoS, C2, Exploits)
                  </p>
                </div>
              </div>
              <span className="text-xs font-mono text-cyan-400 px-2.5 py-1 rounded-lg bg-cyan-950/60 border border-cyan-800/60 self-start sm:self-auto">
                {logs.length} Alertes
              </span>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
              {/* Recharts Pie Chart (5 cols) */}
              <div className="lg:col-span-5 h-[250px] w-full flex items-center justify-center relative">
                {pieData.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={pieData}
                        cx="50%"
                        cy="50%"
                        innerRadius={55}
                        outerRadius={88}
                        paddingAngle={4}
                        dataKey="value"
                        nameKey="name"
                        stroke="#0f172a"
                        strokeWidth={2}
                      >
                        {pieData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip content={<CustomTooltip />} />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="text-xs text-slate-500 font-mono">Aucune donnée disponible</div>
                )}
                {/* Center Summary Label */}
                <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                  <span className="text-2xl font-bold font-mono text-white">{logs.length}</span>
                  <span className="text-[10px] font-mono text-slate-400 uppercase tracking-widest">
                    Logs
                  </span>
                </div>
              </div>

              {/* Interactive Legend & Breakdown Bars (7 cols) */}
              <div className="lg:col-span-7 grid grid-cols-1 sm:grid-cols-2 gap-3">
                {pieData.map((item, idx) => (
                  <div
                    key={idx}
                    className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 hover:border-slate-700 transition flex flex-col justify-between space-y-2"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 min-w-0">
                        <span
                          className="w-3 h-3 rounded-full flex-shrink-0"
                          style={{ backgroundColor: item.color }}
                        />
                        <span className="text-xs font-semibold text-slate-200 truncate">
                          {item.name}
                        </span>
                      </div>
                      <span className="text-xs font-mono font-bold text-white ml-2 flex-shrink-0">
                        {item.value} <span className="text-slate-500 font-normal">({item.percentage}%)</span>
                      </span>
                    </div>
                    <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all duration-500"
                        style={{
                          width: `${item.percentage}%`,
                          backgroundColor: item.color,
                        }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        );

      case 'mitre_attack_vectors':
        return (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Target className="w-5 h-5 text-red-400" />
                <h3 className="text-base font-bold text-white">
                  Vecteurs d'Attaques Identifiés ({analysis.attackVectors.length})
                </h3>
              </div>
              <span className="text-xs text-slate-400 font-mono">Mapping MITRE ATT&CK</span>
            </div>

            <div className="space-y-4">
              {analysis.attackVectors.map((vector, idx) => (
                <div
                  key={idx}
                  className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 hover:border-slate-700 shadow-xl space-y-4 transition"
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="flex items-center gap-2.5">
                      <span className="w-2.5 h-2.5 rounded-full bg-red-500 animate-ping" />
                      <h4 className="text-sm font-bold text-white">{vector.name}</h4>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-cyan-400 border border-slate-700">
                        {vector.mitreTechniqueId}
                      </span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-950 text-red-400 border border-red-800 font-bold">
                        {vector.severity}
                      </span>
                    </div>
                  </div>

                  <p className="text-xs text-slate-300 leading-relaxed">{vector.description}</p>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2 text-xs font-mono">
                    <div className="p-2.5 rounded-xl bg-slate-950/70 border border-slate-800/80">
                      <span className="text-[10px] text-slate-500 uppercase block mb-1">
                        IPs Attaquantes Détectées
                      </span>
                      <div className="flex flex-wrap gap-1">
                        {vector.attackerIps.map((ip, i) => (
                          <span
                            key={i}
                            className="px-2 py-0.5 rounded bg-red-950/60 text-red-300 border border-red-900/80 font-bold"
                          >
                            {ip}
                          </span>
                        ))}
                      </div>
                    </div>

                    <div className="p-2.5 rounded-xl bg-slate-950/70 border border-slate-800/80">
                      <span className="text-[10px] text-slate-500 uppercase block mb-1">
                        Cibles Internes Visées
                      </span>
                      <div className="flex flex-wrap gap-1">
                        {vector.targetAssets.map((asset, i) => (
                          <span
                            key={i}
                            className="px-2 py-0.5 rounded bg-slate-800 text-slate-200 border border-slate-700 font-bold"
                          >
                            {asset}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>

            {/* Category distribution */}
            <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-4">
              <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono">
                Répartition des Alertes par Module Nebula
              </h4>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {Object.entries(categoryCounts).map(([cat, count]) => (
                  <div key={cat} className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80">
                    <span className="text-[10px] font-mono text-slate-500 block truncate">{cat}</span>
                    <span className="text-lg font-bold font-mono text-white mt-1 block">{count} logs</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        );

      case 'malicious_ips_hosts':
        return (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Globe className="w-5 h-5 text-amber-400" />
                <h3 className="text-base font-bold text-white">Top IPs Malveillantes</h3>
              </div>
              <span className="text-xs text-slate-400 font-mono">IOCs Actifs</span>
            </div>

            <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-3.5">
              {analysis.iocList
                .filter((ioc) => ioc.type === 'IP')
                .slice(0, 6)
                .map((ioc, idx) => {
                  const blocked = isIpBlocked(ioc.value);
                  const matchingAction = analysis.stopActions.find((a) => a.target === ioc.value);

                  return (
                    <div
                      key={idx}
                      className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 hover:border-slate-700 transition space-y-2"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-mono font-bold text-white">{ioc.value}</span>
                          {ioc.country && (
                            <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-800 text-slate-300">
                              {ioc.country}
                            </span>
                          )}
                        </div>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded font-bold bg-red-950 text-red-400 border border-red-800">
                          {ioc.severity}
                        </span>
                      </div>

                      <p className="text-[11px] text-slate-400">{ioc.threat}</p>

                      <div className="flex items-center justify-between pt-1">
                        {blocked ? (
                          <span className="inline-flex items-center gap-1 text-[11px] font-mono text-emerald-400 font-bold">
                            <CheckCircle className="w-3.5 h-3.5" /> Bloqué sur Nebula WAN
                          </span>
                        ) : (
                          <button
                            onClick={() => {
                              if (matchingAction) {
                                onEnforceDefense(matchingAction);
                              } else {
                                onNavigateToCountermeasures();
                              }
                            }}
                            className="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg bg-red-600/90 hover:bg-red-500 text-white font-mono text-[11px] font-semibold transition"
                          >
                            <Lock className="w-3 h-3" /> Bloquer l'IP
                          </button>
                        )}
                      </div>
                    </div>
                  );
                })}
            </div>

            {/* Internal Compromised Hosts */}
            <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-3.5">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Laptop className="w-5 h-5 text-purple-400" />
                  <h3 className="text-sm font-bold text-white">Postes LAN Compromis</h3>
                </div>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800">
                  Nebula CDR
                </span>
              </div>

              {analysis.compromisedHosts.length === 0 ? (
                <p className="text-xs text-slate-500 text-center py-2">
                  Aucun hôte interne compromis détecté.
                </p>
              ) : (
                analysis.compromisedHosts.map((host, idx) => (
                  <div
                    key={idx}
                    className="p-3 rounded-xl bg-purple-950/20 border border-purple-900/50 space-y-2"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-mono font-bold text-purple-300">{host.ip}</span>
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-purple-900/50 text-purple-200">
                        {host.status}
                      </span>
                    </div>
                    {host.hostname && (
                      <p className="text-[11px] text-slate-300 font-mono">Hôte : {host.hostname}</p>
                    )}
                    <p className="text-[11px] text-slate-400">{host.evidence}</p>
                    {host.recommendedIsolation && (
                      <div className="pt-1">
                        <span className="text-[10px] font-mono text-amber-400 flex items-center gap-1 font-semibold">
                          <AlertTriangle className="w-3 h-3" /> Quarantaine VLAN recommandée
                        </span>
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>
        );

      case 'predictive_vectors':
        return (
          <PredictiveAttackVectors
            analysis={analysis}
            logs={logs}
            deviceName={deviceName}
            onEnforceDefense={onEnforceDefense}
            onNavigateToCountermeasures={onNavigateToCountermeasures}
          />
        );

      case 'incident_calendar':
        return <IncidentCalendarView logs={logs} historyList={historyList} />;

      case 'audio_briefing':
        return (
          <ThreatAudioBriefing
            analysis={analysis}
            deviceName={deviceName}
            activeDefensesCount={activeDefenses.filter((d) => d.status === 'ACTIVE').length}
          />
        );

      case 'analysis_history':
        return (
          <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-4">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-lg bg-indigo-950 text-indigo-400 border border-indigo-800 flex items-center justify-center">
                  <History className="w-4 h-4" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-base font-bold text-white tracking-tight">
                      Historique Local des Analyses Récentes
                    </h3>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-950 text-indigo-300 border border-indigo-800">
                      {historyList.length} / 10 sauvegardées
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 font-mono">
                    Stockage persistant (localStorage) des 10 derniers rapports de sécurité
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2 self-start sm:self-auto">
                {historyList.length > 0 && onClearHistory && (
                  <button
                    onClick={onClearHistory}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800/80 hover:bg-red-950/60 hover:text-red-300 text-slate-400 text-xs font-mono border border-slate-700 hover:border-red-800/60 transition"
                    title="Vider l'historique local du navigateur"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    <span>Vider l'historique</span>
                  </button>
                )}
                <button
                  onClick={() => setIsHistoryOpen(!isHistoryOpen)}
                  className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition"
                  title={isHistoryOpen ? 'Réduire' : 'Déplier'}
                >
                  {isHistoryOpen ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {isHistoryOpen && (
              <>
                {historyList.length === 0 ? (
                  <div className="p-8 text-center rounded-xl bg-slate-950/40 border border-slate-800/50 space-y-2">
                    <Archive className="w-8 h-8 text-slate-600 mx-auto" />
                    <p className="text-xs text-slate-400">
                      Aucune analyse archivée dans le navigateur pour le moment.
                    </p>
                    <p className="text-[11px] text-slate-500 font-mono">
                      Chaque nouvelle analyse de logs Nebula sera automatiquement mémorisée ici (jusqu'à 10 analyses).
                    </p>
                  </div>
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 max-h-[380px] overflow-y-auto pr-1">
                    {historyList.map((item) => {
                      const isCurrent = analysis.summary === item.analysis.summary;
                      const dateFormatted = new Date(item.timestamp).toLocaleString('fr-FR', {
                        day: '2-digit',
                        month: '2-digit',
                        year: 'numeric',
                        hour: '2-digit',
                        minute: '2-digit',
                        second: '2-digit',
                      });

                      return (
                        <div
                          key={item.id}
                          className={`p-3.5 rounded-xl border text-xs transition flex flex-col justify-between space-y-3 ${
                            isCurrent
                              ? 'bg-slate-950/90 border-cyan-700/70 shadow-md shadow-cyan-950/20'
                              : 'bg-slate-950/60 border-slate-800/80 hover:border-slate-700'
                          }`}
                        >
                          <div className="space-y-1.5">
                            <div className="flex items-center justify-between gap-2">
                              <span className="text-[11px] font-mono text-slate-400 flex items-center gap-1">
                                <Clock className="w-3 h-3 text-slate-500" />
                                {dateFormatted}
                              </span>
                              <div className="flex items-center gap-1.5">
                                <span
                                  className={`text-[10px] font-mono font-bold px-1.5 py-0.2 rounded ${
                                    item.threatLevel === 'CRITICAL'
                                      ? 'bg-red-950 text-red-400 border border-red-800'
                                      : item.threatLevel === 'HIGH'
                                      ? 'bg-amber-950 text-amber-400 border border-amber-800'
                                      : 'bg-slate-800 text-slate-300'
                                  }`}
                                >
                                  {item.threatLevel} ({item.riskScore}/100)
                                </span>
                                {isCurrent && (
                                  <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                                    ACTIVE
                                  </span>
                                )}
                              </div>
                            </div>

                            <h4 className="text-xs font-bold text-white truncate" title={item.title}>
                              {item.title}
                            </h4>
                            <p className="text-[11px] text-slate-400 font-mono truncate">
                              {item.deviceName} • {item.logCount} logs • {item.attacksCount} attaques
                            </p>
                          </div>

                          <div className="flex items-center justify-between pt-2 border-t border-slate-800/60 text-[11px] font-mono">
                            <span className="text-slate-500 truncate max-w-[140px]">
                              {item.analysis.attackVectors[0]?.name || 'Attaque analysée'}
                            </span>

                            <div className="flex items-center gap-2">
                              <button
                                onClick={() => {
                                  setIsComparisonOpen(true);
                                  window.scrollTo({ top: 0, behavior: 'smooth' });
                                }}
                                className="inline-flex items-center gap-1 px-2 py-1 rounded-lg text-xs font-mono font-semibold bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 transition"
                                title="Comparer ce rapport avec le rapport actif dans le comparateur côte à côte"
                              >
                                <GitCompare className="w-3 h-3" />
                                <span>Comparer</span>
                              </button>

                              {onDeleteHistoryItem && (
                                <button
                                  onClick={() => onDeleteHistoryItem(item.id)}
                                  className="p-1 rounded hover:bg-slate-800 text-slate-500 hover:text-red-400 transition"
                                  title="Supprimer cette entrée de l'historique"
                                >
                                  <Trash2 className="w-3.5 h-3.5" />
                                </button>
                              )}
                              {onRestoreAnalysis && (
                                <button
                                  onClick={() => onRestoreAnalysis(item)}
                                  disabled={isCurrent}
                                  className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-lg font-semibold transition ${
                                    isCurrent
                                      ? 'bg-slate-800 text-slate-500 cursor-default'
                                      : 'bg-cyan-600 hover:bg-cyan-500 text-white shadow-sm'
                                  }`}
                                >
                                  <RotateCcw className="w-3 h-3" />
                                  <span>{isCurrent ? 'Active' : 'Charger'}</span>
                                </button>
                              )}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </>
            )}
          </div>
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* Consolidated Executive SOC Toolbar: Site Monitoring, Posture & Layout Controls */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 p-3.5 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl backdrop-blur-md">
        {/* Left: Monitored Site Selector & Posture status */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse" />
            <select
              value={activeMonitoredSite}
              onChange={(e) => handleQuickSyncSite(e.target.value)}
              className="bg-slate-950 border border-slate-800 text-white font-semibold text-xs rounded-xl px-2.5 py-1.5 focus:outline-none focus:ring-1 focus:ring-cyan-500 cursor-pointer"
              title="Changer de site Zyxel Nebula surveillé"
            >
              <option value="SITE-PARIS-ATP700">Site Paris (ATP700)</option>
              <option value="SITE-HQ-USGFLEX500">Siège HQ (USG FLEX 500)</option>
              <option value="SITE-LYON-USGFLEX200">Site Lyon (USG FLEX 200)</option>
              <option value="SITE-BORDEAUX-ATP500">Site Bordeaux (ATP500)</option>
              <option value="SITE-LILLE-CHU-ATP800">Site Lille CHU (ATP800)</option>
              <option value="SITE-TOULOUSE-AERO-ATP800">Site Toulouse Aéro (ATP800)</option>
            </select>
          </div>

          <div className="h-4 w-px bg-slate-800 hidden sm:block" />

          {/* Posture status */}
          <div className="flex items-center gap-2 text-xs font-mono">
            <span className="text-slate-400">Score :</span>
            <span className={`font-bold ${analysis.riskScore >= 75 ? 'text-rose-400' : 'text-amber-400'}`}>
              {analysis.riskScore}/100 ({analysis.threatLevel})
            </span>
            <span className="text-slate-600">·</span>
            <span className="text-slate-400">{analysis.attackVectors.length} vecteurs</span>
            <span className="text-slate-600">·</span>
            <span className="text-slate-400">{logs.length} logs</span>
          </div>
        </div>

        {/* Right: Layout Preset Tabs & Action Controls */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Preset Layout Buttons */}
          <div className="flex items-center gap-1 p-1 bg-slate-950 rounded-xl border border-slate-800 text-xs font-mono">
            <button
              onClick={() => applyPresetLayout('executive')}
              className="px-2.5 py-1 rounded-lg text-slate-300 hover:text-white hover:bg-slate-800 transition text-[11px] font-semibold flex items-center gap-1.5"
              title="Vue Essentielle : KPIs, Carte Leaflet, Heatmap 24h et Riposte Pare-Feu"
            >
              <Zap className="w-3 h-3 text-cyan-400" />
              <span>Essentielle</span>
            </button>
            <button
              onClick={() => applyPresetLayout('geo_time')}
              className="px-2.5 py-1 rounded-lg text-slate-300 hover:text-white hover:bg-slate-800 transition text-[11px] font-semibold flex items-center gap-1.5"
              title="Vue Cartographie & Horaires : Carte Leaflet mondiale et Heatmap 24h en pleine largeur"
            >
              <Globe className="w-3 h-3 text-emerald-400" />
              <span>Carte & Heures</span>
            </button>
            <button
              onClick={() => applyPresetLayout('hunting')}
              className="px-2.5 py-1 rounded-lg text-slate-300 hover:text-white hover:bg-slate-800 transition text-[11px] font-semibold flex items-center gap-1.5"
              title="Vue Chasse aux Menaces : Topologie D3, IOCs et Vecteurs MITRE"
            >
              <Target className="w-3 h-3 text-red-400" />
              <span>Chasse Menaces</span>
            </button>
            <button
              onClick={() => applyPresetLayout('full')}
              className="px-2.5 py-1 rounded-lg text-slate-300 hover:text-white hover:bg-slate-800 transition text-[11px] font-semibold"
              title="Disposition complète : tous les indicateurs"
            >
              Tous ({widgets.length})
            </button>
          </div>

          {/* Active Widgets Count indicator */}
          <span className="hidden xl:inline-flex text-[11px] font-mono text-slate-400 px-2 py-1 rounded-lg bg-slate-950 border border-slate-800">
            {visibleWidgets.length}/{widgets.length} actifs
          </span>

          {/* Grid Customization Toggle */}
          <button
            onClick={() => setIsCustomizingGrid(!isCustomizingGrid)}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-medium transition border ${
              isCustomizingGrid
                ? 'bg-emerald-600 text-white border-emerald-500 shadow-sm'
                : 'bg-slate-800 text-slate-300 hover:text-white border-slate-700'
            }`}
            title="Personnaliser les widgets du tableau de bord"
          >
            <LayoutGrid className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">{isCustomizingGrid ? 'Terminer' : 'Personnaliser'}</span>
          </button>

          {/* Side-by-Side Compare */}
          <button
            onClick={() => setIsComparisonOpen(!isComparisonOpen)}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-medium transition border ${
              isComparisonOpen
                ? 'bg-cyan-600 text-white border-cyan-500 shadow-sm'
                : 'bg-slate-800 text-slate-300 hover:text-white border-slate-700'
            }`}
            title="Comparer avec une analyse précédente"
          >
            <GitCompare className="w-3.5 h-3.5 text-cyan-300" />
            <span className="hidden sm:inline">Comparer</span>
          </button>

          {/* Sync Site Logs */}
          <button
            type="button"
            onClick={() => handleQuickSyncSite(activeMonitoredSite)}
            disabled={isSyncingSite}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-gradient-to-r from-cyan-600 to-teal-600 hover:from-cyan-500 hover:to-teal-500 text-white font-medium text-xs shadow-sm transition disabled:opacity-50"
            title="Synchroniser immédiatement les flux de ce site"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isSyncingSite ? 'animate-spin' : ''}`} />
            <span>{isSyncingSite ? 'Sync...' : 'Synchroniser'}</span>
          </button>
        </div>
      </div>

      {syncStatusMsg && (
        <div className="p-2.5 rounded-xl bg-emerald-950/40 border border-emerald-800/80 text-xs font-mono text-emerald-300 flex items-center justify-between gap-2">
          <div className="flex items-center gap-1.5">
            <CheckCircle className="w-3.5 h-3.5 text-emerald-400 flex-shrink-0" />
            <span>{syncStatusMsg}</span>
          </div>
          <button
            type="button"
            onClick={() => setSyncStatusMsg(null)}
            className="text-slate-400 hover:text-white text-xs px-2"
          >
            ✕
          </button>
        </div>
      )}

      {/* Interactive Widget Customization Drawer */}
      {isCustomizingGrid && (
        <div className="p-5 rounded-2xl bg-slate-900/95 border-2 border-emerald-700/60 shadow-2xl space-y-5 animate-fadeIn">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl bg-emerald-950 border border-emerald-700/70 flex items-center justify-center text-emerald-400">
                <SlidersHorizontal className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  Configuration de la Grille de Widgets SOC
                  <span className="text-[11px] font-mono font-normal text-emerald-400">
                    · Glisser-déposer activé
                  </span>
                </h3>
                <p className="text-xs text-slate-400 font-mono">
                  Réorganisez l'ordre des indicateurs, ajustez leur largeur (12, 8, 6 ou 4 colonnes) ou masquez ceux dont vous n'avez pas besoin.
                </p>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <button
                onClick={resetDefaultLayout}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white text-xs font-mono border border-slate-700 transition"
                title="Restaurer l'ordre et la visibilité par défaut de tous les indicateurs"
              >
                <RotateCcw className="w-3.5 h-3.5 text-cyan-400" />
                <span>Disposition par défaut</span>
              </button>
            </div>
          </div>

          {/* Preset Views Bar */}
          <div className="flex flex-wrap items-center justify-between gap-3 p-3 rounded-xl bg-slate-950/80 border border-slate-800">
            <span className="text-xs font-mono text-slate-400 font-semibold">
              Profils d'affichage rapides :
            </span>
            <div className="flex flex-wrap items-center gap-1.5">
              <button
                onClick={() => applyPresetLayout('full')}
                className="px-3 py-1.5 rounded-lg text-xs font-mono font-semibold bg-slate-800 hover:bg-slate-700 text-white border border-slate-700 transition"
              >
                Vue Complète ({widgets.length})
              </button>
              <button
                onClick={() => applyPresetLayout('hunting')}
                className="px-3 py-1.5 rounded-lg text-xs font-mono font-semibold bg-slate-800 hover:bg-red-950/70 text-red-300 border border-red-900/50 transition"
              >
                Chasse aux Menaces & Live IPS
              </button>
              <button
                onClick={() => applyPresetLayout('executive')}
                className="px-3 py-1.5 rounded-lg text-xs font-mono font-semibold bg-slate-800 hover:bg-cyan-950/70 text-cyan-300 border border-cyan-900/50 transition"
              >
                Synthèse Exécutive & KPIs
              </button>
              <button
                onClick={() => applyPresetLayout('predictive')}
                className="px-3 py-1.5 rounded-lg text-xs font-mono font-semibold bg-slate-800 hover:bg-purple-950/70 text-purple-300 border border-purple-900/50 transition"
              >
                Analyse Prédictive & Tendances
              </button>
            </div>
          </div>

          {/* Widget Manager Cards List */}
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
            {widgets.map((widget, index) => (
              <div
                key={widget.id}
                draggable
                onDragStart={() => setDraggedWidgetId(widget.id)}
                onDragOver={(e) => {
                  e.preventDefault();
                  if (draggedWidgetId && draggedWidgetId !== widget.id) {
                    setDragOverWidgetId(widget.id);
                  }
                }}
                onDragLeave={() => setDragOverWidgetId(null)}
                onDrop={(e) => {
                  e.preventDefault();
                  if (draggedWidgetId && draggedWidgetId !== widget.id) {
                    reorderWidgetsByDrag(draggedWidgetId, widget.id);
                  }
                  setDraggedWidgetId(null);
                  setDragOverWidgetId(null);
                }}
                onDragEnd={() => {
                  setDraggedWidgetId(null);
                  setDragOverWidgetId(null);
                }}
                className={`p-3.5 rounded-xl border transition flex flex-col justify-between gap-3 cursor-grab active:cursor-grabbing ${
                  dragOverWidgetId === widget.id
                    ? 'bg-emerald-950/40 border-emerald-400 ring-2 ring-emerald-500/30'
                    : widget.visible
                    ? 'bg-slate-950/90 border-slate-800 hover:border-slate-700'
                    : 'bg-slate-950/40 border-slate-800/50 opacity-60'
                }`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-start gap-2.5 min-w-0">
                    <div className="mt-0.5 text-slate-500 hover:text-slate-300">
                      <GripVertical className="w-4 h-4" />
                    </div>
                    <div className="min-w-0">
                      <div className="flex items-center gap-1.5">
                        <span className="text-[10px] font-mono text-slate-500 font-bold">
                          #{index + 1}
                        </span>
                        {getWidgetIcon(widget.id)}
                        <h4 className="text-xs font-bold text-white truncate" title={widget.title}>
                          {widget.title}
                        </h4>
                      </div>
                      <p className="text-[11px] text-slate-400 line-clamp-1 mt-0.5">
                        {widget.description}
                      </p>
                    </div>
                  </div>

                  {/* Visibility Toggle Button */}
                  <button
                    onClick={() => toggleWidgetVisibility(widget.id)}
                    className={`px-2.5 py-1 rounded-lg text-[11px] font-mono font-bold flex items-center gap-1 transition flex-shrink-0 ${
                      widget.visible
                        ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-700/70 hover:bg-emerald-900/60'
                        : 'bg-slate-800 text-slate-400 border border-slate-700 hover:text-white'
                    }`}
                    title={widget.visible ? 'Masquer ce widget' : 'Afficher ce widget'}
                  >
                    {widget.visible ? (
                      <>
                        <Eye className="w-3.5 h-3.5" />
                        <span>Actif</span>
                      </>
                    ) : (
                      <>
                        <EyeOff className="w-3.5 h-3.5" />
                        <span>Masqué</span>
                      </>
                    )}
                  </button>
                </div>

                {/* Bottom Controls: Order & Column Width */}
                <div className="flex items-center justify-between pt-2 border-t border-slate-800/80 text-[11px] font-mono">
                  <div className="flex items-center gap-1">
                    <span className="text-slate-500 mr-1">Largeur :</span>
                    {([12, 8, 6, 4] as WidgetColSpan[]).map((span) => (
                      <button
                        key={span}
                        onClick={() => changeWidgetColSpan(widget.id, span)}
                        className={`px-1.5 py-0.5 rounded text-[10px] font-bold transition ${
                          widget.colSpan === span
                            ? 'bg-cyan-600 text-white'
                            : 'bg-slate-800 text-slate-400 hover:text-white'
                        }`}
                        title={`Définir la largeur sur ${span}/12 colonnes`}
                      >
                        {span === 12 ? '100%' : span === 8 ? '2/3' : span === 6 ? '1/2' : '1/3'}
                      </button>
                    ))}
                  </div>

                  <div className="flex items-center gap-1">
                    <button
                      onClick={() => moveWidget(widget.id, 'up')}
                      disabled={index === 0}
                      className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 disabled:opacity-30 disabled:pointer-events-none transition"
                      title="Monter ce widget"
                    >
                      <ArrowUp className="w-3.5 h-3.5" />
                    </button>
                    <button
                      onClick={() => moveWidget(widget.id, 'down')}
                      disabled={index === widgets.length - 1}
                      className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 disabled:opacity-30 disabled:pointer-events-none transition"
                      title="Descendre ce widget"
                    >
                      <ArrowDown className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Quick Restore Bar for Hidden Widgets (when some widgets are hidden) */}
      {hiddenWidgets.length > 0 && !isCustomizingGrid && (
        <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-2.5 rounded-xl bg-slate-900/70 border border-slate-800/90 text-xs font-mono">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-slate-400 flex items-center gap-1.5">
              <EyeOff className="w-3.5 h-3.5 text-slate-500" />
              Indicateurs masqués ({hiddenWidgets.length}) :
            </span>
            {hiddenWidgets.map((hw) => (
              <button
                key={hw.id}
                onClick={() => toggleWidgetVisibility(hw.id)}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-800/90 hover:bg-slate-700 text-slate-300 hover:text-cyan-300 border border-slate-700 transition text-[11px]"
                title={`Réafficher le widget "${hw.title}"`}
              >
                <Eye className="w-3 h-3 text-cyan-400" />
                <span>+ {hw.title}</span>
              </button>
            ))}
          </div>
          <button
            onClick={() => applyPresetLayout('full')}
            className="text-[11px] text-cyan-400 hover:text-cyan-300 underline underline-offset-4"
          >
            Tout réafficher
          </button>
        </div>
      )}

      {/* Side-by-Side Report Comparison & Regression Section (when opened) */}
      {isComparisonOpen && (
        <ReportComparisonSection
          currentAnalysis={analysis}
          historyList={historyList}
          currentDeviceName={deviceName}
          onRestoreAnalysis={onRestoreAnalysis}
          onClose={() => setIsComparisonOpen(false)}
        />
      )}

      {/* Customizable 12-Column Security Widget Grid */}
      {visibleWidgets.length === 0 ? (
        <div className="p-12 rounded-2xl bg-slate-900/80 border border-slate-800 text-center space-y-4">
          <LayoutGrid className="w-10 h-10 text-slate-600 mx-auto" />
          <div className="space-y-1">
            <h3 className="text-base font-bold text-white">
              Tous les widgets du Dashboard sont actuellement masqués
            </h3>
            <p className="text-xs text-slate-400 font-mono">
              Activez les indicateurs de votre choix ou restaurez la disposition par défaut.
            </p>
          </div>
          <button
            onClick={resetDefaultLayout}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono font-bold transition"
          >
            <RotateCcw className="w-4 h-4" />
            <span>Restaurer tous les widgets</span>
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-12 gap-6 items-start">
          {visibleWidgets.map((widget) => {
            const globalIndex = widgets.findIndex((w) => w.id === widget.id);
            const isBeingDraggedOver = dragOverWidgetId === widget.id;

            return (
              <div
                key={widget.id}
                draggable={isCustomizingGrid}
                onDragStart={() => {
                  setDraggedWidgetId(widget.id);
                }}
                onDragOver={(e) => {
                  e.preventDefault();
                  if (draggedWidgetId && draggedWidgetId !== widget.id) {
                    setDragOverWidgetId(widget.id);
                  }
                }}
                onDragLeave={() => {
                  if (dragOverWidgetId === widget.id) {
                    setDragOverWidgetId(null);
                  }
                }}
                onDrop={(e) => {
                  e.preventDefault();
                  if (draggedWidgetId && draggedWidgetId !== widget.id) {
                    reorderWidgetsByDrag(draggedWidgetId, widget.id);
                  }
                  setDraggedWidgetId(null);
                  setDragOverWidgetId(null);
                }}
                onDragEnd={() => {
                  setDraggedWidgetId(null);
                  setDragOverWidgetId(null);
                }}
                className={`${getColSpanClass(widget.colSpan)} group/widget relative transition-all duration-200 ${
                  isBeingDraggedOver
                    ? 'ring-2 ring-emerald-400 rounded-2xl bg-emerald-950/10'
                    : ''
                } ${
                  isCustomizingGrid
                    ? 'p-2 rounded-2xl border border-dashed border-emerald-700/60 bg-slate-950/30'
                    : ''
                }`}
              >
                {/* Widget Control Header Bar */}
                <div
                  className={`flex items-center justify-between gap-2 px-3 py-1.5 mb-2 rounded-xl border text-xs font-mono transition-all ${
                    isCustomizingGrid
                      ? 'bg-slate-900 border-emerald-800/80 text-slate-200 shadow-md'
                      : 'bg-slate-900/75 border-slate-800/80 text-slate-400 opacity-85 hover:opacity-100 hover:border-slate-700'
                  }`}
                >
                  <div
                    draggable={isCustomizingGrid}
                    onDragStart={(e) => {
                      if (!isCustomizingGrid) return;
                      e.stopPropagation();
                      setDraggedWidgetId(widget.id);
                    }}
                    className={`flex items-center gap-2 min-w-0 ${
                      isCustomizingGrid ? 'cursor-grab active:cursor-grabbing' : ''
                    }`}
                    title={isCustomizingGrid ? "Glisser-déposer pour déplacer ce widget dans la grille" : undefined}
                  >
                    {isCustomizingGrid && (
                      <GripVertical className="w-3.5 h-3.5 text-slate-500 hover:text-cyan-400 flex-shrink-0" />
                    )}
                    {getWidgetIcon(widget.id)}
                    <span className="font-semibold text-slate-200 truncate text-[11px]">
                      {widget.title}
                    </span>
                    <span className="hidden sm:inline text-[10px] text-slate-500 font-sans">
                      · {widget.category}
                    </span>
                  </div>

                  {/* Widget Action Buttons */}
                  <div className="flex items-center gap-1 flex-shrink-0">
                    {isCustomizingGrid && (
                      <>
                        <button
                          onClick={() => moveWidget(widget.id, 'up')}
                          disabled={globalIndex === 0}
                          className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-white disabled:opacity-25 disabled:pointer-events-none transition"
                          title="Monter ce widget dans la grille"
                        >
                          <ArrowUp className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => moveWidget(widget.id, 'down')}
                          disabled={globalIndex === widgets.length - 1}
                          className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-white disabled:opacity-25 disabled:pointer-events-none transition"
                          title="Descendre ce widget dans la grille"
                        >
                          <ArrowDown className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => cycleWidgetWidth(widget.id)}
                          className="hidden xl:inline-flex items-center gap-1 px-1.5 py-0.5 rounded hover:bg-slate-800 text-slate-400 hover:text-cyan-300 transition text-[10px]"
                          title={
                            widget.colSpan === 12
                              ? 'Réduire en demi-largeur (6 colonnes)'
                              : 'Étendre en pleine largeur (12 colonnes)'
                          }
                        >
                          {widget.colSpan === 12 ? (
                            <Minimize2 className="w-3 h-3" />
                          ) : (
                            <Maximize2 className="w-3 h-3" />
                          )}
                          <span>{widget.colSpan === 12 ? '100%' : `${Math.round((widget.colSpan / 12) * 100)}%`}</span>
                        </button>
                      </>
                    )}
                    <button
                      onClick={() => toggleWidgetCollapse(widget.id)}
                      className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-white transition"
                      title={widget.collapsed ? 'Déplier le contenu du widget' : 'Réduire le contenu du widget'}
                    >
                      {widget.collapsed ? (
                        <ChevronDown className="w-3.5 h-3.5" />
                      ) : (
                        <ChevronUp className="w-3.5 h-3.5" />
                      )}
                    </button>
                    <button
                      onClick={() => toggleWidgetVisibility(widget.id)}
                      className="p-1 rounded hover:bg-red-950/60 text-slate-500 hover:text-red-400 transition"
                      title="Masquer cet indicateur du Dashboard"
                    >
                      <EyeOff className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>

                {/* Widget Content Body */}
                {!widget.collapsed && renderWidgetBody(widget.id)}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

