import React, { useMemo, useState } from 'react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Cell,
  CartesianGrid,
  Legend,
  ComposedChart,
  Area,
  Line,
} from 'recharts';
import {
  Globe,
  Clock,
  Flame,
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  Filter,
  Search,
  ExternalLink,
  ChevronRight,
  TrendingUp,
  MapPin,
  Calendar,
  Layers,
  Sparkles,
} from 'lucide-react';
import { LogEntry, ThreatAnalysisResult, StopAction } from '../types';

interface AttackHeatmapVisualizerProps {
  logs: LogEntry[];
  analysis: ThreatAnalysisResult;
  onInspectLog?: (log: LogEntry) => void;
  onEnforceDefense?: (action: StopAction) => Promise<void>;
  deviceName?: string;
}

export type HeatmapViewMode = 'TIME_OF_DAY' | 'GEO_LOCATION' | 'CROSS_MATRIX';
export type HeatmapSeverityFilter = 'ALL' | 'CRITICAL_HIGH' | 'BLOCKED_ONLY';

// Geographic metadata mapping for external source IPs
export interface GeoCountryMeta {
  code: string;
  name: string;
  flag: string;
  continent: string;
}

const KNOWN_GEO_COUNTRIES: Record<string, GeoCountryMeta> = {
  RU: { code: 'RU', name: 'Russie', flag: '🇷🇺', continent: 'Europe de l\'Est' },
  CN: { code: 'CN', name: 'Chine', flag: '🇨🇳', continent: 'Asie-Pacifique' },
  US: { code: 'US', name: 'États-Unis', flag: '🇺🇸', continent: 'Amérique du Nord' },
  NL: { code: 'NL', name: 'Pays-Bas', flag: '🇳🇱', continent: 'Europe de l\'Ouest' },
  KP: { code: 'KP', name: 'Corée du Nord', flag: '🇰🇵', continent: 'Asie de l\'Est' },
  IR: { code: 'IR', name: 'Iran', flag: '🇮🇷', continent: 'Moyen-Orient' },
  BR: { code: 'BR', name: 'Brésil', flag: '🇧🇷', continent: 'Amérique du Sud' },
  DE: { code: 'DE', name: 'Allemagne', flag: '🇩🇪', continent: 'Europe de l\'Ouest' },
  FR: { code: 'FR', name: 'France', flag: '🇫🇷', continent: 'Europe de l\'Ouest' },
  UA: { code: 'UA', name: 'Ukraine', flag: '🇺🇦', continent: 'Europe de l\'Est' },
  RO: { code: 'RO', name: 'Roumanie', flag: '🇷🇴', continent: 'Europe de l\'Est' },
  VN: { code: 'VN', name: 'Vietnam', flag: '🇻🇳', continent: 'Asie du Sud-Est' },
  IN: { code: 'IN', name: 'Inde', flag: '🇮🇳', continent: 'Asie du Sud' },
  GB: { code: 'GB', name: 'Royaume-Uni', flag: '🇬🇧', continent: 'Europe de l\'Ouest' },
};

// Fallback IP to country determinator
function resolveCountryForIp(ip: string, logCountry?: string, iocCountry?: string): GeoCountryMeta {
  if (logCountry && KNOWN_GEO_COUNTRIES[logCountry.toUpperCase()]) {
    return KNOWN_GEO_COUNTRIES[logCountry.toUpperCase()];
  }
  if (iocCountry && KNOWN_GEO_COUNTRIES[iocCountry.toUpperCase()]) {
    return KNOWN_GEO_COUNTRIES[iocCountry.toUpperCase()];
  }

  // Check RFC1918 private IPs
  if (
    ip.startsWith('192.168.') ||
    ip.startsWith('10.') ||
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip) ||
    ip === '127.0.0.1' ||
    ip === '0.0.0.0'
  ) {
    return { code: 'LAN', name: 'Réseau Interne (LAN)', flag: '🏢', continent: 'Intranet Privé' };
  }

  // Deterministic mapping for public IPs based on IP prefix
  if (ip.startsWith('91.240.') || ip.startsWith('185.220.') || ip.startsWith('45.154.')) {
    return KNOWN_GEO_COUNTRIES['RU'];
  }
  if (ip.startsWith('218.92.') || ip.startsWith('103.') || ip.startsWith('112.')) {
    return KNOWN_GEO_COUNTRIES['CN'];
  }
  if (ip.startsWith('198.51.') || ip.startsWith('23.') || ip.startsWith('52.')) {
    return KNOWN_GEO_COUNTRIES['US'];
  }
  if (ip.startsWith('194.26.') || ip.startsWith('185.100.')) {
    return KNOWN_GEO_COUNTRIES['NL'];
  }
  if (ip.startsWith('175.45.') || ip.startsWith('210.52.')) {
    return KNOWN_GEO_COUNTRIES['KP'];
  }
  if (ip.startsWith('5.127.') || ip.startsWith('91.98.')) {
    return KNOWN_GEO_COUNTRIES['IR'];
  }
  if (ip.startsWith('177.') || ip.startsWith('187.')) {
    return KNOWN_GEO_COUNTRIES['BR'];
  }

  // Hash-based fallback from available country list for variety in demo/test environments
  const charSum = ip.split('').reduce((acc, c) => acc + c.charCodeAt(0), 0);
  const countryCodes = ['RU', 'CN', 'US', 'NL', 'IR', 'KP', 'BR', 'DE', 'RO'];
  const code = countryCodes[charSum % countryCodes.length];
  return KNOWN_GEO_COUNTRIES[code] || {
    code: 'EXT',
    name: 'WAN Indéterminé',
    flag: '🌐',
    continent: 'International',
  };
}

// Color scale for attack density / heat rating
function getHeatColor(count: number, maxCount: number): string {
  if (count === 0) return '#0f172a'; // slate-900 (neutral/quiet)
  const ratio = maxCount > 0 ? count / maxCount : 0;
  if (ratio > 0.8) return '#ef4444'; // Red-500 (critical peak)
  if (ratio > 0.55) return '#f97316'; // Orange-500 (high)
  if (ratio > 0.35) return '#f59e0b'; // Amber-500 (moderate-high)
  if (ratio > 0.15) return '#06b6d4'; // Cyan-500 (moderate)
  return '#10b981'; // Emerald-500 (low/baseline)
}

function getIntensityLabel(count: number, maxCount: number): string {
  if (count === 0) return 'Inactif';
  const ratio = maxCount > 0 ? count / maxCount : 0;
  if (ratio > 0.8) return 'Critique (Saturation)';
  if (ratio > 0.55) return 'Très Élevé';
  if (ratio > 0.35) return 'Élevé';
  if (ratio > 0.15) return 'Modéré';
  return 'Faible';
}

const TIME_SLOTS_6 = [
  { id: '00-04', label: '00h - 04h (Nuit profonde)', shortLabel: '00h-04h', startH: 0, endH: 3 },
  { id: '04-08', label: '04h - 08h (Aube)', shortLabel: '04h-08h', startH: 4, endH: 7 },
  { id: '08-12', label: '08h - 12h (Matinée)', shortLabel: '08h-12h', startH: 8, endH: 11 },
  { id: '12-16', label: '12h - 16h (Après-midi)', shortLabel: '12h-16h', startH: 12, endH: 15 },
  { id: '16-20', label: '16h - 20h (Fin de journée)', shortLabel: '16h-20h', startH: 16, endH: 19 },
  { id: '20-24', label: '20h - 24h (Soirée)', shortLabel: '20h-24h', startH: 20, endH: 23 },
];

export const AttackHeatmapVisualizer: React.FC<AttackHeatmapVisualizerProps> = ({
  logs,
  analysis,
  onInspectLog,
  onEnforceDefense,
  deviceName = 'Passerelle Zyxel Nebula ATP',
}) => {
  const [viewMode, setViewMode] = useState<HeatmapViewMode>('TIME_OF_DAY');
  const [severityFilter, setSeverityFilter] = useState<HeatmapSeverityFilter>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedCountryCode, setSelectedCountryCode] = useState<string | null>(null);
  const [selectedHour, setSelectedHour] = useState<number | null>(null);

  // Filter logs based on severity and query
  const filteredLogs = useMemo(() => {
    return logs.filter((log) => {
      if (severityFilter === 'CRITICAL_HIGH') {
        if (log.severity !== 'CRITICAL' && log.severity !== 'HIGH') return false;
      } else if (severityFilter === 'BLOCKED_ONLY') {
        if (log.action !== 'Blocked' && log.action !== 'Dropped' && log.action !== 'Quarantined') {
          return false;
        }
      }

      if (searchQuery.trim()) {
        const q = searchQuery.trim().toLowerCase();
        const hay = `${log.srcIp} ${log.dstIp} ${log.threatName} ${log.category} ${log.country || ''}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }

      return true;
    });
  }, [logs, severityFilter, searchQuery]);

  // Extract hour from log timestamp (0 to 23)
  const getLogHour = (log: LogEntry): number => {
    try {
      const date = new Date(log.timestamp);
      if (!isNaN(date.getTime())) {
        return date.getHours();
      }
    } catch {
      // ignore
    }
    // Fallback: search regex HH:MM
    const match = log.timestamp.match(/(\d{2}):(\d{2})/);
    if (match) {
      return parseInt(match[1], 10) % 24;
    }
    // Hash fallback
    return (log.id.length * 7) % 24;
  };

  // 1. Time of Day Data (24 Hours)
  const hourlyData = useMemo(() => {
    const hours = Array.from({ length: 24 }, (_, i) => ({
      hour: i,
      hourLabel: `${i.toString().padStart(2, '0')}:00`,
      totalAttacks: 0,
      criticalAttacks: 0,
      blockedAttacks: 0,
      alertedAttacks: 0,
      topThreats: new Map<string, number>(),
      sourceIps: new Set<string>(),
      logs: [] as LogEntry[],
    }));

    filteredLogs.forEach((log) => {
      const h = getLogHour(log);
      const slot = hours[h];
      if (slot) {
        slot.totalAttacks += 1;
        if (log.severity === 'CRITICAL') slot.criticalAttacks += 1;
        if (log.action === 'Blocked' || log.action === 'Dropped' || log.action === 'Quarantined') {
          slot.blockedAttacks += 1;
        } else {
          slot.alertedAttacks += 1;
        }
        slot.topThreats.set(log.threatName, (slot.topThreats.get(log.threatName) || 0) + 1);
        slot.sourceIps.add(log.srcIp);
        slot.logs.push(log);
      }
    });

    const maxCount = Math.max(...hours.map((h) => h.totalAttacks), 1);

    return hours.map((h) => {
      const sortedThreats = Array.from(h.topThreats.entries()).sort((a, b) => b[1] - a[1]);
      const dominantThreat = sortedThreats[0]?.[0] || 'Activité résiduelle';
      const heatColor = getHeatColor(h.totalAttacks, maxCount);
      const blockRate = h.totalAttacks > 0 ? Math.round((h.blockedAttacks / h.totalAttacks) * 100) : 100;

      return {
        ...h,
        dominantThreat,
        uniqueIps: h.sourceIps.size,
        heatColor,
        blockRate,
        intensity: getIntensityLabel(h.totalAttacks, maxCount),
      };
    });
  }, [filteredLogs]);

  const maxHourlyCount = useMemo(() => {
    return Math.max(...hourlyData.map((h) => h.totalAttacks), 1);
  }, [hourlyData]);

  const peakHour = useMemo(() => {
    return hourlyData.reduce((max, cur) => (cur.totalAttacks > max.totalAttacks ? cur : max), hourlyData[0]);
  }, [hourlyData]);

  // 2. Geographic Location Data
  const geoData = useMemo(() => {
    const countryMap = new Map<
      string,
      {
        countryMeta: GeoCountryMeta;
        totalAttacks: number;
        criticalAttacks: number;
        blockedAttacks: number;
        alertedAttacks: number;
        sourceIps: Set<string>;
        topThreats: Map<string, number>;
        timeSlots: Record<string, number>;
        logs: LogEntry[];
      }
    >();

    filteredLogs.forEach((log) => {
      const iocMatch = analysis.iocList.find((i) => i.value === log.srcIp);
      const meta = resolveCountryForIp(log.srcIp, log.country, iocMatch?.country);

      if (!countryMap.has(meta.code)) {
        countryMap.set(meta.code, {
          countryMeta: meta,
          totalAttacks: 0,
          criticalAttacks: 0,
          blockedAttacks: 0,
          alertedAttacks: 0,
          sourceIps: new Set(),
          topThreats: new Map(),
          timeSlots: {
            '00-04': 0,
            '04-08': 0,
            '08-12': 0,
            '12-16': 0,
            '16-20': 0,
            '20-24': 0,
          },
          logs: [],
        });
      }

      const entry = countryMap.get(meta.code)!;
      entry.totalAttacks += 1;
      if (log.severity === 'CRITICAL') entry.criticalAttacks += 1;
      if (log.action === 'Blocked' || log.action === 'Dropped' || log.action === 'Quarantined') {
        entry.blockedAttacks += 1;
      } else {
        entry.alertedAttacks += 1;
      }
      entry.sourceIps.add(log.srcIp);
      entry.topThreats.set(log.threatName, (entry.topThreats.get(log.threatName) || 0) + 1);
      entry.logs.push(log);

      // Slot allocation
      const hour = getLogHour(log);
      const slot = TIME_SLOTS_6.find((s) => hour >= s.startH && hour <= s.endH) || TIME_SLOTS_6[0];
      entry.timeSlots[slot.id] = (entry.timeSlots[slot.id] || 0) + 1;
    });

    const list = Array.from(countryMap.values()).map((c) => {
      const topThreatEntries = Array.from(c.topThreats.entries()).sort((a, b) => b[1] - a[1]);
      const primaryThreat = topThreatEntries[0]?.[0] || 'Vecteur WAN indéterminé';
      const blockRate = c.totalAttacks > 0 ? Math.round((c.blockedAttacks / c.totalAttacks) * 100) : 100;

      return {
        code: c.countryMeta.code,
        name: c.countryMeta.name,
        flag: c.countryMeta.flag,
        continent: c.countryMeta.continent,
        totalAttacks: c.totalAttacks,
        criticalAttacks: c.criticalAttacks,
        blockedAttacks: c.blockedAttacks,
        alertedAttacks: c.alertedAttacks,
        uniqueIps: c.sourceIps.size,
        sourceIpsList: Array.from(c.sourceIps),
        primaryThreat,
        blockRate,
        timeSlots: c.timeSlots,
        logs: c.logs,
      };
    });

    return list.sort((a, b) => b.totalAttacks - a.totalAttacks);
  }, [filteredLogs, analysis]);

  const maxGeoCount = useMemo(() => {
    return Math.max(...geoData.map((g) => g.totalAttacks), 1);
  }, [geoData]);

  const topAttackingCountry = geoData[0] || null;

  // 3. Cross Matrix Data (Top 7 countries x 6 time slots)
  const crossMatrixData = useMemo(() => {
    const topCountries = geoData.slice(0, 7);

    return TIME_SLOTS_6.map((slot) => {
      const row: Record<string, any> = {
        slotId: slot.id,
        slotLabel: slot.shortLabel,
        fullLabel: slot.label,
        totalInSlot: 0,
      };

      topCountries.forEach((country) => {
        const val = country.timeSlots[slot.id] || 0;
        row[country.code] = val;
        row.totalInSlot += val;
      });

      return row;
    });
  }, [geoData]);

  // Overall KPI metrics
  const totalAttacksCount = filteredLogs.length;
  const criticalAttacksCount = filteredLogs.filter((l) => l.severity === 'CRITICAL').length;
  const overallBlockedRate =
    totalAttacksCount > 0
      ? Math.round(
          (filteredLogs.filter(
            (l) => l.action === 'Blocked' || l.action === 'Dropped' || l.action === 'Quarantined'
          ).length /
            totalAttacksCount) *
            100
        )
      : 100;

  return (
    <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-6">
      {/* Top Header & Interactive Mode Switcher */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="p-2 rounded-xl bg-gradient-to-br from-rose-500/20 to-amber-500/10 border border-rose-500/30 text-rose-400">
              <Flame className="w-5 h-5 animate-pulse" />
            </span>
            <div>
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                Heatmap des Sources d’Attaque (Recharts)
                <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-rose-950/80 text-rose-300 border border-rose-800/80">
                  Matrice Temporelle & Géo-Spatiale
                </span>
              </h3>
              <p className="text-xs text-slate-400 font-mono">
                Visualisation Recharts de l’intensité des agressions par tranche horaire (00h-23h) et par localisation géographique WAN
              </p>
            </div>
          </div>
        </div>

        {/* View Mode Toggle Buttons */}
        <div className="flex flex-wrap items-center gap-1.5 p-1 rounded-xl bg-slate-950/90 border border-slate-800 self-start lg:self-auto">
          <button
            onClick={() => setViewMode('TIME_OF_DAY')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition ${
              viewMode === 'TIME_OF_DAY'
                ? 'bg-cyan-600 text-white shadow-md shadow-cyan-900/30'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/70'
            }`}
            title="Afficher la distribution thermique sur les 24 heures de la journée"
          >
            <Clock className="w-3.5 h-3.5" />
            <span>Heure de la Journée (00h-23h)</span>
          </button>

          <button
            onClick={() => setViewMode('GEO_LOCATION')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition ${
              viewMode === 'GEO_LOCATION'
                ? 'bg-amber-600 text-white shadow-md shadow-amber-900/30'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/70'
            }`}
            title="Afficher la carte thermique par pays d'origine et régions"
          >
            <Globe className="w-3.5 h-3.5" />
            <span>Localisation Géographique</span>
          </button>

          <button
            onClick={() => setViewMode('CROSS_MATRIX')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition ${
              viewMode === 'CROSS_MATRIX'
                ? 'bg-purple-600 text-white shadow-md shadow-purple-900/30'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/70'
            }`}
            title="Afficher la matrice croisée Pays × Plages horaires"
          >
            <Layers className="w-3.5 h-3.5" />
            <span>Matrice Croisée (Géo × Heure)</span>
          </button>
        </div>
      </div>

      {/* KPI Top Highlights Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
        <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 space-y-1">
          <div className="flex items-center justify-between text-slate-400">
            <span>Volume Total Observé</span>
            <AlertTriangle className="w-3.5 h-3.5 text-cyan-400" />
          </div>
          <div className="text-xl font-bold text-white">{totalAttacksCount} flux</div>
          <div className="text-[10px] text-rose-400 font-bold">{criticalAttacksCount} événements critiques</div>
        </div>

        <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 space-y-1">
          <div className="flex items-center justify-between text-slate-400">
            <span>Pic Horaire Critique</span>
            <Clock className="w-3.5 h-3.5 text-rose-400" />
          </div>
          <div className="text-xl font-bold text-rose-300">
            {peakHour ? `${peakHour.hourLabel}` : 'N/A'}
          </div>
          <div className="text-[10px] text-slate-400 truncate">
            {peakHour ? `${peakHour.totalAttacks} attaques (${peakHour.dominantThreat})` : 'Aucun pic'}
          </div>
        </div>

        <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 space-y-1">
          <div className="flex items-center justify-between text-slate-400">
            <span>Top Foyer Géographique</span>
            <Globe className="w-3.5 h-3.5 text-amber-400" />
          </div>
          <div className="text-xl font-bold text-amber-300 flex items-center gap-1.5 truncate">
            <span>{topAttackingCountry?.flag || '🌐'}</span>
            <span className="truncate">{topAttackingCountry?.name || 'Inconnu'}</span>
          </div>
          <div className="text-[10px] text-amber-400/90 truncate">
            {topAttackingCountry ? `${topAttackingCountry.totalAttacks} alertes (${topAttackingCountry.uniqueIps} IPs)` : 'N/A'}
          </div>
        </div>

        <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 space-y-1">
          <div className="flex items-center justify-between text-slate-400">
            <span>Taux de Blocage IDP</span>
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div className="text-xl font-bold text-emerald-400">{overallBlockedRate}%</div>
          <div className="text-[10px] text-slate-400">Interceptions passerelle Zyxel</div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-slate-400 flex items-center gap-1">
            <Filter className="w-3 h-3 text-slate-500" />
            Filtrer par sévérité :
          </span>
          <button
            onClick={() => setSeverityFilter('ALL')}
            className={`px-2.5 py-1 rounded-lg border transition ${
              severityFilter === 'ALL'
                ? 'bg-slate-800 text-white border-slate-600'
                : 'bg-slate-950/60 text-slate-400 border-slate-800 hover:text-white'
            }`}
          >
            Tous les flux ({logs.length})
          </button>
          <button
            onClick={() => setSeverityFilter('CRITICAL_HIGH')}
            className={`px-2.5 py-1 rounded-lg border transition ${
              severityFilter === 'CRITICAL_HIGH'
                ? 'bg-rose-950 text-rose-300 border-rose-700'
                : 'bg-slate-950/60 text-slate-400 border-slate-800 hover:text-rose-300'
            }`}
          >
            Critique & Élevé
          </button>
          <button
            onClick={() => setSeverityFilter('BLOCKED_ONLY')}
            className={`px-2.5 py-1 rounded-lg border transition ${
              severityFilter === 'BLOCKED_ONLY'
                ? 'bg-emerald-950 text-emerald-300 border-emerald-700'
                : 'bg-slate-950/60 text-slate-400 border-slate-800 hover:text-emerald-300'
            }`}
          >
            Bloqués / Droppés
          </button>
        </div>

        {/* Live Search Input */}
        <div className="relative min-w-[200px] flex-1 max-w-xs">
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Rechercher IP, Pays, signature..."
            className="w-full bg-slate-950/90 border border-slate-800 rounded-lg pl-8 pr-3 py-1 text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 text-xs"
          />
        </div>
      </div>

      {/* MODE 1: TIME OF DAY HEATMAP (00H - 23H) */}
      {viewMode === 'TIME_OF_DAY' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono">
            <span className="text-slate-300 font-bold flex items-center gap-1.5">
              <Clock className="w-4 h-4 text-cyan-400" />
              Distribution Thermique par Heure de la Journée (Heure Locale / UTC)
            </span>
            <div className="flex items-center gap-2 text-[11px] text-slate-400">
              <span className="flex items-center gap-1">
                <span className="w-2.5 h-2.5 rounded-sm bg-slate-800 inline-block" /> Nul (0)
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2.5 h-2.5 rounded-sm bg-emerald-500 inline-block" /> Faible
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2.5 h-2.5 rounded-sm bg-cyan-500 inline-block" /> Modéré
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2.5 h-2.5 rounded-sm bg-amber-500 inline-block" /> Élevé
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2.5 h-2.5 rounded-sm bg-rose-500 inline-block" /> Critique
              </span>
            </div>
          </div>

          {/* Recharts Bar Heatmap */}
          <div className="h-64 w-full bg-slate-950/80 rounded-xl p-3 border border-slate-800">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={hourlyData}
                margin={{ top: 10, right: 10, left: -20, bottom: 20 }}
                onClick={(e: any) => {
                  if (e && e.activePayload && e.activePayload[0]) {
                    const data = e.activePayload[0].payload;
                    setSelectedHour(data.hour);
                  }
                }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis
                  dataKey="hourLabel"
                  stroke="#64748b"
                  fontSize={10}
                  tickLine={false}
                  interval={1}
                />
                <YAxis stroke="#64748b" fontSize={10} tickLine={false} />
                <Tooltip
                  cursor={{ fill: 'rgba(255, 255, 255, 0.05)' }}
                  content={({ active, payload }) => {
                    if (active && payload && payload.length) {
                      const data = payload[0].payload;
                      return (
                        <div className="p-3 bg-slate-950 border border-slate-700 rounded-xl shadow-2xl text-xs font-mono space-y-1.5 z-50">
                          <div className="flex items-center justify-between gap-3 border-b border-slate-800 pb-1">
                            <span className="font-bold text-white flex items-center gap-1">
                              <Clock className="w-3.5 h-3.5 text-cyan-400" />
                              Créneau {data.hourLabel} - {`${(data.hour + 1).toString().padStart(2, '0')}:00`}
                            </span>
                            <span
                              className="px-1.5 py-0.5 rounded text-[10px] font-bold"
                              style={{ backgroundColor: `${data.heatColor}25`, color: data.heatColor }}
                            >
                              {data.intensity}
                            </span>
                          </div>
                          <div className="space-y-1 text-[11px]">
                            <div className="text-slate-300">
                              Total flux d'attaques : <span className="font-bold text-white">{data.totalAttacks}</span>
                            </div>
                            <div className="text-rose-400">
                              Attaques critiques : <span className="font-bold">{data.criticalAttacks}</span>
                            </div>
                            <div className="text-emerald-400">
                              Blocages Zyxel : <span className="font-bold">{data.blockedAttacks} ({data.blockRate}%)</span>
                            </div>
                            <div className="text-amber-300">
                              Adresses IP sources distinctes : <span className="font-bold">{data.uniqueIps}</span>
                            </div>
                            <div className="text-slate-400 truncate max-w-[220px]">
                              Menace prédominante : <span className="text-cyan-300">{data.dominantThreat}</span>
                            </div>
                          </div>
                          <div className="text-[10px] text-cyan-400/90 pt-1 border-t border-slate-800/80">
                            Cliquez pour isoler les logs de cette heure
                          </div>
                        </div>
                      );
                    }
                    return null;
                  }}
                />
                <Bar dataKey="totalAttacks" radius={[4, 4, 0, 0]}>
                  {hourlyData.map((entry, index) => (
                    <Cell
                      key={`cell-${index}`}
                      fill={entry.heatColor}
                      stroke={selectedHour === entry.hour ? '#ffffff' : 'none'}
                      strokeWidth={selectedHour === entry.hour ? 2 : 0}
                      className="cursor-pointer transition-all hover:opacity-80"
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* 2D Interactive Hour Matrix Grid Cells */}
          <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 space-y-2">
            <div className="flex items-center justify-between text-xs font-mono text-slate-400">
              <span className="font-bold text-slate-300">Matrice Thermique des 24 Heures (Densité par Cellule) :</span>
              {selectedHour !== null && (
                <button
                  onClick={() => setSelectedHour(null)}
                  className="text-cyan-400 hover:text-cyan-300 underline text-[11px]"
                >
                  Réinitialiser le filtre heure ({selectedHour}:00)
                </button>
              )}
            </div>

            <div className="grid grid-cols-6 sm:grid-cols-12 md:grid-cols-24 gap-1">
              {hourlyData.map((h) => {
                const isSelected = selectedHour === h.hour;
                return (
                  <button
                    key={h.hour}
                    onClick={() => setSelectedHour(isSelected ? null : h.hour)}
                    className={`p-1.5 rounded-lg border text-center transition flex flex-col items-center justify-between min-h-[58px] ${
                      isSelected
                        ? 'border-white ring-2 ring-cyan-400/50 bg-slate-800'
                        : 'border-slate-800/80 hover:border-slate-600'
                    }`}
                    style={{
                      backgroundColor: isSelected ? undefined : `${h.heatColor}18`,
                    }}
                    title={`${h.hourLabel} : ${h.totalAttacks} attaques (${h.intensity})`}
                  >
                    <span className="text-[10px] font-mono text-slate-400">{h.hour}h</span>
                    <span
                      className="text-xs font-mono font-bold"
                      style={{ color: h.totalAttacks === 0 ? '#64748b' : h.heatColor }}
                    >
                      {h.totalAttacks}
                    </span>
                    <div
                      className="w-full h-1 rounded-full mt-1"
                      style={{ backgroundColor: h.heatColor }}
                    />
                  </button>
                );
              })}
            </div>
          </div>

          {/* 6 Time Slots Breakdown (Operational Shift Analysis) */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 text-xs font-mono">
            {TIME_SLOTS_6.map((slot) => {
              const inSlot = hourlyData.filter((h) => h.hour >= slot.startH && h.hour <= slot.endH);
              const slotTotal = inSlot.reduce((sum, h) => sum + h.totalAttacks, 0);
              const slotCrit = inSlot.reduce((sum, h) => sum + h.criticalAttacks, 0);
              const slotRatio = maxHourlyCount * 4 > 0 ? slotTotal / (maxHourlyCount * 4) : 0;
              const slotColor = getHeatColor(slotTotal, maxHourlyCount * 4);

              return (
                <div
                  key={slot.id}
                  className="p-3 rounded-xl bg-slate-950/80 border border-slate-800/90 flex flex-col justify-between space-y-2 hover:border-slate-700 transition"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-slate-200">{slot.label}</span>
                    <span
                      className="px-2 py-0.5 rounded text-[10px] font-bold"
                      style={{ backgroundColor: `${slotColor}25`, color: slotColor }}
                    >
                      {slotTotal} flux
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-[11px] text-slate-400">
                    <span>Attaques critiques : <strong className="text-rose-400">{slotCrit}</strong></span>
                    <span>Ratio : <strong>{Math.round(slotRatio * 100)}%</strong></span>
                  </div>
                  <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                    <div
                      className="h-full rounded-full transition-all duration-300"
                      style={{ width: `${Math.min(100, Math.round(slotRatio * 100))}%`, backgroundColor: slotColor }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* MODE 2: GEOGRAPHIC LOCATION HEATMAP */}
      {viewMode === 'GEO_LOCATION' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono">
            <span className="text-slate-300 font-bold flex items-center gap-1.5">
              <Globe className="w-4 h-4 text-amber-400" />
              Répartition Thermique par Pays & Territoire d'Origine WAN
            </span>
            <div className="flex items-center gap-2 text-[11px] text-slate-400">
              <span className="flex items-center gap-1">
                <span className="w-2.5 h-2.5 rounded-sm bg-emerald-500 inline-block" /> Surveillance normale
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2.5 h-2.5 rounded-sm bg-amber-500 inline-block" /> Foyer sous tension
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2.5 h-2.5 rounded-sm bg-rose-500 inline-block" /> Foyer hostile critique
              </span>
            </div>
          </div>

          {/* Recharts Horizontal Bar Chart for Countries */}
          <div className="h-72 w-full bg-slate-950/80 rounded-xl p-3 border border-slate-800">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={geoData.slice(0, 10)}
                layout="vertical"
                margin={{ top: 10, right: 30, left: 60, bottom: 10 }}
                onClick={(e: any) => {
                  if (e && e.activePayload && e.activePayload[0]) {
                    const country = e.activePayload[0].payload;
                    setSelectedCountryCode(country.code);
                  }
                }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                <XAxis type="number" stroke="#64748b" fontSize={10} tickLine={false} />
                <YAxis
                  type="category"
                  dataKey="name"
                  stroke="#94a3b8"
                  fontSize={11}
                  tickLine={false}
                  tick={({ x, y, payload }) => {
                    const country = geoData.find((g) => g.name === payload.value);
                    return (
                      <g transform={`translate(${x},${y})`}>
                        <text
                          x={-6}
                          y={4}
                          textAnchor="end"
                          fill="#cbd5e1"
                          fontSize={11}
                          fontFamily="monospace"
                        >
                          {country?.flag} {payload.value}
                        </text>
                      </g>
                    );
                  }}
                />
                <Tooltip
                  cursor={{ fill: 'rgba(255, 255, 255, 0.05)' }}
                  content={({ active, payload }) => {
                    if (active && payload && payload.length) {
                      const data = payload[0].payload;
                      const heatColor = getHeatColor(data.totalAttacks, maxGeoCount);
                      return (
                        <div className="p-3 bg-slate-950 border border-slate-700 rounded-xl shadow-2xl text-xs font-mono space-y-1.5 z-50">
                          <div className="flex items-center justify-between gap-3 border-b border-slate-800 pb-1">
                            <span className="font-bold text-white flex items-center gap-1.5">
                              <span>{data.flag}</span>
                              <span>{data.name} ({data.code})</span>
                            </span>
                            <span className="text-slate-400 text-[10px]">{data.continent}</span>
                          </div>
                          <div className="space-y-1 text-[11px]">
                            <div className="text-slate-300">
                              Volume total : <strong className="text-white">{data.totalAttacks}</strong> alertes
                            </div>
                            <div className="text-rose-400">
                              Attaques critiques : <strong>{data.criticalAttacks}</strong>
                            </div>
                            <div className="text-emerald-400">
                              Taux de neutralisation Zyxel : <strong>{data.blockRate}%</strong>
                            </div>
                            <div className="text-amber-300">
                              IPs émettrices distinctes : <strong>{data.uniqueIps}</strong>
                            </div>
                            <div className="text-cyan-300 truncate max-w-[240px]">
                              Vecteur d'attaque dominant : <strong>{data.primaryThreat}</strong>
                            </div>
                          </div>
                          <div className="text-[10px] text-cyan-400/90 pt-1 border-t border-slate-800/80">
                            Cliquez pour examiner les IPs de ce pays
                          </div>
                        </div>
                      );
                    }
                    return null;
                  }}
                />
                <Bar dataKey="totalAttacks" radius={[0, 4, 4, 0]}>
                  {geoData.slice(0, 10).map((entry, index) => {
                    const color = getHeatColor(entry.totalAttacks, maxGeoCount);
                    return (
                      <Cell
                        key={`geo-cell-${index}`}
                        fill={color}
                        stroke={selectedCountryCode === entry.code ? '#ffffff' : 'none'}
                        strokeWidth={selectedCountryCode === entry.code ? 2 : 0}
                        className="cursor-pointer hover:opacity-80 transition"
                      />
                    );
                  })}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Country Threat Cards Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 text-xs font-mono">
            {geoData.map((country) => {
              const heatColor = getHeatColor(country.totalAttacks, maxGeoCount);
              const isSelected = selectedCountryCode === country.code;

              return (
                <div
                  key={country.code}
                  onClick={() => setSelectedCountryCode(isSelected ? null : country.code)}
                  className={`p-3.5 rounded-xl border transition cursor-pointer flex flex-col justify-between space-y-3 ${
                    isSelected
                      ? 'bg-slate-900 border-amber-500 ring-2 ring-amber-500/30 shadow-lg'
                      : 'bg-slate-950/70 border-slate-800/90 hover:border-slate-700'
                  }`}
                >
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="text-lg">{country.flag}</span>
                        <div>
                          <h4 className="font-bold text-white text-xs">{country.name}</h4>
                          <span className="text-[10px] text-slate-500">{country.continent}</span>
                        </div>
                      </div>
                      <span
                        className="px-2 py-0.5 rounded text-[10px] font-bold"
                        style={{ backgroundColor: `${heatColor}25`, color: heatColor }}
                      >
                        {country.totalAttacks} flux
                      </span>
                    </div>

                    <div className="pt-1 space-y-1 text-[11px]">
                      <div className="flex items-center justify-between text-slate-400">
                        <span>Attaques critiques :</span>
                        <strong className="text-rose-400">{country.criticalAttacks}</strong>
                      </div>
                      <div className="flex items-center justify-between text-slate-400">
                        <span>IPs uniques observées :</span>
                        <strong className="text-amber-300">{country.uniqueIps}</strong>
                      </div>
                      <div className="flex items-center justify-between text-slate-400">
                        <span>Blocages passerelle :</span>
                        <strong className="text-emerald-400">{country.blockRate}%</strong>
                      </div>
                    </div>
                  </div>

                  <div className="pt-2 border-t border-slate-800/70 text-[10px] text-slate-400 flex items-center justify-between">
                    <span className="truncate max-w-[170px]" title={country.primaryThreat}>
                      {country.primaryThreat}
                    </span>
                    <span className="text-cyan-400 font-bold hover:underline">
                      {isSelected ? 'Sélectionné' : 'Détails →'}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* MODE 3: CROSS MATRIX HEATMAP (TOP COUNTRIES × TIME SLOTS) */}
      {viewMode === 'CROSS_MATRIX' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono">
            <span className="text-slate-300 font-bold flex items-center gap-1.5">
              <Layers className="w-4 h-4 text-purple-400" />
              Matrice Croisée Recharts : Origine Géographique × Tranche Horaire
            </span>
            <span className="text-[11px] text-slate-400">
              Détection des campagnes d'attaques synchronisées par zone temporelle
            </span>
          </div>

          {/* Recharts Stacked / Composed Chart */}
          <div className="h-72 w-full bg-slate-950/80 rounded-xl p-3 border border-slate-800">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={crossMatrixData}
                margin={{ top: 15, right: 15, left: -10, bottom: 20 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis dataKey="fullLabel" stroke="#64748b" fontSize={10} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={10} tickLine={false} />
                <Tooltip
                  cursor={{ fill: 'rgba(255, 255, 255, 0.05)' }}
                  content={({ active, payload, label }) => {
                    if (active && payload && payload.length) {
                      return (
                        <div className="p-3 bg-slate-950 border border-slate-700 rounded-xl shadow-2xl text-xs font-mono space-y-2 z-50 min-w-[200px]">
                          <div className="font-bold text-white border-b border-slate-800 pb-1 flex items-center gap-1.5">
                            <Clock className="w-3.5 h-3.5 text-purple-400" />
                            {label}
                          </div>
                          <div className="space-y-1 text-[11px]">
                            {payload.map((entry: any, idx: number) => {
                              const country = geoData.find((g) => g.code === entry.dataKey);
                              return (
                                <div key={idx} className="flex items-center justify-between gap-3">
                                  <span className="flex items-center gap-1 text-slate-300">
                                    <span className="w-2 h-2 rounded-full" style={{ backgroundColor: entry.color }} />
                                    <span>{country?.flag} {country?.name || entry.dataKey}</span>
                                  </span>
                                  <span className="font-bold text-white">{entry.value} flux</span>
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      );
                    }
                    return null;
                  }}
                />
                <Legend
                  wrapperStyle={{ fontSize: '11px', fontFamily: 'monospace', paddingTop: '10px' }}
                />
                {geoData.slice(0, 6).map((country, idx) => {
                  const colors = ['#ef4444', '#f97316', '#f59e0b', '#06b6d4', '#a855f7', '#10b981'];
                  const color = colors[idx % colors.length];
                  return (
                    <Bar
                      key={country.code}
                      dataKey={country.code}
                      name={`${country.flag} ${country.name}`}
                      stackId="geoSlots"
                      fill={color}
                      radius={idx === 5 ? [4, 4, 0, 0] : [0, 0, 0, 0]}
                    />
                  );
                })}
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Cross Table Matrix Grid */}
          <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-950/70 p-3">
            <table className="w-full text-xs font-mono border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 text-left">
                  <th className="p-2">Pays Source WAN</th>
                  {TIME_SLOTS_6.map((slot) => (
                    <th key={slot.id} className="p-2 text-center">
                      {slot.shortLabel}
                    </th>
                  ))}
                  <th className="p-2 text-right">Total Flux</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {geoData.slice(0, 7).map((country) => (
                  <tr key={country.code} className="hover:bg-slate-900/40 transition">
                    <td className="p-2 text-slate-200 font-bold flex items-center gap-2">
                      <span className="text-base">{country.flag}</span>
                      <span>{country.name}</span>
                    </td>
                    {TIME_SLOTS_6.map((slot) => {
                      const count = country.timeSlots[slot.id] || 0;
                      const cellColor = getHeatColor(count, 15);
                      return (
                        <td key={slot.id} className="p-2 text-center">
                          <span
                            className="inline-block px-2 py-0.5 rounded text-[11px] font-bold"
                            style={{
                              backgroundColor: count === 0 ? '#1e293b30' : `${cellColor}25`,
                              color: count === 0 ? '#64748b' : cellColor,
                            }}
                          >
                            {count}
                          </span>
                        </td>
                      );
                    })}
                    <td className="p-2 text-right font-bold text-amber-300">
                      {country.totalAttacks}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Selected Drill-Down Logs & Context Actions (when a country or hour is clicked) */}
      {(selectedCountryCode || selectedHour !== null) && (
        <div className="p-4 rounded-xl bg-slate-950/95 border border-cyan-800/70 space-y-3">
          <div className="flex items-center justify-between text-xs font-mono">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-ping" />
              <span className="font-bold text-cyan-200">
                Focus d'Investigation :{' '}
                {selectedCountryCode && (
                  <span>
                    Pays{' '}
                    <strong className="text-white">
                      {geoData.find((g) => g.code === selectedCountryCode)?.name || selectedCountryCode}
                    </strong>
                  </span>
                )}
                {selectedCountryCode && selectedHour !== null && ' + '}
                {selectedHour !== null && (
                  <span>
                    Heure <strong className="text-white">{selectedHour}:00 - {selectedHour + 1}:00</strong>
                  </span>
                )}
              </span>
            </div>

            <button
              onClick={() => {
                setSelectedCountryCode(null);
                setSelectedHour(null);
              }}
              className="text-slate-400 hover:text-white underline text-[11px]"
            >
              Fermer le focus
            </button>
          </div>

          <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
            {filteredLogs
              .filter((log) => {
                if (selectedHour !== null && getLogHour(log) !== selectedHour) return false;
                if (selectedCountryCode) {
                  const iocMatch = analysis.iocList.find((i) => i.value === log.srcIp);
                  const meta = resolveCountryForIp(log.srcIp, log.country, iocMatch?.country);
                  if (meta.code !== selectedCountryCode) return false;
                }
                return true;
              })
              .slice(0, 10)
              .map((log) => (
                <div
                  key={log.id}
                  className="p-2 rounded-lg bg-slate-900/80 border border-slate-800 flex items-center justify-between text-xs font-mono gap-3 hover:border-slate-700"
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <span
                      className={`text-[9px] px-1.5 py-0.2 rounded font-bold ${
                        log.severity === 'CRITICAL'
                          ? 'bg-red-950 text-red-400 border border-red-800'
                          : 'bg-amber-950 text-amber-400 border border-amber-800'
                      }`}
                    >
                      {log.severity}
                    </span>
                    <span className="text-slate-300 font-bold truncate">{log.srcIp}</span>
                    <span className="text-slate-500">→ {log.dstIp}</span>
                    <span className="text-cyan-300 truncate">{log.threatName}</span>
                  </div>

                  <div className="flex items-center gap-2 flex-shrink-0">
                    <span className="text-slate-500 text-[10px] hidden sm:inline">{log.timestamp}</span>
                    {onInspectLog && (
                      <button
                        onClick={() => onInspectLog(log)}
                        className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 text-[10px] transition"
                        title="Inspecter cet événement dans l'Explorateur de Logs"
                      >
                        Inspecter
                      </button>
                    )}
                  </div>
                </div>
              ))}
          </div>
        </div>
      )}
    </div>
  );
};
