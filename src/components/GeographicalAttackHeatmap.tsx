import React, { useMemo, useState } from 'react';
import {
  ResponsiveContainer,
  Treemap,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  Cell,
} from 'recharts';
import {
  Globe,
  MapPin,
  Flame,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Search,
  Filter,
  Layers,
  ArrowRight,
  ExternalLink,
  ChevronRight,
  CheckCircle2,
  Lock,
  Zap,
  Activity,
  Maximize2,
  Crosshair,
  Radar,
  Radio,
  Eye,
  Check,
} from 'lucide-react';
import {
  LogEntry,
  ThreatAnalysisResult,
  StopAction,
  SeverityLevel,
} from '../types';

interface GeographicalAttackHeatmapProps {
  logs: LogEntry[];
  analysis: ThreatAnalysisResult;
  onInspectLog?: (log: LogEntry) => void;
  onEnforceDefense?: (action: StopAction) => Promise<void>;
  deviceName?: string;
}

export type GeoHeatmapViewMode = 'WORLD_MAP_HEAT' | 'TREEMAP_HEAT' | 'BAR_DENSITY' | 'VECTOR_MATRIX';
export type GeoFilterContinent = 'ALL' | 'EUROPE' | 'ASIA' | 'AMERICAS' | 'MIDDLE_EAST';

export interface CountryOriginStats {
  code: string;
  name: string;
  flag: string;
  continent: string;
  continentKey: GeoFilterContinent;
  x: number; // percentage on map (0-100)
  y: number; // percentage on map (0-100)
  totalAttacks: number;
  criticalAttacks: number;
  highAttacks: number;
  blockedAttacks: number;
  alertedAttacks: number;
  uniqueIpsCount: number;
  sourceIpsList: string[];
  dominantThreat: string;
  mitreTactic: string;
  blockRate: number;
  riskScore: number;
  heatColor: string;
  threatDistribution: {
    malware: number;
    rce: number;
    c2: number;
    ddos: number;
    bruteForce: number;
    phishing: number;
  };
  logs: LogEntry[];
}

// Geographic lookup reference with map coordinates (x, y percentages)
const KNOWN_GEO_COUNTRIES: Record<
  string,
  { name: string; flag: string; continent: string; continentKey: GeoFilterContinent; x: number; y: number }
> = {
  RU: { name: 'Russie', flag: '🇷🇺', continent: 'Europe de l\'Est / Asie', continentKey: 'EUROPE', x: 72, y: 26 },
  CN: { name: 'Chine', flag: '🇨🇳', continent: 'Asie-Pacifique', continentKey: 'ASIA', x: 78, y: 44 },
  US: { name: 'États-Unis', flag: '🇺🇸', continent: 'Amérique du Nord', continentKey: 'AMERICAS', x: 22, y: 38 },
  NL: { name: 'Pays-Bas', flag: '🇳🇱', continent: 'Europe de l\'Ouest', continentKey: 'EUROPE', x: 49.5, y: 29 },
  KP: { name: 'Corée du Nord', flag: '🇰🇵', continent: 'Asie de l\'Est', continentKey: 'ASIA', x: 83, y: 40 },
  IR: { name: 'Iran', flag: '🇮🇷', continent: 'Moyen-Orient', continentKey: 'MIDDLE_EAST', x: 63, y: 43 },
  BR: { name: 'Brésil', flag: '🇧🇷', continent: 'Amérique du Sud', continentKey: 'AMERICAS', x: 35, y: 72 },
  DE: { name: 'Allemagne', flag: '🇩🇪', continent: 'Europe de l\'Ouest', continentKey: 'EUROPE', x: 51, y: 31 },
  FR: { name: 'France (Cible SOC)', flag: '🇫🇷', continent: 'Europe de l\'Ouest', continentKey: 'EUROPE', x: 48, y: 33 },
  UA: { name: 'Ukraine', flag: '🇺🇦', continent: 'Europe de l\'Est', continentKey: 'EUROPE', x: 57, y: 32 },
  RO: { name: 'Roumanie', flag: '🇷🇴', continent: 'Europe de l\'Est', continentKey: 'EUROPE', x: 56, y: 35 },
  VN: { name: 'Vietnam', flag: '🇻🇳', continent: 'Asie du Sud-Est', continentKey: 'ASIA', x: 78, y: 53 },
  IN: { name: 'Inde', flag: '🇮🇳', continent: 'Asie du Sud', continentKey: 'ASIA', x: 70, y: 49 },
  GB: { name: 'Royaume-Uni', flag: '🇬🇧', continent: 'Europe de l\'Ouest', continentKey: 'EUROPE', x: 46.5, y: 28 },
  ID: { name: 'Indonésie', flag: '🇮🇩', continent: 'Asie du Sud-Est', continentKey: 'ASIA', x: 80, y: 64 },
  SC: { name: 'Seychelles', flag: '🇸🇨', continent: 'Océan Indien', continentKey: 'MIDDLE_EAST', x: 64, y: 62 },
  CH: { name: 'Suisse', flag: '🇨🇭', continent: 'Europe de l\'Ouest', continentKey: 'EUROPE', x: 50, y: 33 },
};

function resolveCountryForLog(log: LogEntry, iocCountry?: string) {
  const ip = log.srcIp || '0.0.0.0';

  if (log.country && KNOWN_GEO_COUNTRIES[log.country.toUpperCase()]) {
    return { code: log.country.toUpperCase(), ...KNOWN_GEO_COUNTRIES[log.country.toUpperCase()] };
  }
  if (iocCountry && KNOWN_GEO_COUNTRIES[iocCountry.toUpperCase()]) {
    return { code: iocCountry.toUpperCase(), ...KNOWN_GEO_COUNTRIES[iocCountry.toUpperCase()] };
  }

  // RFC1918 Private IPs
  if (
    ip.startsWith('192.168.') ||
    ip.startsWith('10.') ||
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip) ||
    ip === '127.0.0.1' ||
    ip === '0.0.0.0'
  ) {
    return {
      code: 'LAN',
      name: 'Réseau Interne (LAN)',
      flag: '🏢',
      continent: 'Intranet Privé',
      continentKey: 'EUROPE' as GeoFilterContinent,
      x: 48,
      y: 33,
    };
  }

  // IP block mapping heuristics
  if (ip.startsWith('91.240.') || ip.startsWith('45.142.') || ip.startsWith('193.106.') || ip.startsWith('45.154.')) {
    return { code: 'RU', ...KNOWN_GEO_COUNTRIES['RU'] };
  }
  if (ip.startsWith('218.92.') || ip.startsWith('103.') || ip.startsWith('112.')) {
    return { code: 'CN', ...KNOWN_GEO_COUNTRIES['CN'] };
  }
  if (ip.startsWith('198.51.') || ip.startsWith('23.') || ip.startsWith('52.')) {
    return { code: 'US', ...KNOWN_GEO_COUNTRIES['US'] };
  }
  if (ip.startsWith('194.26.') || ip.startsWith('185.220.') || ip.startsWith('185.100.')) {
    return { code: 'NL', ...KNOWN_GEO_COUNTRIES['NL'] };
  }
  if (ip.startsWith('175.45.') || ip.startsWith('210.52.')) {
    return { code: 'KP', ...KNOWN_GEO_COUNTRIES['KP'] };
  }
  if (ip.startsWith('5.127.') || ip.startsWith('91.98.')) {
    return { code: 'IR', ...KNOWN_GEO_COUNTRIES['IR'] };
  }
  if (ip.startsWith('177.') || ip.startsWith('187.')) {
    return { code: 'BR', ...KNOWN_GEO_COUNTRIES['BR'] };
  }
  if (ip.startsWith('103.152.')) {
    return { code: 'ID', ...KNOWN_GEO_COUNTRIES['ID'] };
  }
  if (ip.startsWith('195.133.')) {
    return { code: 'RO', ...KNOWN_GEO_COUNTRIES['RO'] };
  }
  if (ip.startsWith('80.82.')) {
    return { code: 'SC', ...KNOWN_GEO_COUNTRIES['SC'] };
  }
  if (ip.startsWith('179.43.')) {
    return { code: 'CH', ...KNOWN_GEO_COUNTRIES['CH'] };
  }

  const charSum = ip.split('').reduce((acc, c) => acc + c.charCodeAt(0), 0);
  const codes = ['RU', 'CN', 'US', 'NL', 'IR', 'KP', 'BR', 'DE', 'RO'];
  const code = codes[charSum % codes.length];
  return { code, ...KNOWN_GEO_COUNTRIES[code] };
}

// Heat color determination based on risk score and attack density
function getHeatmapColor(volume: number, criticalRatio: number): string {
  if (volume === 0) return '#0f172a';
  if (criticalRatio > 0.4 || volume >= 8) return '#ef4444'; // Red (Critical host)
  if (criticalRatio > 0.2 || volume >= 5) return '#f97316'; // Orange (Elevated)
  if (criticalRatio > 0.1 || volume >= 3) return '#f59e0b'; // Amber (Moderate)
  if (volume >= 2) return '#06b6d4'; // Cyan
  return '#10b981'; // Emerald (Low/baseline)
}

export const GeographicalAttackHeatmap: React.FC<GeographicalAttackHeatmapProps> = ({
  logs,
  analysis,
  onInspectLog,
  onEnforceDefense,
  deviceName = 'Passerelle Zyxel Nebula ATP',
}) => {
  const [viewMode, setViewMode] = useState<GeoHeatmapViewMode>('WORLD_MAP_HEAT');
  const [continentFilter, setContinentFilter] = useState<GeoFilterContinent>('ALL');
  const [severityFilter, setSeverityFilter] = useState<'ALL' | 'CRITICAL' | 'BLOCKED'>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedCountryCode, setSelectedCountryCode] = useState<string | null>(null);
  const [isDeployingRule, setIsDeployingRule] = useState<string | null>(null);
  const [ruleDeployedToast, setRuleDeployedToast] = useState<string | null>(null);

  // 1. Process and aggregate parsed log data into geographical origin records
  const geoOrigins = useMemo<CountryOriginStats[]>(() => {
    const map = new Map<string, CountryOriginStats>();

    logs.forEach((log) => {
      // Severity filtering
      if (severityFilter === 'CRITICAL' && log.severity !== 'CRITICAL' && log.severity !== 'HIGH') {
        return;
      }
      if (
        severityFilter === 'BLOCKED' &&
        log.action !== 'Blocked' &&
        log.action !== 'Dropped' &&
        log.action !== 'Quarantined'
      ) {
        return;
      }

      const iocMatch = analysis.iocList.find((i) => i.value === log.srcIp);
      const meta = resolveCountryForLog(log, iocMatch?.country);

      if (!map.has(meta.code)) {
        map.set(meta.code, {
          code: meta.code,
          name: meta.name,
          flag: meta.flag,
          continent: meta.continent,
          continentKey: meta.continentKey,
          x: meta.x,
          y: meta.y,
          totalAttacks: 0,
          criticalAttacks: 0,
          highAttacks: 0,
          blockedAttacks: 0,
          alertedAttacks: 0,
          uniqueIpsCount: 0,
          sourceIpsList: [],
          dominantThreat: log.threatName,
          mitreTactic: 'Accès Initial & Exploitation',
          blockRate: 100,
          riskScore: 50,
          heatColor: '#06b6d4',
          threatDistribution: {
            malware: 0,
            rce: 0,
            c2: 0,
            ddos: 0,
            bruteForce: 0,
            phishing: 0,
          },
          logs: [],
        });
      }

      const entry = map.get(meta.code)!;
      entry.totalAttacks += 1;
      if (log.severity === 'CRITICAL') entry.criticalAttacks += 1;
      if (log.severity === 'HIGH') entry.highAttacks += 1;

      if (log.action === 'Blocked' || log.action === 'Dropped' || log.action === 'Quarantined') {
        entry.blockedAttacks += 1;
      } else {
        entry.alertedAttacks += 1;
      }

      if (!entry.sourceIpsList.includes(log.srcIp)) {
        entry.sourceIpsList.push(log.srcIp);
      }
      entry.logs.push(log);

      // Threat distribution categorization
      const lower = `${log.threatName} ${log.category}`.toLowerCase();
      if (lower.includes('lockbit') || lower.includes('malware') || lower.includes('virus') || lower.includes('trojan')) {
        entry.threatDistribution.malware += 1;
        entry.dominantThreat = log.threatName;
        entry.mitreTactic = 'Impact & Chiffrement';
      } else if (lower.includes('log4j') || lower.includes('rce') || lower.includes('exploit') || lower.includes('jndi')) {
        entry.threatDistribution.rce += 1;
        entry.dominantThreat = log.threatName;
        entry.mitreTactic = 'Exécution & Débordement';
      } else if (lower.includes('c2') || lower.includes('beacon') || lower.includes('botnet') || lower.includes('cobalt')) {
        entry.threatDistribution.c2 += 1;
        entry.dominantThreat = log.threatName;
        entry.mitreTactic = 'Command & Control';
      } else if (lower.includes('syn_flood') || lower.includes('ddos') || lower.includes('flood')) {
        entry.threatDistribution.ddos += 1;
        entry.dominantThreat = 'DDoS SYN Flood';
        entry.mitreTactic = 'Déni de Service (DoS)';
      } else if (lower.includes('ssh') || lower.includes('brute') || lower.includes('auth')) {
        entry.threatDistribution.bruteForce += 1;
        entry.dominantThreat = 'Brute Force Dictionnaire';
        entry.mitreTactic = 'Accès aux Identifiants';
      } else if (lower.includes('phishing') || lower.includes('stealer')) {
        entry.threatDistribution.phishing += 1;
        entry.dominantThreat = 'Phishing & Stealer';
        entry.mitreTactic = 'Ingénierie Sociale';
      }
    });

    // Compute derived rates & heat colors
    const results: CountryOriginStats[] = [];
    map.forEach((c) => {
      c.uniqueIpsCount = c.sourceIpsList.length;
      c.blockRate = c.totalAttacks > 0 ? Math.round((c.blockedAttacks / c.totalAttacks) * 100) : 100;
      const critRatio = c.totalAttacks > 0 ? c.criticalAttacks / c.totalAttacks : 0;
      c.riskScore = Math.min(100, Math.round(c.criticalAttacks * 20 + c.highAttacks * 10 + c.totalAttacks * 2));
      c.heatColor = getHeatmapColor(c.totalAttacks, critRatio);
      results.push(c);
    });

    return results.sort((a, b) => b.totalAttacks - a.totalAttacks);
  }, [logs, analysis, severityFilter]);

  // Filtered by continent and search
  const filteredOrigins = useMemo(() => {
    return geoOrigins.filter((origin) => {
      if (continentFilter !== 'ALL' && origin.continentKey !== continentFilter) {
        return false;
      }
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchName = origin.name.toLowerCase().includes(q);
        const matchCode = origin.code.toLowerCase().includes(q);
        const matchThreat = origin.dominantThreat.toLowerCase().includes(q);
        const matchIp = origin.sourceIpsList.some((ip) => ip.includes(q));
        if (!matchName && !matchCode && !matchThreat && !matchIp) return false;
      }
      return true;
    });
  }, [geoOrigins, continentFilter, searchQuery]);

  // Selected country details
  const selectedCountry = useMemo(() => {
    if (!selectedCountryCode) return filteredOrigins[0] || geoOrigins[0] || null;
    return geoOrigins.find((c) => c.code === selectedCountryCode) || filteredOrigins[0] || null;
  }, [selectedCountryCode, geoOrigins, filteredOrigins]);

  // Top summary KPIs
  const totalMappedCountries = geoOrigins.length;
  const topHostileCountry = geoOrigins[0] || null;
  const totalAttacksCount = geoOrigins.reduce((acc, c) => acc + c.totalAttacks, 0);
  const globalBlockRate =
    totalAttacksCount > 0
      ? Math.round((geoOrigins.reduce((acc, c) => acc + c.blockedAttacks, 0) / totalAttacksCount) * 100)
      : 100;

  // Recharts Treemap data transformation
  const treemapData = useMemo(() => {
    return filteredOrigins.map((origin) => ({
      name: origin.name,
      code: origin.code,
      flag: origin.flag,
      size: origin.totalAttacks,
      criticalAttacks: origin.criticalAttacks,
      blockRate: origin.blockRate,
      uniqueIps: origin.uniqueIpsCount,
      heatColor: origin.heatColor,
      dominantThreat: origin.dominantThreat,
      continent: origin.continent,
    }));
  }, [filteredOrigins]);

  // Handle Deploy Geo-IP blocking rule via Nebula
  const handleDeployGeoBlock = async (country: CountryOriginStats) => {
    setIsDeployingRule(country.code);
    try {
      const stopAction: StopAction = {
        id: `geo-block-${country.code.toLowerCase()}-${Date.now()}`,
        title: `Blocage Geo-IP Zyxel Nebula : ${country.name} (${country.code})`,
        type: 'GEO_BLOCK',
        target: country.code,
        priority: 'IMMEDIATE',
        rationale: `Foyer hostile identifié avec ${country.totalAttacks} attaques détectées dont ${country.criticalAttacks} critiques.`,
        zyxelNebulaRule: {
          ruleName: `DROP_GEO_${country.code}`,
          direction: 'WAN to LAN',
          action: 'DROP',
          sourceObject: `Geo_${country.code}`,
          destinationObject: 'Any',
        },
        zyxelCliCommand: `configure terminal\ngeo-ip-object Geo_${country.code} country ${country.code}\nfirewall rule 10\n  name DROP_GEO_${country.code}\n  from WAN to Any\n  source-address Geo_${country.code}\n  action drop\n  log alert\nexit\nwrite memory`,
        iptablesCommand: `sudo iptables -I INPUT -m geoip --src-cc ${country.code} -j DROP`,
        nftablesCommand: `sudo nft add rule inet filter input geoip saddr ${country.code} drop`,
        pfSenseRule: `<rule><type>block</type><interface>wan</interface><source><geo>${country.code}</geo></source><descr>Geo-IP Block ${country.name}</descr></rule>`,
      };

      if (onEnforceDefense) {
        await onEnforceDefense(stopAction);
      } else {
        await fetch('/api/nebula/push-firewall-rule', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            siteId: 'site-paris-hq',
            ruleName: `DROP_GEO_${country.code}`,
            target: country.code,
            actionType: 'GEO_BLOCK',
            direction: 'WAN to LAN',
            zyxelCliCommand: stopAction.zyxelCliCommand,
          }),
        });
      }

      setRuleDeployedToast(`Règle Geo-IP DROP ${country.name} déployée avec succès sur Nebula !`);
      setTimeout(() => setRuleDeployedToast(null), 4000);
    } catch (err: any) {
      console.error('Erreur déploiement règle Geo-IP:', err);
    } finally {
      setIsDeployingRule(null);
    }
  };

  // Custom Treemap Cell Rendering
  const renderCustomTreemapNode = (props: any) => {
    const { x, y, width, height, name, flag, size, heatColor, code } = props;
    if (width < 35 || height < 30) return <g />;

    const isSelected = selectedCountryCode === code;

    return (
      <g
        className="cursor-pointer transition-transform duration-200 hover:opacity-90"
        onClick={() => setSelectedCountryCode(code)}
      >
        <rect
          x={x + 2}
          y={y + 2}
          width={width - 4}
          height={height - 4}
          rx={6}
          fill={heatColor}
          stroke={isSelected ? '#38bdf8' : '#0f172a'}
          strokeWidth={isSelected ? 3 : 1.5}
          fillOpacity={0.88}
        />
        {width > 60 && height > 45 && (
          <>
            <text
              x={x + 8}
              y={y + 18}
              fill="#ffffff"
              fontSize={width > 120 ? 12 : 10}
              fontWeight="bold"
              fontFamily="monospace"
            >
              {flag} {code}
            </text>
            <text
              x={x + 8}
              y={y + 34}
              fill="#ffffff"
              fontSize={width > 120 ? 11 : 9}
              opacity={0.9}
              fontFamily="monospace"
            >
              {size} attaque{size > 1 ? 's' : ''}
            </text>
            {height > 65 && width > 90 && (
              <text
                x={x + 8}
                y={y + 48}
                fill="#f8fafc"
                fontSize={8.5}
                opacity={0.75}
                fontFamily="sans-serif"
              >
                {name.length > 14 ? `${name.substring(0, 12)}…` : name}
              </text>
            )}
          </>
        )}
      </g>
    );
  };

  // France SOC Target Coordinates (Paris Gateway)
  const targetX = 48.5;
  const targetY = 32.5;

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/90 p-5 shadow-2xl space-y-5">
      {/* Toast Notification */}
      {ruleDeployedToast && (
        <div className="fixed bottom-6 right-6 z-50 flex items-center gap-2.5 px-4 py-3 rounded-xl bg-emerald-950 border border-emerald-700 text-emerald-200 text-sm shadow-2xl backdrop-blur-md animate-in fade-in slide-in-from-bottom-3">
          <Check className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{ruleDeployedToast}</span>
        </div>
      )}

      {/* Header Bar */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2.5">
            <span className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
              <Globe className="w-5 h-5 animate-pulse" />
            </span>
            <h2 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
              <span>Carte Thermique Géographique des Cyberattaques</span>
              <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-cyan-950 text-cyan-300 border border-cyan-800">
                Heatmap WAN
              </span>
            </h2>
          </div>
          <p className="text-xs text-slate-400 max-w-2xl">
            Visualisation cartographique mondiale thermique et Treemap des zones d’origine des attaques
            identifiées dans les logs Zyxel Nebula SecuReporter.
          </p>
        </div>

        {/* View Mode Toggle Buttons */}
        <div className="flex flex-wrap items-center gap-1.5 p-1 rounded-xl bg-slate-950/90 border border-slate-800 self-start lg:self-auto">
          <button
            onClick={() => setViewMode('WORLD_MAP_HEAT')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition ${
              viewMode === 'WORLD_MAP_HEAT'
                ? 'bg-gradient-to-r from-cyan-600 to-blue-600 text-white shadow-md shadow-cyan-900/30'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/70'
            }`}
            title="Afficher la carte mondiale thermique interactive avec foyers de chaleur"
          >
            <Radar className="w-3.5 h-3.5" />
            <span>Carte Mondiale Thermique</span>
          </button>

          <button
            onClick={() => setViewMode('TREEMAP_HEAT')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition ${
              viewMode === 'TREEMAP_HEAT'
                ? 'bg-cyan-600 text-white shadow-md shadow-cyan-900/30'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/70'
            }`}
            title="Afficher la Treemap thermique proportionnelle par pays"
          >
            <Maximize2 className="w-3.5 h-3.5" />
            <span>Treemap Thermique</span>
          </button>

          <button
            onClick={() => setViewMode('BAR_DENSITY')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition ${
              viewMode === 'BAR_DENSITY'
                ? 'bg-amber-600 text-white shadow-md shadow-amber-900/30'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/70'
            }`}
            title="Afficher le classement thermique horizontal par pays"
          >
            <Flame className="w-3.5 h-3.5" />
            <span>Barres de Densité</span>
          </button>

          <button
            onClick={() => setViewMode('VECTOR_MATRIX')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition ${
              viewMode === 'VECTOR_MATRIX'
                ? 'bg-purple-600 text-white shadow-md shadow-purple-900/30'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/70'
            }`}
            title="Afficher la matrice Pays × Vecteurs d'attaque"
          >
            <Layers className="w-3.5 h-3.5" />
            <span>Matrice Menaces</span>
          </button>
        </div>
      </div>

      {/* Top 4 KPI Metrics */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
        <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 space-y-1">
          <div className="flex items-center justify-between text-slate-400">
            <span>Zones Géographiques</span>
            <MapPin className="w-3.5 h-3.5 text-cyan-400" />
          </div>
          <div className="text-xl font-bold text-white">{totalMappedCountries} pays détectés</div>
          <div className="text-[10px] text-slate-400">Origines extraites des logs WAN</div>
        </div>

        <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 space-y-1">
          <div className="flex items-center justify-between text-slate-400">
            <span>Foyer le Plus Agressif</span>
            <Flame className="w-3.5 h-3.5 text-rose-400" />
          </div>
          <div className="text-xl font-bold text-rose-300 flex items-center gap-1.5 truncate">
            <span>{topHostileCountry?.flag}</span>
            <span className="truncate">{topHostileCountry?.name || 'N/A'}</span>
          </div>
          <div className="text-[10px] text-rose-400/90 truncate">
            {topHostileCountry ? `${topHostileCountry.totalAttacks} flux (${topHostileCountry.criticalAttacks} critiques)` : 'N/A'}
          </div>
        </div>

        <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 space-y-1">
          <div className="flex items-center justify-between text-slate-400">
            <span>Taux de Blocage Zyxel</span>
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div className="text-xl font-bold text-emerald-400">{globalBlockRate}%</div>
          <div className="text-[10px] text-slate-400">Règles IDP/IPS & Anti-Malware</div>
        </div>

        <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 space-y-1">
          <div className="flex items-center justify-between text-slate-400">
            <span>Vecteur Transfrontalier</span>
            <Zap className="w-3.5 h-3.5 text-amber-400" />
          </div>
          <div className="text-sm font-bold text-amber-300 truncate">
            {topHostileCountry?.dominantThreat || 'Reconnaissance WAN'}
          </div>
          <div className="text-[10px] text-slate-400 truncate">
            {topHostileCountry?.mitreTactic || 'Accès Initial'}
          </div>
        </div>
      </div>

      {/* Filter and Continent Selector */}
      <div className="flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-slate-400 flex items-center gap-1">
            <Filter className="w-3 h-3 text-slate-500" />
            Région géographique :
          </span>
          <button
            onClick={() => setContinentFilter('ALL')}
            className={`px-2.5 py-1 rounded-lg border transition ${
              continentFilter === 'ALL'
                ? 'bg-slate-800 text-white border-slate-600'
                : 'bg-slate-950/60 text-slate-400 border-slate-800 hover:text-white'
            }`}
          >
            Tous ({geoOrigins.length})
          </button>
          <button
            onClick={() => setContinentFilter('EUROPE')}
            className={`px-2.5 py-1 rounded-lg border transition ${
              continentFilter === 'EUROPE'
                ? 'bg-cyan-950 text-cyan-300 border-cyan-700'
                : 'bg-slate-950/60 text-slate-400 border-slate-800 hover:text-cyan-300'
            }`}
          >
            Europe
          </button>
          <button
            onClick={() => setContinentFilter('ASIA')}
            className={`px-2.5 py-1 rounded-lg border transition ${
              continentFilter === 'ASIA'
                ? 'bg-rose-950 text-rose-300 border-rose-700'
                : 'bg-slate-950/60 text-slate-400 border-slate-800 hover:text-rose-300'
            }`}
          >
            Asie-Pacifique
          </button>
          <button
            onClick={() => setContinentFilter('AMERICAS')}
            className={`px-2.5 py-1 rounded-lg border transition ${
              continentFilter === 'AMERICAS'
                ? 'bg-amber-950 text-amber-300 border-amber-700'
                : 'bg-slate-950/60 text-slate-400 border-slate-800 hover:text-amber-300'
            }`}
          >
            Amériques
          </button>
          <button
            onClick={() => setContinentFilter('MIDDLE_EAST')}
            className={`px-2.5 py-1 rounded-lg border transition ${
              continentFilter === 'MIDDLE_EAST'
                ? 'bg-purple-950 text-purple-300 border-purple-700'
                : 'bg-slate-950/60 text-slate-400 border-slate-800 hover:text-purple-300'
            }`}
          >
            Moyen-Orient
          </button>
        </div>

        {/* Live Search */}
        <div className="relative min-w-[200px] flex-1 max-w-xs">
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Rechercher pays, IP ou signature..."
            className="w-full bg-slate-950/90 border border-slate-800 rounded-lg pl-8 pr-3 py-1 text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 text-xs"
          />
        </div>
      </div>

      {/* VIEW 0: INTERACTIVE SVG WORLD MAP HEATMAP (Carte Thermique Géographique) */}
      {viewMode === 'WORLD_MAP_HEAT' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono">
            <span className="text-slate-300 font-bold flex items-center gap-1.5">
              <Radar className="w-4 h-4 text-cyan-400" />
              Carte Thermique Mondiale Interactive (Foyers de rayonnement thermique &amp; Trajectoires d'attaque vers la passerelle)
            </span>
            <div className="flex items-center gap-2 text-[11px] text-slate-400">
              <span className="flex items-center gap-1">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 inline-block" /> Faible
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2.5 h-2.5 rounded-full bg-cyan-500 inline-block" /> Modéré
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2.5 h-2.5 rounded-full bg-amber-500 inline-block" /> Élevé
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2.5 h-2.5 rounded-full bg-rose-500 inline-block animate-ping" /> Foyer Critique
              </span>
            </div>
          </div>

          {/* SVG World Map Canvas */}
          <div className="relative w-full h-[420px] bg-slate-950/95 rounded-2xl border border-slate-800/90 overflow-hidden shadow-inner select-none">
            {/* Grid Coordinates Overlay */}
            <svg className="absolute inset-0 w-full h-full pointer-events-none opacity-20">
              <defs>
                <pattern id="geo-grid" width="40" height="40" patternUnits="userSpaceOnUse">
                  <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#334155" strokeWidth="0.5" />
                </pattern>
              </defs>
              <rect width="100%" height="100%" fill="url(#geo-grid)" />
              {/* Equator & Prime Meridian lines */}
              <line x1="0" y1="50%" x2="100%" y2="50%" stroke="#06b6d4" strokeWidth="0.75" strokeDasharray="4,4" />
              <line x1="50%" y1="0" x2="50%" y2="100%" stroke="#06b6d4" strokeWidth="0.75" strokeDasharray="4,4" />
            </svg>

            {/* Stylized World Continent Outlines (SVG Polygons) */}
            <svg className="absolute inset-0 w-full h-full pointer-events-none" viewBox="0 0 1000 500" preserveAspectRatio="none">
              {/* North America */}
              <path
                d="M 120 80 Q 200 70 280 90 Q 260 180 230 240 Q 180 230 140 180 Z"
                fill="#0f172a"
                stroke="#1e293b"
                strokeWidth="1.5"
              />
              {/* South America */}
              <path
                d="M 270 270 Q 360 300 340 420 Q 280 470 260 410 Q 250 320 270 270 Z"
                fill="#0f172a"
                stroke="#1e293b"
                strokeWidth="1.5"
              />
              {/* Europe & Scandinavia */}
              <path
                d="M 460 100 Q 560 90 580 180 Q 510 230 450 200 Q 440 140 460 100 Z"
                fill="#0f172a"
                stroke="#1e293b"
                strokeWidth="1.5"
              />
              {/* Africa */}
              <path
                d="M 460 210 Q 560 200 570 310 Q 530 430 480 390 Q 430 300 460 210 Z"
                fill="#0f172a"
                stroke="#1e293b"
                strokeWidth="1.5"
              />
              {/* Eurasia / Russia / China */}
              <path
                d="M 580 90 Q 860 80 880 200 Q 800 290 680 280 Q 600 210 580 90 Z"
                fill="#0f172a"
                stroke="#1e293b"
                strokeWidth="1.5"
              />
              {/* Australia / Oceania */}
              <path
                d="M 770 330 Q 890 320 880 410 Q 800 430 760 380 Z"
                fill="#0f172a"
                stroke="#1e293b"
                strokeWidth="1.5"
              />

              {/* Dynamic Attack Arc Trajectories flying toward Target (Paris HQ: x=485, y=162) */}
              {filteredOrigins.map((country) => {
                const srcX = (country.x / 100) * 1000;
                const srcY = (country.y / 100) * 500;
                const dstX = 485;
                const dstY = 165;
                const midX = (srcX + dstX) / 2;
                const midY = Math.min(srcY, dstY) - 50;

                const isCrit = country.criticalAttacks > 0;

                return (
                  <g key={`arc-${country.code}`}>
                    <path
                      d={`M ${srcX} ${srcY} Q ${midX} ${midY} ${dstX} ${dstY}`}
                      fill="none"
                      stroke={country.heatColor}
                      strokeWidth={isCrit ? 2.5 : 1.5}
                      strokeDasharray={isCrit ? '6,4' : '4,4'}
                      opacity={selectedCountryCode === country.code ? 1 : 0.65}
                    />
                  </g>
                );
              })}
            </svg>

            {/* Target SOC Node: Paris Gateway */}
            <div
              className="absolute z-20 -translate-x-1/2 -translate-y-1/2 pointer-events-auto cursor-pointer group"
              style={{ left: `${targetX}%`, top: `${targetY}%` }}
            >
              <div className="relative flex items-center justify-center">
                <span className="absolute w-8 h-8 rounded-full bg-cyan-500/20 animate-ping" />
                <span className="w-5 h-5 rounded-full bg-cyan-500 border-2 border-white flex items-center justify-center shadow-lg shadow-cyan-500/50">
                  <ShieldCheck className="w-3 h-3 text-slate-950" />
                </span>
                {/* Gateway Label Badge */}
                <div className="absolute top-6 left-1/2 -translate-x-1/2 whitespace-nowrap px-2 py-0.5 rounded bg-slate-950/90 border border-cyan-500/50 text-[10px] font-mono text-cyan-300 font-bold shadow-md">
                  🇫🇷 Passerelle Zyxel ATP (Paris)
                </div>
              </div>
            </div>

            {/* Attacker Country Thermal Heat Nodes */}
            {filteredOrigins.map((country) => {
              const isSelected = selectedCountryCode === country.code;
              const isCritical = country.criticalAttacks > 0 || country.totalAttacks >= 8;
              const haloSize = Math.min(90, Math.max(38, country.totalAttacks * 6));

              return (
                <div
                  key={`node-${country.code}`}
                  onClick={() => setSelectedCountryCode(country.code)}
                  className="absolute z-30 -translate-x-1/2 -translate-y-1/2 cursor-pointer transition-transform duration-200 hover:scale-110"
                  style={{ left: `${country.x}%`, top: `${country.y}%` }}
                >
                  {/* Radial Heat Gradient Halo */}
                  <div
                    className="absolute -translate-x-1/2 -translate-y-1/2 rounded-full pointer-events-none opacity-40 blur-md transition-all"
                    style={{
                      left: '50%',
                      top: '50%',
                      width: `${haloSize}px`,
                      height: `${haloSize}px`,
                      backgroundColor: country.heatColor,
                    }}
                  />

                  {/* Pulsing Critical Ping */}
                  {isCritical && (
                    <span
                      className="absolute -translate-x-1/2 -translate-y-1/2 w-6 h-6 rounded-full animate-ping pointer-events-none"
                      style={{
                        left: '50%',
                        top: '50%',
                        backgroundColor: country.heatColor,
                      }}
                    />
                  )}

                  {/* Country Node Icon */}
                  <div
                    className={`relative flex items-center gap-1 px-2 py-1 rounded-xl border font-mono text-[11px] font-bold shadow-xl transition ${
                      isSelected
                        ? 'ring-2 ring-white scale-110 bg-slate-900 border-white text-white'
                        : 'bg-slate-950/90 hover:bg-slate-900'
                    }`}
                    style={{ borderColor: country.heatColor }}
                  >
                    <span>{country.flag}</span>
                    <span style={{ color: country.heatColor }}>{country.code}</span>
                    <span className="px-1 py-0.2 rounded-full text-[9px] bg-slate-800 text-slate-300">
                      {country.totalAttacks}
                    </span>
                  </div>
                </div>
              );
            })}

            {/* Bottom-left Map Controls & Legend */}
            <div className="absolute bottom-3 left-3 z-30 bg-slate-950/90 border border-slate-800 rounded-xl p-2.5 text-[11px] font-mono space-y-1 text-slate-300 shadow-xl">
              <div className="flex items-center gap-2 font-bold text-white">
                <Crosshair className="w-3.5 h-3.5 text-cyan-400" />
                <span>Origine Géographique des Cyberattaques</span>
              </div>
              <div className="text-[10px] text-slate-400">
                {filteredOrigins.length} foyers cartographiés • Cliquez sur un pays pour inspecter les flux
              </div>
            </div>
          </div>
        </div>
      )}

      {/* VIEW 1: RECHARTS TREEMAP GEOGRAPHICAL HEATMAP */}
      {viewMode === 'TREEMAP_HEAT' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono">
            <span className="text-slate-300 font-bold flex items-center gap-1.5">
              <Maximize2 className="w-4 h-4 text-cyan-400" />
              Treemap Thermique Recharts (Superficie = Volume d'attaques · Couleur = Niveau de criticité)
            </span>
            <div className="flex items-center gap-2 text-[11px] text-slate-400">
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
                <span className="w-2.5 h-2.5 rounded-sm bg-rose-500 inline-block" /> Critique / Foyer hostile
              </span>
            </div>
          </div>

          <div className="h-80 w-full bg-slate-950/80 rounded-xl p-3 border border-slate-800">
            {treemapData.length === 0 ? (
              <div className="h-full flex items-center justify-center text-slate-500 text-xs font-mono">
                Aucun pays correspondant aux filtres
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <Treemap
                  data={treemapData}
                  dataKey="size"
                  aspectRatio={4 / 3}
                  stroke="#0f172a"
                  content={renderCustomTreemapNode}
                >
                  <Tooltip
                    content={({ active, payload }) => {
                      if (active && payload && payload.length) {
                        const data = payload[0].payload;
                        return (
                          <div className="p-3 bg-slate-950 border border-slate-700 rounded-xl shadow-2xl text-xs font-mono space-y-1.5 z-50">
                            <div className="flex items-center justify-between gap-3 border-b border-slate-800 pb-1">
                              <span className="font-bold text-white flex items-center gap-1.5">
                                <span>{data.flag}</span>
                                <span>{data.name} ({data.code})</span>
                              </span>
                              <span className="text-[10px] text-slate-400">{data.continent}</span>
                            </div>
                            <div className="space-y-1 text-[11px]">
                              <div className="text-slate-300">
                                Volume total d'attaques : <strong className="text-white">{data.size}</strong>
                              </div>
                              <div className="text-rose-400">
                                Attaques critiques : <strong>{data.criticalAttacks}</strong>
                              </div>
                              <div className="text-emerald-400">
                                Taux d'arrêt Zyxel : <strong>{data.blockRate}%</strong>
                              </div>
                              <div className="text-amber-300">
                                Adresses IP sources (IOCs) : <strong>{data.uniqueIps}</strong>
                              </div>
                              <div className="text-cyan-300 truncate max-w-[220px]">
                                Menace principale : <strong>{data.dominantThreat}</strong>
                              </div>
                            </div>
                            <div className="text-[10px] text-cyan-400/90 pt-1 border-t border-slate-800/80">
                              Cliquez pour ouvrir l'isolation et la riposte
                            </div>
                          </div>
                        );
                      }
                      return null;
                    }}
                  />
                </Treemap>
              </ResponsiveContainer>
            )}
          </div>
        </div>
      )}

      {/* VIEW 2: HORIZONTAL DENSITY BAR HEATMAP */}
      {viewMode === 'BAR_DENSITY' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono">
            <span className="text-slate-300 font-bold flex items-center gap-1.5">
              <Flame className="w-4 h-4 text-amber-400" />
              Densité d'Attaques par Pays d'Origine (Recharts Bar Heatmap)
            </span>
            <span className="text-[11px] text-slate-400">
              Dégradé thermique proportionnel au ratio d'attaques critiques
            </span>
          </div>

          <div className="h-80 w-full bg-slate-950/80 rounded-xl p-3 border border-slate-800">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={filteredOrigins.slice(0, 10)}
                layout="vertical"
                margin={{ top: 10, right: 30, left: 70, bottom: 10 }}
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
                    const country = geoOrigins.find((g) => g.name === payload.value);
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
                      return (
                        <div className="p-3 bg-slate-950 border border-slate-700 rounded-xl shadow-2xl text-xs font-mono space-y-1.5 z-50">
                          <div className="flex items-center justify-between gap-3 border-b border-slate-800 pb-1">
                            <span className="font-bold text-white flex items-center gap-1.5">
                              <span>{data.flag}</span>
                              <span>{data.name} ({data.code})</span>
                            </span>
                            <span className="text-[10px] text-slate-400">{data.continent}</span>
                          </div>
                          <div className="space-y-1 text-[11px]">
                            <div className="text-slate-300">
                              Volume total : <strong className="text-white">{data.totalAttacks}</strong> flux
                            </div>
                            <div className="text-rose-400">
                              Attaques critiques : <strong>{data.criticalAttacks}</strong>
                            </div>
                            <div className="text-emerald-400">
                              Blocages Zyxel ATP : <strong>{data.blockedAttacks} ({data.blockRate}%)</strong>
                            </div>
                            <div className="text-amber-300">
                              IPs sources uniques : <strong>{data.uniqueIpsCount}</strong>
                            </div>
                            <div className="text-cyan-300 truncate max-w-[220px]">
                              Menace principale : <strong>{data.dominantThreat}</strong>
                            </div>
                          </div>
                        </div>
                      );
                    }
                    return null;
                  }}
                />
                <Bar dataKey="totalAttacks" radius={[0, 4, 4, 0]}>
                  {filteredOrigins.slice(0, 10).map((entry, index) => (
                    <Cell
                      key={`geo-bar-${index}`}
                      fill={entry.heatColor}
                      stroke={selectedCountryCode === entry.code ? '#ffffff' : 'none'}
                      strokeWidth={selectedCountryCode === entry.code ? 2 : 0}
                      className="cursor-pointer hover:opacity-80 transition"
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* VIEW 3: THREAT VECTOR CROSS-MATRIX */}
      {viewMode === 'VECTOR_MATRIX' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono">
            <span className="text-slate-300 font-bold flex items-center gap-1.5">
              <Layers className="w-4 h-4 text-purple-400" />
              Matrice Thermique Recharts : Pays d'Origine × Catégories de Menaces
            </span>
            <span className="text-[11px] text-slate-400">
              Distribution des typologies d'intrusion selon la zone géographique
            </span>
          </div>

          <div className="h-80 w-full bg-slate-950/80 rounded-xl p-3 border border-slate-800">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={filteredOrigins.slice(0, 8).map((c) => ({
                  name: `${c.flag} ${c.code}`,
                  fullName: c.name,
                  flag: c.flag,
                  Malwares: c.threatDistribution.malware,
                  'Exploits RCE': c.threatDistribution.rce,
                  'C2 Botnets': c.threatDistribution.c2,
                  'DDoS Floods': c.threatDistribution.ddos,
                  'Brute-Force': c.threatDistribution.bruteForce,
                  Phishing: c.threatDistribution.phishing,
                }))}
                margin={{ top: 20, right: 20, left: -10, bottom: 20 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis dataKey="name" stroke="#64748b" fontSize={11} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={10} tickLine={false} />
                <Tooltip
                  cursor={{ fill: 'rgba(255, 255, 255, 0.05)' }}
                  content={({ active, payload, label }) => {
                    if (active && payload && payload.length) {
                      return (
                        <div className="p-3 bg-slate-950 border border-slate-700 rounded-xl shadow-2xl text-xs font-mono space-y-1.5 z-50">
                          <div className="font-bold text-white border-b border-slate-800 pb-1">
                            {label} ({payload[0]?.payload.fullName})
                          </div>
                          <div className="space-y-1 text-[11px]">
                            {payload.map((p: any, idx: number) => (
                              <div key={idx} className="flex items-center justify-between gap-3">
                                <span className="flex items-center gap-1.5 text-slate-300">
                                  <span className="w-2 h-2 rounded-full" style={{ backgroundColor: p.color }} />
                                  <span>{p.name} :</span>
                                </span>
                                <strong className="text-white">{p.value}</strong>
                              </div>
                            ))}
                          </div>
                        </div>
                      );
                    }
                    return null;
                  }}
                />
                <Legend
                  wrapperStyle={{ paddingTop: 10, fontSize: 11, fontFamily: 'monospace' }}
                  iconType="circle"
                />
                <Bar dataKey="Malwares" stackId="threat" fill="#ef4444" />
                <Bar dataKey="Exploits RCE" stackId="threat" fill="#f97316" />
                <Bar dataKey="C2 Botnets" stackId="threat" fill="#a855f7" />
                <Bar dataKey="DDoS Floods" stackId="threat" fill="#38bdf8" />
                <Bar dataKey="Brute-Force" stackId="threat" fill="#eab308" />
                <Bar dataKey="Phishing" stackId="threat" fill="#ec4899" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Selected Country Drilldown Card */}
      {selectedCountry && (
        <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3 font-mono text-xs">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/80 pb-3">
            <div className="flex items-center gap-2">
              <span className="text-2xl">{selectedCountry.flag}</span>
              <div>
                <h4 className="font-bold text-white text-sm">
                  {selectedCountry.name} ({selectedCountry.code})
                </h4>
                <span className="text-[10px] text-slate-400">
                  {selectedCountry.continent} • Score de Risque :{' '}
                  <strong style={{ color: selectedCountry.heatColor }}>{selectedCountry.riskScore}/100</strong>
                </span>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => handleDeployGeoBlock(selectedCountry)}
                disabled={isDeployingRule === selectedCountry.code}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-red-950 hover:bg-red-900 text-red-200 border border-red-800 text-xs font-bold transition disabled:opacity-50"
              >
                <Lock className="w-3.5 h-3.5 text-red-400" />
                <span>
                  {isDeployingRule === selectedCountry.code
                    ? 'Déploiement en cours...'
                    : `Bloquer la Zone Geo-IP (${selectedCountry.code})`}
                </span>
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-[11px]">
            <div className="space-y-1">
              <div className="text-slate-500">Volume Total :</div>
              <div className="text-white font-bold">
                {selectedCountry.totalAttacks} événements ({selectedCountry.criticalAttacks} critiques)
              </div>
            </div>

            <div className="space-y-1">
              <div className="text-slate-500">Taux de Blocage Actuel :</div>
              <div className="text-emerald-400 font-bold">
                {selectedCountry.blockedAttacks} bloqués ({selectedCountry.blockRate}%)
              </div>
            </div>

            <div className="space-y-1">
              <div className="text-slate-500">Menace Dominante :</div>
              <div className="text-amber-300 font-bold truncate">
                {selectedCountry.dominantThreat}
              </div>
            </div>
          </div>

          {/* Source IP list from this country */}
          <div className="pt-2 border-t border-slate-800/80">
            <span className="text-[10px] text-slate-400 uppercase font-bold tracking-wider">
              Adresses IP Sources Malveillantes Détectées ({selectedCountry.sourceIpsList.length}) :
            </span>
            <div className="flex flex-wrap gap-1.5 mt-1.5">
              {selectedCountry.sourceIpsList.map((ip) => (
                <span
                  key={ip}
                  className="px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-cyan-300 text-[10px]"
                >
                  {ip}
                </span>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
