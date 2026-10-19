import React, { useEffect, useMemo, useRef, useState } from 'react';
import L from 'leaflet';
import * as d3 from 'd3';
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
  ZoomIn,
  ZoomOut,
  RotateCcw,
  Copy,
  Navigation,
  Compass,
  Target,
  Info,
  Sparkles,
  Maximize,
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

export type GeoHeatmapViewMode =
  | 'LEAFLET_MAP'
  | 'D3_TACTICAL_MAP'
  | 'TREEMAP_HEAT'
  | 'BAR_DENSITY'
  | 'VECTOR_MATRIX';

export type GeoFilterContinent = 'ALL' | 'EUROPE' | 'ASIA' | 'AMERICAS' | 'MIDDLE_EAST' | 'AFRICA';

export interface MaliciousIpGeoItem {
  ip: string;
  countryCode: string;
  countryName: string;
  city: string;
  flag: string;
  lat: number;
  lng: number;
  continent: string;
  continentKey: GeoFilterContinent;
  isp: string;
  threatName: string;
  mitreTactic: string;
  severity: SeverityLevel;
  eventCount: number;
  criticalCount: number;
  isBlocked: boolean;
  rawLogs: LogEntry[];
  targetPort: number | string;
  protocol: string;
  lastSeen: string;
}

export interface CountryOriginStats {
  code: string;
  name: string;
  flag: string;
  continent: string;
  continentKey: GeoFilterContinent;
  lat: number;
  lng: number;
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

// Target SOC Gateway Location (Paris HQ Default)
const TARGET_GATEWAY_GEO = {
  name: 'Passerelle Zyxel ATP / USG FLEX (Paris HQ)',
  city: 'Paris',
  country: 'France',
  flag: '🇫🇷',
  lat: 48.8566,
  lng: 2.3522,
};

// Comprehensive Geo-IP Database mapping for high accuracy
const KNOWN_GEO_COUNTRIES: Record<
  string,
  {
    name: string;
    flag: string;
    continent: string;
    continentKey: GeoFilterContinent;
    lat: number;
    lng: number;
    defaultCity: string;
    defaultIsp: string;
  }
> = {
  RU: {
    name: 'Russie',
    flag: '🇷🇺',
    continent: "Europe de l'Est / Asie",
    continentKey: 'EUROPE',
    lat: 55.7558,
    lng: 37.6173,
    defaultCity: 'Moscou',
    defaultIsp: 'Selectel / Rostelecom',
  },
  CN: {
    name: 'Chine',
    flag: '🇨🇳',
    continent: 'Asie-Pacifique',
    continentKey: 'ASIA',
    lat: 31.2304,
    lng: 121.4737,
    defaultCity: 'Shanghai',
    defaultIsp: 'China Telecom / Chinanet',
  },
  US: {
    name: 'États-Unis',
    flag: '🇺🇸',
    continent: 'Amérique du Nord',
    continentKey: 'AMERICAS',
    lat: 38.9072,
    lng: -77.0369,
    defaultCity: 'Ashburn (VA)',
    defaultIsp: 'Amazon AWS / DigitalOcean',
  },
  NL: {
    name: 'Pays-Bas',
    flag: '🇳🇱',
    continent: "Europe de l'Ouest",
    continentKey: 'EUROPE',
    lat: 52.3676,
    lng: 4.9041,
    defaultCity: 'Amsterdam',
    defaultIsp: 'Quasi Networks / Tor Exit',
  },
  KP: {
    name: 'Corée du Nord',
    flag: '🇰🇵',
    continent: "Asie de l'Est",
    continentKey: 'ASIA',
    lat: 39.0392,
    lng: 125.7625,
    defaultCity: 'Pyongyang',
    defaultIsp: 'Star Joint Venture Co.',
  },
  IR: {
    name: 'Iran',
    flag: '🇮🇷',
    continent: 'Moyen-Orient',
    continentKey: 'MIDDLE_EAST',
    lat: 35.6892,
    lng: 51.389,
    defaultCity: 'Téhéran',
    defaultIsp: 'TIC / Afranet',
  },
  BR: {
    name: 'Brésil',
    flag: '🇧🇷',
    continent: 'Amérique du Sud',
    continentKey: 'AMERICAS',
    lat: -23.5505,
    lng: -46.6333,
    defaultCity: 'São Paulo',
    defaultIsp: 'Claro Brasil / Telecom',
  },
  DE: {
    name: 'Allemagne',
    flag: '🇩🇪',
    continent: "Europe de l'Ouest",
    continentKey: 'EUROPE',
    lat: 50.1109,
    lng: 8.6821,
    defaultCity: 'Francfort',
    defaultIsp: 'Hetzner Online GmbH',
  },
  FR: {
    name: 'France',
    flag: '🇫🇷',
    continent: "Europe de l'Ouest",
    continentKey: 'EUROPE',
    lat: 48.8566,
    lng: 2.3522,
    defaultCity: 'Paris',
    defaultIsp: 'OVHcloud / Orange',
  },
  UA: {
    name: 'Ukraine',
    flag: '🇺🇦',
    continent: "Europe de l'Est",
    continentKey: 'EUROPE',
    lat: 50.4501,
    lng: 30.5234,
    defaultCity: 'Kyiv',
    defaultIsp: 'Ukrtelecom',
  },
  RO: {
    name: 'Roumanie',
    flag: '🇷🇴',
    continent: "Europe de l'Est",
    continentKey: 'EUROPE',
    lat: 44.4268,
    lng: 26.1025,
    defaultCity: 'Bucarest',
    defaultIsp: 'RCS & RDS',
  },
  VN: {
    name: 'Vietnam',
    flag: '🇻🇳',
    continent: 'Asie du Sud-Est',
    continentKey: 'ASIA',
    lat: 21.0285,
    lng: 105.8542,
    defaultCity: 'Hanoï',
    defaultIsp: 'Viettel Group',
  },
  IN: {
    name: 'Inde',
    flag: '🇮🇳',
    continent: 'Asie du Sud',
    continentKey: 'ASIA',
    lat: 19.076,
    lng: 72.8777,
    defaultCity: 'Mumbai',
    defaultIsp: 'Tata Communications',
  },
  GB: {
    name: 'Royaume-Uni',
    flag: '🇬🇧',
    continent: "Europe de l'Ouest",
    continentKey: 'EUROPE',
    lat: 51.5074,
    lng: -0.1278,
    defaultCity: 'Londres',
    defaultIsp: 'British Telecom',
  },
  ID: {
    name: 'Indonésie',
    flag: '🇮🇩',
    continent: 'Asie du Sud-Est',
    continentKey: 'ASIA',
    lat: -6.2088,
    lng: 106.8456,
    defaultCity: 'Jakarta',
    defaultIsp: 'Telkom Indonesia',
  },
  SC: {
    name: 'Seychelles',
    flag: '🇸🇨',
    continent: 'Afrique / Océan Indien',
    continentKey: 'AFRICA',
    lat: -4.6796,
    lng: 55.492,
    defaultCity: 'Victoria',
    defaultIsp: 'Cable & Wireless Seychelles',
  },
  CH: {
    name: 'Suisse',
    flag: '🇨🇭',
    continent: "Europe de l'Ouest",
    continentKey: 'EUROPE',
    lat: 47.3769,
    lng: 8.5417,
    defaultCity: 'Zurich',
    defaultIsp: 'Swisscom / Proton Hosting',
  },
  SG: {
    name: 'Singapour',
    flag: '🇸🇬',
    continent: 'Asie du Sud-Est',
    continentKey: 'ASIA',
    lat: 1.3521,
    lng: 103.8198,
    defaultCity: 'Singapour',
    defaultIsp: 'Singtel',
  },
  JP: {
    name: 'Japon',
    flag: '🇯🇵',
    continent: "Asie de l'Est",
    continentKey: 'ASIA',
    lat: 35.6762,
    lng: 139.6503,
    defaultCity: 'Tokyo',
    defaultIsp: 'NTT Communications',
  },
  CA: {
    name: 'Canada',
    flag: '🇨🇦',
    continent: 'Amérique du Nord',
    continentKey: 'AMERICAS',
    lat: 45.4215,
    lng: -75.6972,
    defaultCity: 'Montréal',
    defaultIsp: 'OVH BHS / Bell Canada',
  },
  SE: {
    name: 'Suède',
    flag: '🇸🇪',
    continent: "Europe du Nord",
    continentKey: 'EUROPE',
    lat: 59.3293,
    lng: 18.0686,
    defaultCity: 'Stockholm',
    defaultIsp: 'Telia Company',
  },
  TR: {
    name: 'Turquie',
    flag: '🇹🇷',
    continent: 'Moyen-Orient',
    continentKey: 'MIDDLE_EAST',
    lat: 39.9334,
    lng: 32.8597,
    defaultCity: 'Ankara',
    defaultIsp: 'Turk Telekom',
  },
  ZA: {
    name: 'Afrique du Sud',
    flag: '🇿🇦',
    continent: 'Afrique',
    continentKey: 'AFRICA',
    lat: -26.2041,
    lng: 28.0473,
    defaultCity: 'Johannesburg',
    defaultIsp: 'Telkom SA',
  },
};

// Known exact IP coordinates dictionary for standard malicious IOCs
const KNOWN_EXACT_IPS: Record<
  string,
  {
    countryCode: string;
    city: string;
    lat: number;
    lng: number;
    isp: string;
  }
> = {
  '91.240.118.232': {
    countryCode: 'RU',
    city: 'Moscou',
    lat: 55.7558,
    lng: 37.6173,
    isp: 'AS48282 / Selectel C2 Cluster',
  },
  '45.142.212.18': {
    countryCode: 'RU',
    city: 'Saint-Pétersbourg',
    lat: 59.9343,
    lng: 30.3351,
    isp: 'AS200000 / Webzilla Bulletproof',
  },
  '193.106.191.66': {
    countryCode: 'RU',
    city: 'Samara',
    lat: 53.2415,
    lng: 50.2212,
    isp: 'AS12389 / Rostelecom WAN Scanner',
  },
  '45.154.255.89': {
    countryCode: 'RU',
    city: 'Novossibirsk',
    lat: 55.0084,
    lng: 82.9357,
    isp: 'AS57523 / C2 Server Node',
  },
  '218.92.0.188': {
    countryCode: 'CN',
    city: 'Nankin (Jiangsu)',
    lat: 32.0617,
    lng: 118.7632,
    isp: 'AS4134 / China Telecom Brute-Force Botnet',
  },
  '112.85.42.19': {
    countryCode: 'CN',
    city: 'Pékin',
    lat: 39.9042,
    lng: 116.4074,
    isp: 'AS4808 / CNCGROUP IP Explorer',
  },
  '103.152.220.45': {
    countryCode: 'ID',
    city: 'Jakarta',
    lat: -6.2088,
    lng: 106.8456,
    isp: 'AS138997 / PT Cyber Akses',
  },
  '194.26.29.112': {
    countryCode: 'NL',
    city: 'Amsterdam',
    lat: 52.3676,
    lng: 4.9041,
    isp: 'AS60117 / Quasi Networks Tor Relay',
  },
  '185.220.101.5': {
    countryCode: 'NL',
    city: 'Rotterdam',
    lat: 51.9244,
    lng: 4.4777,
    isp: 'AS208323 / Zwiebelfreunde Tor Exit Node',
  },
  '185.100.87.202': {
    countryCode: 'NL',
    city: 'Utrecht',
    lat: 52.0907,
    lng: 5.1214,
    isp: 'AS49981 / WorldStream Cloud',
  },
  '198.51.100.23': {
    countryCode: 'US',
    city: 'New York (NY)',
    lat: 40.7128,
    lng: -74.006,
    isp: 'AS15169 / Testbed WAN Attacker',
  },
  '23.129.64.100': {
    countryCode: 'US',
    city: 'Seattle (WA)',
    lat: 47.6062,
    lng: -122.3321,
    isp: 'AS394536 / Emerald Onion Relay',
  },
  '52.14.88.19': {
    countryCode: 'US',
    city: 'Ashburn (VA)',
    lat: 39.0438,
    lng: -77.4874,
    isp: 'AS16509 / Compromised EC2 Proxy',
  },
  '175.45.176.10': {
    countryCode: 'KP',
    city: 'Pyongyang',
    lat: 39.0392,
    lng: 125.7625,
    isp: 'AS131279 / Ryugyong APT Lazarus Group',
  },
  '210.52.109.22': {
    countryCode: 'KP',
    city: 'Sinuiju',
    lat: 40.1006,
    lng: 124.398,
    isp: 'AS131279 / Star JV Subnet',
  },
  '5.127.220.14': {
    countryCode: 'IR',
    city: 'Téhéran',
    lat: 35.6892,
    lng: 51.389,
    isp: 'AS197207 / Mobile Telecommunication Iran',
  },
  '91.98.12.88': {
    countryCode: 'IR',
    city: 'Ispahan',
    lat: 32.6546,
    lng: 51.668,
    isp: 'AS43754 / Asiatech Data Center',
  },
  '177.54.120.3': {
    countryCode: 'BR',
    city: 'São Paulo',
    lat: -23.5505,
    lng: -46.6333,
    isp: 'AS28573 / Claro Brasil Botnet Node',
  },
  '187.63.14.90': {
    countryCode: 'BR',
    city: 'Rio de Janeiro',
    lat: -22.9068,
    lng: -43.1729,
    isp: 'AS7738 / Telemar Norte Leste',
  },
  '195.133.40.12': {
    countryCode: 'RO',
    city: 'Bucarest',
    lat: 44.4268,
    lng: 26.1025,
    isp: 'AS8708 / RCS & RDS Scanner',
  },
  '80.82.77.33': {
    countryCode: 'SC',
    city: 'Victoria',
    lat: -4.6796,
    lng: 55.492,
    isp: 'AS202425 / IP Volume Offshore Host',
  },
  '179.43.155.202': {
    countryCode: 'CH',
    city: 'Zurich',
    lat: 47.3769,
    lng: 8.5417,
    isp: 'AS51852 / Private Layer Bulletproof',
  },
  '89.248.167.131': {
    countryCode: 'DE',
    city: 'Francfort',
    lat: 50.1109,
    lng: 8.6821,
    isp: 'AS202425 / Shodan Automated Scanner',
  },
  '185.17.41.9': {
    countryCode: 'UA',
    city: 'Kyiv',
    lat: 50.4501,
    lng: 30.5234,
    isp: 'AS44034 / Web-Hosting Node',
  },
};

// Deterministic Geo Resolver for any IP
function resolveIpGeoDetails(ip: string, fallbackCountry?: string): {
  countryCode: string;
  countryName: string;
  city: string;
  flag: string;
  lat: number;
  lng: number;
  continent: string;
  continentKey: GeoFilterContinent;
  isp: string;
} {
  const cleanIp = (ip || '0.0.0.0').trim();

  // 1. Direct match in exact dictionary
  if (KNOWN_EXACT_IPS[cleanIp]) {
    const exact = KNOWN_EXACT_IPS[cleanIp];
    const cMeta = KNOWN_GEO_COUNTRIES[exact.countryCode] || KNOWN_GEO_COUNTRIES['RU'];
    return {
      countryCode: exact.countryCode,
      countryName: cMeta.name,
      city: exact.city,
      flag: cMeta.flag,
      lat: exact.lat,
      lng: exact.lng,
      continent: cMeta.continent,
      continentKey: cMeta.continentKey,
      isp: exact.isp,
    };
  }

  // 2. Private LAN IPs
  if (
    cleanIp.startsWith('192.168.') ||
    cleanIp.startsWith('10.') ||
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(cleanIp) ||
    cleanIp === '127.0.0.1' ||
    cleanIp === '0.0.0.0'
  ) {
    return {
      countryCode: 'FR',
      countryName: 'Réseau Interne (LAN)',
      city: 'Paris Intranet',
      flag: '🏢',
      lat: 48.8566 + 0.02,
      lng: 2.3522 + 0.02,
      continent: 'Intranet Privé',
      continentKey: 'EUROPE',
      isp: 'Zyxel Subnet Local',
    };
  }

  // 3. Fallback country provided
  if (fallbackCountry && KNOWN_GEO_COUNTRIES[fallbackCountry.toUpperCase()]) {
    const code = fallbackCountry.toUpperCase();
    const cMeta = KNOWN_GEO_COUNTRIES[code];
    // Add small deterministic jitter so distinct IPs in same country don't overlap exactly
    const hash = cleanIp.split('').reduce((acc, c) => acc + c.charCodeAt(0), 0);
    const latOffset = ((hash % 100) - 50) / 40;
    const lngOffset = (((hash * 7) % 100) - 50) / 40;

    return {
      countryCode: code,
      countryName: cMeta.name,
      city: cMeta.defaultCity,
      flag: cMeta.flag,
      lat: cMeta.lat + latOffset,
      lng: cMeta.lng + lngOffset,
      continent: cMeta.continent,
      continentKey: cMeta.continentKey,
      isp: cMeta.defaultIsp,
    };
  }

  // 4. IP prefix heuristics
  if (cleanIp.startsWith('91.240.') || cleanIp.startsWith('45.142.') || cleanIp.startsWith('193.106.') || cleanIp.startsWith('45.154.')) {
    return resolveIpGeoDetails(cleanIp, 'RU');
  }
  if (cleanIp.startsWith('218.92.') || cleanIp.startsWith('103.') || cleanIp.startsWith('112.')) {
    return resolveIpGeoDetails(cleanIp, 'CN');
  }
  if (cleanIp.startsWith('198.51.') || cleanIp.startsWith('23.') || cleanIp.startsWith('52.')) {
    return resolveIpGeoDetails(cleanIp, 'US');
  }
  if (cleanIp.startsWith('194.26.') || cleanIp.startsWith('185.220.') || cleanIp.startsWith('185.100.')) {
    return resolveIpGeoDetails(cleanIp, 'NL');
  }
  if (cleanIp.startsWith('175.45.') || cleanIp.startsWith('210.52.')) {
    return resolveIpGeoDetails(cleanIp, 'KP');
  }
  if (cleanIp.startsWith('5.127.') || cleanIp.startsWith('91.98.')) {
    return resolveIpGeoDetails(cleanIp, 'IR');
  }
  if (cleanIp.startsWith('177.') || cleanIp.startsWith('187.')) {
    return resolveIpGeoDetails(cleanIp, 'BR');
  }

  // 5. Hash based deterministic resolution
  const sum = cleanIp.split('').reduce((acc, c) => acc + c.charCodeAt(0), 0);
  const countryCodes = ['RU', 'CN', 'US', 'NL', 'IR', 'KP', 'BR', 'DE', 'RO', 'VN', 'SC'];
  const code = countryCodes[sum % countryCodes.length];
  const cMeta = KNOWN_GEO_COUNTRIES[code];
  const latOffset = ((sum % 100) - 50) / 40;
  const lngOffset = (((sum * 13) % 100) - 50) / 40;

  return {
    countryCode: code,
    countryName: cMeta.name,
    city: cMeta.defaultCity,
    flag: cMeta.flag,
    lat: cMeta.lat + latOffset,
    lng: cMeta.lng + lngOffset,
    continent: cMeta.continent,
    continentKey: cMeta.continentKey,
    isp: cMeta.defaultIsp,
  };
}

function getSeverityColor(sev: SeverityLevel): string {
  switch (sev) {
    case 'CRITICAL':
      return '#ef4444'; // Red
    case 'HIGH':
      return '#f97316'; // Orange
    case 'MEDIUM':
      return '#06b6d4'; // Cyan
    case 'LOW':
    default:
      return '#10b981'; // Emerald
  }
}

export const GeographicalAttackHeatmap: React.FC<GeographicalAttackHeatmapProps> = ({
  logs,
  analysis,
  onInspectLog,
  onEnforceDefense,
  deviceName = 'Passerelle Zyxel Nebula ATP',
}) => {
  const [viewMode, setViewMode] = useState<GeoHeatmapViewMode>('LEAFLET_MAP');
  const [continentFilter, setContinentFilter] = useState<GeoFilterContinent>('ALL');
  const [severityFilter, setSeverityFilter] = useState<'ALL' | 'CRITICAL' | 'BLOCKED' | 'ACTIVE_ONLY'>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedIp, setSelectedIp] = useState<string | null>(null);
  const [selectedCountryCode, setSelectedCountryCode] = useState<string | null>(null);
  const [isDeployingRule, setIsDeployingRule] = useState<string | null>(null);
  const [ruleDeployedToast, setRuleDeployedToast] = useState<string | null>(null);

  // Map display toggles
  const [showAttackArcs, setShowAttackArcs] = useState<boolean>(true);
  const [showHeatHalos, setShowHeatHalos] = useState<boolean>(true);

  // References for map containers and instances
  const leafletContainerRef = useRef<HTMLDivElement | null>(null);
  const leafletMapRef = useRef<L.Map | null>(null);
  const leafletMarkersGroupRef = useRef<L.LayerGroup | null>(null);
  const leafletArcsGroupRef = useRef<L.LayerGroup | null>(null);

  const d3ContainerRef = useRef<SVGSVGElement | null>(null);

  // 1. Process logs and extract unique Malicious Source IP items
  const maliciousIpList = useMemo<MaliciousIpGeoItem[]>(() => {
    const ipMap = new Map<string, MaliciousIpGeoItem>();

    logs.forEach((log) => {
      const srcIp = log.srcIp?.trim();
      if (!srcIp) return;

      const iocMatch = analysis.iocList.find((i) => i.value === srcIp);
      const isBlocked =
        log.action === 'Blocked' ||
        log.action === 'Dropped' ||
        log.action === 'Quarantined';

      if (!ipMap.has(srcIp)) {
        const geo = resolveIpGeoDetails(srcIp, log.country || iocMatch?.country);
        ipMap.set(srcIp, {
          ip: srcIp,
          countryCode: geo.countryCode,
          countryName: geo.countryName,
          city: geo.city,
          flag: geo.flag,
          lat: geo.lat,
          lng: geo.lng,
          continent: geo.continent,
          continentKey: geo.continentKey,
          isp: geo.isp,
          threatName: log.threatName || 'Attaque Réseau Non Définie',
          mitreTactic: 'Accès Initial & Exploitation',
          severity: log.severity,
          eventCount: 1,
          criticalCount: log.severity === 'CRITICAL' ? 1 : 0,
          isBlocked,
          rawLogs: [log],
          targetPort: log.dstPort || 'WAN-443',
          protocol: log.protocol || 'TCP',
          lastSeen: log.timestamp || new Date().toISOString(),
        });
      } else {
        const existing = ipMap.get(srcIp)!;
        existing.eventCount += 1;
        if (log.severity === 'CRITICAL') {
          existing.criticalCount += 1;
          existing.severity = 'CRITICAL';
        } else if (log.severity === 'HIGH' && existing.severity !== 'CRITICAL') {
          existing.severity = 'HIGH';
        }
        if (isBlocked) {
          existing.isBlocked = true;
        }
        existing.rawLogs.push(log);
      }
    });

    // Also verify any IOCs that might not have a direct log entry
    analysis.iocList
      .filter((i) => i.type === 'IP')
      .forEach((ioc) => {
        if (!ipMap.has(ioc.value)) {
          const geo = resolveIpGeoDetails(ioc.value, ioc.country);
          ipMap.set(ioc.value, {
            ip: ioc.value,
            countryCode: geo.countryCode,
            countryName: geo.countryName,
            city: geo.city,
            flag: geo.flag,
            lat: geo.lat,
            lng: geo.lng,
            continent: geo.continent,
            continentKey: geo.continentKey,
            isp: geo.isp,
            threatName: ioc.threat || 'IOC Malveillant Répertorié',
            mitreTactic: 'C2 / Exfiltration',
            severity: 'CRITICAL',
            eventCount: 1,
            criticalCount: 1,
            isBlocked: false,
            rawLogs: [],
            targetPort: '443',
            protocol: 'TCP',
            lastSeen: new Date().toISOString(),
          });
        }
      });

    return Array.from(ipMap.values()).sort((a, b) => b.eventCount - a.eventCount);
  }, [logs, analysis]);

  // 2. Aggregate into country statistics for Treemap and Country View
  const countryStatsList = useMemo<CountryOriginStats[]>(() => {
    const map = new Map<string, CountryOriginStats>();

    maliciousIpList.forEach((item) => {
      if (!map.has(item.countryCode)) {
        map.set(item.countryCode, {
          code: item.countryCode,
          name: item.countryName,
          flag: item.flag,
          continent: item.continent,
          continentKey: item.continentKey,
          lat: item.lat,
          lng: item.lng,
          totalAttacks: 0,
          criticalAttacks: 0,
          highAttacks: 0,
          blockedAttacks: 0,
          alertedAttacks: 0,
          uniqueIpsCount: 0,
          sourceIpsList: [],
          dominantThreat: item.threatName,
          mitreTactic: item.mitreTactic,
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

      const c = map.get(item.countryCode)!;
      c.totalAttacks += item.eventCount;
      c.criticalAttacks += item.criticalCount;
      if (item.severity === 'HIGH') c.highAttacks += item.eventCount;
      if (item.isBlocked) c.blockedAttacks += item.eventCount;
      else c.alertedAttacks += item.eventCount;

      c.uniqueIpsCount += 1;
      if (!c.sourceIpsList.includes(item.ip)) {
        c.sourceIpsList.push(item.ip);
      }
      c.logs.push(...item.rawLogs);

      // Threat breakdown
      const threatLower = (item.threatName + ' ' + item.protocol).toLowerCase();
      if (threatLower.includes('malware') || threatLower.includes('trojan') || threatLower.includes('ransomware') || threatLower.includes('lockbit')) {
        c.threatDistribution.malware += item.eventCount;
      } else if (threatLower.includes('rce') || threatLower.includes('cve') || threatLower.includes('exploit') || threatLower.includes('log4shell')) {
        c.threatDistribution.rce += item.eventCount;
      } else if (threatLower.includes('c2') || threatLower.includes('cobalt') || threatLower.includes('beacon') || threatLower.includes('botnet')) {
        c.threatDistribution.c2 += item.eventCount;
      } else if (threatLower.includes('ddos') || threatLower.includes('flood') || threatLower.includes('udp') || threatLower.includes('syn')) {
        c.threatDistribution.ddos += item.eventCount;
      } else if (threatLower.includes('brute') || threatLower.includes('ssh') || threatLower.includes('login') || threatLower.includes('auth')) {
        c.threatDistribution.bruteForce += item.eventCount;
      } else {
        c.threatDistribution.phishing += item.eventCount;
      }
    });

    // Compute rates and heat colors
    const results = Array.from(map.values());
    results.forEach((c) => {
      c.blockRate = c.totalAttacks > 0 ? Math.round((c.blockedAttacks / c.totalAttacks) * 100) : 100;
      const critRatio = c.totalAttacks > 0 ? c.criticalAttacks / c.totalAttacks : 0;
      let score = 30 + c.totalAttacks * 5 + c.criticalAttacks * 10;
      if (c.blockRate < 100) score += 20;
      c.riskScore = Math.min(99, Math.max(25, score));

      if (critRatio >= 0.4 || c.criticalAttacks >= 3 || c.totalAttacks >= 8) {
        c.heatColor = '#ef4444'; // Red
      } else if (critRatio >= 0.2 || c.totalAttacks >= 4) {
        c.heatColor = '#f97316'; // Orange
      } else if (c.totalAttacks >= 2) {
        c.heatColor = '#06b6d4'; // Cyan
      } else {
        c.heatColor = '#10b981'; // Emerald
      }
    });

    return results.sort((a, b) => b.totalAttacks - a.totalAttacks);
  }, [maliciousIpList]);

  // 3. Filtered malicious IP items
  const filteredIpList = useMemo(() => {
    return maliciousIpList.filter((item) => {
      // Continent filter
      if (continentFilter !== 'ALL' && item.continentKey !== continentFilter) {
        return false;
      }

      // Severity filter
      if (severityFilter === 'CRITICAL' && item.severity !== 'CRITICAL' && item.severity !== 'HIGH') {
        return false;
      }
      if (severityFilter === 'BLOCKED' && !item.isBlocked) {
        return false;
      }
      if (severityFilter === 'ACTIVE_ONLY' && item.isBlocked) {
        return false;
      }

      // Search query
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase().trim();
        const matches =
          item.ip.toLowerCase().includes(q) ||
          item.countryName.toLowerCase().includes(q) ||
          item.countryCode.toLowerCase().includes(q) ||
          item.city.toLowerCase().includes(q) ||
          item.threatName.toLowerCase().includes(q) ||
          item.isp.toLowerCase().includes(q);
        if (!matches) return false;
      }

      return true;
    });
  }, [maliciousIpList, continentFilter, severityFilter, searchQuery]);

  // Top summary KPIs
  const totalHostileIps = maliciousIpList.length;
  const criticalIpsCount = maliciousIpList.filter((i) => i.severity === 'CRITICAL').length;
  const topHostileCountry = countryStatsList[0] || null;
  const globalBlockRate = useMemo(() => {
    const total = maliciousIpList.reduce((acc, i) => acc + i.eventCount, 0);
    const blocked = maliciousIpList.filter((i) => i.isBlocked).reduce((acc, i) => acc + i.eventCount, 0);
    return total > 0 ? Math.round((blocked / total) * 100) : 100;
  }, [maliciousIpList]);

  // 4. Initialize and update Leaflet Map
  useEffect(() => {
    if (viewMode !== 'LEAFLET_MAP') return;
    if (!leafletContainerRef.current) return;

    // Destroy previous instance cleanly if exists
    if (leafletMapRef.current) {
      leafletMapRef.current.remove();
      leafletMapRef.current = null;
    }

    try {
      // Create new Leaflet Map instance
      const map = L.map(leafletContainerRef.current, {
        center: [32, 20],
        zoom: 2.2,
        minZoom: 1.5,
        maxZoom: 13,
        zoomControl: false,
        attributionControl: true,
        worldCopyJump: true,
      });

      // Add Zoom Control at bottom right
      L.control
        .zoom({
          position: 'bottomright',
        })
        .addTo(map);

      // Dark Matter SOC Tile Layer from CARTO
      L.tileLayer(
        'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
        {
          subdomains: 'abcd',
          maxZoom: 19,
          attribution:
            '&copy; <a href="https://carto.com/">CARTO</a> &copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>',
        }
      ).addTo(map);

      // Create LayerGroups for clean updates
      const arcsGroup = L.layerGroup().addTo(map);
      const markersGroup = L.layerGroup().addTo(map);

      leafletMapRef.current = map;
      leafletArcsGroupRef.current = arcsGroup;
      leafletMarkersGroupRef.current = markersGroup;

      // Add Gateway Target Marker (Paris HQ)
      const gatewayIconHtml = `
        <div class="relative flex items-center justify-center -translate-x-1/2 -translate-y-1/2 group cursor-pointer">
          <span class="absolute w-12 h-12 rounded-full bg-cyan-500/25 animate-ping pointer-events-none"></span>
          <span class="absolute w-8 h-8 rounded-full bg-cyan-500/40 blur-xs pointer-events-none"></span>
          <div class="w-7 h-7 rounded-full bg-gradient-to-tr from-cyan-600 to-emerald-500 border-2 border-white shadow-[0_0_20px_rgba(6,182,212,0.8)] flex items-center justify-center text-slate-950 font-bold">
            <svg class="w-3.5 h-3.5 text-slate-950 fill-current" viewBox="0 0 24 24">
              <path d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z"/>
            </svg>
          </div>
          <div class="absolute top-8 left-1/2 -translate-x-1/2 px-2.5 py-0.5 rounded-lg bg-slate-950/95 border border-cyan-400/80 text-[10px] font-mono font-bold text-cyan-200 whitespace-nowrap shadow-xl">
            🇫🇷 ${deviceName} (Paris HQ)
          </div>
        </div>
      `;

      const gatewayIcon = L.divIcon({
        className: 'custom-gateway-icon',
        html: gatewayIconHtml,
        iconSize: [28, 28],
        iconAnchor: [14, 14],
      });

      const gatewayMarker = L.marker([TARGET_GATEWAY_GEO.lat, TARGET_GATEWAY_GEO.lng], {
        icon: gatewayIcon,
        zIndexOffset: 1000,
      }).addTo(map);

      gatewayMarker.bindPopup(`
        <div class="p-2 space-y-2 font-mono text-xs">
          <div class="flex items-center gap-2 border-b border-cyan-900 pb-1.5">
            <span class="text-xl">🇫🇷</span>
            <div>
              <div class="font-bold text-white text-sm">${deviceName}</div>
              <div class="text-[10px] text-cyan-400">Centre d'Opérations de Sécurité (SOC) Paris</div>
            </div>
          </div>
          <div class="text-slate-300 text-[11px] space-y-1">
            <div>Statut : <span class="text-emerald-400 font-bold">ACTIF & PROTÉGÉ</span></div>
            <div>Moteur : <span class="text-white">Zyxel Nebula ATP / USG FLEX Firewall</span></div>
            <div>Attaques bloquées : <span class="text-cyan-300 font-bold">${globalBlockRate}% d'efficacité</span></div>
          </div>
        </div>
      `);

      // Invalidate size once after mounting so tiles render smoothly
      setTimeout(() => {
        map.invalidateSize();
      }, 200);
    } catch (err) {
      console.error('Error initializing Leaflet map:', err);
    }

    return () => {
      if (leafletMapRef.current) {
        leafletMapRef.current.remove();
        leafletMapRef.current = null;
      }
    };
  }, [viewMode, deviceName]);

  // 5. Update Leaflet markers and attack arcs whenever filtered data or toggles change
  useEffect(() => {
    if (viewMode !== 'LEAFLET_MAP') return;
    const map = leafletMapRef.current;
    const markersGroup = leafletMarkersGroupRef.current;
    const arcsGroup = leafletArcsGroupRef.current;
    if (!map || !markersGroup || !arcsGroup) return;

    markersGroup.clearLayers();
    arcsGroup.clearLayers();

    const targetLat = TARGET_GATEWAY_GEO.lat;
    const targetLng = TARGET_GATEWAY_GEO.lng;

    // Render each malicious IP marker
    filteredIpList.forEach((item) => {
      const isCritical = item.severity === 'CRITICAL';
      const color = getSeverityColor(item.severity);
      const isSelected = selectedIp === item.ip;

      // Pulsing Heat Halos around regions if enabled
      if (showHeatHalos) {
        const heatCircle = L.circle([item.lat, item.lng], {
          radius: Math.min(500000, 100000 + item.eventCount * 40000),
          color: color,
          fillColor: color,
          fillOpacity: isCritical ? 0.22 : 0.12,
          weight: 1,
          dashArray: '3,3',
          interactive: false,
        });
        markersGroup.addLayer(heatCircle);
      }

      // Attack Trajectory Lines flying towards Paris Gateway
      if (showAttackArcs) {
        // Compute curved intermediate point for geodesic visual style
        const midLat = (item.lat + targetLat) / 2 + Math.abs(item.lng - targetLng) * 0.08;
        const midLng = (item.lng + targetLng) / 2;

        const polyline = L.polyline(
          [
            [item.lat, item.lng],
            [midLat, midLng],
            [targetLat, targetLng],
          ],
          {
            color: color,
            weight: isCritical || isSelected ? 2.5 : 1.5,
            opacity: isSelected ? 1 : isCritical ? 0.8 : 0.5,
            dashArray: isCritical ? '6,4' : '4,4',
          }
        );
        arcsGroup.addLayer(polyline);
      }

      // Custom HTML Marker using L.divIcon
      const markerHtml = `
        <div class="relative flex items-center justify-center -translate-x-1/2 -translate-y-1/2 cursor-pointer group">
          ${
            isCritical
              ? `<span class="absolute w-8 h-8 rounded-full pointer-events-none animate-ping" style="background-color: ${color}; opacity: 0.4;"></span>`
              : ''
          }
          <div class="w-5 h-5 rounded-full flex items-center justify-center shadow-lg transition-transform duration-200 group-hover:scale-125 ${
            isSelected ? 'ring-2 ring-white scale-125' : ''
          }" style="background-color: ${color}; box-shadow: 0 0 12px ${color};">
            <span class="w-2 h-2 rounded-full bg-slate-950"></span>
          </div>
          <div class="absolute top-6 left-1/2 -translate-x-1/2 px-1.5 py-0.5 rounded-md bg-slate-950/95 border text-[9px] font-mono font-bold whitespace-nowrap shadow-md flex items-center gap-1 ${
            isSelected ? 'border-white text-white' : 'text-slate-200'
          }" style="border-color: ${isSelected ? '#ffffff' : color};">
            <span>${item.flag}</span>
            <span>${item.ip}</span>
          </div>
        </div>
      `;

      const customIcon = L.divIcon({
        className: 'custom-malicious-ip-icon',
        html: markerHtml,
        iconSize: [20, 20],
        iconAnchor: [10, 10],
      });

      const marker = L.marker([item.lat, item.lng], {
        icon: customIcon,
        zIndexOffset: isCritical ? 500 : 200,
      });

      // Interactive popup
      const popupContent = `
        <div class="p-3 space-y-2.5 font-mono text-xs select-text min-w-[260px]">
          <div class="flex items-center justify-between border-b border-slate-800 pb-2">
            <div class="flex items-center gap-2">
              <span class="text-xl">${item.flag}</span>
              <div>
                <div class="font-bold text-white text-sm flex items-center gap-1.5">
                  <span>${item.ip}</span>
                  <span class="text-[9px] px-1.5 py-0.2 rounded font-bold uppercase ${
                    isCritical
                      ? 'bg-rose-950 text-rose-300 border border-rose-700'
                      : 'bg-amber-950 text-amber-300 border border-amber-700'
                  }">${item.severity}</span>
                </div>
                <div class="text-[10px] text-slate-400">${item.city}, ${item.countryName} (${item.countryCode})</div>
              </div>
            </div>
          </div>

          <div class="space-y-1.5 text-[11px] text-slate-300">
            <div class="flex items-center justify-between">
              <span class="text-slate-400">Signature Détectée :</span>
              <span class="font-bold text-cyan-300 truncate max-w-[140px]">${item.threatName}</span>
            </div>
            <div class="flex items-center justify-between">
              <span class="text-slate-400">Volume Événements :</span>
              <span class="font-bold text-white">${item.eventCount} paquets analysés</span>
            </div>
            <div class="flex items-center justify-between">
              <span class="text-slate-400">Port / Protocole cible :</span>
              <span class="text-purple-300">${item.protocol} / ${item.targetPort}</span>
            </div>
            <div class="flex items-center justify-between">
              <span class="text-slate-400">Fournisseur / ASN :</span>
              <span class="text-slate-300 truncate max-w-[140px]">${item.isp}</span>
            </div>
            <div class="flex items-center justify-between">
              <span class="text-slate-400">Statut Pare-feu Zyxel :</span>
              <span class="${
                item.isBlocked ? 'text-emerald-400 font-bold' : 'text-rose-400 font-bold animate-pulse'
              }">${item.isBlocked ? '✓ BLOCAGE ACTIF' : '⚠️ NON MITIGÉ (ALERTE)'}</span>
            </div>
          </div>

          <div class="pt-2 border-t border-slate-800 flex items-center gap-2">
            ${
              !item.isBlocked
                ? `<button id="btn-block-${item.ip.replace(/\./g, '-')}" class="flex-1 py-1.5 px-2 rounded-lg bg-red-600 hover:bg-red-500 text-white font-bold text-[10px] transition text-center shadow-md">
                    Bloquer l'IP
                  </button>`
                : `<span class="flex-1 py-1.5 px-2 rounded-lg bg-emerald-950/80 border border-emerald-800 text-emerald-300 font-bold text-[10px] text-center">
                    ✓ IP Déjà Bloquée
                  </span>`
            }
          </div>
        </div>
      `;

      marker.bindPopup(popupContent);

      marker.on('popupopen', () => {
        setSelectedIp(item.ip);
        setSelectedCountryCode(item.countryCode);

        // Bind 1-click block button inside popup
        setTimeout(() => {
          const btn = document.getElementById(`btn-block-${item.ip.replace(/\./g, '-')}`);
          if (btn) {
            btn.onclick = () => {
              handleDeployIpBlock(item);
            };
          }
        }, 50);
      });

      marker.on('click', () => {
        setSelectedIp(item.ip);
        setSelectedCountryCode(item.countryCode);
      });

      markersGroup.addLayer(marker);
    });
  }, [viewMode, filteredIpList, showAttackArcs, showHeatHalos, selectedIp]);

  // 6. D3 Tactical Map Render (when in D3_TACTICAL_MAP mode)
  useEffect(() => {
    if (viewMode !== 'D3_TACTICAL_MAP') return;
    if (!d3ContainerRef.current) return;

    const svg = d3.select(d3ContainerRef.current);
    svg.selectAll('*').remove();

    const width = 960;
    const height = 480;

    // Define D3 Mercator Projection
    const projection = d3
      .geoMercator()
      .scale(130)
      .translate([width / 2, height / 1.5]);

    const path = d3.geoPath().projection(projection);

    const g = svg.append('g').attr('class', 'd3-map-root');

    // Add Zoom behavior
    const zoom = d3
      .zoom<SVGSVGElement, unknown>()
      .scaleExtent([1, 8])
      .on('zoom', (event) => {
        g.attr('transform', event.transform);
      });

    svg.call(zoom);

    // Draw Graticule lines
    const graticule = d3.geoGraticule();
    g.append('path')
      .datum(graticule)
      .attr('class', 'graticule')
      .attr('d', path as any)
      .attr('fill', 'none')
      .attr('stroke', '#1e293b')
      .attr('stroke-width', 0.5)
      .attr('stroke-opacity', 0.5);

    // Schematic continent polygons
    const continents = [
      // North America
      [
        [-160, 70],
        [-60, 70],
        [-80, 20],
        [-110, 20],
        [-130, 50],
      ],
      // South America
      [
        [-80, 10],
        [-35, -5],
        [-55, -55],
        [-75, -45],
        [-80, 10],
      ],
      // Europe
      [
        [-10, 35],
        [40, 35],
        [40, 70],
        [-10, 70],
      ],
      // Africa
      [
        [-15, 35],
        [50, 35],
        [40, -35],
        [15, -35],
        [-15, 10],
      ],
      // Asia
      [
        [40, 70],
        [180, 70],
        [140, 10],
        [100, -10],
        [60, 20],
        [40, 35],
      ],
      // Australia
      [
        [115, -15],
        [155, -15],
        [150, -40],
        [115, -35],
      ],
    ];

    continents.forEach((polyCoords, idx) => {
      const geoPoly = {
        type: 'Polygon',
        coordinates: [polyCoords],
      };

      g.append('path')
        .datum(geoPoly)
        .attr('d', path as any)
        .attr('fill', '#0f172a')
        .attr('stroke', '#334155')
        .attr('stroke-width', 1.2)
        .attr('opacity', 0.85);
    });

    const targetPos = projection([TARGET_GATEWAY_GEO.lng, TARGET_GATEWAY_GEO.lat]) || [width / 2, height / 2];

    // Attack Arcs & Particle flows
    filteredIpList.forEach((item, idx) => {
      const srcPos = projection([item.lng, item.lat]);
      if (!srcPos) return;

      const isCrit = item.severity === 'CRITICAL';
      const color = getSeverityColor(item.severity);

      // Arc path
      const midX = (srcPos[0] + targetPos[0]) / 2;
      const midY = (srcPos[1] + targetPos[1]) / 2 - 40;
      const pathD = `M ${srcPos[0]} ${srcPos[1]} Q ${midX} ${midY} ${targetPos[0]} ${targetPos[1]}`;

      const arc = g
        .append('path')
        .attr('d', pathD)
        .attr('fill', 'none')
        .attr('stroke', color)
        .attr('stroke-width', isCrit ? 2 : 1.2)
        .attr('stroke-dasharray', isCrit ? '5,3' : '3,3')
        .attr('opacity', isCrit ? 0.8 : 0.5);

      // Animated flying cyber missile / particle along the arc
      const particle = g
        .append('circle')
        .attr('r', isCrit ? 3.5 : 2.5)
        .attr('fill', color)
        .attr('filter', 'drop-shadow(0 0 6px ' + color + ')');

      // Continuous animation loop along path
      function animateParticle() {
        particle
          .transition()
          .duration(2000 + (idx % 4) * 500)
          .ease(d3.easeLinear)
          .attrTween('transform', function () {
            const arcNode = arc.node();
            if (!arcNode) return () => '';
            const length = arcNode.getTotalLength();
            return function (t: number) {
              const point = arcNode.getPointAtLength(t * length);
              return `translate(${point.x}, ${point.y})`;
            };
          })
          .on('end', animateParticle);
      }
      animateParticle();

      // Attacker node circle
      const nodeG = g
        .append('g')
        .attr('transform', `translate(${srcPos[0]}, ${srcPos[1]})`)
        .attr('class', 'cursor-pointer')
        .on('click', () => {
          setSelectedIp(item.ip);
          setSelectedCountryCode(item.countryCode);
        });

      if (isCrit) {
        nodeG
          .append('circle')
          .attr('r', 12)
          .attr('fill', color)
          .attr('opacity', 0.25)
          .attr('class', 'animate-ping');
      }

      nodeG
        .append('circle')
        .attr('r', isCrit ? 5 : 3.5)
        .attr('fill', color)
        .attr('stroke', '#ffffff')
        .attr('stroke-width', 1.5);

      nodeG
        .append('text')
        .attr('x', 7)
        .attr('y', 3)
        .attr('fill', '#f1f5f9')
        .attr('font-size', '9px')
        .attr('font-family', 'monospace')
        .attr('font-weight', 'bold')
        .text(`${item.flag} ${item.ip}`);
    });

    // Gateway target Node
    const gatewayG = g
      .append('g')
      .attr('transform', `translate(${targetPos[0]}, ${targetPos[1]})`);

    gatewayG
      .append('circle')
      .attr('r', 16)
      .attr('fill', '#06b6d4')
      .attr('opacity', 0.2)
      .attr('class', 'animate-ping');

    gatewayG
      .append('circle')
      .attr('r', 7)
      .attr('fill', '#06b6d4')
      .attr('stroke', '#ffffff')
      .attr('stroke-width', 2);

    gatewayG
      .append('text')
      .attr('x', 10)
      .attr('y', 4)
      .attr('fill', '#67e8f9')
      .attr('font-size', '10px')
      .attr('font-family', 'monospace')
      .attr('font-weight', 'bold')
      .text(`🇫🇷 Passerelle Zyxel ATP (Paris)`);
  }, [viewMode, filteredIpList]);

  // Actions: 1-Click IP block
  const handleDeployIpBlock = async (item: MaliciousIpGeoItem) => {
    setIsDeployingRule(item.ip);
    try {
      const stopAction: StopAction = {
        id: `stop-geo-${Date.now()}`,
        title: `Blocage WAN de l'IP malveillante ${item.ip} (${item.countryName})`,
        type: 'FIREWALL_BLOCK',
        target: item.ip,
        priority: 'IMMEDIATE',
        rationale: `Bloquer immédiatement tout trafic entrant depuis l'IP ${item.ip} (${item.city}, ${item.countryName} - ${item.threatName}) sur le pare-feu Zyxel.`,
        zyxelNebulaRule: {
          ruleName: `DROP_WAN_${item.ip.replace(/[^a-zA-Z0-9]/g, '_')}`,
          direction: 'WAN to LAN',
          action: 'DROP',
          sourceObject: `HOST_${item.ip}`,
          destinationObject: 'any',
        },
        zyxelCliCommand: `Router(config)# ip access-list WAN_GEO_DROP deny ip host ${item.ip} any\nRouter(config)# interface wan1 apply access-list WAN_GEO_DROP in`,
        iptablesCommand: `iptables -A INPUT -s ${item.ip} -j DROP`,
        nftablesCommand: `nft add rule ip filter input ip saddr ${item.ip} drop`,
        pfSenseRule: `<rule><action>block</action><source><address>${item.ip}</address></source></rule>`,
      };

      if (onEnforceDefense) {
        await onEnforceDefense(stopAction);
      }

      item.isBlocked = true;
      setRuleDeployedToast(`Règle pare-feu déployée : IP ${item.ip} (${item.countryName}) bloquée sur Zyxel WAN !`);
      setTimeout(() => setRuleDeployedToast(null), 4000);
    } catch (err) {
      console.error('Error deploying block rule:', err);
    } finally {
      setIsDeployingRule(null);
    }
  };

  // Actions: 1-Click Country Geo-IP block
  const handleDeployGeoBlock = async (c: CountryOriginStats) => {
    setIsDeployingRule(c.code);
    try {
      const stopAction: StopAction = {
        id: `stop-country-${Date.now()}`,
        title: `Blocage Geo-IP Zyxel : Zone entière ${c.name} (${c.code})`,
        type: 'GEO_BLOCK',
        target: `GEO-${c.code}`,
        priority: 'IMMEDIATE',
        rationale: `Activer la règle de filtrage géographique Zyxel Geo-IP pour rejeter tout trafic hostile non sollicité originaire de ${c.name}.`,
        zyxelNebulaRule: {
          ruleName: `GEO_BLOCK_${c.code}`,
          direction: 'WAN to LAN',
          action: 'DROP',
          sourceObject: `GEO_${c.code}`,
          destinationObject: 'any',
        },
        zyxelCliCommand: `Router(config)# security-policy rule-add GEO_BLOCK_${c.code} action drop src-geo-ip ${c.code} dst-zone LAN\nRouter(config)# write memory`,
        iptablesCommand: `iptables -A INPUT -m geoip --src-cc ${c.code} -j DROP`,
        nftablesCommand: `nft add rule ip filter input geoip saddr ${c.code} drop`,
        pfSenseRule: `<rule><action>block</action><source><geoip>${c.code}</geoip></source></rule>`,
      };

      if (onEnforceDefense) {
        await onEnforceDefense(stopAction);
      }

      setRuleDeployedToast(`Règle Geo-IP activée : Zone ${c.name} (${c.code}) bloquée avec succès sur Zyxel !`);
      setTimeout(() => setRuleDeployedToast(null), 4000);
    } catch (err) {
      console.error('Error deploying country block rule:', err);
    } finally {
      setIsDeployingRule(null);
    }
  };

  // Focus map on specific IP
  const handleFocusOnIp = (item: MaliciousIpGeoItem) => {
    setSelectedIp(item.ip);
    setSelectedCountryCode(item.countryCode);

    if (leafletMapRef.current) {
      leafletMapRef.current.flyTo([item.lat, item.lng], 6, {
        duration: 1.2,
      });
    }
  };

  // Reset Leaflet Map view
  const handleResetMapView = () => {
    if (leafletMapRef.current) {
      leafletMapRef.current.flyTo([32, 20], 2.2, {
        duration: 1,
      });
    }
  };

  // Focus on Gateway
  const handleFocusOnGateway = () => {
    if (leafletMapRef.current) {
      leafletMapRef.current.flyTo([TARGET_GATEWAY_GEO.lat, TARGET_GATEWAY_GEO.lng], 5, {
        duration: 1,
      });
    }
  };

  // Focus on Top Critical Host
  const handleFocusOnTopThreat = () => {
    const topCrit = maliciousIpList.find((i) => i.severity === 'CRITICAL') || maliciousIpList[0];
    if (topCrit && leafletMapRef.current) {
      leafletMapRef.current.flyTo([topCrit.lat, topCrit.lng], 5.5, {
        duration: 1.2,
      });
      setSelectedIp(topCrit.ip);
      setSelectedCountryCode(topCrit.countryCode);
    }
  };

  // Active selected country / IP metadata
  const selectedCountry = useMemo(() => {
    if (!selectedCountryCode) return null;
    return countryStatsList.find((c) => c.code === selectedCountryCode) || null;
  }, [selectedCountryCode, countryStatsList]);

  const selectedIpItem = useMemo(() => {
    if (!selectedIp) return null;
    return maliciousIpList.find((i) => i.ip === selectedIp) || null;
  }, [selectedIp, maliciousIpList]);

  // Treemap custom renderer
  const renderCustomTreemapNode = (props: any) => {
    const { x, y, width, height, name, flag, code, size, heatColor } = props;
    if (width < 32 || height < 24) return <g />;

    return (
      <g>
        <rect
          x={x}
          y={y}
          width={width}
          height={height}
          style={{
            fill: heatColor,
            stroke: '#020617',
            strokeWidth: 2,
            opacity: 0.9,
            cursor: 'pointer',
          }}
          onClick={() => setSelectedCountryCode(code)}
        />
        {width > 60 && height > 40 && (
          <text
            x={x + width / 2}
            y={y + height / 2 - 4}
            textAnchor="middle"
            fill="#ffffff"
            fontSize={12}
            fontFamily="monospace"
            fontWeight="bold"
            pointerEvents="none"
          >
            {flag} {code}
          </text>
        )}
        {width > 70 && height > 55 && (
          <text
            x={x + width / 2}
            y={y + height / 2 + 12}
            textAnchor="middle"
            fill="#f1f5f9"
            fontSize={10}
            fontFamily="monospace"
            pointerEvents="none"
          >
            {size} alertes
          </text>
        )}
      </g>
    );
  };

  const treemapData = useMemo(() => {
    return countryStatsList.map((c) => ({
      name: `${c.flag} ${c.name}`,
      code: c.code,
      flag: c.flag,
      fullName: c.name,
      continent: c.continent,
      size: c.totalAttacks,
      criticalAttacks: c.criticalAttacks,
      blockRate: c.blockRate,
      uniqueIps: c.uniqueIpsCount,
      heatColor: c.heatColor,
    }));
  }, [countryStatsList]);

  return (
    <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-2xl space-y-6">
      {/* Toast confirmation message */}
      {ruleDeployedToast && (
        <div className="p-3 rounded-xl bg-gradient-to-r from-emerald-950 to-teal-950 border border-emerald-500/80 text-emerald-200 text-xs font-mono font-bold flex items-center justify-between shadow-xl animate-in fade-in">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
            <span>{ruleDeployedToast}</span>
          </div>
          <button
            onClick={() => setRuleDeployedToast(null)}
            className="text-slate-400 hover:text-white text-xs px-2"
          >
            ✕
          </button>
        </div>
      )}

      {/* Header bar with Mode Toggles */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <div className="flex items-center gap-2.5 mb-1">
            <span className="w-8 h-8 rounded-lg bg-cyan-950 text-cyan-400 border border-cyan-800 flex items-center justify-center">
              <Globe className="w-5 h-5 animate-pulse" />
            </span>
            <h2 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
              <span>Carte Géographique Interactive des Cyberattaques</span>
              <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-cyan-950 text-cyan-300 border border-cyan-800">
                Leaflet / D3 Dark SOC
              </span>
            </h2>
          </div>
          <p className="text-xs text-slate-400 max-w-2xl font-sans">
            Visualisation géolocalisée haute résolution de la provenance des adresses IP malveillantes
            interceptées par le pare-feu Zyxel Nebula avec zoom interactif, trajectoires d'attaques et riposte en 1 clic.
          </p>
        </div>

        {/* View Mode Toggle Buttons */}
        <div className="flex flex-wrap items-center gap-1.5 p-1 rounded-xl bg-slate-950/90 border border-slate-800 self-start lg:self-auto">
          <button
            onClick={() => setViewMode('LEAFLET_MAP')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition ${
              viewMode === 'LEAFLET_MAP'
                ? 'bg-gradient-to-r from-cyan-600 to-blue-600 text-white shadow-md shadow-cyan-900/40 ring-1 ring-cyan-400/50'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/70'
            }`}
            title="Carte géographique interactive Leaflet avec tuiles sombres, zoom molette et géolocalisation exacte des IPs"
          >
            <Compass className="w-3.5 h-3.5 text-cyan-300" />
            <span>Carte Leaflet (Tuiles & Zoom)</span>
          </button>

          <button
            onClick={() => setViewMode('D3_TACTICAL_MAP')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition ${
              viewMode === 'D3_TACTICAL_MAP'
                ? 'bg-gradient-to-r from-purple-600 to-indigo-600 text-white shadow-md shadow-purple-900/40'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/70'
            }`}
            title="Carte vectorielle D3 avec animation de particules le long des arcs d'attaque"
          >
            <Radar className="w-3.5 h-3.5 text-purple-300" />
            <span>Carte D3 Tactique (Flux Animé)</span>
          </button>

          <button
            onClick={() => setViewMode('TREEMAP_HEAT')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition ${
              viewMode === 'TREEMAP_HEAT'
                ? 'bg-cyan-700 text-white shadow-md'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/70'
            }`}
            title="Treemap de densité proportionnelle par pays"
          >
            <Maximize2 className="w-3.5 h-3.5" />
            <span>Treemap</span>
          </button>

          <button
            onClick={() => setViewMode('BAR_DENSITY')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition ${
              viewMode === 'BAR_DENSITY'
                ? 'bg-amber-600 text-white shadow-md'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/70'
            }`}
            title="Classement horizontal par volume de flux"
          >
            <Flame className="w-3.5 h-3.5" />
            <span>Barres</span>
          </button>

          <button
            onClick={() => setViewMode('VECTOR_MATRIX')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition ${
              viewMode === 'VECTOR_MATRIX'
                ? 'bg-rose-700 text-white shadow-md'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/70'
            }`}
            title="Matrice menaces par pays et catégories Zyxel"
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
            <span>IPs Hostiles Uniques</span>
            <Target className="w-3.5 h-3.5 text-cyan-400" />
          </div>
          <div className="text-xl font-bold text-white">{totalHostileIps} adresses IP</div>
          <div className="text-[10px] text-cyan-400/90">{criticalIpsCount} classées critiques</div>
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
            <span>Efficacité Pare-Feu Zyxel</span>
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div className="text-xl font-bold text-emerald-400">{globalBlockRate}% neutralisés</div>
          <div className="text-[10px] text-slate-400">IDP/IPS & Réputation WAN</div>
        </div>

        <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 space-y-1">
          <div className="flex items-center justify-between text-slate-400">
            <span>Cible Protégée (Passerelle)</span>
            <Navigation className="w-3.5 h-3.5 text-cyan-400" />
          </div>
          <div className="text-sm font-bold text-cyan-300 truncate">
            {TARGET_GATEWAY_GEO.flag} {TARGET_GATEWAY_GEO.city}
          </div>
          <div className="text-[10px] text-slate-400 truncate">
            {deviceName}
          </div>
        </div>
      </div>

      {/* Filter and Continent Selector */}
      <div className="flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-slate-400 flex items-center gap-1">
            <Filter className="w-3 h-3 text-slate-500" />
            Région :
          </span>
          {(
            [
              { key: 'ALL', label: `Tous (${maliciousIpList.length})` },
              { key: 'EUROPE', label: 'Europe' },
              { key: 'ASIA', label: 'Asie' },
              { key: 'AMERICAS', label: 'Amériques' },
              { key: 'MIDDLE_EAST', label: 'Moyen-Orient' },
              { key: 'AFRICA', label: 'Afrique' },
            ] as const
          ).map((c) => (
            <button
              key={c.key}
              onClick={() => setContinentFilter(c.key)}
              className={`px-2.5 py-1 rounded-lg border transition ${
                continentFilter === c.key
                  ? 'bg-cyan-950 text-cyan-300 border-cyan-700 shadow-sm'
                  : 'bg-slate-950/60 text-slate-400 border-slate-800 hover:text-white'
              }`}
            >
              {c.label}
            </button>
          ))}
        </div>

        {/* Severity / Status Filter */}
        <div className="flex items-center gap-2">
          <span className="text-slate-400">Sévérité :</span>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value as any)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-slate-200 text-xs font-mono focus:outline-none focus:ring-1 focus:ring-cyan-500"
          >
            <option value="ALL">Toutes les sévérités</option>
            <option value="CRITICAL">Critiques & Élevées uniquement</option>
            <option value="ACTIVE_ONLY">⚠️ Non bloquées uniquement</option>
            <option value="BLOCKED">✓ Déjà bloquées</option>
          </select>
        </div>
      </div>

      {/* Search Input Bar */}
      <div className="relative">
        <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Rechercher par adresse IP, pays, ville, signature de menace (ex: 91.240..., Russie, Cobalt Strike)..."
          className="w-full pl-9 pr-4 py-2 bg-slate-950/80 border border-slate-800 rounded-xl text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 transition"
        />
        {searchQuery && (
          <button
            onClick={() => setSearchQuery('')}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-white text-xs"
          >
            ✕
          </button>
        )}
      </div>

      {/* ============================================================== */}
      {/* VIEW 0: INTERACTIVE LEAFLET WORLD MAP (Primary Interactive Map) */}
      {/* ============================================================== */}
      {viewMode === 'LEAFLET_MAP' && (
        <div className="space-y-3">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono">
            <span className="text-slate-300 font-bold flex items-center gap-1.5">
              <Compass className="w-4 h-4 text-cyan-400" />
              Carte Leaflet Interactive (Tuiles CARTO Dark Matter • Molette / Glisser pour naviguer • Clic pour inspecter l'IP)
            </span>

            {/* Quick Map Navigation Controls */}
            <div className="flex items-center gap-1.5">
              <button
                type="button"
                onClick={handleResetMapView}
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-mono border border-slate-700 transition"
                title="Rétablir la vue mondiale complète"
              >
                <RotateCcw className="w-3 h-3 text-slate-400" />
                <span>Monde</span>
              </button>
              <button
                type="button"
                onClick={handleFocusOnGateway}
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 text-[11px] font-mono border border-cyan-800/60 transition"
                title="Centrer la carte sur la passerelle Zyxel à Paris"
              >
                <Target className="w-3 h-3 text-cyan-400" />
                <span>Passerelle Paris</span>
              </button>
              <button
                type="button"
                onClick={handleFocusOnTopThreat}
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-rose-300 text-[11px] font-mono border border-rose-800/60 transition"
                title="Centrer la carte sur le foyer cyber le plus hostile"
              >
                <Flame className="w-3 h-3 text-rose-400" />
                <span>Foyer Hostile</span>
              </button>
            </div>
          </div>

          {/* Leaflet Map Canvas Container */}
          <div className="relative w-full h-[480px] sm:h-[520px] rounded-2xl border border-slate-800/90 overflow-hidden shadow-2xl bg-slate-950">
            <div ref={leafletContainerRef} className="w-full h-full" />

            {/* Floating Map Legend & Toggles Overlay */}
            <div className="absolute top-3 left-3 z-[900] bg-slate-950/90 border border-slate-800/90 backdrop-blur-md rounded-xl p-3 text-[11px] font-mono space-y-2 text-slate-300 shadow-2xl pointer-events-auto max-w-xs">
              <div className="flex items-center justify-between border-b border-slate-800 pb-1.5">
                <span className="font-bold text-white flex items-center gap-1.5">
                  <Crosshair className="w-3.5 h-3.5 text-cyan-400" />
                  Calques Cartographiques
                </span>
                <span className="text-[10px] text-cyan-400 font-bold">{filteredIpList.length} IPs</span>
              </div>

              <div className="space-y-1.5 text-[10px]">
                <label className="flex items-center gap-2 cursor-pointer text-slate-300 hover:text-white">
                  <input
                    type="checkbox"
                    checked={showAttackArcs}
                    onChange={(e) => setShowAttackArcs(e.target.checked)}
                    className="rounded border-slate-700 bg-slate-900 text-cyan-500 focus:ring-0 cursor-pointer"
                  />
                  <span>Trajectoires vers Zyxel Paris (Arcs)</span>
                </label>

                <label className="flex items-center gap-2 cursor-pointer text-slate-300 hover:text-white">
                  <input
                    type="checkbox"
                    checked={showHeatHalos}
                    onChange={(e) => setShowHeatHalos(e.target.checked)}
                    className="rounded border-slate-700 bg-slate-900 text-cyan-500 focus:ring-0 cursor-pointer"
                  />
                  <span>Halos thermiques de concentration</span>
                </label>
              </div>

              {/* Severity Legend */}
              <div className="pt-1.5 border-t border-slate-800/80 flex items-center justify-between text-[10px]">
                <span className="flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-rose-500 animate-ping inline-block" /> Critique
                </span>
                <span className="flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-amber-500 inline-block" /> Élevé
                </span>
                <span className="flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-cyan-400 inline-block" /> Moyen
                </span>
                <span className="flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-emerald-400 inline-block" /> Bloqué
                </span>
              </div>
            </div>

            {/* Bottom Target Status Overlay */}
            <div className="absolute bottom-3 left-3 z-[900] bg-slate-950/90 border border-cyan-800/80 backdrop-blur-md rounded-xl px-3 py-2 text-[11px] font-mono text-cyan-300 shadow-xl pointer-events-auto flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span>Cible surveillée : 🇫🇷 <strong>{deviceName}</strong> [48.85°N, 2.35°E]</span>
            </div>
          </div>
        </div>
      )}

      {/* ============================================================== */}
      {/* VIEW 1: D3 TACTICAL VECTOR PROJECTION WITH ANIMATED FLOWS */}
      {/* ============================================================== */}
      {viewMode === 'D3_TACTICAL_MAP' && (
        <div className="space-y-3">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono">
            <span className="text-slate-300 font-bold flex items-center gap-1.5">
              <Radar className="w-4 h-4 text-purple-400" />
              Carte D3 Tactique (Projection Mercator • Particules Cyber en vol continu vers la Passerelle Zyxel)
            </span>
            <span className="text-[11px] text-slate-400">
              Glisser pour déplacer • Molette pour zoomer • Cliquer sur une IP pour inspecter
            </span>
          </div>

          <div className="relative w-full h-[480px] sm:h-[520px] rounded-2xl border border-slate-800 overflow-hidden shadow-2xl bg-slate-950">
            <svg ref={d3ContainerRef} className="w-full h-full cursor-grab active:cursor-grabbing" />
          </div>
        </div>
      )}

      {/* ============================================================== */}
      {/* VIEW 2: RECHARTS TREEMAP HEATMAP */}
      {/* ============================================================== */}
      {viewMode === 'TREEMAP_HEAT' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono">
            <span className="text-slate-300 font-bold flex items-center gap-1.5">
              <Maximize2 className="w-4 h-4 text-cyan-400" />
              Treemap Thermique Recharts (Superficie = Volume d'attaques · Couleur = Niveau de criticité)
            </span>
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
                                <span>
                                  {data.name} ({data.code})
                                </span>
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

      {/* ============================================================== */}
      {/* VIEW 3: BAR DENSITY CHART */}
      {/* ============================================================== */}
      {viewMode === 'BAR_DENSITY' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between text-xs font-mono">
            <span className="text-slate-300 font-bold flex items-center gap-1.5">
              <Flame className="w-4 h-4 text-amber-400" />
              Volume d'Attaques par Pays d'Origine
            </span>
          </div>

          <div className="h-80 w-full bg-slate-950/80 rounded-xl p-3 border border-slate-800">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={countryStatsList.slice(0, 10).map((c) => ({
                  name: `${c.flag} ${c.code}`,
                  fullName: c.name,
                  Total: c.totalAttacks,
                  Critiques: c.criticalAttacks,
                  Bloquées: c.blockedAttacks,
                  fill: c.heatColor,
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
                <Bar dataKey="Total" fill="#06b6d4" />
                <Bar dataKey="Critiques" fill="#ef4444" />
                <Bar dataKey="Bloquées" fill="#10b981" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* ============================================================== */}
      {/* VIEW 4: THREAT VECTOR MATRIX */}
      {/* ============================================================== */}
      {viewMode === 'VECTOR_MATRIX' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between text-xs font-mono">
            <span className="text-slate-300 font-bold flex items-center gap-1.5">
              <Layers className="w-4 h-4 text-purple-400" />
              Matrice de Répartition par Catégorie de Menace Zyxel
            </span>
          </div>

          <div className="h-80 w-full bg-slate-950/80 rounded-xl p-3 border border-slate-800">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={countryStatsList.slice(0, 8).map((c) => ({
                  name: `${c.flag} ${c.code}`,
                  fullName: c.name,
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

      {/* ============================================================== */}
      {/* MALICIOUS IP SOURCES DIRECTORY & ACTION LIST (Under Map) */}
      {/* ============================================================== */}
      <div className="space-y-3 pt-2 border-t border-slate-800/80">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Target className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-white font-mono">
              Répertoire des Adresses IP Sources Malveillantes ({filteredIpList.length})
            </h3>
          </div>
          <span className="text-[11px] text-slate-400 font-mono">
            Cliquez sur « Localiser » pour centrer la carte Leaflet sur l'IP
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
          {filteredIpList.slice(0, 9).map((item) => {
            const isCrit = item.severity === 'CRITICAL';
            const isSelected = selectedIp === item.ip;

            return (
              <div
                key={item.ip}
                className={`p-3.5 rounded-xl border transition-all duration-200 flex flex-col justify-between space-y-2.5 font-mono text-xs ${
                  isSelected
                    ? 'bg-slate-900 border-cyan-400 ring-1 ring-cyan-400/50 shadow-lg shadow-cyan-950/50'
                    : 'bg-slate-950/70 border-slate-800/90 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="text-xl flex-shrink-0">{item.flag}</span>
                    <div className="min-w-0">
                      <div className="font-bold text-white text-xs truncate flex items-center gap-1.5">
                        <span>{item.ip}</span>
                        <span
                          className={`text-[9px] px-1.5 py-0.2 rounded font-bold uppercase ${
                            isCrit
                              ? 'bg-rose-950 text-rose-300 border border-rose-800'
                              : 'bg-amber-950 text-amber-300 border border-amber-800'
                          }`}
                        >
                          {item.severity}
                        </span>
                      </div>
                      <div className="text-[10px] text-slate-400 truncate">
                        {item.city}, {item.countryName}
                      </div>
                    </div>
                  </div>

                  <span className="text-xs font-bold text-cyan-300 px-2 py-0.5 rounded bg-slate-900 border border-slate-800">
                    {item.eventCount} evt(s)
                  </span>
                </div>

                <div className="text-[11px] text-slate-300 space-y-0.5 bg-slate-900/60 p-2 rounded-lg border border-slate-800/60">
                  <div className="truncate text-cyan-200 font-semibold">{item.threatName}</div>
                  <div className="text-[10px] text-slate-400 truncate">ASN / FAI : {item.isp}</div>
                  <div className="text-[10px] text-purple-300">
                    Port WAN cible : {item.protocol}/{item.targetPort}
                  </div>
                </div>

                <div className="flex items-center justify-between pt-1 gap-2">
                  <button
                    type="button"
                    onClick={() => handleFocusOnIp(item)}
                    className="flex-1 inline-flex items-center justify-center gap-1 py-1 px-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-[10px] font-bold border border-slate-700 transition"
                    title="Centrer la carte Leaflet sur cette adresse IP"
                  >
                    <Compass className="w-3 h-3 text-cyan-400" />
                    <span>Localiser</span>
                  </button>

                  {!item.isBlocked ? (
                    <button
                      type="button"
                      onClick={() => handleDeployIpBlock(item)}
                      disabled={isDeployingRule === item.ip}
                      className="flex-1 inline-flex items-center justify-center gap-1 py-1 px-2 rounded-lg bg-red-950 hover:bg-red-900 text-red-200 text-[10px] font-bold border border-red-800 transition disabled:opacity-50"
                      title="Créer une règle de blocage pare-feu WAN immédiate pour cette IP"
                    >
                      <Lock className="w-3 h-3 text-red-400" />
                      <span>{isDeployingRule === item.ip ? 'Envoi...' : 'Bloquer IP'}</span>
                    </button>
                  ) : (
                    <span className="flex-1 inline-flex items-center justify-center gap-1 py-1 px-2 rounded-lg bg-emerald-950 text-emerald-300 text-[10px] font-bold border border-emerald-800">
                      <Check className="w-3 h-3 text-emerald-400" />
                      <span>Bloquée</span>
                    </span>
                  )}

                  {onInspectLog && item.rawLogs[0] && (
                    <button
                      type="button"
                      onClick={() => onInspectLog(item.rawLogs[0])}
                      className="p-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white border border-slate-700 transition"
                      title="Inspecter les logs de cette IP avec l'IA SOC"
                    >
                      <Eye className="w-3.5 h-3.5 text-cyan-400" />
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* ============================================================== */}
      {/* Selected Country Drilldown Card */}
      {/* ============================================================== */}
      {selectedCountry && (
        <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3 font-mono text-xs animate-in fade-in">
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
                type="button"
                onClick={() => handleDeployGeoBlock(selectedCountry)}
                disabled={isDeployingRule === selectedCountry.code}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-red-950 hover:bg-red-900 text-red-200 border border-red-800 text-xs font-bold transition disabled:opacity-50"
              >
                <Lock className="w-3.5 h-3.5 text-red-400" />
                <span>
                  {isDeployingRule === selectedCountry.code
                    ? 'Déploiement en cours...'
                    : `Bloquer la Zone Geo-IP Entière (${selectedCountry.code})`}
                </span>
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-[11px]">
            <div className="space-y-1">
              <div className="text-slate-500">Volume Total des Attaques :</div>
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
                <button
                  key={ip}
                  type="button"
                  onClick={() => {
                    const item = maliciousIpList.find((i) => i.ip === ip);
                    if (item) handleFocusOnIp(item);
                  }}
                  className="px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-cyan-300 text-[10px] hover:border-cyan-500 hover:text-white transition flex items-center gap-1"
                >
                  <MapPin className="w-2.5 h-2.5 text-cyan-400" />
                  <span>{ip}</span>
                </button>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
