import React, { useState, useMemo, useRef, useEffect } from 'react';
import {
  Search,
  Eye,
  ShieldAlert,
  AlertTriangle,
  AlertCircle,
  Info,
  Sparkles,
  Copy,
  Check,
  ChevronDown,
  X,
  RotateCcw,
  SlidersHorizontal,
  Flame,
  ArrowUpDown,
  Layers,
  CheckSquare,
  Square,
} from 'lucide-react';
import { LogEntry, SeverityLevel } from '../types';

interface LogExplorerViewProps {
  logs: LogEntry[];
  onAskAiAboutLog: (log: LogEntry) => void;
}

interface SeverityConfig {
  id: string;
  label: string;
  shortLabel: string;
  description: string;
  color: string;
  bgColor: string;
  borderColor: string;
  textColor: string;
  badgeBg: string;
  dotColor: string;
  rank: number;
}

const SEVERITY_LEVELS: SeverityLevel[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

const SEVERITY_CONFIGS: Record<string, SeverityConfig> = {
  ALL: {
    id: 'ALL',
    label: 'Toutes les Sévérités',
    shortLabel: 'Tous',
    description: 'Ensemble des événements de sécurité sans filtre de criticité',
    color: '#38bdf8',
    bgColor: 'bg-slate-800',
    borderColor: 'border-slate-700',
    textColor: 'text-slate-200',
    badgeBg: 'bg-slate-700 text-white',
    dotColor: 'bg-cyan-400',
    rank: 0,
  },
  CRITICAL: {
    id: 'CRITICAL',
    label: 'CRITICAL (Critique)',
    shortLabel: 'CRITICAL',
    description: 'Attaques actives, Ransomware, Fuites C2, Exploits RCE distants',
    color: '#ef4444',
    bgColor: 'bg-red-950/80',
    borderColor: 'border-red-600',
    textColor: 'text-red-300',
    badgeBg: 'bg-red-900 text-red-200',
    dotColor: 'bg-red-500',
    rank: 4,
  },
  HIGH: {
    id: 'HIGH',
    label: 'HIGH (Élevée)',
    shortLabel: 'HIGH',
    description: 'Tentatives d\'intrusion, Scans massifs, Brute-Force VPN',
    color: '#f97316',
    bgColor: 'bg-amber-950/80',
    borderColor: 'border-amber-600',
    textColor: 'text-amber-300',
    badgeBg: 'bg-amber-900 text-amber-200',
    dotColor: 'bg-amber-500',
    rank: 3,
  },
  MEDIUM: {
    id: 'MEDIUM',
    label: 'MEDIUM (Moyenne)',
    shortLabel: 'MEDIUM',
    description: 'Anomalies de flux, Énumération SMB, Filtre DNS Dynamique',
    color: '#eab308',
    bgColor: 'bg-yellow-950/80',
    borderColor: 'border-yellow-600',
    textColor: 'text-yellow-300',
    badgeBg: 'bg-yellow-900 text-yellow-200',
    dotColor: 'bg-yellow-500',
    rank: 2,
  },
  LOW: {
    id: 'LOW',
    label: 'LOW (Faible / Info)',
    shortLabel: 'LOW',
    description: 'Connexions VPN légitimes, télémétrie Cloud, règles d\'audit',
    color: '#3b82f6',
    bgColor: 'bg-blue-950/80',
    borderColor: 'border-blue-600',
    textColor: 'text-blue-300',
    badgeBg: 'bg-blue-900 text-blue-200',
    dotColor: 'bg-blue-500',
    rank: 1,
  },
};

export const LogExplorerView: React.FC<LogExplorerViewProps> = ({ logs, onAskAiAboutLog }) => {
  const [search, setSearch] = useState('');
  // Support single or multi-severity selection (empty array = ALL)
  const [selectedSeverities, setSelectedSeverities] = useState<string[]>([]);
  const [isMultiSelectMode, setIsMultiSelectMode] = useState<boolean>(false);
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [selectedAction, setSelectedAction] = useState<string>('ALL');
  const [sortBy, setSortBy] = useState<'TIME_DESC' | 'SEVERITY_DESC' | 'SEVERITY_ASC'>('TIME_DESC');
  const [selectedLog, setSelectedLog] = useState<LogEntry | null>(null);
  const [copiedRaw, setCopiedRaw] = useState(false);
  const [copiedFilteredBatch, setCopiedFilteredBatch] = useState(false);
  const [isSeverityDropdownOpen, setIsSeverityDropdownOpen] = useState(false);
  const severityMenuRef = useRef<HTMLDivElement>(null);

  // Close dropdown menu on outside click
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (severityMenuRef.current && !severityMenuRef.current.contains(event.target as Node)) {
        setIsSeverityDropdownOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Compute severity counts
  const severityCounts = useMemo(() => {
    const counts: Record<string, number> = {
      ALL: logs.length,
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
    };
    logs.forEach((log) => {
      const normalized = log.severity === 'INFO' ? 'LOW' : log.severity;
      if (counts[normalized] !== undefined) {
        counts[normalized] += 1;
      }
    });
    return counts;
  }, [logs]);

  // Toggle or isolate a severity level
  const handleSelectSeverity = (sev: string) => {
    if (sev === 'ALL') {
      setSelectedSeverities([]);
      return;
    }

    if (isMultiSelectMode) {
      setSelectedSeverities((prev) =>
        prev.includes(sev) ? prev.filter((s) => s !== sev) : [...prev, sev]
      );
    } else {
      // Single isolation mode: clicking the already isolated severity resets to ALL
      setSelectedSeverities((prev) => (prev.length === 1 && prev[0] === sev ? [] : [sev]));
    }
  };

  // Preset: Isolate CRITICAL + HIGH
  const handleIsolateUrgent = () => {
    const isAlreadyUrgent =
      selectedSeverities.length === 2 &&
      selectedSeverities.includes('CRITICAL') &&
      selectedSeverities.includes('HIGH');
    if (isAlreadyUrgent) {
      setSelectedSeverities([]);
    } else {
      setSelectedSeverities(['CRITICAL', 'HIGH']);
    }
  };

  const filteredLogs = useMemo(() => {
    const result = logs.filter((log) => {
      // Search
      const searchLower = search.toLowerCase();
      const matchesSearch =
        !search ||
        log.srcIp.toLowerCase().includes(searchLower) ||
        log.dstIp.toLowerCase().includes(searchLower) ||
        log.threatName.toLowerCase().includes(searchLower) ||
        log.source.toLowerCase().includes(searchLower) ||
        log.raw.toLowerCase().includes(searchLower);

      // Severity (normalize INFO -> LOW)
      const normalizedSev = log.severity === 'INFO' ? 'LOW' : log.severity;
      const matchesSeverity =
        selectedSeverities.length === 0 || selectedSeverities.includes(normalizedSev);

      // Category
      const matchesCategory =
        selectedCategory === 'ALL' || log.category === selectedCategory;

      // Action
      const matchesAction =
        selectedAction === 'ALL' ||
        (selectedAction === 'BLOCKED_DROPPED'
          ? log.action === 'Blocked' || log.action === 'Dropped'
          : log.action === selectedAction);

      return matchesSearch && matchesSeverity && matchesCategory && matchesAction;
    });

    // Apply sorting
    if (sortBy === 'SEVERITY_DESC') {
      return [...result].sort(
        (a, b) =>
          (SEVERITY_CONFIGS[b.severity]?.rank || 1) - (SEVERITY_CONFIGS[a.severity]?.rank || 1)
      );
    }
    if (sortBy === 'SEVERITY_ASC') {
      return [...result].sort(
        (a, b) =>
          (SEVERITY_CONFIGS[a.severity]?.rank || 1) - (SEVERITY_CONFIGS[b.severity]?.rank || 1)
      );
    }
    return result;
  }, [logs, search, selectedSeverities, selectedCategory, selectedAction, sortBy]);

  const handleCopyRaw = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedRaw(true);
    setTimeout(() => setCopiedRaw(false), 2000);
  };

  const handleCopyFilteredBatch = () => {
    const batchText = filteredLogs.map((l) => l.raw).join('\n');
    navigator.clipboard.writeText(batchText);
    setCopiedFilteredBatch(true);
    setTimeout(() => setCopiedFilteredBatch(false), 2000);
  };

  const handleResetFilters = () => {
    setSearch('');
    setSelectedSeverities([]);
    setSelectedCategory('ALL');
    setSelectedAction('ALL');
    setSortBy('TIME_DESC');
  };

  const primarySelectedSeverity =
    selectedSeverities.length === 1 ? selectedSeverities[0] : 'ALL';
  const currentConfig = SEVERITY_CONFIGS[primarySelectedSeverity] || SEVERITY_CONFIGS.ALL;

  return (
    <div className="space-y-6">
      {/* 4 Interactive Severity Isolation Cards (CRITICAL, HIGH, MEDIUM, LOW) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {SEVERITY_LEVELS.map((sevKey) => {
          const cfg = SEVERITY_CONFIGS[sevKey];
          const count = severityCounts[sevKey] || 0;
          const pct = logs.length > 0 ? Math.round((count / logs.length) * 100) : 0;
          const isIsolated = selectedSeverities.includes(sevKey);

          const SeverityIcon =
            sevKey === 'CRITICAL'
              ? Flame
              : sevKey === 'HIGH'
              ? ShieldAlert
              : sevKey === 'MEDIUM'
              ? AlertTriangle
              : Info;

          return (
            <button
              key={sevKey}
              type="button"
              onClick={() => handleSelectSeverity(sevKey)}
              className={`text-left p-4 rounded-2xl border transition-all flex flex-col justify-between group ${
                isIsolated
                  ? `${cfg.bgColor} ${cfg.borderColor} ring-2 ring-offset-2 ring-offset-slate-950 ring-cyan-500/50 shadow-xl`
                  : 'bg-slate-900/90 border-slate-800 hover:border-slate-700 hover:bg-slate-900'
              }`}
            >
              <div className="flex items-center justify-between w-full mb-2">
                <div className="flex items-center gap-2">
                  <span className={`w-2.5 h-2.5 rounded-full ${cfg.dotColor} ${sevKey === 'CRITICAL' && count > 0 ? 'animate-ping' : ''}`} />
                  <span className={`text-xs font-mono font-extrabold tracking-wider ${cfg.textColor}`}>
                    {cfg.shortLabel}
                  </span>
                </div>
                <div className="flex items-center gap-1.5">
                  {isIsolated && (
                    <span className="px-2 py-0.5 rounded-full text-[9px] font-mono font-bold bg-cyan-950 text-cyan-300 border border-cyan-700">
                      ISOLÉ
                    </span>
                  )}
                  <SeverityIcon className={`w-4 h-4 ${cfg.textColor}`} />
                </div>
              </div>

              <div className="my-1 flex items-baseline justify-between">
                <span className="text-2xl font-extrabold font-mono text-white">
                  {count} <span className="text-xs font-normal text-slate-400">logs</span>
                </span>
                <span className="text-xs font-mono font-bold text-slate-400">{pct}%</span>
              </div>

              <div className="w-full h-1.5 rounded-full bg-slate-950 overflow-hidden border border-slate-800/80 my-2">
                <div
                  className={`h-full rounded-full transition-all duration-500 ${cfg.dotColor}`}
                  style={{ width: `${pct}%` }}
                />
              </div>

              <p className="text-[11px] text-slate-400 line-clamp-1 font-sans">
                {cfg.description}
              </p>
            </button>
          );
        })}
      </div>

      {/* Search and Filters Bar */}
      <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-4">
        {/* Top Line: Search & Primary Category & Action & Sort */}
        <div className="flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-3">
          {/* Search box */}
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3.5 top-1/2 transform -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              placeholder="Rechercher par IP, signature d'attaque, domaine, équipement..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-10 pr-4 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono"
            />
            {search && (
              <button
                onClick={() => setSearch('')}
                className="absolute right-3 top-1/2 transform -translate-y-1/2 text-slate-500 hover:text-white"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          {/* Secondary Filters: Module, Action, Sort, Reset */}
          <div className="flex flex-wrap items-center gap-2">
            <select
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              className="bg-slate-950 border border-slate-800 text-xs text-slate-300 rounded-xl px-3 py-2.5 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono"
            >
              <option value="ALL">Tous Modules Nebula</option>
              <option value="IDP/IPS">IDP / IPS</option>
              <option value="Anti-Malware">Anti-Malware</option>
              <option value="IP_Reputation">IP Reputation</option>
              <option value="Content_Filter">Content Filter</option>
              <option value="VPN_Auth">VPN / Auth</option>
              <option value="Traffic_Anomaly">Anomalie Réseau</option>
              <option value="CDR_Quarantine">Quarantaine CDR</option>
            </select>

            <select
              value={selectedAction}
              onChange={(e) => setSelectedAction(e.target.value)}
              className="bg-slate-950 border border-slate-800 text-xs text-slate-300 rounded-xl px-3 py-2.5 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono"
            >
              <option value="ALL">Toutes Actions</option>
              <option value="BLOCKED_DROPPED">Bloqué / Dropped</option>
              <option value="Quarantined">Quarantaine CDR</option>
              <option value="Alerted">Alerted (Non bloqué)</option>
              <option value="Allowed">Allowed (Autorisé)</option>
            </select>

            <button
              type="button"
              onClick={() =>
                setSortBy((prev) =>
                  prev === 'TIME_DESC'
                    ? 'SEVERITY_DESC'
                    : prev === 'SEVERITY_DESC'
                    ? 'SEVERITY_ASC'
                    : 'TIME_DESC'
                )
              }
              className="inline-flex items-center gap-1.5 px-3 py-2.5 rounded-xl bg-slate-950 border border-slate-800 hover:border-slate-700 text-xs font-mono text-slate-300 transition"
              title="Changer l'ordre de tri des événements"
            >
              <ArrowUpDown className="w-3.5 h-3.5 text-cyan-400" />
              <span>
                {sortBy === 'TIME_DESC'
                  ? 'Tri : Chronologique'
                  : sortBy === 'SEVERITY_DESC'
                  ? 'Tri : CRITICAL → LOW'
                  : 'Tri : LOW → CRITICAL'}
              </span>
            </button>

            {(selectedSeverities.length > 0 ||
              selectedCategory !== 'ALL' ||
              selectedAction !== 'ALL' ||
              search) && (
              <button
                onClick={handleResetFilters}
                className="inline-flex items-center gap-1.5 px-3 py-2.5 rounded-xl bg-slate-800/80 hover:bg-slate-700 text-slate-300 text-xs font-mono border border-slate-700 transition"
                title="Réinitialiser tous les filtres"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">Réinitialiser</span>
              </button>
            )}

            <span className="text-xs font-mono text-cyan-400 px-3 py-2.5 bg-cyan-950/60 rounded-xl border border-cyan-800/60 whitespace-nowrap font-bold">
              {filteredLogs.length} / {logs.length} logs
            </span>
          </div>
        </div>

        {/* Severity Isolation Bar: Dropdown + Multi-select toggle + Quick Buttons */}
        <div className="pt-3 border-t border-slate-800/80 flex flex-col xl:flex-row xl:items-center justify-between gap-3">
          {/* Left: Dropdown + Multi-Select Mode Toggle + Urgent Preset */}
          <div className="flex flex-wrap items-center gap-2.5">
            <span className="text-xs font-mono text-slate-400 flex items-center gap-1.5 uppercase font-semibold">
              <SlidersHorizontal className="w-3.5 h-3.5 text-cyan-400" />
              Isoler par Sévérité :
            </span>

            {/* Custom Dropdown Menu for Severity */}
            <div className="relative" ref={severityMenuRef}>
              <button
                type="button"
                onClick={() => setIsSeverityDropdownOpen(!isSeverityDropdownOpen)}
                className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-xl text-xs font-mono border transition ${
                  selectedSeverities.length === 0
                    ? 'bg-slate-950 border-slate-800 text-slate-200 hover:border-slate-700'
                    : `${currentConfig.bgColor} ${currentConfig.borderColor} ${currentConfig.textColor} font-bold`
                }`}
              >
                <span className={`w-2 h-2 rounded-full ${currentConfig.dotColor}`} />
                <span>
                  {selectedSeverities.length === 0
                    ? 'Toutes les Sévérités'
                    : selectedSeverities.length === 1
                    ? currentConfig.label
                    : `${selectedSeverities.join(' + ')}`}
                </span>
                <ChevronDown
                  className={`w-3.5 h-3.5 transition-transform ${
                    isSeverityDropdownOpen ? 'rotate-180' : ''
                  }`}
                />
              </button>

              {isSeverityDropdownOpen && (
                <div className="absolute left-0 top-full mt-2 w-72 sm:w-80 rounded-2xl bg-slate-900 border border-slate-700 shadow-2xl p-2 z-50 backdrop-blur-xl animate-in fade-in slide-in-from-top-2">
                  <div className="px-3 py-2 border-b border-slate-800 flex items-center justify-between text-[10px] font-mono text-slate-400 uppercase tracking-wider">
                    <span>Sélectionner la criticité</span>
                    <button
                      type="button"
                      onClick={() => setIsMultiSelectMode(!isMultiSelectMode)}
                      className="text-cyan-400 hover:underline"
                    >
                      {isMultiSelectMode ? 'Mode Multi : ON' : 'Mode Multi : OFF'}
                    </button>
                  </div>
                  <div className="space-y-1 py-1">
                    {Object.values(SEVERITY_CONFIGS).map((cfg) => {
                      const count = severityCounts[cfg.id] || 0;
                      const isSelected =
                        cfg.id === 'ALL'
                          ? selectedSeverities.length === 0
                          : selectedSeverities.includes(cfg.id);

                      return (
                        <button
                          key={cfg.id}
                          onClick={() => {
                            handleSelectSeverity(cfg.id);
                            if (!isMultiSelectMode || cfg.id === 'ALL') {
                              setIsSeverityDropdownOpen(false);
                            }
                          }}
                          className={`w-full text-left p-2.5 rounded-xl transition flex items-start justify-between gap-3 text-xs ${
                            isSelected
                              ? 'bg-slate-800/90 border border-slate-600 shadow-sm'
                              : 'hover:bg-slate-800/60'
                          }`}
                        >
                          <div className="space-y-0.5">
                            <div className="flex items-center gap-2">
                              <span
                                className={`w-2.5 h-2.5 rounded-full ${cfg.dotColor} flex-shrink-0`}
                              />
                              <span className={`font-mono font-bold ${cfg.textColor}`}>
                                {cfg.label}
                              </span>
                            </div>
                            <p className="text-[10px] text-slate-400 font-sans pl-4">
                              {cfg.description}
                            </p>
                          </div>

                          <span
                            className={`font-mono text-[10px] px-2 py-0.5 rounded-full font-bold ${cfg.badgeBg}`}
                          >
                            {count}
                          </span>
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>

            {/* Urgent Preset Button (CRITICAL + HIGH) */}
            <button
              type="button"
              onClick={handleIsolateUrgent}
              className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-mono transition border ${
                selectedSeverities.length === 2 &&
                selectedSeverities.includes('CRITICAL') &&
                selectedSeverities.includes('HIGH')
                  ? 'bg-red-950/90 text-red-200 border-red-600 font-bold shadow-md'
                  : 'bg-slate-950/80 hover:bg-slate-800 text-amber-300 border-slate-800'
              }`}
              title="Isoler simultanément les événements CRITICAL et HIGH"
            >
              <Flame className="w-3.5 h-3.5 text-red-400" />
              <span>Urgences (CRITICAL + HIGH)</span>
              <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-slate-900 text-red-300 font-bold">
                {severityCounts.CRITICAL + severityCounts.HIGH}
              </span>
            </button>

            {/* Multi-select checkbox mode toggle */}
            <button
              type="button"
              onClick={() => setIsMultiSelectMode(!isMultiSelectMode)}
              className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl text-[11px] font-mono transition border ${
                isMultiSelectMode
                  ? 'bg-cyan-950 text-cyan-300 border-cyan-700 font-bold'
                  : 'bg-slate-950 text-slate-400 hover:text-slate-200 border-slate-800'
              }`}
              title="Permettre la sélection simultanée de plusieurs niveaux de sévérité"
            >
              {isMultiSelectMode ? (
                <CheckSquare className="w-3.5 h-3.5 text-cyan-400" />
              ) : (
                <Square className="w-3.5 h-3.5" />
              )}
              <span>Multi-sélection</span>
            </button>
          </div>

          {/* Right: Quick Segmented Severity Buttons (ALL, CRITICAL, HIGH, MEDIUM, LOW) */}
          <div className="flex flex-wrap items-center gap-1.5">
            {Object.values(SEVERITY_CONFIGS).map((cfg) => {
              const isSelected =
                cfg.id === 'ALL'
                  ? selectedSeverities.length === 0
                  : selectedSeverities.includes(cfg.id);
              const count = severityCounts[cfg.id] || 0;

              return (
                <button
                  key={cfg.id}
                  onClick={() => handleSelectSeverity(cfg.id)}
                  className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl text-xs font-mono transition ${
                    isSelected
                      ? `${cfg.bgColor} ${cfg.textColor} border ${cfg.borderColor} font-bold shadow-md shadow-slate-950/50`
                      : 'bg-slate-950/70 hover:bg-slate-800 text-slate-400 hover:text-white border border-slate-800'
                  }`}
                  title={`${cfg.label} (${count} logs)`}
                >
                  <span className={`w-1.5 h-1.5 rounded-full ${cfg.dotColor}`} />
                  <span>{cfg.shortLabel}</span>
                  <span
                    className={`text-[10px] px-1.5 py-0.2 rounded-full font-bold ${
                      isSelected ? cfg.badgeBg : 'bg-slate-900 text-slate-400'
                    }`}
                  >
                    {count}
                  </span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Active Severity Isolation Banner */}
        {selectedSeverities.length > 0 && (
          <div className="p-3 rounded-xl bg-cyan-950/30 border border-cyan-800/60 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono">
            <div className="flex items-center gap-2 text-cyan-200">
              <Layers className="w-4 h-4 text-cyan-400 flex-shrink-0" />
              <span>
                Isolation active sur{' '}
                <strong className="text-white">{selectedSeverities.join(', ')}</strong> :{' '}
                <strong className="text-cyan-300">{filteredLogs.length}</strong> événement(s)
                affiché(s) sur {logs.length}.
              </span>
            </div>
            <div className="flex items-center gap-2">
              {filteredLogs.length > 0 && (
                <button
                  type="button"
                  onClick={handleCopyFilteredBatch}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 text-[11px] transition"
                >
                  {copiedFilteredBatch ? (
                    <>
                      <Check className="w-3 h-3 text-emerald-400" />
                      <span className="text-emerald-400">Logs copiés !</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3 h-3 text-cyan-400" />
                      <span>Copier les logs isolés</span>
                    </>
                  )}
                </button>
              )}
              <button
                type="button"
                onClick={() => setSelectedSeverities([])}
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-cyan-900/50 hover:bg-cyan-800/60 text-cyan-200 text-[11px] font-bold transition"
              >
                <X className="w-3 h-3" />
                <span>Afficher tout</span>
              </button>
            </div>
          </div>
        )}

        {/* Visual Severity Distribution Bar (Interactive) */}
        {logs.length > 0 && (
          <div className="pt-1">
            <div className="w-full h-2 rounded-full bg-slate-950 overflow-hidden flex border border-slate-800/80">
              {severityCounts.CRITICAL > 0 && (
                <button
                  type="button"
                  onClick={() => handleSelectSeverity('CRITICAL')}
                  title={`CRITICAL: ${severityCounts.CRITICAL} logs (${Math.round(
                    (severityCounts.CRITICAL / logs.length) * 100
                  )}%)`}
                  className="h-full bg-red-500 hover:brightness-125 transition-all"
                  style={{ width: `${(severityCounts.CRITICAL / logs.length) * 100}%` }}
                />
              )}
              {severityCounts.HIGH > 0 && (
                <button
                  type="button"
                  onClick={() => handleSelectSeverity('HIGH')}
                  title={`HIGH: ${severityCounts.HIGH} logs (${Math.round(
                    (severityCounts.HIGH / logs.length) * 100
                  )}%)`}
                  className="h-full bg-amber-500 hover:brightness-125 transition-all"
                  style={{ width: `${(severityCounts.HIGH / logs.length) * 100}%` }}
                />
              )}
              {severityCounts.MEDIUM > 0 && (
                <button
                  type="button"
                  onClick={() => handleSelectSeverity('MEDIUM')}
                  title={`MEDIUM: ${severityCounts.MEDIUM} logs (${Math.round(
                    (severityCounts.MEDIUM / logs.length) * 100
                  )}%)`}
                  className="h-full bg-yellow-500 hover:brightness-125 transition-all"
                  style={{ width: `${(severityCounts.MEDIUM / logs.length) * 100}%` }}
                />
              )}
              {severityCounts.LOW > 0 && (
                <button
                  type="button"
                  onClick={() => handleSelectSeverity('LOW')}
                  title={`LOW: ${severityCounts.LOW} logs (${Math.round(
                    (severityCounts.LOW / logs.length) * 100
                  )}%)`}
                  className="h-full bg-blue-500 hover:brightness-125 transition-all"
                  style={{ width: `${(severityCounts.LOW / logs.length) * 100}%` }}
                />
              )}
            </div>
          </div>
        )}
      </div>

      {/* Logs Table */}
      <div className="rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
              <tr>
                <th className="p-3.5">Horodatage</th>
                <th className="p-3.5">Équipement</th>
                <th className="p-3.5">Module</th>
                <th className="p-3.5">Gravité</th>
                <th className="p-3.5">Source IP:Port</th>
                <th className="p-3.5">Destination IP:Port</th>
                <th className="p-3.5">Menace Détectée</th>
                <th className="p-3.5">Action Passerelle</th>
                <th className="p-3.5 text-right">Inspecter</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80 bg-slate-900/30">
              {filteredLogs.length === 0 ? (
                <tr>
                  <td colSpan={9} className="p-8 text-center text-slate-500">
                    <div className="space-y-2">
                      <p className="text-sm">Aucun événement ne correspond aux critères de filtre.</p>
                      {selectedSeverities.length > 0 && (
                        <button
                          onClick={() => setSelectedSeverities([])}
                          className="text-xs text-cyan-400 hover:underline font-mono"
                        >
                          Afficher toutes les sévérités ({logs.length} logs disponibles)
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ) : (
                filteredLogs.map((log) => {
                  const normSev = log.severity === 'INFO' ? 'LOW' : log.severity;
                  return (
                    <tr
                      key={log.id}
                      onClick={() => setSelectedLog(log)}
                      className="hover:bg-slate-800/50 cursor-pointer transition"
                    >
                      <td className="p-3.5 text-slate-400 whitespace-nowrap text-[11px]">
                        {log.timestamp.replace('T', ' ').replace('Z', '')}
                      </td>
                      <td className="p-3.5 text-slate-300 font-semibold">{log.source}</td>
                      <td className="p-3.5">
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-cyan-300 border border-slate-700">
                          {log.category}
                        </span>
                      </td>
                      <td className="p-3.5">
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleSelectSeverity(normSev);
                          }}
                          title={`Cliquer pour isoler la sévérité ${normSev}`}
                          className={`px-2 py-0.5 rounded text-[10px] font-bold transition hover:scale-105 ${
                            normSev === 'CRITICAL'
                              ? 'bg-red-950 text-red-400 border border-red-800'
                              : normSev === 'HIGH'
                              ? 'bg-amber-950 text-amber-400 border border-amber-800'
                              : normSev === 'MEDIUM'
                              ? 'bg-yellow-950 text-yellow-400 border border-yellow-800'
                              : 'bg-blue-950 text-blue-400 border border-blue-800'
                          }`}
                        >
                          {normSev}
                        </button>
                      </td>
                      <td className="p-3.5 text-red-400 font-bold whitespace-nowrap">
                        {log.srcIp}
                        {log.srcPort ? `:${log.srcPort}` : ''}
                      </td>
                      <td className="p-3.5 text-cyan-300 whitespace-nowrap">
                        {log.dstIp}
                        {log.dstPort ? `:${log.dstPort}` : ''}
                      </td>
                      <td className="p-3.5 text-white max-w-xs truncate" title={log.threatName}>
                        {log.threatName}
                      </td>
                      <td className="p-3.5">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                            log.action === 'Blocked' || log.action === 'Dropped'
                              ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                              : log.action === 'Quarantined'
                              ? 'bg-purple-950 text-purple-300 border border-purple-800'
                              : 'bg-amber-950 text-amber-400 border border-amber-800'
                          }`}
                        >
                          {log.action}
                        </span>
                      </td>
                      <td className="p-3.5 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedLog(log);
                          }}
                          className="p-1 rounded hover:bg-slate-700 text-slate-400 hover:text-white transition"
                        >
                          <Eye className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Log Detail Modal */}
      {selectedLog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-3xl w-full p-6 space-y-6 shadow-2xl relative max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between pb-4 border-b border-slate-800">
              <div className="flex items-center gap-2.5">
                <span className="p-2 rounded-xl bg-cyan-950 text-cyan-400 border border-cyan-800">
                  <ShieldAlert className="w-5 h-5" />
                </span>
                <div>
                  <h3 className="text-base font-bold text-white">Détail du Log Nebula Secure Report</h3>
                  <p className="text-xs text-slate-400 font-mono">
                    ID: {selectedLog.id} • Équipement: {selectedLog.source}
                  </p>
                </div>
              </div>
              <button
                onClick={() => setSelectedLog(null)}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 font-mono text-sm"
              >
                ✕ Fermer
              </button>
            </div>

            {/* Grid Attributes */}
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 font-mono text-xs">
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-[10px] text-slate-500 uppercase block mb-1">Horodatage</span>
                <span className="text-white font-bold">{selectedLog.timestamp}</span>
              </div>
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-[10px] text-slate-500 uppercase block mb-1">Module Nebula</span>
                <span className="text-cyan-400 font-bold">{selectedLog.category}</span>
              </div>
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-[10px] text-slate-500 uppercase block mb-1">Niveau</span>
                <span className="text-red-400 font-bold">{selectedLog.severity}</span>
              </div>
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-[10px] text-slate-500 uppercase block mb-1">IP Source</span>
                <span className="text-red-400 font-bold">{selectedLog.srcIp}</span>
              </div>
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-[10px] text-slate-500 uppercase block mb-1">IP Destination</span>
                <span className="text-emerald-400 font-bold">{selectedLog.dstIp}</span>
              </div>
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-[10px] text-slate-500 uppercase block mb-1">Action Réseau</span>
                <span className="text-purple-400 font-bold">{selectedLog.action}</span>
              </div>
            </div>

            {/* Threat description */}
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-1">
              <span className="text-[10px] font-mono text-slate-500 uppercase">Menace / Signature</span>
              <p className="text-sm font-bold text-white">{selectedLog.threatName}</p>
              {selectedLog.signature && (
                <p className="text-xs font-mono text-cyan-400">Signature ID: {selectedLog.signature}</p>
              )}
            </div>

            {/* Raw Log Line */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono text-slate-400">Ligne de log brute (Syslog / CEF) :</span>
                <button
                  onClick={() => handleCopyRaw(selectedLog.raw)}
                  className="inline-flex items-center gap-1 text-[11px] font-mono text-slate-400 hover:text-white"
                >
                  {copiedRaw ? (
                    <>
                      <Check className="w-3 h-3 text-emerald-400" />
                      <span className="text-emerald-400">Copié</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3 h-3" />
                      <span>Copier la ligne</span>
                    </>
                  )}
                </button>
              </div>
              <pre className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-cyan-400 text-xs font-mono overflow-x-auto whitespace-pre-wrap leading-relaxed">
                {selectedLog.raw}
              </pre>
            </div>

            {/* Ask AI button */}
            <div className="pt-2 flex justify-end gap-3">
              <button
                onClick={() => {
                  onAskAiAboutLog(selectedLog);
                  setSelectedLog(null);
                }}
                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-semibold text-xs shadow-md shadow-cyan-600/30 transition"
              >
                <Sparkles className="w-4 h-4" />
                <span>Demander à l'IA d'analyser ce log</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
