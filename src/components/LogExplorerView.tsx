import React, { useState, useMemo, useRef, useEffect } from 'react';
import {
  Search,
  Filter,
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
} from 'lucide-react';
import { LogCategory, LogEntry, SeverityLevel } from '../types';

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
}

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
  },
  HIGH: {
    id: 'HIGH',
    label: 'HIGH (Élevée)',
    shortLabel: 'HIGH',
    description: 'Tentatives d\'intrusion, Scans massifs, Injections SQL/XSS',
    color: '#f97316',
    bgColor: 'bg-amber-950/80',
    borderColor: 'border-amber-600',
    textColor: 'text-amber-300',
    badgeBg: 'bg-amber-900 text-amber-200',
    dotColor: 'bg-amber-500',
  },
  MEDIUM: {
    id: 'MEDIUM',
    label: 'MEDIUM (Moyenne)',
    shortLabel: 'MEDIUM',
    description: 'Anomalies de flux, Échecs de connexion répétés, Filtre DNS',
    color: '#eab308',
    bgColor: 'bg-yellow-950/80',
    borderColor: 'border-yellow-600',
    textColor: 'text-yellow-300',
    badgeBg: 'bg-yellow-900 text-yellow-200',
    dotColor: 'bg-yellow-500',
  },
  LOW: {
    id: 'LOW',
    label: 'LOW (Faible / Info)',
    shortLabel: 'LOW',
    description: 'Connexions VPN légitimes, règles d\'audit, requêtes autorisées',
    color: '#3b82f6',
    bgColor: 'bg-blue-950/80',
    borderColor: 'border-blue-600',
    textColor: 'text-blue-300',
    badgeBg: 'bg-blue-900 text-blue-200',
    dotColor: 'bg-blue-500',
  },
};

export const LogExplorerView: React.FC<LogExplorerViewProps> = ({ logs, onAskAiAboutLog }) => {
  const [search, setSearch] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [selectedLog, setSelectedLog] = useState<LogEntry | null>(null);
  const [copiedRaw, setCopiedRaw] = useState(false);
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
      if (counts[log.severity] !== undefined) {
        counts[log.severity] += 1;
      }
    });
    return counts;
  }, [logs]);

  const filteredLogs = useMemo(() => {
    return logs.filter((log) => {
      // Search
      const searchLower = search.toLowerCase();
      const matchesSearch =
        !search ||
        log.srcIp.toLowerCase().includes(searchLower) ||
        log.dstIp.toLowerCase().includes(searchLower) ||
        log.threatName.toLowerCase().includes(searchLower) ||
        log.source.toLowerCase().includes(searchLower) ||
        log.raw.toLowerCase().includes(searchLower);

      // Severity
      const matchesSeverity =
        selectedSeverity === 'ALL' || log.severity === selectedSeverity;

      // Category
      const matchesCategory =
        selectedCategory === 'ALL' || log.category === selectedCategory;

      return matchesSearch && matchesSeverity && matchesCategory;
    });
  }, [logs, search, selectedSeverity, selectedCategory]);

  const handleCopyRaw = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedRaw(true);
    setTimeout(() => setCopiedRaw(false), 2000);
  };

  const handleResetFilters = () => {
    setSearch('');
    setSelectedSeverity('ALL');
    setSelectedCategory('ALL');
  };

  const currentConfig = SEVERITY_CONFIGS[selectedSeverity] || SEVERITY_CONFIGS.ALL;

  return (
    <div className="space-y-6">
      {/* Search and Filters Bar */}
      <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-4">
        {/* Top Line: Search & Primary Category & Stats */}
        <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-4">
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

          {/* Quick Category filter & Reset */}
          <div className="flex items-center gap-2">
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

            {(selectedSeverity !== 'ALL' || selectedCategory !== 'ALL' || search) && (
              <button
                onClick={handleResetFilters}
                className="inline-flex items-center gap-1.5 px-3 py-2.5 rounded-xl bg-slate-800/80 hover:bg-slate-700 text-slate-300 text-xs font-mono border border-slate-700 transition"
                title="Réinitialiser tous les filtres"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">Réinitialiser</span>
              </button>
            )}

            <span className="text-xs font-mono text-cyan-400 px-3 py-2.5 bg-cyan-950/60 rounded-xl border border-cyan-800/60 whitespace-nowrap">
              {filteredLogs.length} / {logs.length} logs
            </span>
          </div>
        </div>

        {/* Menu de Filtrage par Niveau de Sévérité (Boutons Pilules + Dropdown Descriptif) */}
        <div className="pt-2 border-t border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          {/* Label + Interactive Dropdown Menu */}
          <div className="flex items-center gap-3">
            <span className="text-xs font-mono text-slate-400 flex items-center gap-1.5 uppercase font-semibold">
              <SlidersHorizontal className="w-3.5 h-3.5 text-cyan-400" />
              Filtrer par Sévérité :
            </span>

            {/* Custom Dropdown Menu for Severity */}
            <div className="relative" ref={severityMenuRef}>
              <button
                type="button"
                onClick={() => setIsSeverityDropdownOpen(!isSeverityDropdownOpen)}
                className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-xl text-xs font-mono border transition ${
                  selectedSeverity === 'ALL'
                    ? 'bg-slate-950 border-slate-800 text-slate-200 hover:border-slate-700'
                    : `${currentConfig.bgColor} ${currentConfig.borderColor} ${currentConfig.textColor} font-bold ring-1 ring-opacity-50`
                }`}
              >
                <span className={`w-2 h-2 rounded-full ${currentConfig.dotColor} ${selectedSeverity === 'CRITICAL' ? 'animate-ping' : ''}`} />
                <span>{currentConfig.label}</span>
                <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-slate-900/80 border border-slate-700 text-white font-mono">
                  {severityCounts[selectedSeverity]}
                </span>
                <ChevronDown className={`w-3.5 h-3.5 transition-transform ${isSeverityDropdownOpen ? 'rotate-180' : ''}`} />
              </button>

              {/* Dropdown popup menu with descriptions */}
              {isSeverityDropdownOpen && (
                <div className="absolute left-0 top-full mt-2 w-72 sm:w-80 rounded-2xl bg-slate-900 border border-slate-700 shadow-2xl p-2 z-50 backdrop-blur-xl animate-in fade-in slide-in-from-top-2">
                  <div className="px-3 py-2 border-b border-slate-800 text-[10px] font-mono text-slate-400 uppercase tracking-wider">
                    Sélectionner un niveau d'impact
                  </div>
                  <div className="space-y-1 py-1">
                    {Object.values(SEVERITY_CONFIGS).map((cfg) => {
                      const count = severityCounts[cfg.id] || 0;
                      const isSelected = selectedSeverity === cfg.id;

                      return (
                        <button
                          key={cfg.id}
                          onClick={() => {
                            setSelectedSeverity(cfg.id);
                            setIsSeverityDropdownOpen(false);
                          }}
                          className={`w-full text-left p-2.5 rounded-xl transition flex items-start justify-between gap-3 text-xs ${
                            isSelected
                              ? 'bg-slate-800/90 border border-slate-600 shadow-sm'
                              : 'hover:bg-slate-800/60'
                          }`}
                        >
                          <div className="space-y-0.5">
                            <div className="flex items-center gap-2">
                              <span className={`w-2.5 h-2.5 rounded-full ${cfg.dotColor} flex-shrink-0`} />
                              <span className={`font-mono font-bold ${cfg.textColor}`}>
                                {cfg.label}
                              </span>
                            </div>
                            <p className="text-[10px] text-slate-400 font-sans pl-4">
                              {cfg.description}
                            </p>
                          </div>

                          <span className={`font-mono text-[10px] px-2 py-0.5 rounded-full font-bold ${cfg.badgeBg}`}>
                            {count}
                          </span>
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Quick Segmented Severity Buttons (Instant Tabs) */}
          <div className="flex flex-wrap items-center gap-1.5">
            {Object.values(SEVERITY_CONFIGS).map((cfg) => {
              const isSelected = selectedSeverity === cfg.id;
              const count = severityCounts[cfg.id] || 0;

              return (
                <button
                  key={cfg.id}
                  onClick={() => setSelectedSeverity(cfg.id)}
                  className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-xl text-xs font-mono transition ${
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

        {/* Visual Severity Distribution Bar (Interactive) */}
        {logs.length > 0 && (
          <div className="pt-2">
            <div className="w-full h-2 rounded-full bg-slate-950 overflow-hidden flex border border-slate-800/80">
              {severityCounts.CRITICAL > 0 && (
                <button
                  type="button"
                  onClick={() => setSelectedSeverity('CRITICAL')}
                  title={`CRITICAL: ${severityCounts.CRITICAL} logs (${Math.round((severityCounts.CRITICAL / logs.length) * 100)}%)`}
                  className="h-full bg-red-500 hover:brightness-125 transition-all"
                  style={{ width: `${(severityCounts.CRITICAL / logs.length) * 100}%` }}
                />
              )}
              {severityCounts.HIGH > 0 && (
                <button
                  type="button"
                  onClick={() => setSelectedSeverity('HIGH')}
                  title={`HIGH: ${severityCounts.HIGH} logs (${Math.round((severityCounts.HIGH / logs.length) * 100)}%)`}
                  className="h-full bg-amber-500 hover:brightness-125 transition-all"
                  style={{ width: `${(severityCounts.HIGH / logs.length) * 100}%` }}
                />
              )}
              {severityCounts.MEDIUM > 0 && (
                <button
                  type="button"
                  onClick={() => setSelectedSeverity('MEDIUM')}
                  title={`MEDIUM: ${severityCounts.MEDIUM} logs (${Math.round((severityCounts.MEDIUM / logs.length) * 100)}%)`}
                  className="h-full bg-yellow-500 hover:brightness-125 transition-all"
                  style={{ width: `${(severityCounts.MEDIUM / logs.length) * 100}%` }}
                />
              )}
              {severityCounts.LOW > 0 && (
                <button
                  type="button"
                  onClick={() => setSelectedSeverity('LOW')}
                  title={`LOW: ${severityCounts.LOW} logs (${Math.round((severityCounts.LOW / logs.length) * 100)}%)`}
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
                      {selectedSeverity !== 'ALL' && (
                        <button
                          onClick={() => setSelectedSeverity('ALL')}
                          className="text-xs text-cyan-400 hover:underline font-mono"
                        >
                          Afficher toutes les sévérités ({logs.length} logs disponibles)
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ) : (
                filteredLogs.map((log) => (
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
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          log.severity === 'CRITICAL'
                            ? 'bg-red-950 text-red-400 border border-red-800'
                            : log.severity === 'HIGH'
                            ? 'bg-amber-950 text-amber-400 border border-amber-800'
                            : log.severity === 'MEDIUM'
                            ? 'bg-yellow-950 text-yellow-400 border border-yellow-800'
                            : 'bg-blue-950 text-blue-400 border border-blue-800'
                        }`}
                      >
                        {log.severity}
                      </span>
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
                ))
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
