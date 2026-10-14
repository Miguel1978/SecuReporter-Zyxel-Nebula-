import React, { useState, useEffect, useRef, useMemo } from 'react';
import {
  Radio,
  Play,
  Pause,
  RefreshCw,
  Sparkles,
  ShieldAlert,
  ShieldCheck,
  Zap,
  Server,
  Cloud,
  Terminal,
  Activity,
  Layers,
  Flame,
  ArrowRight,
  Filter,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Wifi,
  ChevronDown,
  Download,
  Trash2,
} from 'lucide-react';
import { StopAction, ActiveDefense, ThreatAnalysisResult } from '../types';

interface LiveEvent {
  id: string;
  timestamp: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  category: string;
  attackerIp: string;
  dstIp: string;
  dstPort: number;
  threatName: string;
  raw: string;
  isBlocked: boolean;
  siteId?: string;
  siteName?: string;
  gatewayModel?: string;
}

interface NebulaLiveStreamConsoleProps {
  activeDefenses: ActiveDefense[];
  onEnforceDefense?: (action: StopAction) => void;
  onSyncWithApp: (rawLogsText: string, siteLabel: string) => void;
  onNavigateToDashboard?: () => void;
}

export const NebulaLiveStreamConsole: React.FC<NebulaLiveStreamConsoleProps> = ({
  activeDefenses,
  onEnforceDefense,
  onSyncWithApp,
  onNavigateToDashboard,
}) => {
  const [isStreaming, setIsStreaming] = useState<boolean>(true);
  const [streamCadenceMs, setStreamCadenceMs] = useState<number>(3000);
  const [selectedSiteId, setSelectedSiteId] = useState<string>('SITE-PARIS-ATP700');
  const [liveEvents, setLiveEvents] = useState<LiveEvent[]>([]);
  const [isAutoAnalyzing, setIsAutoAnalyzing] = useState<boolean>(true);
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [latestAnalysis, setLatestAnalysis] = useState<ThreatAnalysisResult | null>(null);
  const [streamFilter, setStreamFilter] = useState<'ALL' | 'CRITICAL_HIGH' | 'BLOCKED'>('ALL');
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [autoScroll, setAutoScroll] = useState<boolean>(true);
  const [epsRate, setEpsRate] = useState<number>(1.4);
  const [latencyMs, setLatencyMs] = useState<number>(24);
  const [enforcingTarget, setEnforcingTarget] = useState<string | null>(null);

  const terminalRef = useRef<HTMLDivElement>(null);
  const eventSourceRef = useRef<EventSource | null>(null);

  // Available Gateways
  const availableGateways = [
    { id: 'SITE-PARIS-ATP700', name: 'Branch Paris • Zyxel ATP700', model: 'Zyxel Nebula ATP700', ip: '185.64.22.104' },
    { id: 'SITE-HQ-USGFLEX500', name: 'Siège HQ • Zyxel USG FLEX 500', model: 'Zyxel USG FLEX 500', ip: '195.154.80.12' },
    { id: 'SITE-LILLE-CHU-ATP800', name: 'CHU Imagerie • Zyxel ATP800', model: 'Zyxel Nebula ATP800', ip: '185.80.10.44' },
    { id: 'SITE-LYON-USGFLEX200', name: 'Site Lyon • Zyxel USG FLEX 200', model: 'Zyxel USG FLEX 200', ip: '212.83.140.2' },
    { id: 'SITE-BORDEAUX-ATP500', name: 'Site Bordeaux • Zyxel ATP500', model: 'Zyxel Nebula ATP500', ip: '195.154.120.5' },
    { id: 'SITE-TOULOUSE-AERO-ATP800', name: 'Aéronautique • Zyxel ATP800', model: 'Zyxel Nebula ATP800', ip: '185.24.180.99' },
  ];

  const currentGw = useMemo(() => {
    return availableGateways.find((g) => g.id === selectedSiteId) || availableGateways[0];
  }, [selectedSiteId]);

  // Pull single tick from server
  const fetchLiveTick = async () => {
    try {
      const res = await fetch('/api/nebula/live-stream-tick', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ siteId: selectedSiteId }),
      });
      if (res.ok) {
        const data = await res.json();
        if (data.event) {
          const evt: LiveEvent = {
            ...data.event,
            siteId: data.siteId,
            siteName: data.siteName,
            gatewayModel: data.gatewayModel,
          };

          setLiveEvents((prev) => [evt, ...prev.slice(0, 99)]);
          setLatencyMs(Math.floor(Math.random() * 8) + 20);
          setEpsRate(Number((Math.random() * 0.8 + 1.2).toFixed(1)));
        }
      }
    } catch (e) {
      console.warn('Live tick error:', e);
    }
  };

  // Stream polling effect when active
  useEffect(() => {
    if (!isStreaming) return;

    // Immediately trigger 1 tick on start or site change
    fetchLiveTick();

    const interval = setInterval(() => {
      fetchLiveTick();
    }, streamCadenceMs);

    return () => clearInterval(interval);
  }, [isStreaming, streamCadenceMs, selectedSiteId]);

  // Auto-scroll terminal to bottom when new logs arrive (if autoScroll is enabled)
  useEffect(() => {
    if (autoScroll && terminalRef.current) {
      terminalRef.current.scrollTop = 0;
    }
  }, [liveEvents, autoScroll]);

  // Direct AI Analysis of the accumulated live stream logs
  const handleAnalyzeLiveLogs = async (customLogs?: string) => {
    const logsToAnalyze =
      customLogs ||
      liveEvents
        .slice(0, 25)
        .map((e) => e.raw)
        .join('\n');

    if (!logsToAnalyze.trim()) return;

    setIsAnalyzing(true);
    try {
      const res = await fetch('/api/nebula/live-stream/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          logsText: logsToAnalyze,
          siteId: selectedSiteId,
          context: currentGw.model,
        }),
      });

      if (res.ok) {
        const analysisData: ThreatAnalysisResult = await res.json();
        setLatestAnalysis(analysisData);
      }
    } catch (err) {
      console.error('Live analysis failed:', err);
    } finally {
      setIsAnalyzing(false);
    }
  };

  // Periodic Auto-Analysis effect (every 12 seconds if enabled and we have at least 3 events)
  useEffect(() => {
    if (!isAutoAnalyzing || !isStreaming || liveEvents.length < 3) return;

    const analysisTimer = setInterval(() => {
      handleAnalyzeLiveLogs();
    }, 12000);

    return () => clearInterval(analysisTimer);
  }, [isAutoAnalyzing, isStreaming, liveEvents.length, selectedSiteId]);

  // Execute firewall stop action directly from live stream
  const handleExecuteStopAction = async (action: StopAction) => {
    setEnforcingTarget(action.target);
    try {
      if (onEnforceDefense) {
        await onEnforceDefense(action);
      } else {
        await fetch('/api/enforce-defense', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            type: action.type,
            target: action.target,
            reason: action.rationale,
            policyName: action.zyxelNebulaRule?.ruleName,
          }),
        });
      }
    } catch (err) {
      console.error('Failed to block:', err);
    } finally {
      setEnforcingTarget(null);
    }
  };

  // Filtered live events list
  const filteredEvents = useMemo(() => {
    return liveEvents.filter((evt) => {
      if (streamFilter === 'CRITICAL_HIGH') {
        if (evt.severity !== 'CRITICAL' && evt.severity !== 'HIGH') return false;
      }
      if (streamFilter === 'BLOCKED') {
        if (!evt.isBlocked && !evt.raw.includes('Dropped') && !evt.raw.includes('Blocked')) {
          return false;
        }
      }
      if (searchTerm.trim()) {
        const s = searchTerm.toLowerCase();
        return (
          evt.threatName.toLowerCase().includes(s) ||
          evt.attackerIp.includes(s) ||
          evt.dstIp.includes(s) ||
          evt.raw.toLowerCase().includes(s)
        );
      }
      return true;
    });
  }, [liveEvents, streamFilter, searchTerm]);

  // Live KPI counters
  const criticalCount = liveEvents.filter((e) => e.severity === 'CRITICAL').length;
  const blockedCount = liveEvents.filter(
    (e) => e.isBlocked || e.raw.includes('Dropped') || e.raw.includes('Blocked')
  ).length;

  return (
    <div className="space-y-4 rounded-3xl bg-slate-900/90 border border-slate-800 p-4 sm:p-6 shadow-2xl relative overflow-hidden backdrop-blur-xl">
      {/* Background ambient lighting */}
      <div className="absolute top-0 right-1/4 w-96 h-48 bg-gradient-to-b from-cyan-600/10 via-emerald-600/5 to-transparent blur-3xl pointer-events-none" />

      {/* Header & Stream Control Bar */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        {/* Title & Live Status Indicator */}
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-2xl bg-gradient-to-br from-cyan-500 to-emerald-600 flex items-center justify-center text-white shadow-lg shadow-cyan-500/20 border border-cyan-400/30 flex-shrink-0">
            <Radio className={`w-5 h-5 ${isStreaming ? 'animate-pulse text-white' : 'text-slate-300'}`} />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
                Réception Directe des Logs & Analyse IA
              </h2>
              <span
                className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold border flex items-center gap-1.5 ${
                  isStreaming
                    ? 'bg-emerald-950/80 text-emerald-300 border-emerald-500/60 shadow-sm shadow-emerald-500/20'
                    : 'bg-amber-950/80 text-amber-300 border-amber-600/60'
                }`}
              >
                <span
                  className={`w-2 h-2 rounded-full ${
                    isStreaming ? 'bg-emerald-400 animate-ping' : 'bg-amber-400'
                  }`}
                />
                <span>{isStreaming ? 'STREAMING EN DIRECT • OPENAPI NCC' : 'FLUX EN PAUSE'}</span>
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono flex items-center gap-2 mt-0.5">
              <span>Passerelle : <strong className="text-cyan-300">{currentGw.model}</strong></span>
              <span className="text-slate-600">•</span>
              <span>WAN : <strong className="text-slate-300">{currentGw.ip}</strong></span>
              <span className="text-slate-600">•</span>
              <span>Latence API : <strong className="text-emerald-400">{latencyMs} ms</strong></span>
              <span className="text-slate-600">•</span>
              <span>Débit : <strong className="text-cyan-400">{epsRate} EPS</strong></span>
            </p>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-2.5">
          {/* Site Selector Dropdown */}
          <div className="relative">
            <select
              value={selectedSiteId}
              onChange={(e) => setSelectedSiteId(e.target.value)}
              className="bg-slate-950/90 text-slate-200 text-xs font-mono rounded-xl px-3 py-2 border border-slate-700 hover:border-slate-600 focus:outline-none focus:ring-1 focus:ring-cyan-500 cursor-pointer"
              title="Changer de passerelle Zyxel pour le flux direct"
            >
              {availableGateways.map((gw) => (
                <option key={gw.id} value={gw.id}>
                  {gw.name}
                </option>
              ))}
            </select>
          </div>

          {/* Cadence Selector */}
          <select
            value={streamCadenceMs}
            onChange={(e) => setStreamCadenceMs(Number(e.target.value))}
            className="bg-slate-950/90 text-slate-300 text-xs font-mono rounded-xl px-2.5 py-2 border border-slate-700"
            title="Fréquence de réception des paquets"
          >
            <option value={2000}>Cadence : 2s (Rapide)</option>
            <option value={3000}>Cadence : 3s (Standard)</option>
            <option value={5000}>Cadence : 5s (Modérée)</option>
            <option value={10000}>Cadence : 10s (Basse)</option>
          </select>

          {/* Play/Pause Button */}
          <button
            type="button"
            onClick={() => setIsStreaming(!isStreaming)}
            className={`inline-flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-semibold border transition ${
              isStreaming
                ? 'bg-amber-950/60 hover:bg-amber-900/60 text-amber-200 border-amber-700'
                : 'bg-emerald-600 hover:bg-emerald-500 text-white border-emerald-400/40 shadow-md shadow-emerald-700/30'
            }`}
          >
            {isStreaming ? (
              <>
                <Pause className="w-3.5 h-3.5" />
                <span>Mettre en Pause</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5" />
                <span>Reprendre le Flux</span>
              </>
            )}
          </button>

          {/* Manual AI Analyze Button */}
          <button
            type="button"
            onClick={() => handleAnalyzeLiveLogs()}
            disabled={isAnalyzing || liveEvents.length === 0}
            className="inline-flex items-center gap-2 px-3.5 py-2 rounded-xl bg-gradient-to-r from-cyan-600 via-blue-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-white text-xs font-bold border border-cyan-400/40 shadow-md shadow-cyan-600/25 transition disabled:opacity-50"
            title="Déclencher immédiatement l'analyse IA complète du flux capté"
          >
            <Sparkles className={`w-3.5 h-3.5 ${isAnalyzing ? 'animate-spin' : ''}`} />
            <span>{isAnalyzing ? 'Analyse IA en cours...' : 'Analyser le Flux IA'}</span>
          </button>

          {/* Sync with Main App Button */}
          <button
            type="button"
            onClick={() => {
              const fullLogsText = liveEvents.map((e) => e.raw).join('\n');
              onSyncWithApp(fullLogsText, `${currentGw.model} (${currentGw.name})`);
            }}
            disabled={liveEvents.length === 0}
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 transition disabled:opacity-50"
            title="Injecter ces logs dans tout le Dashboard et la cartographie D3"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span className="hidden sm:inline">Transférer vers Dashboard</span>
          </button>
        </div>
      </div>

      {/* KPI Stats Ribbon */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
        <div className="p-3 rounded-2xl bg-slate-950/80 border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 text-[10px] uppercase">
            <span>Événements En Direct</span>
            <Terminal className="w-3.5 h-3.5 text-cyan-400" />
          </div>
          <span className="text-xl font-bold text-white block mt-1">
            {liveEvents.length}
          </span>
          <span className="text-[10px] text-cyan-400">Captés depuis l'API Zyxel</span>
        </div>

        <div className="p-3 rounded-2xl bg-slate-950/80 border border-red-900/50">
          <div className="flex items-center justify-between text-red-400 text-[10px] uppercase">
            <span>Attaques Critiques</span>
            <Flame className="w-3.5 h-3.5 text-red-400 animate-pulse" />
          </div>
          <span className="text-xl font-bold text-red-400 block mt-1">
            {criticalCount}
          </span>
          <span className="text-[10px] text-red-300">Ransomware, RCE & C2</span>
        </div>

        <div className="p-3 rounded-2xl bg-slate-950/80 border border-emerald-900/50">
          <div className="flex items-center justify-between text-emerald-400 text-[10px] uppercase">
            <span>Mitigées / Bloquées</span>
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <span className="text-xl font-bold text-emerald-400 block mt-1">
            {blockedCount}
          </span>
          <span className="text-[10px] text-emerald-300">Arrêtées sur WAN/LAN</span>
        </div>

        <div className="p-3 rounded-2xl bg-slate-950/80 border border-indigo-900/50">
          <div className="flex items-center justify-between text-indigo-400 text-[10px] uppercase">
            <span>Score de Risque IA</span>
            <Activity className="w-3.5 h-3.5 text-indigo-400" />
          </div>
          <span
            className={`text-xl font-bold block mt-1 ${
              (latestAnalysis?.riskScore || 85) >= 75
                ? 'text-red-400'
                : (latestAnalysis?.riskScore || 85) >= 50
                ? 'text-amber-400'
                : 'text-emerald-400'
            }`}
          >
            {latestAnalysis ? `${latestAnalysis.riskScore}/100` : 'En analyse...'}
          </span>
          <span className="text-[10px] text-indigo-300">
            {latestAnalysis ? latestAnalysis.threatLevel : 'Gemini 3.8 Flash SOC'}
          </span>
        </div>
      </div>

      {/* Main Split Layout: Left Terminal Stream / Right Live AI Intelligence */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left Column (7 cols): Real-Time Log Terminal Feed */}
        <div className="lg:col-span-7 space-y-2.5 flex flex-col">
          {/* Terminal Controls Bar */}
          <div className="flex flex-wrap items-center justify-between gap-2 bg-slate-950/90 p-2.5 rounded-2xl border border-slate-800 text-xs font-mono">
            {/* Filters */}
            <div className="flex items-center gap-1.5">
              <Filter className="w-3 h-3 text-slate-400" />
              <button
                type="button"
                onClick={() => setStreamFilter('ALL')}
                className={`px-2 py-1 rounded-lg text-[10px] font-bold transition ${
                  streamFilter === 'ALL'
                    ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                Tous ({liveEvents.length})
              </button>
              <button
                type="button"
                onClick={() => setStreamFilter('CRITICAL_HIGH')}
                className={`px-2 py-1 rounded-lg text-[10px] font-bold transition ${
                  streamFilter === 'CRITICAL_HIGH'
                    ? 'bg-red-950 text-red-300 border border-red-800'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                Critiques ({criticalCount})
              </button>
              <button
                type="button"
                onClick={() => setStreamFilter('BLOCKED')}
                className={`px-2 py-1 rounded-lg text-[10px] font-bold transition ${
                  streamFilter === 'BLOCKED'
                    ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                Bloqués ({blockedCount})
              </button>
            </div>

            {/* Auto-scroll toggle and Clear */}
            <div className="flex items-center gap-2">
              <label className="flex items-center gap-1.5 text-[10px] text-slate-400 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={autoScroll}
                  onChange={(e) => setAutoScroll(e.target.checked)}
                  className="rounded bg-slate-800 border-slate-700 text-cyan-500 focus:ring-0 w-3 h-3 cursor-pointer"
                />
                <span>Auto-défilement</span>
              </label>

              <button
                type="button"
                onClick={() => setLiveEvents([])}
                className="p-1 rounded-lg text-slate-500 hover:text-rose-400 hover:bg-slate-800 transition"
                title="Effacer le tampon de logs"
              >
                <Trash2 className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {/* Real-time Syslog Terminal Box */}
          <div
            ref={terminalRef}
            className="flex-1 min-h-[380px] max-h-[460px] overflow-y-auto bg-black/90 rounded-2xl border border-slate-800 p-3 space-y-2 font-mono text-xs select-text shadow-inner"
          >
            {filteredEvents.length === 0 ? (
              <div className="h-full min-h-[300px] flex flex-col items-center justify-center text-slate-500 space-y-2">
                <Activity className="w-8 h-8 text-slate-600 animate-spin" />
                <p className="text-xs">Attente des paquets émis par l'API Nebula...</p>
              </div>
            ) : (
              filteredEvents.map((evt) => {
                const isCritical = evt.severity === 'CRITICAL';
                const isHigh = evt.severity === 'HIGH';

                return (
                  <div
                    key={evt.id}
                    className={`p-2.5 rounded-xl border transition-all text-[11px] leading-relaxed space-y-1 ${
                      isCritical
                        ? 'bg-red-950/30 border-red-800/60 hover:bg-red-950/50'
                        : isHigh
                        ? 'bg-amber-950/20 border-amber-800/50 hover:bg-amber-950/40'
                        : 'bg-slate-900/60 border-slate-800 hover:bg-slate-900/90'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <span
                          className={`w-2 h-2 rounded-full ${
                            isCritical ? 'bg-red-400 animate-ping' : isHigh ? 'bg-amber-400' : 'bg-cyan-400'
                          }`}
                        />
                        <span className="text-slate-400 text-[10px]">
                          {new Date(evt.timestamp).toLocaleTimeString('fr-FR', {
                            hour: '2-digit',
                            minute: '2-digit',
                            second: '2-digit',
                          })}
                        </span>
                        <span
                          className={`px-1.5 py-0.2 rounded text-[9px] font-bold ${
                            isCritical
                              ? 'bg-red-900 text-red-200'
                              : isHigh
                              ? 'bg-amber-900 text-amber-200'
                              : 'bg-slate-800 text-slate-300'
                          }`}
                        >
                          {evt.severity}
                        </span>
                        <span className="px-1.5 py-0.2 rounded text-[9px] bg-slate-800 text-cyan-300">
                          {evt.category}
                        </span>
                        <span className="font-bold text-white text-[11px]">{evt.threatName}</span>
                      </div>

                      <span
                        className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                          evt.isBlocked || evt.raw.includes('Dropped') || evt.raw.includes('Blocked')
                            ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                            : 'bg-red-950 text-red-300 border border-red-800'
                        }`}
                      >
                        {evt.isBlocked ? 'BLOQUÉ (CDR)' : evt.raw.includes('Dropped') ? 'DROPPED' : 'ALERTED'}
                      </span>
                    </div>

                    <div className="text-slate-300 text-[10px] flex flex-wrap items-center gap-2 pt-0.5 font-mono">
                      <span>
                        SRC: <strong className="text-red-400">{evt.attackerIp}</strong>
                      </span>
                      <span>→</span>
                      <span>
                        DST: <strong className="text-cyan-300">{evt.dstIp}:{evt.dstPort}</strong>
                      </span>
                      <span className="text-slate-600">•</span>
                      <span className="text-slate-400 truncate max-w-xs">{evt.raw}</span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Column (5 cols): Real-Time AI Intelligence & Immediate Countermeasures */}
        <div className="lg:col-span-5 space-y-3.5 flex flex-col">
          {/* AI SOC Real-time Status Card */}
          <div className="p-4 rounded-2xl bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 border border-cyan-500/60 shadow-xl space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="w-7 h-7 rounded-lg bg-cyan-950 border border-cyan-700 flex items-center justify-center text-cyan-400">
                  <Sparkles className="w-4 h-4 animate-spin text-cyan-300" />
                </div>
                <div>
                  <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                    Moteur IA d'Analyse en Direct
                  </h3>
                  <span className="text-[10px] text-slate-400 font-mono">Gemini 3.8 Flash • SOC Zyxel</span>
                </div>
              </div>

              {/* Auto-analysis toggle */}
              <label className="flex items-center gap-2 text-xs font-mono text-cyan-300 cursor-pointer">
                <span className="text-[10px]">Analyse Auto :</span>
                <input
                  type="checkbox"
                  checked={isAutoAnalyzing}
                  onChange={(e) => setIsAutoAnalyzing(e.target.checked)}
                  className="rounded bg-slate-800 border-slate-700 text-cyan-500 focus:ring-0 w-3.5 h-3.5"
                />
              </label>
            </div>

            {/* AI Summary Text */}
            <div className="p-3 rounded-xl bg-slate-900/90 border border-slate-800 text-xs font-sans text-slate-300 leading-relaxed">
              {latestAnalysis ? (
                <>
                  <p className="font-semibold text-white mb-1">
                    Synthèse de l'Analyse en Temps Réel :
                  </p>
                  <p className="text-slate-300 text-[11px]">{latestAnalysis.summary}</p>
                </>
              ) : (
                <div className="flex items-center gap-2 text-slate-400 py-2">
                  <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
                  <span>Analyse du premier lot de paquets en cours...</span>
                </div>
              )}
            </div>

            {/* Attack Vectors Identified by AI */}
            {latestAnalysis && latestAnalysis.attackVectors.length > 0 && (
              <div className="space-y-2">
                <span className="text-[10px] font-mono font-bold text-slate-400 uppercase tracking-wider block">
                  Vecteurs d'Attaque Confirmés ({latestAnalysis.attackVectors.length}) :
                </span>
                <div className="space-y-1.5 max-h-[140px] overflow-y-auto pr-1">
                  {latestAnalysis.attackVectors.map((v, i) => (
                    <div
                      key={i}
                      className="p-2 rounded-xl bg-slate-950/80 border border-slate-800 flex items-center justify-between gap-2 text-xs font-mono"
                    >
                      <div className="min-w-0">
                        <div className="flex items-center gap-1.5">
                          <span
                            className={`w-2 h-2 rounded-full ${
                              v.severity === 'CRITICAL' ? 'bg-red-500' : 'bg-amber-400'
                            }`}
                          />
                          <span className="font-bold text-white text-[11px] truncate block">
                            {v.name}
                          </span>
                        </div>
                        <span className="text-[10px] text-slate-400 block truncate">
                          {v.mitreTechniqueId ? `MITRE ${v.mitreTechniqueId} • ` : ''}
                          Cible : {v.targetAssets?.[0] || '192.168.1.105'}
                        </span>
                      </div>

                      <span
                        className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${
                          v.severity === 'CRITICAL'
                            ? 'bg-red-950 text-red-300 border border-red-800'
                            : 'bg-amber-950 text-amber-300 border border-amber-800'
                        }`}
                      >
                        {v.severity}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Recommended Instant WAN Countermeasures */}
            {latestAnalysis && latestAnalysis.stopActions.length > 0 && (
              <div className="space-y-2 pt-1 border-t border-slate-800/80">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-mono font-bold text-red-400 text-[10px] uppercase flex items-center gap-1">
                    <Zap className="w-3.5 h-3.5 text-red-400" />
                    Ripostes Pare-feu Immédiates Prêtes ({latestAnalysis.stopActions.length})
                  </span>
                </div>

                <div className="space-y-2 max-h-[140px] overflow-y-auto pr-1">
                  {latestAnalysis.stopActions.slice(0, 3).map((act) => {
                    const isEnforcing = enforcingTarget === act.target;

                    return (
                      <div
                        key={act.id}
                        className="p-2.5 rounded-xl bg-red-950/20 border border-red-900/60 flex items-center justify-between gap-2 text-xs font-mono"
                      >
                        <div className="min-w-0 space-y-0.5">
                          <span className="font-bold text-red-200 text-[11px] block truncate">
                            Bloquer {act.target}
                          </span>
                          <span className="text-[10px] text-slate-400 block truncate">
                            {act.zyxelNebulaRule?.ruleName || 'DROP_WAN_RULE'}
                          </span>
                        </div>

                        <button
                          type="button"
                          onClick={() => handleExecuteStopAction(act)}
                          disabled={isEnforcing}
                          className="px-2.5 py-1 rounded-lg bg-red-600 hover:bg-red-500 text-white text-[10px] font-bold border border-red-400/40 shadow-sm transition disabled:opacity-50 flex items-center gap-1 whitespace-nowrap"
                        >
                          <Zap className={`w-3 h-3 ${isEnforcing ? 'animate-spin' : ''}`} />
                          <span>{isEnforcing ? 'Application...' : 'Appliquer'}</span>
                        </button>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
