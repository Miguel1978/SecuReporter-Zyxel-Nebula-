import React, { useState, useEffect, useRef } from 'react';
import {
  Server,
  Radio,
  Terminal,
  Play,
  Pause,
  RefreshCw,
  Copy,
  Check,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Zap,
  Filter,
  Trash2,
  Download,
  Send,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Cpu,
  Layers,
  ArrowRight,
  Sparkles,
  Info,
  Clock,
  Key,
  Globe,
  Database,
  Lock,
  Activity,
  CheckCircle2,
} from 'lucide-react';
import { SyslogPacket, SyslogServerStatus, SeverityLevel } from '../types';

interface SyslogCollectorViewProps {
  onAnalyzeSyslogLogs: (rawLogsText: string, deviceContext: string) => void;
  onNavigateToTab?: (tab: string) => void;
  onDefenseApplied?: () => void;
}

interface ClosedLoopStep {
  step: 1 | 2 | 3;
  status: 'idle' | 'running' | 'success';
  title: string;
  detail: string;
  data?: any;
}

export const SyslogCollectorView: React.FC<SyslogCollectorViewProps> = ({
  onAnalyzeSyslogLogs,
  onNavigateToTab,
  onDefenseApplied,
}) => {
  const [status, setStatus] = useState<SyslogServerStatus | null>(null);
  const [logs, setLogs] = useState<SyslogPacket[]>([]);
  const [totalCount, setTotalCount] = useState<number>(0);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isLivePolling, setIsLivePolling] = useState<boolean>(true);
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [activeConfigTab, setActiveConfigTab] = useState<'architecture' | 'rsyslog' | 'zyxel' | 'syslogng' | 'wazuh'>('architecture');
  const [activeDataTypeTab, setActiveDataTypeTab] = useState<'ALL' | 'TRAFFIC' | 'UTM' | 'AUTH'>('ALL');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [actionSuccessMsg, setActionSuccessMsg] = useState<string | null>(null);
  const [customTestMessage, setCustomTestMessage] = useState<string>('');
  const [isSendingTest, setIsSendingTest] = useState<boolean>(false);
  const [selectedPacket, setSelectedPacket] = useState<SyslogPacket | null>(null);
  const [autoScroll, setAutoScroll] = useState<boolean>(true);

  // Closed loop simulation state (USG Syslog -> IA Detection -> Nebula API Block Action)
  const [isSimulatingLoop, setIsSimulatingLoop] = useState<boolean>(false);
  const [loopSimulationResult, setLoopSimulationResult] = useState<any | null>(null);
  const [loopCurrentStep, setLoopCurrentStep] = useState<number>(0);

  const terminalEndRef = useRef<HTMLDivElement>(null);

  const showNotification = (msg: string) => {
    setActionSuccessMsg(msg);
    setTimeout(() => setActionSuccessMsg(null), 4500);
  };

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2500);
  };

  // Fetch Syslog server status
  const fetchStatus = async () => {
    try {
      const res = await fetch('/api/syslog/status');
      if (res.ok) {
        const data = await res.json();
        setStatus(data);
      }
    } catch (err) {
      console.warn('Erreur récupération statut syslog:', err);
    }
  };

  // Fetch collected logs
  const fetchLogs = async () => {
    try {
      const query = new URLSearchParams({
        limit: '200',
        severity: severityFilter,
        category: categoryFilter,
        search: searchTerm,
      });
      const res = await fetch(`/api/syslog/logs?${query.toString()}`);
      if (res.ok) {
        const data = await res.json();
        let fetchedLogs: SyslogPacket[] = data.logs || [];

        // Secondary filter by specific User Request Data Type
        if (activeDataTypeTab === 'TRAFFIC') {
          fetchedLogs = fetchedLogs.filter(
            (p) => p.category === 'Traffic_Anomaly' || p.bytesSent !== undefined || p.duration !== undefined
          );
        } else if (activeDataTypeTab === 'UTM') {
          fetchedLogs = fetchedLogs.filter((p) =>
            ['IDP/IPS', 'Anti-Malware', 'IP_Reputation', 'Content_Filter', 'CDR_Quarantine'].includes(p.category)
          );
        } else if (activeDataTypeTab === 'AUTH') {
          fetchedLogs = fetchedLogs.filter(
            (p) => p.category === 'VPN_Auth' || p.userName !== undefined || p.authAttempts !== undefined
          );
        }

        setLogs(fetchedLogs);
        setTotalCount(data.totalReceived || 0);
      }
    } catch (err) {
      console.warn('Erreur récupération logs syslog:', err);
    } finally {
      setIsLoading(false);
    }
  };

  // Initial load
  useEffect(() => {
    fetchStatus();
    fetchLogs();
  }, [severityFilter, categoryFilter, searchTerm, activeDataTypeTab]);

  // Live polling every 2.5s if active
  useEffect(() => {
    if (!isLivePolling) return;
    const interval = setInterval(() => {
      fetchStatus();
      fetchLogs();
    }, 2500);
    return () => clearInterval(interval);
  }, [isLivePolling, severityFilter, categoryFilter, searchTerm, activeDataTypeTab]);

  // Auto-scroll terminal
  useEffect(() => {
    if (autoScroll && terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, autoScroll]);

  // Execute the concrete closed-loop example:
  // 1. USG sends Syslog UDP (198.51.100.45 port 22) -> 2. IA analyzes -> 3. Nebula API triggers block rule
  const handleExecuteClosedLoopDemo = async () => {
    setIsSimulatingLoop(true);
    setLoopSimulationResult(null);
    setLoopCurrentStep(1);

    try {
      // Step 1: Simulate transmission & receipt
      await new Promise((r) => setTimeout(r, 600));
      setLoopCurrentStep(2);

      // Step 2: Trigger server simulation & AI detection
      await new Promise((r) => setTimeout(r, 700));
      setLoopCurrentStep(3);

      const res = await fetch('/api/syslog/simulate-closed-loop', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          attackerIp: '198.51.100.45',
          targetPort: 22,
          attempts: 48,
          destinationIp: '195.154.80.12',
          gatewayModel: 'Zyxel USG FLEX 500',
        }),
      });

      if (res.ok) {
        const data = await res.json();
        setLoopSimulationResult(data);
        showNotification("Scénario Boucle Fermée réussi : Attaquant 198.51.100.45 bloqué via l'API Nebula !");
        fetchLogs();
        fetchStatus();
        if (onDefenseApplied) onDefenseApplied();
      }
    } catch (e: any) {
      showNotification(`Erreur démo : ${e?.message}`);
    } finally {
      setIsSimulatingLoop(false);
    }
  };

  // Send real test UDP datagram via local socket
  const handleSendTestDatagram = async () => {
    setIsSendingTest(true);
    try {
      const res = await fetch('/api/syslog/send-test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          customMessage: customTestMessage.trim() || undefined,
        }),
      });
      const data = await res.json();
      if (data.success) {
        showNotification(data.message || 'Paquet UDP émis et capté avec succès !');
        fetchLogs();
        fetchStatus();
        setCustomTestMessage('');
      } else {
        showNotification(`Erreur : ${data.error || 'Échec de transmission UDP'}`);
      }
    } catch (e: any) {
      showNotification(`Erreur réseau : ${e?.message}`);
    } finally {
      setIsSendingTest(false);
    }
  };

  // Inject sample batch
  const handleInjectSampleBatch = async () => {
    try {
      const res = await fetch('/api/syslog/inject-sample', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ deviceType: 'ATP700' }),
      });
      const data = await res.json();
      if (data.success) {
        showNotification(`${data.injectedCount} paquets Syslog Zyxel injectés dans le collecteur UDP`);
        fetchLogs();
        fetchStatus();
      }
    } catch (e: any) {
      showNotification(`Erreur : ${e?.message}`);
    }
  };

  // Clear buffer
  const handleClearBuffer = async () => {
    try {
      const res = await fetch('/api/syslog/clear', { method: 'POST' });
      if (res.ok) {
        setLogs([]);
        showNotification('Tampon de logs Syslog UDP réinitialisé');
        fetchStatus();
      }
    } catch (e: any) {
      showNotification(`Erreur : ${e?.message}`);
    }
  };

  // Forward collected logs to AI SOC analyzer
  const handlePushToAiAnalyzer = async () => {
    try {
      const res = await fetch('/api/syslog/aggregate-for-analysis', { method: 'POST' });
      const data = await res.json();
      if (data.success && data.rawLogs) {
        showNotification(`${data.packetCount} logs Syslog UDP transférés vers l'analyseur IA SOC`);
        onAnalyzeSyslogLogs(data.rawLogs, data.deviceContext || 'Zyxel Syslog UDP Feed');
      } else {
        showNotification(data.error || 'Aucun log à analyser');
      }
    } catch (e: any) {
      showNotification(`Erreur transmission vers IA : ${e?.message}`);
    }
  };

  // Export logs to file
  const handleExportLogs = (format: 'txt' | 'json' | 'csv') => {
    if (logs.length === 0) return;
    let content = '';
    let mimeType = 'text/plain';
    let filename = `zyxel_syslog_udp_export_${new Date().toISOString().slice(0, 10)}`;

    if (format === 'txt') {
      content = logs.map((l) => l.raw).join('\n');
      filename += '.log';
    } else if (format === 'json') {
      content = JSON.stringify(logs, null, 2);
      mimeType = 'application/json';
      filename += '.json';
    } else {
      const header = 'Timestamp,Severity,Facility,SourceDevice,SrcIP,DstIP,ThreatName,Action,BytesSent,Duration,User,Attempts,Raw\n';
      const rows = logs
        .map(
          (l) =>
            `"${l.timestamp}","${l.severity}","${l.facilityName}","${l.sourceDevice}","${l.srcIp || ''}","${
              l.dstIp || ''
            }","${l.threatName || ''}","${l.action || ''}","${l.bytesSent || ''}","${l.duration || ''}","${
              l.userName || ''
            }","${l.authAttempts || ''}","${l.raw.replace(/"/g, '""')}"`
        )
        .join('\n');
      content = header + rows;
      mimeType = 'text/csv';
      filename += '.csv';
    }

    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
    showNotification(`Fichier ${filename} téléchargé`);
  };

  const getSeverityBadge = (severity: SeverityLevel) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-red-950 text-red-300 border-red-800 animate-pulse';
      case 'HIGH':
        return 'bg-amber-950 text-amber-300 border-amber-800';
      case 'MEDIUM':
        return 'bg-blue-950 text-blue-300 border-blue-800';
      case 'LOW':
        return 'bg-slate-800 text-slate-300 border-slate-700';
      default:
        return 'bg-slate-900 text-slate-400 border-slate-800';
    }
  };

  return (
    <div className="space-y-6">
      {/* Toast Notification */}
      {actionSuccessMsg && (
        <div className="fixed bottom-6 right-6 z-50 flex items-center gap-2.5 px-4 py-3 rounded-xl bg-cyan-950 border border-cyan-700 text-cyan-200 text-sm shadow-2xl backdrop-blur-md animate-in fade-in slide-in-from-bottom-3">
          <Check className="w-4 h-4 text-cyan-400 shrink-0" />
          <span>{actionSuccessMsg}</span>
        </div>
      )}

      {/* Top Banner: Status of the UDP Receiver & Live Controls */}
      <div className="rounded-2xl border border-slate-800 bg-gradient-to-r from-slate-900 via-slate-900/90 to-slate-950 p-5 shadow-xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl -z-0 pointer-events-none" />

        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 relative z-10">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2.5">
              <span className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
                <Radio className="w-5 h-5 animate-pulse" />
              </span>
              <h2 className="text-xl font-bold text-white tracking-tight">
                Serveur Récepteur Syslog UDP & Automatisation Nebula
              </h2>
              <span
                className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold border ${
                  status?.isListening
                    ? 'bg-emerald-950/80 text-emerald-300 border-emerald-700'
                    : 'bg-amber-950/80 text-amber-300 border-amber-700'
                }`}
              >
                <span
                  className={`w-2 h-2 rounded-full ${
                    status?.isListening ? 'bg-emerald-400 animate-ping' : 'bg-amber-400'
                  }`}
                />
                {status?.isListening
                  ? `Écoute Active sur UDP ${status?.port || 514}`
                  : 'Démarrage du Socket UDP...'}
              </span>
            </div>
            <p className="text-xs text-slate-400 max-w-3xl">
              Architecture en boucle fermée : réception et décodage standard Syslog Zyxel (Trafic, Sécurité UTM, Auth),
              analyse comportementale par l'IA Gemini et ordres automatiques de blocage via l'API Nebula.
            </p>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={handleExecuteClosedLoopDemo}
              disabled={isSimulatingLoop}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-red-600 via-rose-600 to-amber-600 hover:from-red-500 hover:to-amber-500 text-white text-xs font-bold transition shadow-lg shadow-red-950/40"
              title="Tester le scénario : Attaque SSH Brute Force 198.51.100.45:22 et blocage immédiat via API Nebula"
            >
              <Zap className={`w-4 h-4 ${isSimulatingLoop ? 'animate-spin' : 'text-yellow-300'}`} />
              <span>
                {isSimulatingLoop
                  ? 'Exécution Riposte en Cours...'
                  : 'Tester Cas Concret : Brute-Force SSH (198.51.100.45:22)'}
              </span>
            </button>

            <button
              onClick={handleSendTestDatagram}
              disabled={isSendingTest}
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-semibold transition"
              title="Émettre un paquet UDP réel sur localhost pour tester le port"
            >
              <Send className="w-3.5 h-3.5 text-cyan-400" />
              <span>Tester Socket UDP</span>
            </button>

            <button
              onClick={handleInjectSampleBatch}
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-semibold transition"
              title="Injecter 6 logs réels d'attaque Zyxel ATP/USG dans le collecteur"
            >
              <Cpu className="w-3.5 h-3.5 text-amber-400" />
              <span>Injecter Échantillons</span>
            </button>

            <button
              onClick={handlePushToAiAnalyzer}
              disabled={logs.length === 0}
              className={`inline-flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition shadow-lg ${
                logs.length > 0
                  ? 'bg-gradient-to-r from-cyan-600 to-blue-600 text-white hover:from-cyan-500 hover:to-blue-500 shadow-cyan-900/40'
                  : 'bg-slate-800 text-slate-500 border border-slate-800 cursor-not-allowed'
              }`}
            >
              <Sparkles className="w-4 h-4 text-yellow-300" />
              <span>Analyser avec l'IA ({logs.length})</span>
            </button>
          </div>
        </div>

        {/* Live Metrics Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-4 pt-4 border-t border-slate-800/80">
          <div className="bg-slate-950/60 rounded-xl p-3 border border-slate-800">
            <div className="text-[11px] text-slate-400 flex items-center justify-between">
              <span>Port d'écoute UDP</span>
              <Server className="w-3.5 h-3.5 text-cyan-400" />
            </div>
            <div className="text-lg font-bold font-mono text-cyan-300 mt-1">
              0.0.0.0:{status?.port || 514}
            </div>
            <div className="text-[10px] text-slate-500 mt-0.5">
              {status?.port === 514
                ? 'Port standard privilégié (RFC 3164)'
                : 'Port non-root actif (5140 UDP)'}
            </div>
          </div>

          <div className="bg-slate-950/60 rounded-xl p-3 border border-slate-800">
            <div className="text-[11px] text-slate-400 flex items-center justify-between">
              <span>Paquets Reçus (Total)</span>
              <Layers className="w-3.5 h-3.5 text-emerald-400" />
            </div>
            <div className="text-lg font-bold font-mono text-white mt-1">
              {status?.packetsReceived ?? 0}
            </div>
            <div className="text-[10px] text-slate-500 mt-0.5">
              Tampon actif : {logs.length} logs
            </div>
          </div>

          <div className="bg-slate-950/60 rounded-xl p-3 border border-slate-800">
            <div className="text-[11px] text-slate-400 flex items-center justify-between">
              <span>Débit en Direct</span>
              <Activity className="w-3.5 h-3.5 text-amber-400" />
            </div>
            <div className="text-lg font-bold font-mono text-amber-300 mt-1">
              {status?.eventsPerSecond ?? 0} <span className="text-xs font-normal text-slate-400">EPS</span>
            </div>
            <div className="text-[10px] text-slate-500 mt-0.5">
              Volume : {Math.round(((status?.bytesReceived || 0) / 1024) * 10) / 10} KB
            </div>
          </div>

          <div className="bg-slate-950/60 rounded-xl p-3 border border-slate-800">
            <div className="text-[11px] text-slate-400 flex items-center justify-between">
              <span>Équipements Détectés</span>
              <Radio className="w-3.5 h-3.5 text-purple-400" />
            </div>
            <div className="text-lg font-bold font-mono text-purple-300 mt-1">
              {status?.activeSenders?.length || 0}{' '}
              <span className="text-xs font-normal text-slate-400">source(s)</span>
            </div>
            <div className="text-[10px] text-slate-500 mt-0.5 truncate">
              {status?.activeSenders && status.activeSenders.length > 0
                ? status.activeSenders.map((s) => s.ip).join(', ')
                : 'En attente de paquets...'}
            </div>
          </div>
        </div>
      </div>

      {/* Closed Loop Interactive Simulation Banner (when run or completed) */}
      {(isSimulatingLoop || loopSimulationResult) && (
        <div className="rounded-2xl border border-red-800/80 bg-gradient-to-r from-red-950/50 via-slate-900 to-slate-950 p-5 shadow-2xl space-y-4 animate-in fade-in">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2.5">
              <span className="p-2 rounded-xl bg-red-900/50 text-red-300 border border-red-700">
                <Zap className="w-5 h-5 text-yellow-300 animate-pulse" />
              </span>
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <span>🤖 Interaction en Boucle Fermée : Détection Syslog &gt; IA SOC &gt; Blocage API Nebula</span>
                  <span className="px-2 py-0.5 rounded-full text-[10px] bg-red-900 text-red-200 font-mono">
                    Scénario SSH Brute-Force 198.51.100.45
                  </span>
                </h3>
                <p className="text-xs text-slate-400">
                  Visualisation du cycle complet de réponse à incident autonome.
                </p>
              </div>
            </div>

            <button
              onClick={() => {
                setLoopSimulationResult(null);
                setIsSimulatingLoop(false);
              }}
              className="text-xs text-slate-400 hover:text-slate-200"
            >
              ✕ Fermer
            </button>
          </div>

          {/* 3 Step Visual Flow */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {/* Step 1 */}
            <div
              className={`p-3 rounded-xl border transition ${
                loopCurrentStep >= 1
                  ? 'bg-slate-900 border-cyan-700 text-slate-200'
                  : 'bg-slate-950/60 border-slate-800 text-slate-500'
              }`}
            >
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-[11px] font-bold text-cyan-400 flex items-center gap-1.5">
                  <span className="w-5 h-5 rounded-full bg-cyan-950 border border-cyan-700 flex items-center justify-center text-xs">
                    1
                  </span>
                  <span>1. USG Envoie Flux Syslog</span>
                </span>
                <span className="text-[10px] font-mono text-slate-400">UDP 514</span>
              </div>
              <p className="text-[11px] text-slate-300 leading-relaxed">
                L'USG FLEX détecte des connexions répétées et transmet le paquet Syslog vers le port UDP 514 :
              </p>
              <div className="mt-2 p-1.5 rounded bg-black/80 font-mono text-[10px] text-amber-300 truncate">
                SRC=198.51.100.45:51240 DST=195.154.80.12:22 ATTEMPTS=48
              </div>
            </div>

            {/* Step 2 */}
            <div
              className={`p-3 rounded-xl border transition ${
                loopCurrentStep >= 2
                  ? 'bg-slate-900 border-purple-700 text-slate-200'
                  : 'bg-slate-950/60 border-slate-800 text-slate-500'
              }`}
            >
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-[11px] font-bold text-purple-400 flex items-center gap-1.5">
                  <span className="w-5 h-5 rounded-full bg-purple-950 border border-purple-700 flex items-center justify-center text-xs">
                    2
                  </span>
                  <span>2. L'IA Analyse le Comportement</span>
                </span>
                <span className="text-[10px] font-mono text-purple-400">Gemini SOC</span>
              </div>
              <p className="text-[11px] text-slate-300 leading-relaxed">
                Corrélation d'une attaque par dictionnaire brute-force sur port sensible 22. Risque critique évalué.
              </p>
              <div className="mt-2 p-1.5 rounded bg-black/80 font-mono text-[10px] text-rose-300 truncate">
                T1110.001 Brute Force • Seuil de blocage WAN franchi
              </div>
            </div>

            {/* Step 3 */}
            <div
              className={`p-3 rounded-xl border transition ${
                loopCurrentStep >= 3
                  ? 'bg-slate-900 border-emerald-700 text-slate-200'
                  : 'bg-slate-950/60 border-slate-800 text-slate-500'
              }`}
            >
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-[11px] font-bold text-emerald-400 flex items-center gap-1.5">
                  <span className="w-5 h-5 rounded-full bg-emerald-950 border border-emerald-700 flex items-center justify-center text-xs">
                    3
                  </span>
                  <span>3. Action via API Nebula</span>
                </span>
                <span className="text-[10px] font-mono text-emerald-400">POST /rules</span>
              </div>
              <p className="text-[11px] text-slate-300 leading-relaxed">
                Ordre transmis automatiquement à l'API Nebula. Règle DROP créée sur la passerelle pour neutraliser l'attaquant.
              </p>
              <div className="mt-2 p-1.5 rounded bg-black/80 font-mono text-[10px] text-emerald-300 truncate">
                DROP_ATTACKER_198_51_100_45 (WAN to ZyWALL)
              </div>
            </div>
          </div>

          {/* Detailed payload preview when simulation completed */}
          {loopSimulationResult && (
            <div className="p-3 bg-black/70 rounded-xl border border-slate-800 space-y-2 text-xs">
              <div className="flex items-center justify-between text-slate-300 font-semibold">
                <span className="text-emerald-400 flex items-center gap-1.5">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  <span>Requête OpenAPI Nebula Exécutée avec Succès</span>
                </span>
                <span className="text-[10px] text-slate-500 font-mono">
                  Status: 200 OK • Latence: {loopSimulationResult.step3_nebulaApiOrder.apiCall.latencyMs}ms
                </span>
              </div>
              <pre className="p-2.5 rounded-lg bg-black font-mono text-[11px] text-cyan-300 overflow-x-auto select-all">
                {loopSimulationResult.step3_nebulaApiOrder.apiCall.cliCommand}
              </pre>
            </div>
          )}
        </div>
      )}

      {/* Section 1 & 2 Tabbed Documentation: Données d'Ingestion (Syslog) & Données d'Automatisation (Nebula API) */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5 shadow-lg space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Server className="w-4 h-4 text-cyan-400" />
              <span>Référence d'Ingestion Syslog & Automatisation API Nebula</span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Spécifications des formats Syslog Zyxel extraits pour l'IA et données requises pour le pilotage de l'API Nebula.
            </p>
          </div>

          <div className="flex items-center gap-1 bg-slate-950/80 p-1 rounded-xl border border-slate-800">
            <button
              onClick={() => setActiveConfigTab('architecture')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                activeConfigTab === 'architecture'
                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Données Clés & API
            </button>
            <button
              onClick={() => setActiveConfigTab('rsyslog')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                activeConfigTab === 'rsyslog'
                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              rsyslog (Linux)
            </button>
            <button
              onClick={() => setActiveConfigTab('zyxel')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                activeConfigTab === 'zyxel'
                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Zyxel USG / ATP
            </button>
            <button
              onClick={() => setActiveConfigTab('syslogng')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                activeConfigTab === 'syslogng'
                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              syslog-ng
            </button>
          </div>
        </div>

        {/* Tab 0: Architecture, Données d'Ingestion & Automatisation API Nebula */}
        {activeConfigTab === 'architecture' && (
          <div className="space-y-4">
            {/* 1. Données d'analyse pour votre IA (Ingestion des logs) */}
            <div className="space-y-2.5">
              <h4 className="text-xs font-bold uppercase tracking-wider text-cyan-400 flex items-center gap-1.5">
                <Database className="w-3.5 h-3.5" />
                <span>1. Données d'analyse pour votre IA (Ingestion des logs)</span>
              </h4>
              <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-950/60">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-900/90 text-slate-300 border-b border-slate-800 text-[11px]">
                    <tr>
                      <th className="py-2.5 px-3">Type de donnée</th>
                      <th className="py-2.5 px-3">Format / Protocole</th>
                      <th className="py-2.5 px-3">Informations clés extraites pour l'IA</th>
                      <th className="py-2.5 px-3 text-right">Filtrer dans le flux</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 text-slate-300 text-[11px]">
                    <tr className="hover:bg-slate-900/40">
                      <td className="py-2.5 px-3 font-semibold text-white flex items-center gap-2">
                        <Activity className="w-3.5 h-3.5 text-cyan-400" />
                        <span>Logs de Trafic</span>
                      </td>
                      <td className="py-2.5 px-3 font-mono text-cyan-300">UDP 514 (Syslog)</td>
                      <td className="py-2.5 px-3 text-slate-300">
                        IP source/destination, ports, protocoles (TCP/UDP/ICMP), volumes de données (octets : <code>BYTES_SENT</code>, <code>BYTES_RECVD</code>), durée des sessions (<code>DURATION</code>).
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        <button
                          onClick={() => setActiveDataTypeTab('TRAFFIC')}
                          className="px-2 py-0.5 rounded text-[10px] bg-cyan-950 text-cyan-300 border border-cyan-800 hover:bg-cyan-900"
                        >
                          Afficher Trafic
                        </button>
                      </td>
                    </tr>
                    <tr className="hover:bg-slate-900/40">
                      <td className="py-2.5 px-3 font-semibold text-white flex items-center gap-2">
                        <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                        <span>Logs UTM / Sécurité</span>
                      </td>
                      <td className="py-2.5 px-3 font-mono text-cyan-300">UDP 514 (Syslog)</td>
                      <td className="py-2.5 px-3 text-slate-300">
                        Alertes IDP/IPS (Intrusion : <code>SIG_ID</code>, <code>CVE</code>), signatures de malwares (Anti-Malware : <code>VIRUS</code>, <code>HASH</code>), URL bloquées (Content Filtering : <code>DOMAIN</code>, <code>URL</code>), détections Sandbox (<code>SANDBOX_SCORE</code>).
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        <button
                          onClick={() => setActiveDataTypeTab('UTM')}
                          className="px-2 py-0.5 rounded text-[10px] bg-rose-950 text-rose-300 border border-rose-800 hover:bg-rose-900"
                        >
                          Afficher UTM
                        </button>
                      </td>
                    </tr>
                    <tr className="hover:bg-slate-900/40">
                      <td className="py-2.5 px-3 font-semibold text-white flex items-center gap-2">
                        <Lock className="w-3.5 h-3.5 text-amber-400" />
                        <span>Logs Système &amp; Auth</span>
                      </td>
                      <td className="py-2.5 px-3 font-mono text-cyan-300">UDP 514 (Syslog)</td>
                      <td className="py-2.5 px-3 text-slate-300">
                        Tentatives de connexions (réussies/échouées) à l'administration ou aux VPN (Brute-force : <code>USER</code>, <code>ATTEMPTS</code>, <code>REASON</code>, port 22 SSH, 4433 SSL-VPN).
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        <button
                          onClick={() => setActiveDataTypeTab('AUTH')}
                          className="px-2 py-0.5 rounded text-[10px] bg-amber-950 text-amber-300 border border-amber-800 hover:bg-amber-900"
                        >
                          Afficher Auth
                        </button>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>

            {/* 2. Données d'automatisation (API Nebula) */}
            <div className="space-y-2.5 pt-2 border-t border-slate-800/80">
              <div className="flex items-center justify-between">
                <h4 className="text-xs font-bold uppercase tracking-wider text-emerald-400 flex items-center gap-1.5">
                  <Key className="w-3.5 h-3.5" />
                  <span>2. Données d'automatisation (API Nebula pour ordonner le blocage)</span>
                </h4>
                {onNavigateToTab && (
                  <button
                    onClick={() => onNavigateToTab('nebula-api')}
                    className="text-[11px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
                  >
                    <span>Ouvrir l'onglet API Nebula</span>
                    <ArrowRight className="w-3 h-3" />
                  </button>
                )}
              </div>

              <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-950/60">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-900/90 text-slate-300 border-b border-slate-800 text-[11px]">
                    <tr>
                      <th className="py-2.5 px-3">Donnée requise</th>
                      <th className="py-2.5 px-3">Où la trouver dans Nebula</th>
                      <th className="py-2.5 px-3">Utilité pour votre plateforme IA</th>
                      <th className="py-2.5 px-3 text-right">Valeur configurée</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 text-slate-300 text-[11px]">
                    <tr className="hover:bg-slate-900/40">
                      <td className="py-2.5 px-3 font-semibold text-white">Base URL de l'API</td>
                      <td className="py-2.5 px-3 text-slate-400 font-mono">https://zyxel.com</td>
                      <td className="py-2.5 px-3 text-slate-300">Point d'entrée pour toutes les requêtes de votre IA.</td>
                      <td className="py-2.5 px-3 text-right font-mono text-cyan-400">
                        https://zyxel.com
                      </td>
                    </tr>
                    <tr className="hover:bg-slate-900/40">
                      <td className="py-2.5 px-3 font-semibold text-white">Clé API (API Key)</td>
                      <td className="py-2.5 px-3 text-slate-400">
                        Organization &gt; Administrators &gt; Sélectionner le compte &gt; API Key
                      </td>
                      <td className="py-2.5 px-3 text-slate-300">Authentifie votre plateforme IA auprès de Nebula.</td>
                      <td className="py-2.5 px-3 text-right font-mono text-emerald-400">
                        nebula_sec_994***
                      </td>
                    </tr>
                    <tr className="hover:bg-slate-900/40">
                      <td className="py-2.5 px-3 font-semibold text-white">Organization ID</td>
                      <td className="py-2.5 px-3 text-slate-400">
                        URL du navigateur ou via la requête API <code>GET /organizations</code>
                      </td>
                      <td className="py-2.5 px-3 text-slate-300">Identifie l'organisation Zyxel à cibler.</td>
                      <td className="py-2.5 px-3 text-right font-mono text-cyan-400">
                        ORG-ZYXEL-FR-88412
                      </td>
                    </tr>
                    <tr className="hover:bg-slate-900/40">
                      <td className="py-2.5 px-3 font-semibold text-white">Site ID</td>
                      <td className="py-2.5 px-3 text-slate-400">
                        URL du navigateur ou via la requête API <code>GET /sites</code>
                      </td>
                      <td className="py-2.5 px-3 text-slate-300">Identifie le site spécifique où se trouve l'USG.</td>
                      <td className="py-2.5 px-3 text-right font-mono text-cyan-400">
                        site-paris-hq
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* Tab 1: rsyslog (The exact instructions asked by the user) */}
        {activeConfigTab === 'rsyslog' && (
          <div className="space-y-3.5 bg-slate-950/60 rounded-xl p-4 border border-slate-800/90 text-xs">
            <div className="flex items-center gap-2 text-amber-300 bg-amber-950/30 border border-amber-800/60 p-2.5 rounded-lg">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>
                <strong>Configuration rsyslog standard :</strong> Votre serveur de logs Linux (Ubuntu, Debian, RHEL, CentOS)
                doit être configuré pour écouter sur le protocole UDP (Port 514).
              </span>
            </div>

            <div className="space-y-3">
              {/* Step 1 */}
              <div>
                <div className="flex items-center justify-between text-slate-300 font-semibold mb-1">
                  <span>1. Ouvrez le fichier de configuration rsyslog :</span>
                  <button
                    onClick={() => copyToClipboard('sudo nano /etc/rsyslog.conf', 'step1')}
                    className="flex items-center gap-1 text-[11px] text-cyan-400 hover:text-cyan-300"
                  >
                    {copiedKey === 'step1' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>Copier</span>
                  </button>
                </div>
                <pre className="p-2.5 rounded-lg bg-black/80 font-mono text-cyan-300 border border-slate-800 select-all overflow-x-auto">
sudo nano /etc/rsyslog.conf
                </pre>
              </div>

              {/* Step 2 */}
              <div>
                <div className="flex items-center justify-between text-slate-300 font-semibold mb-1">
                  <span>2. Décommentez ou insérez les lignes suivantes pour activer la réception UDP :</span>
                  <button
                    onClick={() =>
                      copyToClipboard(
                        'module(load="imudp")\ninput(type="imudp" port="514")',
                        'step2'
                      )
                    }
                    className="flex items-center gap-1 text-[11px] text-cyan-400 hover:text-cyan-300"
                  >
                    {copiedKey === 'step2' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>Copier les 2 lignes</span>
                  </button>
                </div>
                <pre className="p-2.5 rounded-lg bg-black/80 font-mono text-emerald-300 border border-emerald-900/40 select-all overflow-x-auto">
{`module(load="imudp")
input(type="imudp" port="514")`}
                </pre>
                <p className="text-[11px] text-amber-400/90 mt-1 italic flex items-center gap-1">
                  <Info className="w-3 h-3 inline shrink-0" />
                  <span>Utilisez le code avec précaution. Assurez-vous qu'aucun autre démon n'occupe déjà le port UDP 514.</span>
                </p>
              </div>

              {/* Step 3 */}
              <div>
                <div className="flex items-center justify-between text-slate-300 font-semibold mb-1">
                  <span>3. Redémarrez le service rsyslog :</span>
                  <button
                    onClick={() => copyToClipboard('sudo systemctl restart rsyslog', 'step3')}
                    className="flex items-center gap-1 text-[11px] text-cyan-400 hover:text-cyan-300"
                  >
                    {copiedKey === 'step3' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>Copier</span>
                  </button>
                </div>
                <pre className="p-2.5 rounded-lg bg-black/80 font-mono text-cyan-300 border border-slate-800 select-all overflow-x-auto">
sudo systemctl restart rsyslog
                </pre>
              </div>

              {/* Step 4: Verification & Firewall */}
              <div className="pt-2 border-t border-slate-800/80">
                <div className="text-slate-300 font-semibold mb-1">
                  4. Vérification de l'écoute du port et pare-feu (UFW / iptables) :
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  <div className="p-2 rounded-lg bg-black/60 border border-slate-800 font-mono text-[11px] text-slate-300">
                    <span className="text-slate-500"># Vérifier l'écoute socket UDP 514 :</span>
                    <br />
                    sudo ss -ulnp | grep 514
                  </div>
                  <div className="p-2 rounded-lg bg-black/60 border border-slate-800 font-mono text-[11px] text-slate-300">
                    <span className="text-slate-500"># Autoriser le port UDP sur UFW :</span>
                    <br />
                    sudo ufw allow 514/udp
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Tab 2: Zyxel Nebula & On-Premise Gateway Setup */}
        {activeConfigTab === 'zyxel' && (
          <div className="space-y-3.5 bg-slate-950/60 rounded-xl p-4 border border-slate-800/90 text-xs">
            <div className="flex items-center gap-2 text-cyan-300 bg-cyan-950/30 border border-cyan-800/60 p-2.5 rounded-lg">
              <Radio className="w-4 h-4 shrink-0" />
              <span>
                <strong>Configuration Zyxel Nebula Control Center (NCC) ou Passerelle Locale (ATP / USG FLEX / ZyWALL) :</strong>
              </span>
            </div>

            <div className="space-y-2.5 text-slate-300">
              <ol className="list-decimal list-inside space-y-2 ml-1 text-slate-300">
                <li>
                  Accédez à : <code>Configuration &gt; Log &amp; Report &gt; Log Setting &gt; Syslog Servers</code>.
                </li>
                <li>
                  Activez le serveur Syslog :
                  <ul className="list-disc list-inside ml-4 mt-1 space-y-1 text-slate-400">
                    <li><strong>Adresse IP du Serveur :</strong> IP de ce serveur SOC (ex: <code>192.168.1.50</code>)</li>
                    <li><strong>Port :</strong> <code>514</code> (Protocole: <code>UDP</code>)</li>
                    <li><strong>Facility de Log :</strong> <code>Local 5 (18)</code></li>
                    <li><strong>Catégories à transmettre :</strong> Tout cocher (Traffic, IDP/IPS, Anti-Malware, IP Reputation, Web Filter, CDR, Auth)</li>
                  </ul>
                </li>
              </ol>

              <div>
                <div className="flex items-center justify-between text-slate-300 font-semibold mt-3 mb-1">
                  <span>Configuration rapide en ligne de commande Zyxel ZySH (CLI SSH) :</span>
                  <button
                    onClick={() =>
                      copyToClipboard(
                        `configure terminal\nsyslog-server 1 ip-address <IP_SERVEUR_SOC> port 514\nsyslog-server 1 facility local5\nsyslog-server 1 log-type traffic-log security-log alert-log\nwrite memory`,
                        'zyxelcli'
                      )
                    }
                    className="flex items-center gap-1 text-[11px] text-cyan-400 hover:text-cyan-300"
                  >
                    {copiedKey === 'zyxelcli' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>Copier commandes CLI</span>
                  </button>
                </div>
                <pre className="p-2.5 rounded-lg bg-black/80 font-mono text-cyan-300 border border-slate-800 select-all overflow-x-auto">
{`configure terminal
syslog-server 1 ip-address <IP_SERVEUR_SOC> port 514
syslog-server 1 facility local5
syslog-server 1 log-type traffic-log security-log alert-log
write memory`}
                </pre>
              </div>
            </div>
          </div>
        )}

        {/* Tab 3: syslog-ng */}
        {activeConfigTab === 'syslogng' && (
          <div className="space-y-3 bg-slate-950/60 rounded-xl p-4 border border-slate-800/90 text-xs text-slate-300">
            <p className="font-semibold text-white">
              Si votre infrastructure utilise <code>syslog-ng</code> à la place de rsyslog :
            </p>
            <pre className="p-3 rounded-lg bg-black/80 font-mono text-emerald-300 border border-slate-800 select-all overflow-x-auto">
{`source s_network_udp {
    udp(ip(0.0.0.0) port(514));
};

destination d_nebula_soc {
    udp("127.0.0.1" port(${status?.port || 514}));
};

log {
    source(s_network_udp);
    destination(d_nebula_soc);
};`}
            </pre>
            <div className="text-slate-400">
              Redémarrez ensuite le service : <code>sudo systemctl restart syslog-ng</code>
            </div>
          </div>
        )}
      </div>

      {/* Real-time Syslog Terminal & Collected Stream */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5 shadow-xl space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <span className="p-2 rounded-xl bg-cyan-950 border border-cyan-800 text-cyan-400">
              <Terminal className="w-5 h-5" />
            </span>
            <div>
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <span>Flux de Logs Syslog UDP Reçus en Direct</span>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-cyan-900 text-cyan-200">
                  {logs.length} paquet(s)
                </span>
              </h3>
              <p className="text-xs text-slate-400">
                Visualisez, filtrez par type de donnée (Trafic / UTM / Auth) ou transférez directement vers l'IA SOC.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            {/* Live Polling toggle */}
            <button
              onClick={() => setIsLivePolling(!isLivePolling)}
              className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold border transition ${
                isLivePolling
                  ? 'bg-emerald-950/80 text-emerald-300 border-emerald-700'
                  : 'bg-slate-800 text-slate-400 border-slate-700'
              }`}
            >
              {isLivePolling ? (
                <>
                  <Pause className="w-3.5 h-3.5" />
                  <span>En Direct (Actif)</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Reprendre Écoute</span>
                </>
              )}
            </button>

            {/* Clear buffer */}
            <button
              onClick={handleClearBuffer}
              disabled={logs.length === 0}
              className="inline-flex items-center gap-1 px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-medium transition disabled:opacity-40"
              title="Effacer le tampon"
            >
              <Trash2 className="w-3.5 h-3.5 text-rose-400" />
              <span>Vider</span>
            </button>

            {/* Export Dropdown */}
            <div className="flex items-center gap-1">
              <button
                onClick={() => handleExportLogs('txt')}
                disabled={logs.length === 0}
                className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition disabled:opacity-40"
                title="Exporter en fichier .log brut"
              >
                <Download className="w-3 h-3 text-cyan-400" />
                <span>.log</span>
              </button>
              <button
                onClick={() => handleExportLogs('json')}
                disabled={logs.length === 0}
                className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition disabled:opacity-40"
                title="Exporter en JSON"
              >
                <span>JSON</span>
              </button>
              <button
                onClick={() => handleExportLogs('csv')}
                disabled={logs.length === 0}
                className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition disabled:opacity-40"
                title="Exporter en CSV"
              >
                <span>CSV</span>
              </button>
            </div>
          </div>
        </div>

        {/* Data Type Quick Filter Chips */}
        <div className="flex items-center gap-2 flex-wrap pt-1">
          <span className="text-[11px] text-slate-400 font-semibold mr-1">Types de Données Ingestion :</span>
          <button
            onClick={() => setActiveDataTypeTab('ALL')}
            className={`px-3 py-1 rounded-xl text-xs font-medium transition ${
              activeDataTypeTab === 'ALL'
                ? 'bg-cyan-600 text-white shadow-sm'
                : 'bg-slate-950 text-slate-400 border border-slate-800 hover:text-white'
            }`}
          >
            Tous ({logs.length})
          </button>
          <button
            onClick={() => setActiveDataTypeTab('TRAFFIC')}
            className={`px-3 py-1 rounded-xl text-xs font-medium transition flex items-center gap-1.5 ${
              activeDataTypeTab === 'TRAFFIC'
                ? 'bg-cyan-600 text-white shadow-sm'
                : 'bg-slate-950 text-slate-400 border border-slate-800 hover:text-cyan-300'
            }`}
          >
            <Activity className="w-3.5 h-3.5 text-cyan-400" />
            <span>Logs de Trafic (Volumes, Durée)</span>
          </button>
          <button
            onClick={() => setActiveDataTypeTab('UTM')}
            className={`px-3 py-1 rounded-xl text-xs font-medium transition flex items-center gap-1.5 ${
              activeDataTypeTab === 'UTM'
                ? 'bg-rose-600 text-white shadow-sm'
                : 'bg-slate-950 text-slate-400 border border-slate-800 hover:text-rose-300'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
            <span>Logs UTM / Sécurité (IDP, Malware, URL)</span>
          </button>
          <button
            onClick={() => setActiveDataTypeTab('AUTH')}
            className={`px-3 py-1 rounded-xl text-xs font-medium transition flex items-center gap-1.5 ${
              activeDataTypeTab === 'AUTH'
                ? 'bg-amber-600 text-white shadow-sm'
                : 'bg-slate-950 text-slate-400 border border-slate-800 hover:text-amber-300'
            }`}
          >
            <Lock className="w-3.5 h-3.5 text-amber-400" />
            <span>Logs Système &amp; Auth (Brute-Force)</span>
          </button>
        </div>

        {/* Filter bar */}
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-2.5 pt-1">
          <div>
            <label className="text-[10px] text-slate-400 mb-1 block">Filtrer par Sévérité :</label>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="w-full px-3 py-1.5 rounded-xl bg-slate-950 border border-slate-800 text-slate-200 text-xs focus:ring-1 focus:ring-cyan-500 focus:outline-none"
            >
              <option value="ALL">Toutes les sévérités</option>
              <option value="CRITICAL">CRITICAL uniquement</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>
          </div>

          <div>
            <label className="text-[10px] text-slate-400 mb-1 block">Filtrer par Catégorie Zyxel :</label>
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              className="w-full px-3 py-1.5 rounded-xl bg-slate-950 border border-slate-800 text-slate-200 text-xs focus:ring-1 focus:ring-cyan-500 focus:outline-none"
            >
              <option value="ALL">Toutes les catégories</option>
              <option value="IDP/IPS">IDP / IPS (Intrusion)</option>
              <option value="Anti-Malware">Anti-Malware / Virus</option>
              <option value="IP_Reputation">IP Reputation / Botnet</option>
              <option value="Content_Filter">Filtre de Contenu Web</option>
              <option value="VPN_Auth">VPN &amp; Authentification</option>
              <option value="CDR_Quarantine">CDR Quarantaine</option>
              <option value="Traffic_Anomaly">Anomalie de Trafic</option>
            </select>
          </div>

          <div className="sm:col-span-2">
            <label className="text-[10px] text-slate-400 mb-1 block">Recherche IP, Utilisateur ou Signature :</label>
            <div className="relative">
              <input
                type="text"
                placeholder="Ex: 198.51.100.45, root, CobaltStrike, Log4j, Dropped..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-3 pr-8 py-1.5 rounded-xl bg-slate-950 border border-slate-800 text-slate-200 text-xs placeholder-slate-600 focus:ring-1 focus:ring-cyan-500 focus:outline-none"
              />
              {searchTerm && (
                <button
                  onClick={() => setSearchTerm('')}
                  className="absolute right-2 top-1.5 text-slate-500 hover:text-slate-300 text-xs"
                >
                  ✕
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Custom UDP Datagram Injector Box */}
        <div className="p-3 bg-slate-950/70 rounded-xl border border-slate-800/80 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span className="font-semibold text-slate-300 flex items-center gap-1.5">
              <Send className="w-3.5 h-3.5 text-cyan-400" />
              <span>Simulateur d'envoi UDP direct (vers 127.0.0.1:{status?.port || 514})</span>
            </span>
            <span className="text-[11px] text-slate-500">
              Format Syslog RFC 3164 avec en-tête PRI &lt;189&gt;
            </span>
          </div>
          <div className="flex gap-2">
            <input
              type="text"
              value={customTestMessage}
              onChange={(e) => setCustomTestMessage(e.target.value)}
              placeholder='<189>Oct 15 15:05:00 zyxel-usg-flex [VPN_Auth] PRIORITY=CRITICAL MSG="SSH Brute Force Attack" USER="root" SRC=198.51.100.45:51240 DST=195.154.80.12:22 ATTEMPTS=48 ACTION=Alerted'
              className="flex-1 px-3 py-2 rounded-xl bg-black/80 border border-slate-800 text-cyan-300 font-mono text-xs placeholder-slate-600 focus:ring-1 focus:ring-cyan-500 focus:outline-none"
            />
            <button
              onClick={handleSendTestDatagram}
              disabled={isSendingTest}
              className="px-4 py-2 rounded-xl bg-cyan-700 hover:bg-cyan-600 text-white text-xs font-semibold transition shrink-0 inline-flex items-center gap-1.5"
            >
              <Send className="w-3.5 h-3.5" />
              <span>Émettre UDP</span>
            </button>
          </div>
        </div>

        {/* Terminal Screen */}
        <div className="bg-black/95 rounded-2xl border border-slate-800/90 p-3 shadow-inner space-y-2 font-mono text-xs overflow-hidden">
          <div className="flex items-center justify-between px-2 py-1 text-[11px] text-slate-400 border-b border-slate-800/80">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-red-500/80" />
              <span className="w-2.5 h-2.5 rounded-full bg-amber-500/80" />
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/80" />
              <span className="ml-2 text-slate-500">syslog-udp-receiver-stream.log</span>
            </div>

            <div className="flex items-center gap-3">
              <label className="flex items-center gap-1 text-[10px] text-slate-400 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={autoScroll}
                  onChange={(e) => setAutoScroll(e.target.checked)}
                  className="rounded bg-slate-900 border-slate-700 text-cyan-500 w-3 h-3 cursor-pointer"
                />
                <span>Auto-défilement</span>
              </label>
              <span className="text-[10px] text-slate-500">
                {logs.length} ligne(s)
              </span>
            </div>
          </div>

          <div className="max-h-[500px] overflow-y-auto space-y-1.5 p-1 select-text">
            {logs.length === 0 ? (
              <div className="py-12 text-center text-slate-500 space-y-2">
                <Server className="w-8 h-8 mx-auto text-slate-700 animate-pulse" />
                <p className="text-sm">Aucun paquet Syslog UDP correspondant pour le moment.</p>
                <p className="text-xs text-slate-600">
                  Cliquez sur "Tester Cas Concret : Brute-Force SSH" ou "Injecter Échantillons" pour afficher le flux.
                </p>
              </div>
            ) : (
              logs.map((pkt) => {
                const isSelected = selectedPacket?.id === pkt.id;
                return (
                  <div
                    key={pkt.id}
                    onClick={() => setSelectedPacket(isSelected ? null : pkt)}
                    className={`p-2.5 rounded-xl border transition cursor-pointer text-[11px] leading-relaxed ${
                      pkt.severity === 'CRITICAL'
                        ? 'bg-red-950/30 border-red-900/60 hover:bg-red-950/50'
                        : pkt.severity === 'HIGH'
                        ? 'bg-amber-950/20 border-amber-900/50 hover:bg-amber-950/40'
                        : 'bg-slate-900/60 border-slate-800/80 hover:bg-slate-900'
                    } ${isSelected ? 'ring-1 ring-cyan-400' : ''}`}
                  >
                    <div className="flex items-center justify-between gap-2 flex-wrap mb-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span
                          className={`w-2 h-2 rounded-full ${
                            pkt.severity === 'CRITICAL'
                              ? 'bg-red-400 animate-ping'
                              : pkt.severity === 'HIGH'
                              ? 'bg-amber-400'
                              : 'bg-cyan-400'
                          }`}
                        />
                        <span className="text-slate-400 text-[10px]">
                          {new Date(pkt.timestamp).toLocaleTimeString('fr-FR', {
                            hour: '2-digit',
                            minute: '2-digit',
                            second: '2-digit',
                          })}
                        </span>
                        <span
                          className={`px-1.5 py-0.5 rounded text-[9px] font-bold border ${getSeverityBadge(
                            pkt.severity
                          )}`}
                        >
                          {pkt.severity}
                        </span>
                        <span className="px-1.5 py-0.5 rounded text-[9px] bg-slate-800 text-cyan-300">
                          {pkt.category}
                        </span>
                        <span className="text-[10px] text-slate-400 font-mono">
                          {pkt.sourceDevice}
                        </span>
                      </div>

                      <div className="flex items-center gap-2 flex-wrap">
                        {/* Traffic & Auth pills */}
                        {pkt.bytesSent !== undefined && (
                          <span className="px-1.5 py-0.2 rounded bg-cyan-950/80 border border-cyan-800 text-[9px] text-cyan-300 font-mono">
                            Vol: {Math.round(pkt.bytesSent / 1024 * 10) / 10} KB
                          </span>
                        )}
                        {pkt.duration !== undefined && (
                          <span className="px-1.5 py-0.2 rounded bg-cyan-950/80 border border-cyan-800 text-[9px] text-cyan-300 font-mono">
                            Durée: {pkt.duration}s
                          </span>
                        )}
                        {pkt.userName && (
                          <span className="px-1.5 py-0.2 rounded bg-amber-950/80 border border-amber-800 text-[9px] text-amber-300 font-mono">
                            User: {pkt.userName} {pkt.authAttempts ? `(${pkt.authAttempts} échecs)` : ''}
                          </span>
                        )}
                        {pkt.srcIp && (
                          <span className="text-[10px] text-amber-300/90 font-mono">
                            SRC: {pkt.srcIp}{pkt.srcPort ? `:${pkt.srcPort}` : ''}
                          </span>
                        )}
                        {pkt.dstIp && (
                          <span className="text-[10px] text-cyan-300/90 font-mono">
                            DST: {pkt.dstIp}{pkt.dstPort ? `:${pkt.dstPort}` : ''}
                          </span>
                        )}
                        <span
                          className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${
                            pkt.isBlocked
                              ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                              : 'bg-slate-800 text-slate-300'
                          }`}
                        >
                          {pkt.action || 'Alerted'}
                        </span>
                      </div>
                    </div>

                    <div className="font-mono text-[11px] text-slate-300 break-all select-all">
                      {pkt.raw}
                    </div>

                    {/* Detailed Accordion when clicked */}
                    {isSelected && (
                      <div className="mt-2 pt-2 border-t border-slate-800/80 text-[10px] text-slate-400 grid grid-cols-2 sm:grid-cols-4 gap-2 bg-black/40 p-2.5 rounded-lg">
                        <div>
                          <span className="text-slate-500">Expéditeur Socket :</span>{' '}
                          <span className="text-white font-mono">{pkt.remoteAddress}:{pkt.remotePort}</span>
                        </div>
                        <div>
                          <span className="text-slate-500">Facility RFC 3164 :</span>{' '}
                          <span className="text-cyan-300">{pkt.facilityName}</span>
                        </div>
                        <div>
                          <span className="text-slate-500">Menace / Signature :</span>{' '}
                          <span className="text-rose-300">{pkt.threatName || 'N/A'}</span>
                        </div>
                        <div>
                          <span className="text-slate-500">Statut Pare-feu :</span>{' '}
                          <span className={pkt.isBlocked ? 'text-emerald-400' : 'text-amber-400'}>
                            {pkt.isBlocked ? 'Bloqué / Dropped' : 'Alerte Active'}
                          </span>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })
            )}
            <div ref={terminalEndRef} />
          </div>
        </div>
      </div>
    </div>
  );
};
