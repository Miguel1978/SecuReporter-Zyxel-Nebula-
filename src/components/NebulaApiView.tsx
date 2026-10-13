import React, { useState, useEffect } from 'react';
import {
  Cloud,
  Server,
  Wifi,
  RefreshCw,
  CheckCircle2,
  ShieldCheck,
  ShieldAlert,
  DownloadCloud,
  UploadCloud,
  Terminal,
  Activity,
  Cpu,
  HardDrive,
  Globe,
  Lock,
  ChevronDown,
  ChevronUp,
  Zap,
  Layers,
  Radio,
  AlertTriangle,
  Eye,
  Flame,
  ArrowRight,
} from 'lucide-react';
import {
  NebulaConnectionStatus,
  NebulaSiteGateway,
  StopAction,
  ActiveDefense,
} from '../types';

interface NebulaApiViewProps {
  stopActions: StopAction[];
  activeDefenses: ActiveDefense[];
  onPullSiteLogs: (rawLogs: string, siteLabel: string) => void;
  onRulePushed: (defense: ActiveDefense, msg: string) => void;
  onNavigateToDashboard?: () => void;
}

export const NebulaApiView: React.FC<NebulaApiViewProps> = ({
  stopActions,
  activeDefenses,
  onPullSiteLogs,
  onRulePushed,
  onNavigateToDashboard,
}) => {
  const [statusData, setStatusData] = useState<NebulaConnectionStatus | null>(null);
  const [selectedSiteId, setSelectedSiteId] = useState<string>('SITE-PARIS-ATP700');
  const [isLoadingStatus, setIsLoadingStatus] = useState<boolean>(false);
  const [testingSiteId, setTestingSiteId] = useState<string | null>(null);
  const [pullingSiteId, setPullingSiteId] = useState<string | null>(null);
  const [pushingRuleId, setPushingRuleId] = useState<string | null>(null);
  const [expandedCallId, setExpandedCallId] = useState<string | null>(null);
  const [feedbackBanner, setFeedbackBanner] = useState<{
    type: 'success' | 'info';
    text: string;
  } | null>(null);

  // Custom API Access & Site Connection Test State
  const [customApiUrl, setCustomApiUrl] = useState<string>('https://api.nebula.zyxel.com/v1');
  const [customOrgId, setCustomOrgId] = useState<string>('ORG-EU-WEST-884920');
  const [customSiteId, setCustomSiteId] = useState<string>('SITE-PARIS-ATP700');
  const [customGatewayModel, setCustomGatewayModel] = useState<string>('Zyxel Nebula ATP800');
  const [isTestingSite, setIsTestingSite] = useState<boolean>(false);
  const [siteTestReport, setSiteTestReport] = useState<any>(null);

  // Attack Monitoring & Log Synchronization State
  const [isSyncingAttacks, setIsSyncingAttacks] = useState<boolean>(false);
  const [isAutoSurveillance, setIsAutoSurveillance] = useState<boolean>(false);
  const [attackSurveillanceReport, setAttackSurveillanceReport] = useState<{
    siteId: string;
    siteName: string;
    gatewayModel: string;
    wanIp: string;
    timestamp: string;
    totalLogs: number;
    criticalThreats: number;
    highThreats: number;
    blockedThreats: number;
    riskScore: number;
    attacksList: Array<{
      name: string;
      category: string;
      attackerIp: string;
      targetIp: string;
      action: string;
      severity: string;
    }>;
  } | null>(null);

  const fetchNebulaStatus = async () => {
    setIsLoadingStatus(true);
    try {
      const res = await fetch('/api/nebula/status');
      if (res.ok) {
        const data: NebulaConnectionStatus = await res.json();
        setStatusData(data);
      }
    } catch (err) {
      console.error('Failed to fetch Nebula API status:', err);
    } finally {
      setIsLoadingStatus(false);
    }
  };

  useEffect(() => {
    fetchNebulaStatus();
  }, []);

  // Synchronize Logs and Launch Real-Time Attack Monitoring
  const handleSyncSiteLogsAndMonitorAttacks = async (
    targetSiteId = customSiteId,
    targetGateway = customGatewayModel
  ) => {
    setIsSyncingAttacks(true);
    try {
      const res = await fetch('/api/nebula/pull-logs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          siteId: targetSiteId,
          apiUrl: customApiUrl,
          orgId: customOrgId,
          gatewayModel: targetGateway,
        }),
      });

      if (res.ok) {
        const data = await res.json();
        const rawLogs: string = data.rawLogs || '';
        const summary = data.attackSummary || {};

        // Parse individual attacks for surveillance display
        const lines = rawLogs.split('\n').filter((l: string) => l.trim().length > 0);
        const parsedAttacks = lines.map((line: string) => {
          const sigMatch = line.match(/NAME="([^"]+)"/) || line.match(/VIRUS="([^"]+)"/) || line.match(/TYPE="([^"]+)"/) || line.match(/MSG="([^"]+)"/);
          const srcMatch = line.match(/SRC=([0-9\.]+)(?::\d+)?/);
          const dstMatch = line.match(/DST=([0-9\.]+)(?::\d+)?/);
          const actMatch = line.match(/ACTION=([^\s]+)/);
          const prioMatch = line.match(/PRIORITY=([^\s]+)/);
          const catMatch = line.match(/CAT="([^"]+)"/) || line.match(/\[([A-Za-z0-9_\/]+)\]/);

          return {
            name: sigMatch ? sigMatch[1] : 'Événement de Sécurité Périmétrique',
            category: catMatch ? catMatch[1] : 'IDP/IPS',
            attackerIp: srcMatch ? srcMatch[1] : '91.240.118.172',
            targetIp: dstMatch ? dstMatch[1] : '192.168.1.105',
            action: actMatch ? actMatch[1] : 'Dropped',
            severity: prioMatch ? prioMatch[1] : 'HIGH',
          };
        });

        setAttackSurveillanceReport({
          siteId: targetSiteId,
          siteName: data.site?.siteName || targetSiteId,
          gatewayModel: data.site?.gatewayModel || targetGateway,
          wanIp: data.site?.wanIp || '185.64.22.104',
          timestamp: new Date().toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
          totalLogs: lines.length,
          criticalThreats: summary.criticalThreats || lines.filter((l: string) => l.includes('PRIORITY=CRITICAL')).length,
          highThreats: summary.highThreats || lines.filter((l: string) => l.includes('PRIORITY=HIGH')).length,
          blockedThreats: summary.blockedThreats || lines.filter((l: string) => l.includes('ACTION=Dropped') || l.includes('ACTION=Blocked')).length,
          riskScore: summary.riskScore || 92,
          attacksList: parsedAttacks,
        });

        // Trigger AI analysis and dashboard synchronization
        onPullSiteLogs(rawLogs, `${targetGateway} (${targetSiteId})`);

        setFeedbackBanner({
          type: 'success',
          text: `Logs du site ${targetSiteId} synchronisés avec succès : ${lines.length} événements captés. Surveillance des attaques activée !`,
        });

        await fetchNebulaStatus();
      }
    } catch (err) {
      console.error('Failed to sync logs and monitor attacks:', err);
    } finally {
      setIsSyncingAttacks(false);
    }
  };

  // Continuous Auto-Surveillance Polling Effect (every 10 seconds)
  useEffect(() => {
    if (!isAutoSurveillance) return;

    const interval = setInterval(() => {
      handleSyncSiteLogsAndMonitorAttacks(customSiteId, customGatewayModel);
    }, 10000);

    return () => clearInterval(interval);
  }, [isAutoSurveillance, customSiteId, customGatewayModel]);

  const handleTestHeartbeat = async (site: NebulaSiteGateway) => {
    setTestingSiteId(site.siteId);
    try {
      const res = await fetch('/api/nebula/test-connection', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ siteId: site.siteId }),
      });
      if (res.ok) {
        const data = await res.json();
        setFeedbackBanner({
          type: 'success',
          text: `Heartbeat API Zyxel Nebula réussi sur ${site.gatewayModel} (${site.wanIp}) — Latence : ${data.latencyMs} ms • Tunnel TLS 1.3 actif.`,
        });
        await fetchNebulaStatus();
      }
    } finally {
      setTestingSiteId(null);
    }
  };

  const handlePullLogsFromSite = async (site: NebulaSiteGateway) => {
    setPullingSiteId(site.siteId);
    try {
      await handleSyncSiteLogsAndMonitorAttacks(site.siteId, site.gatewayModel);
    } finally {
      setPullingSiteId(null);
    }
  };

  const handlePushRuleToNebula = async (action: StopAction) => {
    setPushingRuleId(action.id);
    try {
      const res = await fetch('/api/nebula/push-firewall-rule', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          siteId: selectedSiteId,
          ruleName: action.zyxelNebulaRule.ruleName,
          target: action.target,
          actionType: action.type,
          direction: action.zyxelNebulaRule.direction,
          zyxelCliCommand: action.zyxelCliCommand,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setFeedbackBanner({
          type: 'success',
          text: data.message,
        });
        onRulePushed(data.defense, data.message);
        await fetchNebulaStatus();
      }
    } finally {
      setPushingRuleId(null);
    }
  };

  const selectedSite =
    statusData?.sites.find((s) => s.siteId === selectedSiteId) || statusData?.sites[0];

  return (
    <div className="space-y-8">
      {/* Top Connection Overview Card */}
      <div className="rounded-3xl bg-slate-900/90 border border-slate-800 shadow-2xl p-6 sm:p-7 space-y-6 backdrop-blur-xl">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800 pb-5">
          <div className="flex items-center gap-3.5">
            <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-cyan-950 via-slate-900 to-emerald-950 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-lg shadow-cyan-950/50">
              <Cloud className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <h2 className="text-lg sm:text-xl font-bold text-white">
                  Connecteur Zyxel Nebula Control Center (NCC) OpenAPI
                </h2>
                <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-bold bg-emerald-950 text-emerald-300 border border-emerald-700">
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
                  CONNECTÉ AU CLOUD NEBULA
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                Synchronisation bidirectionnelle avec les passerelles Zyxel ATP / USG FLEX (Pull SecuReporter & Push ACL/CDR)
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <div className="px-3 py-1.5 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 flex items-center gap-2">
              <Wifi className="w-3.5 h-3.5 text-emerald-400" />
              <span>Latence NCC :</span>
              <strong className="text-emerald-400">{statusData?.latencyMs || 26} ms</strong>
            </div>

            <button
              onClick={fetchNebulaStatus}
              disabled={isLoadingStatus}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono border border-slate-700 transition"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoadingStatus ? 'animate-spin text-cyan-400' : ''}`} />
              <span>Rafraîchir Topologie</span>
            </button>
          </div>
        </div>

        {/* Feedback Banner */}
        {feedbackBanner && (
          <div
            className={`p-3.5 rounded-2xl border text-xs font-mono flex items-center justify-between gap-3 ${
              feedbackBanner.type === 'success'
                ? 'bg-emerald-950/40 border-emerald-800 text-emerald-200'
                : 'bg-cyan-950/40 border-cyan-800 text-cyan-200'
            }`}
          >
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 flex-shrink-0 text-emerald-400" />
              <span>{feedbackBanner.text}</span>
            </div>
            <button
              onClick={() => setFeedbackBanner(null)}
              className="text-slate-400 hover:text-white text-xs"
            >
              ✕
            </button>
          </div>
        )}

        {/* 4 Connection Metadata Pills */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5 text-xs font-mono">
          <div className="p-3.5 rounded-2xl bg-slate-950/80 border border-slate-800/90 space-y-1">
            <span className="text-[10px] text-slate-500 uppercase block">Endpoint OpenAPI</span>
            <span className="text-cyan-400 font-bold truncate block">
              {statusData?.apiBaseUrl || 'https://api.nebula.zyxel.com/v1'}
            </span>
            <span className="text-[10px] text-slate-400 block">Proxy Serveur Sécurisé (/api/nebula/*)</span>
          </div>

          <div className="p-3.5 rounded-2xl bg-slate-950/80 border border-slate-800/90 space-y-1">
            <span className="text-[10px] text-slate-500 uppercase block">Organisation NCC</span>
            <span className="text-white font-bold truncate block">
              {statusData?.organizationName || 'Nebula Enterprise SOC - Europe'}
            </span>
            <span className="text-[10px] text-slate-400 block">
              ID : {statusData?.organizationId || 'ORG-EU-WEST-884920'}
            </span>
          </div>

          <div className="p-3.5 rounded-2xl bg-slate-950/80 border border-slate-800/90 space-y-1">
            <span className="text-[10px] text-slate-500 uppercase block">Licences & Services</span>
            <span className="text-emerald-400 font-bold truncate block">
              Gold Security Pack Actif
            </span>
            <span className="text-[10px] text-slate-400 block">
              IDP/IPS • Anti-Malware • CDR • SecuReporter
            </span>
          </div>

          <div className="p-3.5 rounded-2xl bg-slate-950/80 border border-slate-800/90 space-y-1">
            <span className="text-[10px] text-slate-500 uppercase block">Passerelles Gérées</span>
            <span className="text-white font-bold block">
              {statusData?.sites.length || 4} Sites Synchronisés
            </span>
            <span className="text-[10px] text-cyan-400 block">
              {activeDefenses.filter((d) => d.status === 'ACTIVE').length} règles actives déployées
            </span>
          </div>
        </div>
      </div>

      {/* Accès à l’API avec le site pour la connexion au site et tester la connexion */}
      <div className="rounded-3xl bg-slate-900/95 border border-cyan-500/50 shadow-2xl p-6 sm:p-7 space-y-6 backdrop-blur-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-2xl bg-cyan-950 border border-cyan-700/80 flex items-center justify-center text-cyan-400 shadow-md">
              <Globe className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <span>Accès à l’API avec le Site & Test de Connexion</span>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-950 text-cyan-300 border border-cyan-800 font-semibold">
                  OpenAPI Test Suite
                </span>
              </h3>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                Configurez l'URL de l'API, l'identifiant du site passerelle et testez instantanément l'accessibilité et la latence
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            {/* Primary Action: Synchroniser les Logs avec le site pour surveiller les attaques */}
            <button
              type="button"
              onClick={() => handleSyncSiteLogsAndMonitorAttacks(customSiteId, customGatewayModel)}
              disabled={isSyncingAttacks}
              className="inline-flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 via-teal-600 to-emerald-600 hover:from-cyan-500 hover:to-emerald-500 text-white text-xs font-mono font-bold shadow-xl shadow-cyan-950/70 transition disabled:opacity-60 ring-2 ring-cyan-400/40"
              title="Synchroniser immédiatement les logs SecuReporter depuis ce site et exécuter la surveillance SOC des attaques"
            >
              <RefreshCw className={`w-4 h-4 ${isSyncingAttacks ? 'animate-spin' : ''}`} />
              <span>
                {isSyncingAttacks ? 'Synchronisation en cours...' : 'Synchroniser les Logs & Surveiller les Attaques'}
              </span>
            </button>

            {/* Secondary Action: Tester la Connexion au Site */}
            <button
              type="button"
              onClick={async () => {
                setIsTestingSite(true);
                try {
                  const res = await fetch('/api/nebula/test-site-connection', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                      apiUrl: customApiUrl,
                      orgId: customOrgId,
                      siteId: customSiteId,
                      gatewayModel: customGatewayModel,
                    }),
                  });
                  if (res.ok) {
                    const data = await res.json();
                    setSiteTestReport(data.testReport);
                    setFeedbackBanner({
                      type: 'success',
                      text: `Connexion API au site ${customSiteId} réussie ! Latence : ${data.testReport.latencyMs} ms (Tunnel TLS 1.3 actif).`,
                    });
                    await fetchNebulaStatus();
                  }
                } finally {
                  setIsTestingSite(false);
                }
              }}
              disabled={isTestingSite}
              className="inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 hover:text-white text-xs font-mono font-semibold border border-slate-700 transition disabled:opacity-60"
            >
              <Activity className={`w-4 h-4 text-emerald-400 ${isTestingSite ? 'animate-spin' : ''}`} />
              <span>{isTestingSite ? 'Test en cours...' : 'Tester la Connexion'}</span>
            </button>

            {/* Toggle Auto-Surveillance Continue */}
            <label className="inline-flex items-center gap-2 px-3 py-2 rounded-xl bg-slate-950/80 border border-slate-800 text-xs font-mono text-slate-300 cursor-pointer select-none hover:border-slate-700 transition">
              <input
                type="checkbox"
                checked={isAutoSurveillance}
                onChange={(e) => setIsAutoSurveillance(e.target.checked)}
                className="w-4 h-4 rounded bg-slate-900 border-slate-700 text-cyan-600 focus:ring-cyan-500 cursor-pointer"
              />
              <span className="flex items-center gap-1.5">
                <Radio className={`w-3.5 h-3.5 ${isAutoSurveillance ? 'text-emerald-400 animate-pulse' : 'text-slate-500'}`} />
                <span className={isAutoSurveillance ? 'text-emerald-300 font-bold' : 'text-slate-400'}>
                  Auto-Surveillance (10s)
                </span>
              </span>
            </label>
          </div>
        </div>

        {/* Form Inputs for API Access & Site */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 text-xs font-mono">
          <div className="space-y-1.5 p-3.5 rounded-2xl bg-slate-950/80 border border-slate-800">
            <label className="text-[11px] font-bold text-slate-300 block">
              URL du Site / Endpoint API *
            </label>
            <input
              type="text"
              value={customApiUrl}
              onChange={(e) => setCustomApiUrl(e.target.value)}
              placeholder="https://api.nebula.zyxel.com/v1"
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white text-xs focus:outline-none focus:ring-1 focus:ring-cyan-500"
            />
            <span className="text-[10px] text-slate-500 block">ex: https://api.nebula.zyxel.com/v1</span>
          </div>

          <div className="space-y-1.5 p-3.5 rounded-2xl bg-slate-950/80 border border-slate-800">
            <label className="text-[11px] font-bold text-cyan-300 block">
              Identifiant du Site (SITE_ID) *
            </label>
            <input
              type="text"
              value={customSiteId}
              onChange={(e) => setCustomSiteId(e.target.value)}
              placeholder="SITE-PARIS-ATP700"
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white text-xs focus:outline-none focus:ring-1 focus:ring-cyan-500"
            />
            <span className="text-[10px] text-slate-500 block">ID du site / passerelle à tester</span>
          </div>

          <div className="space-y-1.5 p-3.5 rounded-2xl bg-slate-950/80 border border-slate-800">
            <label className="text-[11px] font-bold text-indigo-300 block">
              Organisation (ORG_ID) *
            </label>
            <input
              type="text"
              value={customOrgId}
              onChange={(e) => setCustomOrgId(e.target.value)}
              placeholder="ORG-EU-WEST-884920"
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white text-xs focus:outline-none focus:ring-1 focus:ring-indigo-500"
            />
            <span className="text-[10px] text-slate-500 block">Organisation Nebula Control Center</span>
          </div>

          <div className="space-y-1.5 p-3.5 rounded-2xl bg-slate-950/80 border border-slate-800">
            <label className="text-[11px] font-bold text-emerald-300 block">
              Modèle Passerelle Zyxel
            </label>
            <select
              value={customGatewayModel}
              onChange={(e) => setCustomGatewayModel(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white text-xs focus:outline-none focus:ring-1 focus:ring-emerald-500"
            >
              <option value="Zyxel Nebula ATP800">Zyxel Nebula ATP800</option>
              <option value="Zyxel Nebula ATP700">Zyxel Nebula ATP700</option>
              <option value="Zyxel Nebula ATP500">Zyxel Nebula ATP500</option>
              <option value="Zyxel USG FLEX 700">Zyxel USG FLEX 700</option>
              <option value="Zyxel USG FLEX 500">Zyxel USG FLEX 500</option>
              <option value="Zyxel USG FLEX 200">Zyxel USG FLEX 200</option>
            </select>
            <span className="text-[10px] text-slate-500 block">Équipement périmétrique Zyxel</span>
          </div>
        </div>

        {/* Live Attack Surveillance Console (Displays after Sync) */}
        {attackSurveillanceReport && (
          <div className="p-5 rounded-2xl bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 border-2 border-cyan-500/80 shadow-2xl space-y-4 animate-in fade-in">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-xl bg-red-950/80 border border-red-700 flex items-center justify-center text-red-400">
                  <Flame className="w-4 h-4 animate-pulse" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h4 className="text-sm font-bold text-white font-mono">
                      Surveillance Active des Attaques : {attackSurveillanceReport.siteName}
                    </h4>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950 text-emerald-300 border border-emerald-700 flex items-center gap-1">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                      FLUX SYNCHRONISÉ EN DIRECT
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 font-mono">
                    Passerelle : <strong className="text-cyan-300">{attackSurveillanceReport.gatewayModel}</strong> (WAN {attackSurveillanceReport.wanIp}) • Horodatage : {attackSurveillanceReport.timestamp}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2">
                {onNavigateToDashboard && (
                  <button
                    type="button"
                    onClick={onNavigateToDashboard}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-700 text-xs font-mono font-bold transition shadow-sm"
                  >
                    <span>Voir Topologie D3.js</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => handleSyncSiteLogsAndMonitorAttacks(attackSurveillanceReport.siteId, attackSurveillanceReport.gatewayModel)}
                  disabled={isSyncingAttacks}
                  className="inline-flex items-center gap-1 px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono border border-slate-700 transition"
                >
                  <RefreshCw className={`w-3 h-3 text-cyan-400 ${isSyncingAttacks ? 'animate-spin' : ''}`} />
                  <span>Re-synchroniser</span>
                </button>
              </div>
            </div>

            {/* 4 Attack KPI Cards */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
              <div className="p-3 rounded-xl bg-slate-900/90 border border-slate-800">
                <span className="text-[10px] text-slate-500 uppercase block">Logs Analysés</span>
                <span className="text-xl font-bold text-white block mt-0.5">
                  {attackSurveillanceReport.totalLogs}
                </span>
                <span className="text-[10px] text-cyan-400 block">Événements SecuReporter</span>
              </div>

              <div className="p-3 rounded-xl bg-slate-900/90 border border-red-900/50">
                <span className="text-[10px] text-slate-500 uppercase block">Attaques Critiques</span>
                <span className="text-xl font-bold text-red-400 block mt-0.5">
                  {attackSurveillanceReport.criticalThreats}
                </span>
                <span className="text-[10px] text-red-300 block">IDP / Anti-Malware / C2</span>
              </div>

              <div className="p-3 rounded-xl bg-slate-900/90 border border-amber-900/50">
                <span className="text-[10px] text-slate-500 uppercase block">Alertes Élevées</span>
                <span className="text-xl font-bold text-amber-400 block mt-0.5">
                  {attackSurveillanceReport.highThreats}
                </span>
                <span className="text-[10px] text-amber-300 block">Scans & Déviations Trafic</span>
              </div>

              <div className="p-3 rounded-xl bg-slate-900/90 border border-emerald-900/50">
                <span className="text-[10px] text-slate-500 uppercase block">Attaques Neutralisées</span>
                <span className="text-xl font-bold text-emerald-400 block mt-0.5">
                  {attackSurveillanceReport.blockedThreats}
                </span>
                <span className="text-[10px] text-emerald-300 block">Arrêtées par Passerelle</span>
              </div>
            </div>

            {/* List of Detected Attacks on Synced Site */}
            <div className="space-y-2 pt-1">
              <span className="text-[11px] font-mono font-bold text-slate-300 uppercase tracking-wider block">
                Menaces Actives Détectées sur le Site en Temps Réel :
              </span>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5 max-h-[220px] overflow-y-auto pr-1">
                {attackSurveillanceReport.attacksList.map((atk, i) => (
                  <div
                    key={i}
                    className="p-2.5 rounded-xl bg-slate-950/80 border border-slate-800/90 flex items-center justify-between gap-3 text-xs font-mono"
                  >
                    <div className="space-y-0.5 min-w-0">
                      <div className="flex items-center gap-1.5">
                        <span
                          className={`w-2 h-2 rounded-full ${
                            atk.severity === 'CRITICAL' ? 'bg-red-400' : 'bg-amber-400'
                          }`}
                        />
                        <span className="font-bold text-white text-[11px] truncate block" title={atk.name}>
                          {atk.name}
                        </span>
                      </div>
                      <div className="text-[10px] text-slate-400 flex items-center gap-2">
                        <span>SRC: <strong className="text-red-400">{atk.attackerIp}</strong></span>
                        <span>→</span>
                        <span>DST: <strong className="text-cyan-300">{atk.targetIp}</strong></span>
                      </div>
                    </div>

                    <div className="text-right flex-shrink-0">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          atk.action === 'Dropped' || atk.action === 'Blocked' || atk.action.includes('Quarantined')
                            ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                            : 'bg-red-950 text-red-300 border border-red-800'
                        }`}
                      >
                        {atk.action}
                      </span>
                      <span className="text-[9px] text-slate-500 block mt-0.5">{atk.category}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Site Test Result Diagnostic Box */}
        {siteTestReport && (
          <div className="p-4 rounded-2xl bg-slate-950 border border-emerald-500/60 space-y-3.5 animate-in fade-in">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                <span className="text-sm font-bold text-white font-mono">
                  Résultats du Test de Connexion au Site : {siteTestReport.siteId}
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">
                  STATUT : 200 OK (ONLINE)
                </span>
              </div>
              <div className="flex items-center gap-3 text-xs font-mono text-slate-400">
                <span>Latence : <strong className="text-emerald-400">{siteTestReport.latencyMs} ms</strong></span>
                <span>• Sécurité : <strong className="text-cyan-300">{siteTestReport.tlsVersion}</strong></span>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs font-mono">
              {siteTestReport.checks?.map((chk: any, idx: number) => (
                <div key={idx} className="p-3 rounded-xl bg-slate-900/90 border border-slate-800/90 space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-300 font-bold text-[11px] truncate">{chk.name}</span>
                    <span className="text-emerald-400 font-bold text-[10px]">OK</span>
                  </div>
                  <p className="text-[10px] text-slate-400 font-sans">{chk.details}</p>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Multi-Site Gateways Grid */}
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Server className="w-5 h-5 text-cyan-400" />
            <h3 className="text-base font-bold text-white">
              Sites & Passerelles Zyxel Nebula Connectés ({statusData?.sites.length || 4})
            </h3>
          </div>
          <span className="text-xs font-mono text-slate-400">
            Sélectionnez un site pour synchroniser ses logs en direct ou déployer des règles ACL
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {statusData?.sites.map((site) => {
            const isSelected = site.siteId === selectedSiteId;
            const isTesting = testingSiteId === site.siteId;
            const isPulling = pullingSiteId === site.siteId;
            const isCurrentlyMonitored = attackSurveillanceReport?.siteId === site.siteId;

            return (
              <div
                key={site.siteId}
                onClick={() => setSelectedSiteId(site.siteId)}
                className={`p-5 rounded-2xl border transition cursor-pointer space-y-4 ${
                  isCurrentlyMonitored
                    ? 'bg-slate-900 border-emerald-500/80 ring-2 ring-emerald-500/40 shadow-2xl'
                    : isSelected
                    ? 'bg-slate-900 border-cyan-600/80 ring-1 ring-cyan-500/40 shadow-xl'
                    : 'bg-slate-900/75 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <span
                        className={`w-2.5 h-2.5 rounded-full ${
                          site.status === 'ONLINE' ? 'bg-emerald-400' : 'bg-amber-400 animate-pulse'
                        }`}
                      />
                      <h4 className="text-sm font-bold text-white">{site.siteName}</h4>
                      {isCurrentlyMonitored && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950 text-emerald-300 border border-emerald-700 animate-pulse">
                          Surveillé
                        </span>
                      )}
                    </div>
                    <p className="text-xs font-mono text-cyan-400 mt-0.5">
                      {site.gatewayModel} • WAN {site.wanIp}
                    </p>
                  </div>

                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                      site.status === 'ONLINE'
                        ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                        : 'bg-amber-950 text-amber-300 border border-amber-800'
                    }`}
                  >
                    {site.status}
                  </span>
                </div>

                {/* Telemetry Bars */}
                <div className="grid grid-cols-3 gap-2.5 text-xs font-mono">
                  <div className="p-2.5 rounded-xl bg-slate-950/80 border border-slate-800/80">
                    <span className="text-[10px] text-slate-500 block">Charge CPU</span>
                    <span
                      className={`text-sm font-bold ${
                        site.cpuUsage > 70 ? 'text-amber-400' : 'text-white'
                      }`}
                    >
                      {site.cpuUsage}%
                    </span>
                  </div>
                  <div className="p-2.5 rounded-xl bg-slate-950/80 border border-slate-800/80">
                    <span className="text-[10px] text-slate-500 block">Sessions TCP</span>
                    <span className="text-sm font-bold text-cyan-300">{site.activeSessions}</span>
                  </div>
                  <div className="p-2.5 rounded-xl bg-slate-950/80 border border-slate-800/80">
                    <span className="text-[10px] text-slate-500 block">Menaces 24h</span>
                    <span className="text-sm font-bold text-red-400">{site.threatsBlocked24h}</span>
                  </div>
                </div>

                {/* Firmware & Feature Badges */}
                <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono text-slate-400 pt-1">
                  <span>FW : {site.firmwareVersion}</span>
                  <div className="flex items-center gap-1.5">
                    {site.idpEnabled && (
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-cyan-300 border border-slate-700 text-[10px]">
                        IDP/IPS ON
                      </span>
                    )}
                    {site.cdrEnabled && (
                      <span className="px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800 text-[10px]">
                        Nebula CDR ON
                      </span>
                    )}
                  </div>
                </div>

                {/* Action Buttons */}
                <div className="pt-3 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-2">
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      handleTestHeartbeat(site);
                    }}
                    disabled={isTesting}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono border border-slate-700 transition"
                  >
                    <Activity className={`w-3.5 h-3.5 text-emerald-400 ${isTesting ? 'animate-spin' : ''}`} />
                    <span>{isTesting ? 'Ping API...' : 'Tester Heartbeat'}</span>
                  </button>

                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      handlePullLogsFromSite(site);
                    }}
                    disabled={isPulling}
                    className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl bg-gradient-to-r from-cyan-600 via-teal-600 to-emerald-600 hover:from-cyan-500 hover:to-emerald-500 text-white text-xs font-mono font-bold shadow-md shadow-cyan-950/50 transition"
                    title="Synchroniser les flux SecuReporter et surveiller les attaques de ce site"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${isPulling ? 'animate-spin' : ''}`} />
                    <span>
                      {isPulling ? 'Synchronisation...' : 'Synchroniser les Logs & Surveiller les Attaques'}
                    </span>
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Bottom 2-Column Section: Direct Policy Push & REST API Audit Log */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left: Push Firewall & CDR Policies via Nebula API */}
        <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3.5">
            <div className="flex items-center gap-2.5">
              <UploadCloud className="w-5 h-5 text-red-400" />
              <div>
                <h4 className="text-sm font-bold text-white">
                  Push Direct de Politiques ACL & CDR via API
                </h4>
                <p className="text-[11px] text-slate-400 font-mono">
                  Cible actuelle : {selectedSite?.siteName || 'Branch-Paris'} ({selectedSite?.gatewayModel})
                </p>
              </div>
            </div>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-red-950 text-red-300 border border-red-800 font-bold">
              {stopActions.length} règles prêtes
            </span>
          </div>

          <div className="space-y-3 max-h-[360px] overflow-y-auto pr-1">
            {stopActions.map((action) => {
              const isAlreadySynced = activeDefenses.some(
                (d) => d.target === action.target && d.status === 'ACTIVE'
              );
              const isPushing = pushingRuleId === action.id;

              return (
                <div
                  key={action.id}
                  className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-2 text-xs font-mono"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-bold text-white truncate">{action.title}</span>
                    <span className="px-2 py-0.5 rounded bg-slate-900 text-cyan-300 border border-slate-700 text-[10px]">
                      {action.zyxelNebulaRule.direction}
                    </span>
                  </div>

                  <div className="text-[11px] text-slate-400 font-sans">{action.rationale}</div>

                  <div className="flex items-center justify-between pt-2 border-t border-slate-800/80">
                    <span className="text-[11px] text-slate-300">
                      Objet : <strong className="text-red-400">{action.target}</strong>
                    </span>

                    {isAlreadySynced ? (
                      <span className="inline-flex items-center gap-1 text-[11px] text-emerald-400 font-bold">
                        <CheckCircle2 className="w-3.5 h-3.5" /> Synchronisé sur NCC
                      </span>
                    ) : (
                      <button
                        type="button"
                        onClick={() => handlePushRuleToNebula(action)}
                        disabled={isPushing}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-red-600 hover:bg-red-500 text-white text-[11px] font-bold transition"
                      >
                        <Lock className="w-3 h-3" />
                        <span>{isPushing ? 'Push API...' : 'Push vers Nebula API'}</span>
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right: Live REST API Audit Log */}
        <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3.5">
            <div className="flex items-center gap-2.5">
              <Terminal className="w-5 h-5 text-cyan-400" />
              <div>
                <h4 className="text-sm font-bold text-white">
                  Journal des Transactions REST Zyxel Nebula API
                </h4>
                <p className="text-[11px] text-slate-400 font-mono">
                  Traçabilité temps réel des appels exécutés par le serveur
                </p>
              </div>
            </div>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-cyan-300 border border-slate-700">
              TLS 1.3
            </span>
          </div>

          <div className="space-y-2.5 max-h-[360px] overflow-y-auto pr-1 font-mono text-xs">
            {statusData?.recentApiCalls.map((call) => {
              const isExpanded = expandedCallId === call.id;
              return (
                <div
                  key={call.id}
                  className="p-3 rounded-xl bg-slate-950 border border-slate-800/90 space-y-1.5"
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2 min-w-0">
                      <span
                        className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                          call.method === 'GET'
                            ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                            : call.method === 'POST'
                            ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                            : 'bg-amber-950 text-amber-300 border border-amber-800'
                        }`}
                      >
                        {call.method}
                      </span>
                      <span className="text-slate-200 truncate text-[11px]" title={call.endpoint}>
                        {call.endpoint}
                      </span>
                    </div>

                    <div className="flex items-center gap-2 flex-shrink-0">
                      <span className="text-[10px] text-emerald-400 font-bold">
                        {call.statusCode} OK
                      </span>
                      <span className="text-[10px] text-slate-500">{call.latencyMs}ms</span>
                    </div>
                  </div>

                  <p className="text-[11px] text-slate-400 font-sans">{call.summary}</p>

                  {call.payloadPreview && (
                    <div>
                      <button
                        type="button"
                        onClick={() => setExpandedCallId(isExpanded ? null : call.id)}
                        className="text-[10px] text-cyan-400 hover:underline flex items-center gap-1"
                      >
                        <span>{isExpanded ? 'Masquer payload JSON' : 'Voir payload JSON'}</span>
                        {isExpanded ? (
                          <ChevronUp className="w-3 h-3" />
                        ) : (
                          <ChevronDown className="w-3 h-3" />
                        )}
                      </button>
                      {isExpanded && (
                        <pre className="mt-1.5 p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-[10px] text-cyan-300 overflow-x-auto">
                          {call.payloadPreview}
                        </pre>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};
