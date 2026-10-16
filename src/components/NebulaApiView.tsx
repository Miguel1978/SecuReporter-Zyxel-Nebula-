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
  EyeOff,
  Flame,
  ArrowRight,
  Key,
  Copy,
  Check,
} from 'lucide-react';
import {
  NebulaConnectionStatus,
  NebulaSiteGateway,
  StopAction,
  ActiveDefense,
} from '../types';
import { NebulaLiveStreamConsole } from './NebulaLiveStreamConsole';

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
  const [activeSubTab, setActiveSubTab] = useState<'live-stream' | 'site-connection' | 'multi-site'>('live-stream');
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
  const [testApiKey, setTestApiKey] = useState<string>('zyx_live_org_88412_k9f201');
  const [showApiKey, setShowApiKey] = useState<boolean>(false);
  const [authHeaderType, setAuthHeaderType] = useState<'X-Zyxel-API-Key' | 'Bearer'>('X-Zyxel-API-Key');
  const [isTestingSite, setIsTestingSite] = useState<boolean>(false);
  const [siteTestReport, setSiteTestReport] = useState<any>(null);
  const [copiedReport, setCopiedReport] = useState<boolean>(false);

  // Helper when selecting an organization
  const handleSelectOrgForTest = (orgId: string) => {
    setCustomOrgId(orgId);
    const org = statusData?.organizations?.find((o) => o.id === orgId);
    if (org && org.sites && org.sites.length > 0) {
      setCustomSiteId(org.sites[0].siteId);
      setCustomGatewayModel(org.sites[0].gatewayModel);
      if (org.openApiConnector?.apiKey) {
        setTestApiKey(org.openApiConnector.apiKey);
      }
    }
  };

  // Helper when selecting a site
  const handleSelectSiteForTest = (siteId: string) => {
    setCustomSiteId(siteId);
    const site = statusData?.sites.find((s) => s.siteId === siteId);
    if (site) {
      setCustomGatewayModel(site.gatewayModel);
      if (site.organizationId) {
        setCustomOrgId(site.organizationId);
      }
    }
  };

  // Run the comprehensive API key connectivity test
  const handleRunApiConnectivityTest = async () => {
    setIsTestingSite(true);
    try {
      const res = await fetch('/api/nebula/test-api-connectivity', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          apiUrl: customApiUrl,
          orgId: customOrgId,
          siteId: customSiteId,
          apiKey: testApiKey,
          authHeaderType,
          gatewayModel: customGatewayModel,
        }),
      });

      const data = await res.json();
      setSiteTestReport(data.testReport);
      if (res.ok && data.success) {
        setFeedbackBanner({
          type: 'success',
          text: `Connexion API validée avec succès sur ${customOrgId} / ${customSiteId} (Latence : ${data.testReport.latencyMs} ms). Clé API active et droits vérifiés !`,
        });
      } else {
        setFeedbackBanner({
          type: 'info',
          text: `Échec du test de connectivité API : ${data.testReport?.message || 'Clé API non reconnue ou accès refusé'}.`,
        });
      }
      await fetchNebulaStatus();
    } catch (err: any) {
      setFeedbackBanner({
        type: 'info',
        text: `Erreur réseau lors du test de connectivité : ${err.message}`,
      });
    } finally {
      setIsTestingSite(false);
    }
  };

  const handleCopyReport = () => {
    if (!siteTestReport) return;
    try {
      navigator.clipboard.writeText(JSON.stringify(siteTestReport, null, 2));
      setCopiedReport(true);
      setTimeout(() => setCopiedReport(false), 2000);
    } catch {
      // ignore
    }
  };

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

      {/* Sub-navigation Tabs: Live Stream / Site Connection / Multi-Site */}
      <div className="flex flex-wrap items-center gap-2.5 border-b border-slate-800 pb-3">
        <button
          type="button"
          onClick={() => setActiveSubTab('live-stream')}
          className={`flex items-center gap-2 px-4 py-2.5 rounded-2xl text-xs font-mono font-bold transition shadow-sm ${
            activeSubTab === 'live-stream'
              ? 'bg-gradient-to-r from-cyan-600 to-emerald-600 text-white shadow-cyan-950/60 border border-cyan-400/40 ring-1 ring-cyan-400/30'
              : 'bg-slate-900 text-slate-400 hover:text-white border border-slate-800'
          }`}
        >
          <Radio className="w-4 h-4 text-emerald-300 animate-pulse" />
          <span>Réception des Logs en Direct & Analyse IA</span>
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
        </button>

        <button
          type="button"
          onClick={() => setActiveSubTab('site-connection')}
          className={`flex items-center gap-2 px-4 py-2.5 rounded-2xl text-xs font-mono font-bold transition ${
            activeSubTab === 'site-connection'
              ? 'bg-cyan-950 text-cyan-300 border border-cyan-700 shadow-sm'
              : 'bg-slate-900 text-slate-400 hover:text-white border border-slate-800'
          }`}
        >
          <Key className="w-4 h-4 text-cyan-400" />
          <span>Test de Connectivité API (Validation des Clés)</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveSubTab('multi-site')}
          className={`flex items-center gap-2 px-4 py-2.5 rounded-2xl text-xs font-mono font-bold transition ${
            activeSubTab === 'multi-site'
              ? 'bg-cyan-950 text-cyan-300 border border-cyan-700 shadow-sm'
              : 'bg-slate-900 text-slate-400 hover:text-white border border-slate-800'
          }`}
        >
          <Server className="w-4 h-4 text-cyan-400" />
          <span>Passerelles & Sites Zyxel ({statusData?.sites.length || 4})</span>
        </button>
      </div>

      {/* 1. Real-Time Log Streaming & AI Analysis Console */}
      {activeSubTab === 'live-stream' && (
        <NebulaLiveStreamConsole
          activeDefenses={activeDefenses}
          onSyncWithApp={(rawLogsText, siteLabel) => {
            onPullSiteLogs(rawLogsText, siteLabel);
            setFeedbackBanner({
              type: 'success',
              text: `Flux en direct (${siteLabel}) synchronisé avec succès dans tout le SOC !`,
            });
          }}
          onNavigateToDashboard={onNavigateToDashboard}
        />
      )}

      {/* Test de Connectivité API (Validation des Clés d'API par Organisation et Site) */}
      <div className={`rounded-3xl bg-slate-900/95 border border-cyan-500/50 shadow-2xl p-6 sm:p-7 space-y-6 backdrop-blur-xl ${activeSubTab !== 'site-connection' ? 'hidden' : ''}`}>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div className="flex items-center gap-3">
            <div className="w-11 h-11 rounded-2xl bg-gradient-to-br from-cyan-950 via-slate-900 to-emerald-950 border border-cyan-600/70 flex items-center justify-center text-cyan-400 shadow-md flex-shrink-0">
              <Key className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <h3 className="text-base sm:text-lg font-bold text-white">
                  Test de Connectivité API & Validation des Clés Nebula (NCC)
                </h3>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-950 text-cyan-300 border border-cyan-800 font-semibold">
                  OpenAPI 3.1 Suite
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-950 text-emerald-300 border border-emerald-800 font-semibold">
                  Multi-Tenant & Multi-Site
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                Vérification en direct de la validité cryptographique de la clé d'API (NEBULA_API_KEY), des droits sur l'organisation et de l'accessibilité de la passerelle
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            {/* Primary Action: Exécuter le Test de Connectivité API */}
            <button
              type="button"
              onClick={handleRunApiConnectivityTest}
              disabled={isTestingSite}
              className="inline-flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 via-teal-600 to-emerald-600 hover:from-cyan-500 hover:to-emerald-500 text-white text-xs font-mono font-bold shadow-xl shadow-cyan-950/70 transition disabled:opacity-60 ring-2 ring-cyan-400/40"
              title="Tester en direct la validité de la clé d'API sur l'organisation et le site sélectionnés"
            >
              <Activity className={`w-4 h-4 ${isTestingSite ? 'animate-spin' : 'text-emerald-200'}`} />
              <span>{isTestingSite ? 'Validation en cours...' : 'Exécuter le Test de Connectivité API'}</span>
            </button>

            {/* Secondary Action: Synchroniser les Logs & Surveiller les Attaques */}
            <button
              type="button"
              onClick={() => handleSyncSiteLogsAndMonitorAttacks(customSiteId, customGatewayModel)}
              disabled={isSyncingAttacks}
              className="inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 hover:text-white text-xs font-mono font-semibold border border-slate-700 transition disabled:opacity-60"
              title="Synchroniser immédiatement les logs SecuReporter depuis ce site"
            >
              <RefreshCw className={`w-3.5 h-3.5 text-cyan-400 ${isSyncingAttacks ? 'animate-spin' : ''}`} />
              <span>{isSyncingAttacks ? 'Synchronisation...' : 'Synchroniser les Logs du Site'}</span>
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

        {/* Configuration Matrix: Organization, Site, API Key, Auth Header, Base URL */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 text-xs font-mono">
          {/* 1. Sélection de l'Organisation Zyxel Nebula */}
          <div className="space-y-1.5 p-4 rounded-2xl bg-slate-950/80 border border-slate-800 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="text-[11px] font-bold text-indigo-300 flex items-center gap-1.5">
                  <Server className="w-3.5 h-3.5 text-indigo-400" />
                  <span>Organisation Cible (ORG_ID) *</span>
                </label>
                <span className="text-[10px] text-slate-500">
                  {statusData?.organizations?.length || 1} org(s)
                </span>
              </div>
              <select
                value={customOrgId}
                onChange={(e) => handleSelectOrgForTest(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white text-xs focus:outline-none focus:ring-1 focus:ring-indigo-500 mb-1.5"
              >
                {statusData?.organizations && statusData.organizations.length > 0 ? (
                  statusData.organizations.map((org) => (
                    <option key={org.id} value={org.id}>
                      {org.name} ({org.id})
                    </option>
                  ))
                ) : (
                  <option value={customOrgId}>Nebula Enterprise SOC - Europe ({customOrgId})</option>
                )}
              </select>
            </div>
            <div className="text-[10px] text-slate-400 flex items-center justify-between pt-1 border-t border-slate-800/80">
              <span>Tenant ID : <strong className="text-white font-mono">{customOrgId}</strong></span>
              <span className="text-emerald-400 font-semibold">Licence Gold</span>
            </div>
          </div>

          {/* 2. Sélection du Site & Passerelle Zyxel */}
          <div className="space-y-1.5 p-4 rounded-2xl bg-slate-950/80 border border-slate-800 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="text-[11px] font-bold text-cyan-300 flex items-center gap-1.5">
                  <Wifi className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Site & Passerelle Cible (SITE_ID) *</span>
                </label>
                <span className="text-[10px] text-slate-500">Passerelle Zyxel</span>
              </div>
              <select
                value={customSiteId}
                onChange={(e) => handleSelectSiteForTest(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white text-xs focus:outline-none focus:ring-1 focus:ring-cyan-500 mb-1.5"
              >
                {(() => {
                  const currentOrg = statusData?.organizations?.find((o) => o.id === customOrgId);
                  const availableSites = currentOrg?.sites || statusData?.sites || [];
                  return availableSites.map((site) => (
                    <option key={site.siteId} value={site.siteId}>
                      {site.siteName} — {site.gatewayModel} ({site.siteId})
                    </option>
                  ));
                })()}
              </select>
            </div>
            <div className="text-[10px] text-slate-400 flex items-center justify-between pt-1 border-t border-slate-800/80">
              <span>Équipement : <strong className="text-cyan-300">{customGatewayModel}</strong></span>
              <span className="text-emerald-400 font-mono">Tunnel TLS Actif</span>
            </div>
          </div>

          {/* 3. Base URL OpenAPI */}
          <div className="space-y-1.5 p-4 rounded-2xl bg-slate-950/80 border border-slate-800 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="text-[11px] font-bold text-slate-300 flex items-center gap-1.5">
                  <Globe className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Point d'Entrée API (Base URL) *</span>
                </label>
                <span className="text-[10px] text-slate-500">Port 443 (HTTPS)</span>
              </div>
              <input
                type="text"
                value={customApiUrl}
                onChange={(e) => setCustomApiUrl(e.target.value)}
                placeholder="https://api.nebula.zyxel.com/v1"
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white text-xs focus:outline-none focus:ring-1 focus:ring-cyan-500"
              />
            </div>
            <div className="text-[10px] text-slate-400 flex items-center justify-between pt-1 border-t border-slate-800/80">
              <span>Protocole : <strong className="text-white">TLS 1.3 / OpenAPI 3.1</strong></span>
              <span className="text-cyan-400">Certifié Zyxel</span>
            </div>
          </div>
        </div>

        {/* Clé API Nebula & Mode d'Authentification */}
        <div className="p-4 rounded-2xl bg-slate-950/90 border border-slate-800 space-y-3 font-mono text-xs">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-2">
            <div className="flex items-center gap-2">
              <Key className="w-4 h-4 text-amber-400" />
              <label className="text-xs font-bold text-white">
                Clé d'API Nebula Control Center (NEBULA_API_KEY)
              </label>
              <span className="px-1.5 py-0.2 rounded text-[10px] bg-amber-950 text-amber-300 border border-amber-800">
                Jeton Secret
              </span>
            </div>
            <div className="flex items-center gap-2 text-[11px]">
              <span className="text-slate-400">En-tête HTTP :</span>
              <select
                value={authHeaderType}
                onChange={(e) => setAuthHeaderType(e.target.value as any)}
                className="bg-slate-900 border border-slate-700 rounded-lg px-2 py-1 text-cyan-300 text-[11px] focus:outline-none focus:ring-1 focus:ring-cyan-500"
              >
                <option value="X-Zyxel-API-Key">X-Zyxel-API-Key (Standard Nebula OpenAPI)</option>
                <option value="Bearer">Authorization: Bearer &lt;token&gt; (OAuth 2.0)</option>
              </select>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-3 items-center">
            <div className="lg:col-span-8 relative">
              <input
                type={showApiKey ? 'text' : 'password'}
                value={testApiKey}
                onChange={(e) => setTestApiKey(e.target.value)}
                placeholder="zyx_live_org_88412_k9f201..."
                className="w-full bg-slate-900 border border-slate-700 rounded-xl px-3.5 py-2.5 text-white text-xs font-mono pr-24 focus:outline-none focus:ring-1 focus:ring-amber-500"
              />
              <button
                type="button"
                onClick={() => setShowApiKey((prev) => !prev)}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] font-mono flex items-center gap-1 transition"
                title={showApiKey ? 'Masquer la clé API' : 'Afficher la clé API en clair'}
              >
                {showApiKey ? (
                  <>
                    <EyeOff className="w-3 h-3 text-amber-400" />
                    <span>Masquer</span>
                  </>
                ) : (
                  <>
                    <Eye className="w-3 h-3 text-cyan-400" />
                    <span>Afficher</span>
                  </>
                )}
              </button>
            </div>

            {/* Quick Testing Presets */}
            <div className="lg:col-span-4 flex items-center gap-1.5 flex-wrap">
              <button
                type="button"
                onClick={() => setTestApiKey('zyx_live_org_88412_k9f201')}
                className="px-2.5 py-1.5 rounded-lg bg-emerald-950/70 hover:bg-emerald-900/80 text-emerald-300 border border-emerald-800 text-[10px] transition"
                title="Charger la clé API active et valide"
              >
                ✓ Clé Active Valide
              </button>
              <button
                type="button"
                onClick={() => setTestApiKey('zyx_invalid_token_test_error_403')}
                className="px-2.5 py-1.5 rounded-lg bg-amber-950/70 hover:bg-amber-900/80 text-amber-300 border border-amber-800 text-[10px] transition"
                title="Simuler le rejet d'une clé révoquée ou invalide (Code 403 Forbidden)"
              >
                ⚠ Simuler Clé Invalide (403)
              </button>
              <button
                type="button"
                onClick={() => setTestApiKey('')}
                className="px-2.5 py-1.5 rounded-lg bg-rose-950/70 hover:bg-rose-900/80 text-rose-300 border border-rose-800 text-[10px] transition"
                title="Simuler une clé vide (Code 401 Unauthorized)"
              >
                ✕ Clé Vide (401)
              </button>
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-between text-[11px] text-slate-400 pt-1">
            <span>
              Format attendu : <code className="text-amber-300">zyx_live_&lt;scope&gt;_&lt;hash&gt;</code> • Généré dans : <em>Nebula &gt; Organization &gt; Administrators &gt; API Key</em>
            </span>
            <span className={testApiKey && testApiKey.length >= 10 ? 'text-emerald-400 font-semibold' : 'text-slate-500'}>
              {testApiKey ? `${testApiKey.length} caractères saisis` : 'Aucune clé saisie'}
            </span>
          </div>
        </div>

        {/* Detailed API Connectivity Test Report */}
        {siteTestReport && (
          <div
            className={`p-5 rounded-2xl border-2 space-y-4 animate-in fade-in transition ${
              siteTestReport.success || siteTestReport.httpStatus === 200
                ? 'bg-slate-950 border-emerald-500/70 shadow-2xl'
                : 'bg-slate-950 border-rose-600/80 shadow-2xl'
            }`}
          >
            {/* Header with Status Banner */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
              <div className="flex items-center gap-3">
                {siteTestReport.success || siteTestReport.httpStatus === 200 ? (
                  <div className="w-8 h-8 rounded-xl bg-emerald-950 text-emerald-400 border border-emerald-700 flex items-center justify-center flex-shrink-0">
                    <CheckCircle2 className="w-5 h-5" />
                  </div>
                ) : (
                  <div className="w-8 h-8 rounded-xl bg-rose-950 text-rose-400 border border-rose-700 flex items-center justify-center flex-shrink-0">
                    <AlertTriangle className="w-5 h-5 animate-pulse" />
                  </div>
                )}
                <div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <h4 className="text-sm font-bold text-white font-mono">
                      Rapport d'Audit de Connectivité API & Validation des Clés
                    </h4>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                        siteTestReport.success || siteTestReport.httpStatus === 200
                          ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                          : 'bg-rose-950 text-rose-300 border border-rose-800'
                      }`}
                    >
                      {siteTestReport.success || siteTestReport.httpStatus === 200
                        ? 'HTTP 200 OK — CLÉ VALIDE & CONNECTIVITÉ ÉTABLIE'
                        : `HTTP ${siteTestReport.httpStatus || 401} — ${
                            siteTestReport.status === 'MISSING_KEY'
                              ? 'CLÉ API MANQUANTE'
                              : 'CLÉ API REJETÉE / NON AUTORISÉE'
                          }`}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 font-mono mt-0.5">
                    {siteTestReport.message}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2 text-xs font-mono">
                <span className="text-slate-400">
                  Latence :{' '}
                  <strong
                    className={
                      siteTestReport.latencyMs < 50 ? 'text-emerald-400' : 'text-amber-400'
                    }
                  >
                    {siteTestReport.latencyMs} ms
                  </strong>
                </span>
                <span>•</span>
                <span className="text-slate-400">
                  Horodatage : <strong className="text-white">{new Date(siteTestReport.timestamp).toLocaleTimeString('fr-FR')}</strong>
                </span>
                <button
                  type="button"
                  onClick={handleCopyReport}
                  className="ml-2 inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-mono border border-slate-700 transition"
                  title="Copier le rapport complet au format JSON"
                >
                  {copiedReport ? (
                    <>
                      <Check className="w-3 h-3 text-emerald-400" />
                      <span className="text-emerald-300">Copié !</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3 h-3 text-cyan-400" />
                      <span>Copier JSON</span>
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Step-by-Step 5 Checks Matrix */}
            <div className="space-y-2">
              <span className="text-[11px] font-mono font-bold text-slate-300 uppercase tracking-wider block">
                Étapes de Vérification de la Chaîne OpenAPI :
              </span>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-2.5 text-xs font-mono">
                {siteTestReport.checks?.map((chk: any, idx: number) => {
                  const isOk = chk.status === 'SUCCESS';
                  const isWarn = chk.status === 'WARNING';
                  return (
                    <div
                      key={idx}
                      className={`p-3 rounded-xl border flex flex-col justify-between space-y-1.5 ${
                        isOk
                          ? 'bg-slate-900/90 border-slate-800'
                          : isWarn
                          ? 'bg-amber-950/30 border-amber-800/80'
                          : 'bg-rose-950/30 border-rose-800/80'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-1">
                        <span className="text-[10px] text-slate-500 font-bold">Étape {chk.step || idx + 1}</span>
                        <span
                          className={`px-1.5 py-0.2 rounded text-[9px] font-bold ${
                            isOk
                              ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                              : isWarn
                              ? 'bg-amber-950 text-amber-300 border border-amber-800'
                              : 'bg-rose-950 text-rose-300 border border-rose-800'
                          }`}
                        >
                          {chk.status}
                        </span>
                      </div>
                      <h5 className="text-[11px] font-bold text-white truncate" title={chk.name}>
                        {chk.name}
                      </h5>
                      <p className="text-[10px] text-slate-400 line-clamp-2" title={chk.details}>
                        {chk.details}
                      </p>
                      {chk.target && (
                        <span className="text-[9px] text-cyan-400 truncate font-mono block pt-1 border-t border-slate-800/60">
                          {chk.target}
                        </span>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Key Metadata & Permissions Card */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs font-mono pt-1">
              {/* Clé d'API validée */}
              <div className="p-3 rounded-xl bg-slate-900/90 border border-slate-800 space-y-1">
                <span className="text-[10px] text-slate-500 uppercase block">Clé Validée</span>
                <span className="text-amber-300 font-bold truncate block">
                  {siteTestReport.apiKeyValidation?.maskedKey || 'N/A'}
                </span>
                <span className="text-[10px] text-slate-400 block truncate">
                  {siteTestReport.apiKeyValidation?.authHeader || authHeaderType}
                </span>
              </div>

              {/* Scope & Droits */}
              <div className="p-3 rounded-xl bg-slate-900/90 border border-slate-800 space-y-1">
                <span className="text-[10px] text-slate-500 uppercase block">Portée (Scope)</span>
                <span className="text-white font-bold truncate block">
                  {siteTestReport.organization?.name || customOrgId}
                </span>
                <span className="text-[10px] text-cyan-300 block truncate">
                  {siteTestReport.apiKeyValidation?.scope || 'Admin Scope'}
                </span>
              </div>

              {/* Quota & Rate Limit */}
              <div className="p-3 rounded-xl bg-slate-900/90 border border-slate-800 space-y-1">
                <span className="text-[10px] text-slate-500 uppercase block">Quota API Restant</span>
                <span className="text-emerald-400 font-bold block">
                  {siteTestReport.apiKeyValidation?.rateLimitRemaining || 120} / {siteTestReport.apiKeyValidation?.rateLimitTotal || 120} req/min
                </span>
                <span className="text-[10px] text-slate-400 block">
                  Validité : {siteTestReport.apiKeyValidation?.expiresInDays ? `${siteTestReport.apiKeyValidation.expiresInDays}j restants` : 'Non expirée'}
                </span>
              </div>

              {/* Permissions OpenAPI */}
              <div className="p-3 rounded-xl bg-slate-900/90 border border-slate-800 space-y-1">
                <span className="text-[10px] text-slate-500 uppercase block">Droits OpenAPI</span>
                <div className="flex flex-wrap gap-1 text-[9px] pt-0.5">
                  <span className={`px-1.5 py-0.2 rounded font-bold ${siteTestReport.permissions?.readSecuReporter ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-slate-800 text-slate-400'}`}>
                    Logs SecuReporter
                  </span>
                  <span className={`px-1.5 py-0.2 rounded font-bold ${siteTestReport.permissions?.pushFirewallRules ? 'bg-cyan-950 text-cyan-300 border border-cyan-800' : 'bg-slate-800 text-slate-400'}`}>
                    Push Firewall
                  </span>
                  <span className={`px-1.5 py-0.2 rounded font-bold ${siteTestReport.permissions?.quarantineCdrHosts ? 'bg-purple-950 text-purple-300 border border-purple-800' : 'bg-slate-800 text-slate-400'}`}>
                    CDR Quarantine
                  </span>
                </div>
              </div>
            </div>

            {/* Troubleshooting Guide if test failed */}
            {siteTestReport.troubleshooting && siteTestReport.troubleshooting.length > 0 && (
              <div className="p-3.5 rounded-xl bg-rose-950/40 border border-rose-800 text-xs font-mono space-y-2">
                <div className="flex items-center gap-2 text-rose-300 font-bold">
                  <AlertTriangle className="w-4 h-4 text-rose-400" />
                  <span>Procédure de Dépannage Zyxel Nebula Control Center :</span>
                </div>
                <ol className="list-decimal list-inside space-y-1 text-slate-300 text-[11px] leading-relaxed">
                  {siteTestReport.troubleshooting.map((step: string, i: number) => (
                    <li key={i}>{step}</li>
                  ))}
                </ol>
              </div>
            )}
          </div>
        )}

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
