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
}

export const NebulaApiView: React.FC<NebulaApiViewProps> = ({
  stopActions,
  activeDefenses,
  onPullSiteLogs,
  onRulePushed,
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
      const res = await fetch('/api/nebula/pull-logs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ siteId: site.siteId }),
      });
      if (res.ok) {
        const data = await res.json();
        setFeedbackBanner({
          type: 'info',
          text: `Import API réussi depuis ${site.siteName} (${site.gatewayModel}) : analyse IA déclenchée sur les nouveaux événements SecuReporter.`,
        });
        await fetchNebulaStatus();
        onPullSiteLogs(data.rawLogs, `${site.gatewayModel} (${site.siteName})`);
      }
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
            className="inline-flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white text-xs font-mono font-bold shadow-lg shadow-emerald-950/60 transition disabled:opacity-60"
          >
            <Activity className={`w-4 h-4 ${isTestingSite ? 'animate-spin' : ''}`} />
            <span>{isTestingSite ? 'Test de Connexion en cours...' : 'Tester la Connexion au Site'}</span>
          </button>
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
            Sélectionnez un site pour importer ses logs temps réel ou déployer des règles ACL
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {statusData?.sites.map((site) => {
            const isSelected = site.siteId === selectedSiteId;
            const isTesting = testingSiteId === site.siteId;
            const isPulling = pullingSiteId === site.siteId;

            return (
              <div
                key={site.siteId}
                onClick={() => setSelectedSiteId(site.siteId)}
                className={`p-5 rounded-2xl border transition cursor-pointer space-y-4 ${
                  isSelected
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
                    className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-mono font-bold shadow-md shadow-cyan-950/50 transition"
                  >
                    <DownloadCloud className={`w-3.5 h-3.5 ${isPulling ? 'animate-bounce' : ''}`} />
                    <span>
                      {isPulling ? 'Pull SecuReporter...' : 'Importer & Analyser Logs (Pull API)'}
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
