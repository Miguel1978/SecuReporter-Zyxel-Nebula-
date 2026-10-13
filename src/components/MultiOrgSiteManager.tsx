import React, { useState, useEffect, useMemo } from 'react';
import {
  Building2,
  Server,
  Plus,
  Wifi,
  Activity,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  RefreshCw,
  Layers,
  Radio,
  X,
  Pencil,
  Trash2,
  Lock,
  Play,
  Pause,
  Zap,
  Flame,
  SlidersHorizontal,
  Terminal,
  Globe,
} from 'lucide-react';
import {
  NebulaOrganization,
  NebulaSiteGateway,
  ActiveDefense,
  StopAction,
  NebulaEnvVariablesConfig,
} from '../types';

interface LiveStreamEvent {
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
  siteName?: string;
}

interface MultiOrgSiteManagerProps {
  currentDeviceName?: string;
  activeDefenses?: ActiveDefense[];
  onSelectAndMonitorSite: (rawLogs: string, siteContextLabel: string) => void;
  onEnforceDefense?: (action: StopAction) => Promise<void>;
  onAppendLiveLog?: (rawLine: string) => void;
}

export const MultiOrgSiteManager: React.FC<MultiOrgSiteManagerProps> = ({
  currentDeviceName = '',
  activeDefenses = [],
  onSelectAndMonitorSite,
  onEnforceDefense,
  onAppendLiveLog,
}) => {
  const [organizations, setOrganizations] = useState<NebulaOrganization[]>([]);
  const [selectedOrgId, setSelectedOrgId] = useState<string>('ALL');
  const [activeMonitoredSiteId, setActiveMonitoredSiteId] = useState<string>('SITE-PARIS-ATP700');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [switchingSiteId, setSwitchingSiteId] = useState<string | null>(null);
  const [pingingSiteId, setPingingSiteId] = useState<string | null>(null);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  // Create Drawers
  const [isAddOrgOpen, setIsAddOrgOpen] = useState<boolean>(false);
  const [isAddSiteOpen, setIsAddSiteOpen] = useState<boolean>(false);

  // Edit Organization State
  const [editingOrg, setEditingOrg] = useState<NebulaOrganization | null>(null);
  const [editOrgName, setEditOrgName] = useState('');
  const [editOrgSector, setEditOrgSector] = useState('');
  const [editOrgRegion, setEditOrgRegion] = useState('');
  const [editOrgLicense, setEditOrgLicense] = useState('');
  const [isSavingOrgEdit, setIsSavingOrgEdit] = useState(false);

  // Confirm Delete Organization ID
  const [confirmDeleteOrgId, setConfirmDeleteOrgId] = useState<string | null>(null);

  // Edit Site State
  const [editingSite, setEditingSite] = useState<(NebulaSiteGateway & { orgName?: string }) | null>(
    null
  );
  const [editSiteOrgId, setEditSiteOrgId] = useState('');
  const [editSiteName, setEditSiteName] = useState('');
  const [editSiteLocation, setEditSiteLocation] = useState('');
  const [editSiteGateway, setEditSiteGateway] = useState('');
  const [editSiteWanIp, setEditSiteWanIp] = useState('');
  const [editSiteStatus, setEditSiteStatus] = useState<'ONLINE' | 'DEGRADED'>('ONLINE');
  const [editSiteCdr, setEditSiteCdr] = useState(true);
  const [editSiteIdp, setEditSiteIdp] = useState(true);
  const [isSavingSiteEdit, setIsSavingSiteEdit] = useState(false);

  // Confirm Delete Site ID
  const [confirmDeleteSiteId, setConfirmDeleteSiteId] = useState<string | null>(null);

  // New Organization form state
  const [newOrgName, setNewOrgName] = useState('');
  const [newOrgSector, setNewOrgSector] = useState('Industrie & Services Critiques');
  const [newOrgRegion, setNewOrgRegion] = useState('EU-West (Francfort / Paris)');
  const [newOrgLicense, setNewOrgLicense] = useState('MSP Enterprise Gold Pack');
  const [newOrgInitialSiteName, setNewOrgInitialSiteName] = useState('');
  const [newOrgInitialGateway, setNewOrgInitialGateway] = useState('Zyxel Nebula ATP800');
  const [newOrgInitialWanIp, setNewOrgInitialWanIp] = useState('');
  const [isSubmittingOrg, setIsSubmittingOrg] = useState(false);

  // New Site form state
  const [targetOrgForNewSite, setTargetOrgForNewSite] = useState<string>('');
  const [newSiteName, setNewSiteName] = useState('');
  const [newSiteLocation, setNewSiteLocation] = useState('');
  const [newSiteGateway, setNewSiteGateway] = useState('Zyxel Nebula ATP700');
  const [newSiteWanIp, setNewSiteWanIp] = useState('');
  const [newSiteCdr, setNewSiteCdr] = useState(true);
  const [newSiteIdp, setNewSiteIdp] = useState(true);
  const [isSubmittingSite, setIsSubmittingSite] = useState(false);

  // Live Stream & Instant Attack Blocking State
  const [isLiveStreamActive, setIsLiveStreamActive] = useState<boolean>(false);
  const [isAutoBlockEnabled, setIsAutoBlockEnabled] = useState<boolean>(false);
  const [liveEvents, setLiveEvents] = useState<LiveStreamEvent[]>([]);
  const [blockingIp, setBlockingIp] = useState<string | null>(null);

  // Environment Variables Configuration Panel State (Integrated in Dashboard)
  const [isEnvPanelOpen, setIsEnvPanelOpen] = useState<boolean>(true);
  const [envOrgId, setEnvOrgId] = useState<string>('ORG-EU-WEST-884920');
  const [envSiteId, setEnvSiteId] = useState<string>('SITE-PARIS-ATP700');
  const [envApiUrl, setEnvApiUrl] = useState<string>('https://api.nebula.zyxel.com/v1');
  const [envOrgName, setEnvOrgName] = useState<string>('Nebula Enterprise SOC - Europe');
  const [envSiteName, setEnvSiteName] = useState<string>('Branch-Paris (Siège Opérationnel)');
  const [envGatewayModel, setEnvGatewayModel] = useState<string>('Zyxel Nebula ATP800');
  const [envAutoDiscoverSites, setEnvAutoDiscoverSites] = useState<boolean>(true);
  const [isApplyingEnv, setIsApplyingEnv] = useState<boolean>(false);
  const [isTestingConn, setIsTestingConn] = useState<boolean>(false);
  const [connTestResult, setConnTestResult] = useState<any>(null);

  const fetchOrganizations = async () => {
    setIsLoading(true);
    try {
      const res = await fetch('/api/nebula/organizations');
      if (res.ok) {
        const data = await res.json();
        const orgs: NebulaOrganization[] = data.organizations || [];
        setOrganizations(orgs);
        if (!targetOrgForNewSite && orgs.length > 0) {
          setTargetOrgForNewSite(orgs[0].id);
        }
        if (data.envConfig) {
          const cfg: NebulaEnvVariablesConfig = data.envConfig;
          setEnvOrgId(cfg.ZYXEL_NEBULA_ORG_ID || 'ORG-EU-WEST-884920');
          setEnvSiteId(cfg.ZYXEL_NEBULA_SITE_ID || 'SITE-PARIS-ATP700');
          setEnvApiUrl(cfg.ZYXEL_NEBULA_API_URL || 'https://api.nebula.zyxel.com/v1');
          if (cfg.organizationName) setEnvOrgName(cfg.organizationName);
          if (cfg.siteName) setEnvSiteName(cfg.siteName);
          if (cfg.gatewayModel) setEnvGatewayModel(cfg.gatewayModel);
        }
      }
    } catch (err) {
      console.warn('Could not load Nebula organizations:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleApplyEnvVariablesAndConnect = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!envOrgId.trim() || !envSiteId.trim()) return;

    setIsApplyingEnv(true);
    try {
      const res = await fetch('/api/nebula/env-connect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ZYXEL_NEBULA_ORG_ID: envOrgId.trim(),
          ZYXEL_NEBULA_SITE_ID: envSiteId.trim(),
          ZYXEL_NEBULA_API_URL: envApiUrl.trim() || 'https://api.nebula.zyxel.com/v1',
          organizationName: envOrgName.trim() || undefined,
          siteName: envSiteName.trim() || undefined,
          gatewayModel: envGatewayModel,
          autoDiscoverMultiSites: envAutoDiscoverSites,
        }),
      });

      if (res.ok) {
        const data = await res.json();
        setOrganizations(data.organizations || []);
        const connectedOrg: NebulaOrganization = data.organization;
        const connectedSite: NebulaSiteGateway = data.site;
        setSelectedOrgId(connectedOrg.id);
        setActiveMonitoredSiteId(connectedSite.siteId);
        setStatusMessage(
          `Variables d'environnement appliquées : Organisation "${connectedOrg.name}" (${connectedOrg.id}) et Site "${connectedSite.siteName}" (${connectedSite.siteId}) connectés via ${envApiUrl.trim()}.`
        );

        await handleConnectAndMonitorSite({
          ...connectedSite,
          orgName: connectedOrg.name,
        });
      }
    } finally {
      setIsApplyingEnv(false);
    }
  };

  useEffect(() => {
    fetchOrganizations();
  }, []);

  // Live Stream Polling Effect
  useEffect(() => {
    if (!isLiveStreamActive) return;

    const pullLiveTick = async () => {
      try {
        const res = await fetch('/api/nebula/live-stream-tick', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ siteId: activeMonitoredSiteId }),
        });

        if (res.ok) {
          const data = await res.json();
          const evt: LiveStreamEvent = {
            ...data.event,
            siteName: data.siteName,
          };

          setLiveEvents((prev) => [evt, ...prev].slice(0, 10));
          onAppendLiveLog?.(evt.raw);

          // If Auto-Block IPS is enabled and the threat is CRITICAL and not yet blocked
          if (isAutoBlockEnabled && evt.severity === 'CRITICAL' && !evt.isBlocked) {
            handleInstantBlockLiveEvent(evt, true);
          }
        }
      } catch (e) {
        console.warn('Live tick failed:', e);
      }
    };

    pullLiveTick();
    const interval = setInterval(pullLiveTick, 4500);
    return () => clearInterval(interval);
  }, [isLiveStreamActive, activeMonitoredSiteId, isAutoBlockEnabled]);

  const handleInstantBlockLiveEvent = async (evt: LiveStreamEvent, isAuto = false) => {
    setBlockingIp(evt.attackerIp);
    try {
      if (onEnforceDefense) {
        const stopAction: StopAction = {
          id: `live-block-${Date.now()}`,
          title: `${isAuto ? '[Auto-IPS] ' : ''}Bloquer IP Assaillante ${evt.attackerIp}`,
          type: 'FIREWALL_BLOCK',
          target: evt.attackerIp,
          priority: 'IMMEDIATE',
          rationale: `Blocage temps réel suite à la détection de "${evt.threatName}" sur ${evt.siteName || 'Passerelle Nebula'}.`,
          zyxelNebulaRule: {
            ruleName: `LIVE_DROP_${evt.attackerIp.replace(/\./g, '_')}`,
            direction: 'WAN to LAN',
            action: 'DROP',
            sourceObject: `Host_${evt.attackerIp}`,
            destinationObject: 'Any',
          },
          zyxelCliCommand: `configure terminal\naddress-object Host_${evt.attackerIp.replace(/\./g, '_')} host ${evt.attackerIp}\nfirewall rule 1\n  name LIVE_DROP_${evt.attackerIp.replace(/\./g, '_')}\n  from WAN to Any\n  source-address Host_${evt.attackerIp.replace(/\./g, '_')}\n  action drop\nexit\nwrite memory`,
          iptablesCommand: `sudo iptables -I INPUT -s ${evt.attackerIp} -j DROP`,
          nftablesCommand: `sudo nft add rule inet filter input ip saddr ${evt.attackerIp} drop`,
          pfSenseRule: `<rule><type>block</type><source><address>${evt.attackerIp}</address></source></rule>`,
        };
        await onEnforceDefense(stopAction);
      }

      setLiveEvents((prev) =>
        prev.map((item) =>
          item.attackerIp === evt.attackerIp ? { ...item, isBlocked: true } : item
        )
      );
      setStatusMessage(
        `${isAuto ? '[Auto-IPS] ' : ''}Attaque bloquée en direct : IP ${evt.attackerIp} (${evt.threatName}) neutralisée sur la passerelle.`
      );
    } finally {
      setBlockingIp(null);
    }
  };

  // Aggregate multi-tenant metrics
  const globalStats = useMemo(() => {
    const allSites = organizations.flatMap((o) => o.sites);
    const onlineSites = allSites.filter((s) => s.status === 'ONLINE').length;
    const totalThreats24h = allSites.reduce((acc, s) => acc + (s.threatsBlocked24h || 0), 0);
    return {
      orgCount: organizations.length,
      siteCount: allSites.length,
      onlineSites,
      totalThreats24h,
    };
  }, [organizations]);

  // Visible sites based on selected organization
  const displayedSites = useMemo(() => {
    if (selectedOrgId === 'ALL') {
      return organizations.flatMap((org) =>
        org.sites.map((s) => ({ ...s, orgName: org.name, orgId: org.id }))
      );
    }
    const foundOrg = organizations.find((o) => o.id === selectedOrgId);
    if (!foundOrg) return [];
    return foundOrg.sites.map((s) => ({ ...s, orgName: foundOrg.name, orgId: foundOrg.id }));
  }, [organizations, selectedOrgId]);

  const handleConnectAndMonitorSite = async (site: NebulaSiteGateway & { orgName?: string }) => {
    setSwitchingSiteId(site.siteId);
    try {
      const res = await fetch('/api/nebula/pull-logs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ siteId: site.siteId }),
      });

      if (res.ok) {
        const data = await res.json();
        setActiveMonitoredSiteId(site.siteId);
        const contextLabel = `${site.orgName ? `${site.orgName} • ` : ''}${site.siteName} (${site.gatewayModel})`;
        setStatusMessage(
          `Surveillance active connectée sur ${contextLabel} — Flux SecuReporter synchronisé en direct.`
        );
        onSelectAndMonitorSite(data.rawLogs, contextLabel);
      }
    } finally {
      setSwitchingSiteId(null);
    }
  };

  const handlePingSite = async (site: NebulaSiteGateway) => {
    setPingingSiteId(site.siteId);
    try {
      const res = await fetch('/api/nebula/test-connection', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ siteId: site.siteId }),
      });
      if (res.ok) {
        const data = await res.json();
        setStatusMessage(
          `Heartbeat OK sur ${site.siteName} (${site.gatewayModel} • ${site.wanIp}) — Latence : ${data.latencyMs} ms.`
        );
      }
    } finally {
      setPingingSiteId(null);
    }
  };

  // Create Organization
  const handleCreateOrganization = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newOrgName.trim()) return;

    setIsSubmittingOrg(true);
    try {
      const res = await fetch('/api/nebula/organizations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: newOrgName.trim(),
          sector: newOrgSector,
          region: newOrgRegion,
          licenseTier: newOrgLicense,
          initialSiteName: newOrgInitialSiteName.trim() || `${newOrgName.trim()} - Siège Principal`,
          initialGatewayModel: newOrgInitialGateway,
          initialWanIp: newOrgInitialWanIp.trim() || undefined,
          initialLocation: newOrgRegion,
        }),
      });

      if (res.ok) {
        const data = await res.json();
        setOrganizations(data.organizations || []);
        const createdOrg: NebulaOrganization = data.organization;
        setSelectedOrgId(createdOrg.id);
        setTargetOrgForNewSite(createdOrg.id);
        setIsAddOrgOpen(false);
        setNewOrgName('');
        setNewOrgInitialSiteName('');
        setNewOrgInitialWanIp('');
        setStatusMessage(
          `Organisation "${createdOrg.name}" (${createdOrg.id}) créée et connectée au SOC Multi-Tenant.`
        );

        if (createdOrg.sites && createdOrg.sites.length > 0) {
          await handleConnectAndMonitorSite({
            ...createdOrg.sites[0],
            orgName: createdOrg.name,
          });
        }
      }
    } finally {
      setIsSubmittingOrg(false);
    }
  };

  // Open Edit Organization Drawer
  const startEditingOrganization = (org: NebulaOrganization, e: React.MouseEvent) => {
    e.stopPropagation();
    setEditingOrg(org);
    setEditOrgName(org.name);
    setEditOrgSector(org.sector);
    setEditOrgRegion(org.region);
    setEditOrgLicense(org.licenseTier);
    setEditingSite(null);
    setIsAddOrgOpen(false);
    setIsAddSiteOpen(false);
  };

  // Save Edited Organization
  const handleSaveOrganizationEdit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingOrg || !editOrgName.trim()) return;

    setIsSavingOrgEdit(true);
    try {
      const res = await fetch(`/api/nebula/organizations/${editingOrg.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: editOrgName.trim(),
          sector: editOrgSector.trim(),
          region: editOrgRegion,
          licenseTier: editOrgLicense,
        }),
      });

      if (res.ok) {
        const data = await res.json();
        setOrganizations(data.organizations || []);
        setStatusMessage(`Organisation "${editOrgName.trim()}" mise à jour avec succès.`);
        setEditingOrg(null);
      }
    } finally {
      setIsSavingOrgEdit(false);
    }
  };

  // Delete Organization
  const handleDeleteOrganization = async (orgId: string, orgName: string, e: React.MouseEvent) => {
    e.stopPropagation();
    const res = await fetch(`/api/nebula/organizations/${orgId}`, {
      method: 'DELETE',
    });
    if (res.ok) {
      const data = await res.json();
      setOrganizations(data.organizations || []);
      if (selectedOrgId === orgId) {
        setSelectedOrgId('ALL');
      }
      setConfirmDeleteOrgId(null);
      setStatusMessage(`Organisation "${orgName}" supprimée de la supervision.`);
    }
  };

  // Create Site
  const handleCreateSite = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newSiteName.trim()) return;

    setIsSubmittingSite(true);
    try {
      const orgIdToUse =
        targetOrgForNewSite ||
        (selectedOrgId !== 'ALL' ? selectedOrgId : organizations[0]?.id);

      const res = await fetch('/api/nebula/sites', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          organizationId: orgIdToUse,
          siteName: newSiteName.trim(),
          location: newSiteLocation.trim() || 'France (EU-West)',
          gatewayModel: newSiteGateway,
          wanIp: newSiteWanIp.trim() || undefined,
          cdrEnabled: newSiteCdr,
          idpEnabled: newSiteIdp,
        }),
      });

      if (res.ok) {
        const data = await res.json();
        setOrganizations(data.organizations || []);
        const createdSite: NebulaSiteGateway = data.site;
        const parentOrg: NebulaOrganization = data.organization;
        setIsAddSiteOpen(false);
        setNewSiteName('');
        setNewSiteLocation('');
        setNewSiteWanIp('');
        setStatusMessage(
          `Nouveau site "${createdSite.siteName}" (${createdSite.gatewayModel}) connecté à l'organisation ${parentOrg.name}.`
        );

        await handleConnectAndMonitorSite({
          ...createdSite,
          orgName: parentOrg.name,
        });
      }
    } finally {
      setIsSubmittingSite(false);
    }
  };

  // Open Edit Site Drawer
  const startEditingSite = (
    site: NebulaSiteGateway & { orgName?: string; orgId?: string },
    e: React.MouseEvent
  ) => {
    e.stopPropagation();
    setEditingSite(site);
    setEditSiteOrgId(site.organizationId || site.orgId || organizations[0]?.id || '');
    setEditSiteName(site.siteName);
    setEditSiteLocation(site.location);
    setEditSiteGateway(site.gatewayModel);
    setEditSiteWanIp(site.wanIp);
    setEditSiteStatus(site.status);
    setEditSiteCdr(site.cdrEnabled);
    setEditSiteIdp(site.idpEnabled);
    setEditingOrg(null);
    setIsAddOrgOpen(false);
    setIsAddSiteOpen(false);
  };

  // Save Edited Site
  const handleSaveSiteEdit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingSite || !editSiteName.trim()) return;

    setIsSavingSiteEdit(true);
    try {
      const res = await fetch(`/api/nebula/sites/${editingSite.siteId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          organizationId: editSiteOrgId,
          siteName: editSiteName.trim(),
          location: editSiteLocation.trim(),
          gatewayModel: editSiteGateway,
          wanIp: editSiteWanIp.trim(),
          status: editSiteStatus,
          cdrEnabled: editSiteCdr,
          idpEnabled: editSiteIdp,
        }),
      });

      if (res.ok) {
        const data = await res.json();
        setOrganizations(data.organizations || []);
        setStatusMessage(
          `Site "${editSiteName.trim()}" (${editSiteGateway}) mis à jour avec succès.`
        );
        setEditingSite(null);
      }
    } finally {
      setIsSavingSiteEdit(false);
    }
  };

  // Delete Site
  const handleDeleteSite = async (siteId: string, siteName: string, e: React.MouseEvent) => {
    e.stopPropagation();
    const res = await fetch(`/api/nebula/sites/${siteId}`, {
      method: 'DELETE',
    });
    if (res.ok) {
      const data = await res.json();
      setOrganizations(data.organizations || []);
      setConfirmDeleteSiteId(null);
      setStatusMessage(`Site "${siteName}" retiré et supprimé de la supervision.`);
    }
  };

  const isIpBlockedInActiveDefenses = (ip: string) => {
    return activeDefenses.some((d) => d.target === ip && d.status === 'ACTIVE');
  };

  return (
    <div className="rounded-3xl bg-slate-900/90 border border-slate-800 shadow-2xl p-6 sm:p-7 space-y-6 backdrop-blur-xl">
      {/* Top Header: Multi-Org & Multi-Site Control Center + Live Stream Toggle */}
      <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div className="flex items-center gap-3.5">
          <div className="w-11 h-11 rounded-2xl bg-gradient-to-br from-emerald-950 via-slate-900 to-cyan-950 border border-emerald-500/40 flex items-center justify-center text-emerald-400 shadow-lg shadow-emerald-950/50">
            <Building2 className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h3 className="text-base sm:text-lg font-bold text-white">
                Supervision Multi-Organisations & Multi-Sites (Zyxel Nebula MSP)
              </h3>
              <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-emerald-950 text-emerald-300 border border-emerald-700 flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />
                {globalStats.orgCount} Organisations • {globalStats.siteCount} Sites
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              Créez, éditez, supprimez et surveillez vos organisations et sites en direct avec blocage immédiat des attaques.
            </p>
          </div>
        </div>

        {/* Action Buttons: Variables d'Environnement + Live Stream + Nouvelle Organisation + Nouveau Site + Actualiser */}
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => {
              setIsEnvPanelOpen(!isEnvPanelOpen);
              setIsAddOrgOpen(false);
              setIsAddSiteOpen(false);
              setEditingOrg(null);
              setEditingSite(null);
            }}
            className={`inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-mono font-bold transition shadow-md ${
              isEnvPanelOpen
                ? 'bg-indigo-600 hover:bg-indigo-500 text-white ring-2 ring-indigo-400/50'
                : 'bg-slate-800 hover:bg-slate-700 text-indigo-300 border border-indigo-700/70'
            }`}
            title="Configurer les variables d'environnement ZYXEL_NEBULA_* pour connecter l'organisation et les sites"
          >
            <SlidersHorizontal className="w-3.5 h-3.5" />
            <span>Variables d'Environnement API</span>
          </button>

          <button
            type="button"
            onClick={() => setIsLiveStreamActive(!isLiveStreamActive)}
            className={`inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-mono font-bold transition shadow-md ${
              isLiveStreamActive
                ? 'bg-red-600 hover:bg-red-500 text-white ring-2 ring-red-400/50 animate-pulse'
                : 'bg-slate-800 hover:bg-slate-700 text-red-300 border border-red-800/70'
            }`}
            title="Analyser les logs en direct et bloquer les attaques en temps réel"
          >
            {isLiveStreamActive ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
            <span>
              {isLiveStreamActive ? 'Flux Live Actif (Stop)' : 'Analyser Logs en Direct'}
            </span>
          </button>

          <button
            type="button"
            onClick={() => {
              setIsAddOrgOpen(!isAddOrgOpen);
              setIsAddSiteOpen(false);
              setIsEnvPanelOpen(false);
              setEditingOrg(null);
              setEditingSite(null);
            }}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-mono font-bold shadow-md shadow-emerald-950/50 transition"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Nouvelle Organisation</span>
          </button>

          <button
            type="button"
            onClick={() => {
              if (selectedOrgId !== 'ALL') {
                setTargetOrgForNewSite(selectedOrgId);
              } else if (organizations[0]) {
                setTargetOrgForNewSite(organizations[0].id);
              }
              setIsAddSiteOpen(!isAddSiteOpen);
              setIsAddOrgOpen(false);
              setIsEnvPanelOpen(false);
              setEditingOrg(null);
              setEditingSite(null);
            }}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono font-bold shadow-md shadow-cyan-950/50 transition"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Ajouter un Site</span>
          </button>

          <button
            type="button"
            onClick={fetchOrganizations}
            disabled={isLoading}
            className="p-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
            title="Rafraîchir l'état des organisations et des sites"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin text-cyan-400' : ''}`} />
          </button>
        </div>
      </div>

      {/* Status Notification Banner */}
      {statusMessage && (
        <div className="p-3.5 rounded-2xl bg-emerald-950/40 border border-emerald-800/80 text-xs font-mono text-emerald-200 flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
            <span>{statusMessage}</span>
          </div>
          <button
            type="button"
            onClick={() => setStatusMessage(null)}
            className="text-slate-400 hover:text-white"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* INTEGRATED ENVIRONMENT VARIABLES & API CONNECTION PANEL IN DASHBOARD */}
      {isEnvPanelOpen && (
        <form
          onSubmit={handleApplyEnvVariablesAndConnect}
          className="p-5 rounded-2xl bg-slate-950/95 border border-indigo-500/60 space-y-4 shadow-xl"
        >
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3.5">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-xl bg-indigo-950 border border-indigo-700 flex items-center justify-center text-indigo-400">
                <Terminal className="w-4 h-4" />
              </div>
              <div>
                <div className="flex items-center gap-2 flex-wrap">
                  <h4 className="text-sm font-bold text-white font-mono">
                    Variables d'Environnement Zyxel Nebula (Connexion Organisation & Sites)
                  </h4>
                  <span className="text-[11px] font-mono text-emerald-400">
                    · Proxy Serveur Actif (/api/nebula/*)
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 font-mono">
                  Configurez vos variables <code className="text-indigo-300">ZYXEL_NEBULA_ORG_ID</code>, <code className="text-cyan-300">ZYXEL_NEBULA_SITE_ID</code> et <code className="text-emerald-300">ZYXEL_NEBULA_API_URL</code> directement dans le Dashboard pour créer et connecter automatiquement l'organisation et ses sites.
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => {
                  const randomSuffix = Math.floor(1000 + Math.random() * 8999);
                  setEnvOrgId(`ORG-NEBULA-CLOUD-${randomSuffix}`);
                  setEnvSiteId(`SITE-GW-ATP800-${randomSuffix}`);
                  setEnvOrgName(`Groupe CyberSoc Cloud #${randomSuffix}`);
                  setEnvSiteName(`Passerelle Principale #${randomSuffix}`);
                }}
                className="px-3 py-1.5 rounded-xl bg-slate-900 hover:bg-slate-800 text-indigo-300 border border-indigo-800/70 text-[11px] font-mono transition"
                title="Générer de nouveaux identifiants ORG_ID et SITE_ID pour créer une organisation et ses sites via l'API"
              >
                + Générer Nouvel ORG_ID / SITE_ID
              </button>
              <button
                type="button"
                onClick={() => setIsEnvPanelOpen(false)}
                className="text-slate-400 hover:text-white text-xs font-mono px-2 py-1"
              >
                ✕ Réduire
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
            {/* Variable 1: ZYXEL_NEBULA_ORG_ID */}
            <div className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-[11px] font-bold text-indigo-300">
                  ZYXEL_NEBULA_ORG_ID *
                </label>
                <span className="text-[10px] text-slate-500">ID Organisation</span>
              </div>
              <input
                type="text"
                required
                value={envOrgId}
                onChange={(e) => {
                  const val = e.target.value;
                  setEnvOrgId(val);
                  const existing = organizations.find((o) => o.id === val);
                  if (existing) {
                    setEnvOrgName(existing.name);
                    if (existing.sites[0]) {
                      setEnvSiteId(existing.sites[0].siteId);
                      setEnvSiteName(existing.sites[0].siteName);
                      setEnvGatewayModel(existing.sites[0].gatewayModel);
                    }
                  }
                }}
                placeholder="ex: ORG-EU-WEST-884920"
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-1 focus:ring-indigo-500"
              />
              <input
                type="text"
                value={envOrgName}
                onChange={(e) => setEnvOrgName(e.target.value)}
                placeholder="Nom de l'organisation (ex: Nebula SOC Europe)"
                className="w-full bg-slate-950/60 border border-slate-800 rounded-lg px-2.5 py-1.5 text-[11px] text-slate-300 focus:outline-none focus:ring-1 focus:ring-indigo-500"
              />
            </div>

            {/* Variable 2: ZYXEL_NEBULA_SITE_ID */}
            <div className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-[11px] font-bold text-cyan-300">
                  ZYXEL_NEBULA_SITE_ID *
                </label>
                <span className="text-[10px] text-slate-500">ID Site / Passerelle</span>
              </div>
              <input
                type="text"
                required
                value={envSiteId}
                onChange={(e) => setEnvSiteId(e.target.value)}
                placeholder="ex: SITE-PARIS-ATP700"
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-1 focus:ring-cyan-500"
              />
              <div className="grid grid-cols-2 gap-1.5">
                <input
                  type="text"
                  value={envSiteName}
                  onChange={(e) => setEnvSiteName(e.target.value)}
                  placeholder="Nom du site"
                  className="w-full bg-slate-950/60 border border-slate-800 rounded-lg px-2 py-1.5 text-[11px] text-slate-300 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                />
                <select
                  value={envGatewayModel}
                  onChange={(e) => setEnvGatewayModel(e.target.value)}
                  className="w-full bg-slate-950/60 border border-slate-800 rounded-lg px-2 py-1.5 text-[11px] text-slate-300 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                >
                  <option value="Zyxel Nebula ATP800">ATP800</option>
                  <option value="Zyxel Nebula ATP700">ATP700</option>
                  <option value="Zyxel Nebula ATP500">ATP500</option>
                  <option value="Zyxel USG FLEX 700">USG FLEX 700</option>
                  <option value="Zyxel USG FLEX 500">USG FLEX 500</option>
                </select>
              </div>
            </div>

            {/* Variable 3: ZYXEL_NEBULA_API_URL & Server Auth Status */}
            <div className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-[11px] font-bold text-emerald-300 flex items-center gap-1">
                  <Globe className="w-3 h-3" />
                  <span>ZYXEL_NEBULA_API_URL</span>
                </label>
                <span className="text-[10px] text-emerald-400">OpenAPI v1</span>
              </div>
              <input
                type="text"
                required
                value={envApiUrl}
                onChange={(e) => setEnvApiUrl(e.target.value)}
                placeholder="https://api.nebula.zyxel.com/v1"
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-1 focus:ring-emerald-500"
              />
              <div className="flex items-center justify-between px-2.5 py-1.5 rounded-lg bg-slate-950/70 border border-slate-800 text-[10px] text-slate-400">
                <span>ZYXEL_NEBULA_API_KEY :</span>
                <span className="text-emerald-400 font-semibold">
                  Gérée côté serveur (Proxy /api/nebula)
                </span>
              </div>
            </div>
          </div>

          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-1">
            <label className="inline-flex items-center gap-2 text-xs font-mono text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={envAutoDiscoverSites}
                onChange={(e) => setEnvAutoDiscoverSites(e.target.checked)}
                className="rounded border-slate-700"
              />
              <span>
                Découvrir et créer automatiquement les passerelles secondaires (HA / SD-WAN) de l'organisation via l'API
              </span>
            </label>

            <div className="flex flex-wrap items-center gap-2.5">
              <button
                type="button"
                onClick={async () => {
                  setIsTestingConn(true);
                  try {
                    const res = await fetch('/api/nebula/test-site-connection', {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify({
                        apiUrl: envApiUrl,
                        orgId: envOrgId,
                        siteId: envSiteId,
                        gatewayModel: envGatewayModel,
                      }),
                    });
                    if (res.ok) {
                      const data = await res.json();
                      setConnTestResult(data.testReport);
                      setStatusMessage(
                        `Test de connexion API réussi sur le site "${envSiteId}" (${envGatewayModel}) — Latence : ${data.testReport.latencyMs} ms • Tunnel TLS 1.3 actif.`
                      );
                    }
                  } finally {
                    setIsTestingConn(false);
                  }
                }}
                disabled={isTestingConn}
                className="inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-emerald-700 hover:bg-emerald-600 text-white text-xs font-mono font-bold shadow-lg shadow-emerald-950/60 transition disabled:opacity-60"
              >
                <Activity className={`w-4 h-4 ${isTestingConn ? 'animate-spin text-emerald-300' : ''}`} />
                <span>
                  {isTestingConn ? 'Test API en cours...' : 'Tester la Connexion au Site'}
                </span>
              </button>

              <button
                type="submit"
                disabled={isApplyingEnv}
                className="inline-flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-mono font-bold shadow-lg shadow-indigo-950/60 transition"
              >
                <Wifi className="w-4 h-4" />
                <span>
                  {isApplyingEnv
                    ? 'Synchronisation API en cours...'
                    : 'Appliquer Variables & Connecter Organisation + Sites'}
                </span>
              </button>
            </div>
          </div>

          {/* Test de connexion diagnostic report box */}
          {connTestResult && (
            <div className="p-3.5 rounded-xl bg-slate-900 border border-emerald-500/70 space-y-2.5 animate-in fade-in">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-2">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  <span className="text-xs font-bold text-white">
                    Connexion API au site « {connTestResult.siteId} » établie avec succès
                  </span>
                  <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-950 text-emerald-300 border border-emerald-800 font-bold">
                    200 OK • ONLINE
                  </span>
                </div>
                <div className="flex items-center gap-3 text-[11px] text-slate-400">
                  <span>Latence : <strong className="text-emerald-400">{connTestResult.latencyMs} ms</strong></span>
                  <span>• Chiffrement : <strong className="text-cyan-300">{connTestResult.tlsVersion}</strong></span>
                  <button
                    type="button"
                    onClick={() => setConnTestResult(null)}
                    className="text-slate-400 hover:text-white text-xs ml-1"
                  >
                    ✕
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2 text-[11px]">
                {connTestResult.checks?.map((chk: any, idx: number) => (
                  <div key={idx} className="p-2 rounded-lg bg-slate-950/80 border border-slate-800 space-y-0.5">
                    <div className="flex items-center justify-between text-slate-300 font-bold">
                      <span className="truncate">{chk.name}</span>
                      <span className="text-emerald-400 font-bold text-[10px]">OK</span>
                    </div>
                    <p className="text-[10px] text-slate-400 font-sans">{chk.details}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </form>
      )}

      {/* LIVE LOG STREAM & INSTANT ATTACK BLOCKER PANEL */}
      {isLiveStreamActive && (
        <div className="p-5 rounded-2xl bg-gradient-to-r from-red-950/30 via-slate-950 to-slate-950 border border-red-700/70 space-y-4 shadow-xl animate-in fade-in">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2.5">
              <span className="w-3 h-3 rounded-full bg-red-500 animate-ping" />
              <div>
                <h4 className="text-sm font-bold text-white font-mono flex items-center gap-2">
                  <span>Flux d'Analyse des Logs en Direct & Riposte Immédiate</span>
                  <span className="px-2 py-0.5 rounded text-[10px] bg-red-950 text-red-300 border border-red-800">
                    LIVE SOC STREAM
                  </span>
                </h4>
                <p className="text-[11px] text-slate-400 font-mono">
                  Détection en continu des tentatives d'intrusion et blocage WAN en 1 clic sur la passerelle Zyxel Nebula
                </p>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <label className="inline-flex items-center gap-2 px-3 py-1.5 rounded-xl bg-slate-900 border border-slate-700 text-xs font-mono text-slate-200 cursor-pointer">
                <input
                  type="checkbox"
                  checked={isAutoBlockEnabled}
                  onChange={(e) => setIsAutoBlockEnabled(e.target.checked)}
                  className="rounded border-slate-600"
                />
                <Zap className="w-3.5 h-3.5 text-amber-400" />
                <span>Auto-Block IPS (CRITICAL)</span>
              </label>

              <button
                type="button"
                onClick={() => setIsLiveStreamActive(false)}
                className="px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono"
              >
                Fermer Flux
              </button>
            </div>
          </div>

          <div className="space-y-2 max-h-[260px] overflow-y-auto pr-1 font-mono text-xs">
            {liveEvents.length === 0 ? (
              <div className="p-4 text-center text-slate-400">
                Écoute du flux syslog Nebula SecuReporter en cours...
              </div>
            ) : (
              liveEvents.map((evt) => {
                const blocked =
                  evt.isBlocked || isIpBlockedInActiveDefenses(evt.attackerIp);
                const isBlockingThis = blockingIp === evt.attackerIp;

                return (
                  <div
                    key={evt.id}
                    className={`p-3 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-3 transition ${
                      blocked
                        ? 'bg-emerald-950/20 border-emerald-800/60'
                        : evt.severity === 'CRITICAL'
                        ? 'bg-red-950/25 border-red-800/70'
                        : 'bg-slate-900/90 border-slate-800'
                    }`}
                  >
                    <div className="space-y-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span
                          className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${
                            evt.severity === 'CRITICAL'
                              ? 'bg-red-950 text-red-300 border border-red-800'
                              : 'bg-amber-950 text-amber-300 border border-amber-800'
                          }`}
                        >
                          {evt.severity}
                        </span>
                        <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-cyan-300">
                          {evt.category}
                        </span>
                        <span className="text-white font-bold truncate">{evt.threatName}</span>
                      </div>
                      <div className="text-[11px] text-slate-400 flex items-center gap-2 flex-wrap">
                        <span>
                          Source Hostile :{' '}
                          <strong className="text-red-400">{evt.attackerIp}</strong>
                        </span>
                        <span>→</span>
                        <span>
                          Cible : <strong className="text-cyan-300">{evt.dstIp}:{evt.dstPort}</strong>
                        </span>
                        <span className="text-slate-500">
                          ({new Date(evt.timestamp).toLocaleTimeString('fr-FR')})
                        </span>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 flex-shrink-0">
                      {blocked ? (
                        <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-emerald-950 text-emerald-300 border border-emerald-700 text-[11px] font-bold">
                          <ShieldCheck className="w-3.5 h-3.5" />
                          <span>IP Bloquée sur WAN</span>
                        </span>
                      ) : (
                        <button
                          type="button"
                          onClick={() => handleInstantBlockLiveEvent(evt, false)}
                          disabled={isBlockingThis}
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-red-600 hover:bg-red-500 text-white text-[11px] font-bold shadow-md transition"
                        >
                          <Lock className="w-3.5 h-3.5" />
                          <span>
                            {isBlockingThis ? 'Blocage...' : `Bloquer ${evt.attackerIp}`}
                          </span>
                        </button>
                      )}
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}

      {/* Drawer Form: Edit Existing Organization */}
      {editingOrg && (
        <form
          onSubmit={handleSaveOrganizationEdit}
          className="p-5 rounded-2xl bg-slate-950/95 border border-amber-600/70 space-y-4 animate-in fade-in slide-in-from-top-2"
        >
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <Pencil className="w-4 h-4 text-amber-400" />
              <h4 className="text-sm font-bold text-white font-mono">
                Éditer l'Organisation : {editingOrg.name} ({editingOrg.id})
              </h4>
            </div>
            <button
              type="button"
              onClick={() => setEditingOrg(null)}
              className="text-slate-400 hover:text-white text-xs font-mono"
            >
              ✕ Fermer
            </button>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5 text-xs font-mono">
            <div>
              <label className="block text-[11px] text-slate-400 mb-1">
                Nom de l'Organisation *
              </label>
              <input
                type="text"
                required
                value={editOrgName}
                onChange={(e) => setEditOrgName(e.target.value)}
                className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:ring-1 focus:ring-amber-500"
              />
            </div>

            <div>
              <label className="block text-[11px] text-slate-400 mb-1">Secteur d'Activité</label>
              <input
                type="text"
                value={editOrgSector}
                onChange={(e) => setEditOrgSector(e.target.value)}
                className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:ring-1 focus:ring-amber-500"
              />
            </div>

            <div>
              <label className="block text-[11px] text-slate-400 mb-1">Région Cloud Nebula</label>
              <select
                value={editOrgRegion}
                onChange={(e) => setEditOrgRegion(e.target.value)}
                className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:ring-1 focus:ring-amber-500"
              >
                <option value="EU-West (Francfort / Paris)">EU-West (Francfort / Paris)</option>
                <option value="EU-West (Lille / Marseille)">EU-West (Lille / Marseille)</option>
                <option value="EU-West (Toulouse / Roissy)">EU-West (Toulouse / Roissy)</option>
                <option value="EU-North (Dublin / Amsterdam)">EU-North (Dublin / Amsterdam)</option>
                <option value="Swiss Sovereign Cloud (Genève)">Swiss Sovereign Cloud (Genève)</option>
                <option value="US-East (Virginie)">US-East (Virginie)</option>
                <option value="APAC (Singapour / Tokyo)">APAC (Singapour / Tokyo)</option>
              </select>
            </div>

            <div>
              <label className="block text-[11px] text-slate-400 mb-1">Licence Nebula</label>
              <select
                value={editOrgLicense}
                onChange={(e) => setEditOrgLicense(e.target.value)}
                className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:ring-1 focus:ring-amber-500"
              >
                <option value="MSP Enterprise Gold Pack">MSP Enterprise Gold Pack</option>
                <option value="Nebula Pro + Zero-Trust Medical Pack">
                  Nebula Pro + Zero-Trust Medical Pack
                </option>
                <option value="MSP Critical Infrastructure Pack">
                  MSP Critical Infrastructure Pack
                </option>
                <option value="UTM Security Pack">UTM Security Pack</option>
              </select>
            </div>
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={() => setEditingOrg(null)}
              className="px-4 py-2 rounded-xl bg-slate-800 text-slate-300 text-xs font-mono"
            >
              Annuler
            </button>
            <button
              type="submit"
              disabled={isSavingOrgEdit}
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl bg-amber-600 hover:bg-amber-500 text-white text-xs font-mono font-bold shadow-lg"
            >
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>{isSavingOrgEdit ? 'Sauvegarde...' : 'Enregistrer les Modifications'}</span>
            </button>
          </div>
        </form>
      )}

      {/* Drawer Form: Edit Existing Site */}
      {editingSite && (
        <form
          onSubmit={handleSaveSiteEdit}
          className="p-5 rounded-2xl bg-slate-950/95 border border-amber-600/70 space-y-4 animate-in fade-in slide-in-from-top-2"
        >
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <Pencil className="w-4 h-4 text-amber-400" />
              <h4 className="text-sm font-bold text-white font-mono">
                Éditer le Site / Passerelle : {editingSite.siteName} ({editingSite.siteId})
              </h4>
            </div>
            <button
              type="button"
              onClick={() => setEditingSite(null)}
              className="text-slate-400 hover:text-white text-xs font-mono"
            >
              ✕ Fermer
            </button>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3.5 text-xs font-mono">
            <div>
              <label className="block text-[11px] text-slate-400 mb-1">Organisation</label>
              <select
                value={editSiteOrgId}
                onChange={(e) => setEditSiteOrgId(e.target.value)}
                className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:ring-1 focus:ring-amber-500"
              >
                {organizations.map((org) => (
                  <option key={org.id} value={org.id}>
                    {org.name}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-[11px] text-slate-400 mb-1">Nom du Site *</label>
              <input
                type="text"
                required
                value={editSiteName}
                onChange={(e) => setEditSiteName(e.target.value)}
                className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:ring-1 focus:ring-amber-500"
              />
            </div>

            <div>
              <label className="block text-[11px] text-slate-400 mb-1">Modèle Passerelle</label>
              <select
                value={editSiteGateway}
                onChange={(e) => setEditSiteGateway(e.target.value)}
                className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:ring-1 focus:ring-amber-500"
              >
                <option value="Zyxel Nebula ATP800">Zyxel Nebula ATP800</option>
                <option value="Zyxel Nebula ATP700">Zyxel Nebula ATP700</option>
                <option value="Zyxel Nebula ATP500">Zyxel Nebula ATP500</option>
                <option value="Zyxel USG FLEX 700">Zyxel USG FLEX 700</option>
                <option value="Zyxel USG FLEX 500">Zyxel USG FLEX 500</option>
                <option value="Zyxel USG FLEX 200">Zyxel USG FLEX 200</option>
              </select>
            </div>

            <div>
              <label className="block text-[11px] text-slate-400 mb-1">Localisation</label>
              <input
                type="text"
                value={editSiteLocation}
                onChange={(e) => setEditSiteLocation(e.target.value)}
                className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:ring-1 focus:ring-amber-500"
              />
            </div>

            <div>
              <label className="block text-[11px] text-slate-400 mb-1">IP WAN & Statut</label>
              <div className="flex gap-1.5">
                <input
                  type="text"
                  value={editSiteWanIp}
                  onChange={(e) => setEditSiteWanIp(e.target.value)}
                  className="w-1/2 bg-slate-900 border border-slate-800 rounded-xl px-2.5 py-2 text-white focus:outline-none focus:ring-1 focus:ring-amber-500"
                />
                <select
                  value={editSiteStatus}
                  onChange={(e) =>
                    setEditSiteStatus(e.target.value as 'ONLINE' | 'DEGRADED')
                  }
                  className="w-1/2 bg-slate-900 border border-slate-800 rounded-xl px-2 py-2 text-white focus:outline-none focus:ring-1 focus:ring-amber-500"
                >
                  <option value="ONLINE">ONLINE</option>
                  <option value="DEGRADED">DEGRADED</option>
                </select>
              </div>
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
            <div className="flex items-center gap-4 text-xs font-mono text-slate-300">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={editSiteIdp}
                  onChange={(e) => setEditSiteIdp(e.target.checked)}
                />
                <span>IDP/IPS Actif</span>
              </label>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={editSiteCdr}
                  onChange={(e) => setEditSiteCdr(e.target.checked)}
                />
                <span>Quarantaine Auto CDR Active</span>
              </label>
            </div>

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setEditingSite(null)}
                className="px-4 py-2 rounded-xl bg-slate-800 text-slate-300 text-xs font-mono"
              >
                Annuler
              </button>
              <button
                type="submit"
                disabled={isSavingSiteEdit}
                className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl bg-amber-600 hover:bg-amber-500 text-white text-xs font-mono font-bold shadow-lg"
              >
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>{isSavingSiteEdit ? 'Sauvegarde...' : 'Enregistrer le Site'}</span>
              </button>
            </div>
          </div>
        </form>
      )}

      {/* Drawer Form 1: Create & Connect a New Organization */}
      {isAddOrgOpen && (
        <form
          onSubmit={handleCreateOrganization}
          className="p-5 rounded-2xl bg-slate-950/90 border border-emerald-700/60 space-y-4 animate-in fade-in slide-in-from-top-2"
        >
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <Building2 className="w-4 h-4 text-emerald-400" />
              <h4 className="text-sm font-bold text-white font-mono">
                Créer & Connecter une Nouvelle Organisation Nebula Cloud
              </h4>
            </div>
            <button
              type="button"
              onClick={() => setIsAddOrgOpen(false)}
              className="text-slate-400 hover:text-white text-xs font-mono"
            >
              ✕ Fermer
            </button>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3.5 text-xs font-mono">
            <div>
              <label className="block text-[11px] text-slate-400 mb-1">
                Nom de l'Organisation *
              </label>
              <input
                type="text"
                required
                placeholder="ex: Groupe Industriel AeroTech"
                value={newOrgName}
                onChange={(e) => setNewOrgName(e.target.value)}
                className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:ring-1 focus:ring-emerald-500"
              />
            </div>

            <div>
              <label className="block text-[11px] text-slate-400 mb-1">Secteur d'Activité</label>
              <input
                type="text"
                placeholder="ex: Banque, Santé, Industrie..."
                value={newOrgSector}
                onChange={(e) => setNewOrgSector(e.target.value)}
                className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:ring-1 focus:ring-emerald-500"
              />
            </div>

            <div>
              <label className="block text-[11px] text-slate-400 mb-1">Région Cloud Nebula</label>
              <select
                value={newOrgRegion}
                onChange={(e) => setNewOrgRegion(e.target.value)}
                className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:ring-1 focus:ring-emerald-500"
              >
                <option value="EU-West (Francfort / Paris)">EU-West (Francfort / Paris)</option>
                <option value="EU-North (Dublin / Amsterdam)">EU-North (Dublin / Amsterdam)</option>
                <option value="Swiss Sovereign Cloud (Genève)">Swiss Sovereign Cloud (Genève)</option>
                <option value="US-East (Virginie)">US-East (Virginie)</option>
                <option value="APAC (Singapour / Tokyo)">APAC (Singapour / Tokyo)</option>
              </select>
            </div>

            <div>
              <label className="block text-[11px] text-slate-400 mb-1">
                Nom du 1er Site à Connecter
              </label>
              <input
                type="text"
                placeholder="ex: Siège-Social-Paris"
                value={newOrgInitialSiteName}
                onChange={(e) => setNewOrgInitialSiteName(e.target.value)}
                className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:ring-1 focus:ring-emerald-500"
              />
            </div>

            <div>
              <label className="block text-[11px] text-slate-400 mb-1">
                Passerelle Zyxel du Site
              </label>
              <select
                value={newOrgInitialGateway}
                onChange={(e) => setNewOrgInitialGateway(e.target.value)}
                className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:ring-1 focus:ring-emerald-500"
              >
                <option value="Zyxel Nebula ATP800">Zyxel Nebula ATP800</option>
                <option value="Zyxel Nebula ATP700">Zyxel Nebula ATP700</option>
                <option value="Zyxel Nebula ATP500">Zyxel Nebula ATP500</option>
                <option value="Zyxel USG FLEX 700">Zyxel USG FLEX 700</option>
                <option value="Zyxel USG FLEX 500">Zyxel USG FLEX 500</option>
                <option value="Zyxel USG FLEX 200">Zyxel USG FLEX 200</option>
              </select>
            </div>

            <div>
              <label className="block text-[11px] text-slate-400 mb-1">
                IP WAN Publique (Optionnel)
              </label>
              <input
                type="text"
                placeholder="ex: 185.110.42.18 (auto si vide)"
                value={newOrgInitialWanIp}
                onChange={(e) => setNewOrgInitialWanIp(e.target.value)}
                className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:ring-1 focus:ring-emerald-500"
              />
            </div>
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={() => setIsAddOrgOpen(false)}
              className="px-4 py-2 rounded-xl bg-slate-800 text-slate-300 text-xs font-mono"
            >
              Annuler
            </button>
            <button
              type="submit"
              disabled={isSubmittingOrg}
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-mono font-bold shadow-lg"
            >
              <Wifi className="w-3.5 h-3.5" />
              <span>
                {isSubmittingOrg
                  ? 'Connexion NCC...'
                  : 'Créer, Connecter & Surveiller l\'Organisation'}
              </span>
            </button>
          </div>
        </form>
      )}

      {/* Drawer Form 2: Add & Connect a New Site / Gateway */}
      {isAddSiteOpen && (
        <form
          onSubmit={handleCreateSite}
          className="p-5 rounded-2xl bg-slate-950/90 border border-cyan-700/60 space-y-4 animate-in fade-in slide-in-from-top-2"
        >
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <Server className="w-4 h-4 text-cyan-400" />
              <h4 className="text-sm font-bold text-white font-mono">
                Ajouter & Connecter un Nouveau Site / Passerelle Zyxel Nebula
              </h4>
            </div>
            <button
              type="button"
              onClick={() => setIsAddSiteOpen(false)}
              className="text-slate-400 hover:text-white text-xs font-mono"
            >
              ✕ Fermer
            </button>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5 text-xs font-mono">
            <div>
              <label className="block text-[11px] text-slate-400 mb-1">
                Organisation de Rattachement *
              </label>
              <select
                value={targetOrgForNewSite}
                onChange={(e) => setTargetOrgForNewSite(e.target.value)}
                className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:ring-1 focus:ring-cyan-500"
              >
                {organizations.map((org) => (
                  <option key={org.id} value={org.id}>
                    {org.name} ({org.sites.length} sites)
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-[11px] text-slate-400 mb-1">Nom du Site *</label>
              <input
                type="text"
                required
                placeholder="ex: Agence-Nantes-Ouest"
                value={newSiteName}
                onChange={(e) => setNewSiteName(e.target.value)}
                className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:ring-1 focus:ring-cyan-500"
              />
            </div>

            <div>
              <label className="block text-[11px] text-slate-400 mb-1">
                Modèle de Passerelle Zyxel
              </label>
              <select
                value={newSiteGateway}
                onChange={(e) => setNewSiteGateway(e.target.value)}
                className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:ring-1 focus:ring-cyan-500"
              >
                <option value="Zyxel Nebula ATP800">Zyxel Nebula ATP800</option>
                <option value="Zyxel Nebula ATP700">Zyxel Nebula ATP700</option>
                <option value="Zyxel Nebula ATP500">Zyxel Nebula ATP500</option>
                <option value="Zyxel USG FLEX 700">Zyxel USG FLEX 700</option>
                <option value="Zyxel USG FLEX 500">Zyxel USG FLEX 500</option>
                <option value="Zyxel USG FLEX 200">Zyxel USG FLEX 200</option>
              </select>
            </div>

            <div>
              <label className="block text-[11px] text-slate-400 mb-1">
                Ville / Localisation & IP WAN
              </label>
              <div className="flex gap-2">
                <input
                  type="text"
                  placeholder="ex: Nantes, FR"
                  value={newSiteLocation}
                  onChange={(e) => setNewSiteLocation(e.target.value)}
                  className="w-1/2 bg-slate-900 border border-slate-800 rounded-xl px-2.5 py-2 text-white focus:outline-none focus:ring-1 focus:ring-cyan-500"
                />
                <input
                  type="text"
                  placeholder="IP WAN (auto)"
                  value={newSiteWanIp}
                  onChange={(e) => setNewSiteWanIp(e.target.value)}
                  className="w-1/2 bg-slate-900 border border-slate-800 rounded-xl px-2.5 py-2 text-white focus:outline-none focus:ring-1 focus:ring-cyan-500"
                />
              </div>
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
            <div className="flex items-center gap-4 text-xs font-mono text-slate-300">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={newSiteIdp}
                  onChange={(e) => setNewSiteIdp(e.target.checked)}
                  className="rounded border-slate-700"
                />
                <span>Activer IDP/IPS Deep Inspection</span>
              </label>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={newSiteCdr}
                  onChange={(e) => setNewSiteCdr(e.target.checked)}
                  className="rounded border-slate-700"
                />
                <span>Activer Quarantaine Auto CDR</span>
              </label>
            </div>

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setIsAddSiteOpen(false)}
                className="px-4 py-2 rounded-xl bg-slate-800 text-slate-300 text-xs font-mono"
              >
                Annuler
              </button>
              <button
                type="submit"
                disabled={isSubmittingSite}
                className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono font-bold shadow-lg"
              >
                <Wifi className="w-3.5 h-3.5" />
                <span>
                  {isSubmittingSite ? 'Synchronisation...' : 'Connecter & Surveiller ce Site'}
                </span>
              </button>
            </div>
          </div>
        </form>
      )}

      {/* Organizations Selector Strip (with Edit & Delete buttons) */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
            <Layers className="w-4 h-4 text-emerald-400" />
            <span>Organisations Connectées ({organizations.length})</span>
          </span>

          <button
            type="button"
            onClick={() => setSelectedOrgId('ALL')}
            className={`px-3 py-1 rounded-xl text-xs font-mono transition border ${
              selectedOrgId === 'ALL'
                ? 'bg-cyan-950 text-cyan-300 border-cyan-700 font-bold'
                : 'bg-slate-950 text-slate-400 hover:text-white border-slate-800'
            }`}
          >
            Vue Consolidée : Toutes les Organisations ({globalStats.siteCount} sites)
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5">
          {organizations.map((org) => {
            const isSelected = selectedOrgId === org.id;
            const isConfirmingDelete = confirmDeleteOrgId === org.id;
            const totalOrgThreats = org.sites.reduce(
              (acc, s) => acc + (s.threatsBlocked24h || 0),
              0
            );

            return (
              <div
                key={org.id}
                onClick={() => setSelectedOrgId(isSelected ? 'ALL' : org.id)}
                className={`p-4 rounded-2xl border transition cursor-pointer flex flex-col justify-between gap-3 ${
                  isSelected
                    ? 'bg-slate-950 border-emerald-500/80 ring-1 ring-emerald-500/40 shadow-lg'
                    : 'bg-slate-950/60 border-slate-800/90 hover:border-slate-700'
                }`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span
                        className={`w-2 h-2 rounded-full flex-shrink-0 ${
                          org.avgRiskScore >= 85
                            ? 'bg-red-500 animate-ping'
                            : 'bg-emerald-400'
                        }`}
                      />
                      <h4 className="text-sm font-bold text-white truncate" title={org.name}>
                        {org.name}
                      </h4>
                    </div>
                    <p className="text-[11px] font-mono text-slate-400 truncate mt-0.5">
                      {org.sector} • {org.region}
                    </p>
                  </div>

                  {/* Edit & Delete Organization Controls */}
                  <div className="flex items-center gap-1 flex-shrink-0">
                    <button
                      type="button"
                      onClick={(e) => startEditingOrganization(org, e)}
                      className="p-1.5 rounded-lg bg-slate-900 hover:bg-amber-950/80 text-slate-400 hover:text-amber-300 border border-slate-800 hover:border-amber-700 transition"
                      title="Éditer cette organisation"
                    >
                      <Pencil className="w-3.5 h-3.5" />
                    </button>
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        setConfirmDeleteOrgId(isConfirmingDelete ? null : org.id);
                      }}
                      className="p-1.5 rounded-lg bg-slate-900 hover:bg-red-950/80 text-slate-400 hover:text-red-300 border border-slate-800 hover:border-red-700 transition"
                      title="Effacer / Supprimer cette organisation"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>

                {/* Inline Delete Confirmation */}
                {isConfirmingDelete && (
                  <div
                    onClick={(e) => e.stopPropagation()}
                    className="p-2.5 rounded-xl bg-red-950/60 border border-red-700 flex items-center justify-between gap-2 text-[11px] font-mono"
                  >
                    <span className="text-red-200">Supprimer l'organisation ?</span>
                    <div className="flex items-center gap-1.5">
                      <button
                        type="button"
                        onClick={(e) => handleDeleteOrganization(org.id, org.name, e)}
                        className="px-2 py-0.5 rounded bg-red-600 hover:bg-red-500 text-white font-bold"
                      >
                        Confirmer
                      </button>
                      <button
                        type="button"
                        onClick={() => setConfirmDeleteOrgId(null)}
                        className="px-2 py-0.5 rounded bg-slate-800 text-slate-300"
                      >
                        Annuler
                      </button>
                    </div>
                  </div>
                )}

                <div className="grid grid-cols-3 gap-2 pt-2 border-t border-slate-800/80 text-[11px] font-mono">
                  <div>
                    <span className="text-slate-500 block text-[10px]">Sites</span>
                    <strong className="text-white">{org.sites.length} passerelles</strong>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[10px]">Menaces 24h</span>
                    <strong className="text-amber-400">{totalOrgThreats}</strong>
                  </div>
                  <div className="text-right">
                    <span className="text-slate-500 block text-[10px]">Risque Moy.</span>
                    <strong
                      className={
                        org.avgRiskScore >= 85 ? 'text-red-400' : 'text-emerald-400'
                      }
                    >
                      {org.avgRiskScore}/100
                    </strong>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Sites & Gateways Monitoring Grid (with Edit & Delete buttons) */}
      <div className="space-y-3 pt-2 border-t border-slate-800/80">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <span className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
            <Server className="w-4 h-4 text-cyan-400" />
            <span>
              Passerelles & Sites Surveillés ({displayedSites.length})
              {selectedOrgId !== 'ALL' &&
                ` — ${organizations.find((o) => o.id === selectedOrgId)?.name}`}
            </span>
          </span>
          <span className="text-[11px] font-mono text-slate-400">
            Éditez, supprimez ou cliquez sur « Surveiller en Direct » pour analyser les logs d'un site
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3.5">
          {displayedSites.map((site) => {
            const isMonitored =
              activeMonitoredSiteId === site.siteId ||
              (currentDeviceName && currentDeviceName.includes(site.siteName));
            const isSwitching = switchingSiteId === site.siteId;
            const isPinging = pingingSiteId === site.siteId;
            const isConfirmingSiteDelete = confirmDeleteSiteId === site.siteId;

            return (
              <div
                key={site.siteId}
                className={`p-4 rounded-2xl border transition flex flex-col justify-between gap-3 ${
                  isMonitored
                    ? 'bg-cyan-950/25 border-cyan-500/80 ring-1 ring-cyan-500/40 shadow-lg'
                    : 'bg-slate-950/70 border-slate-800/90 hover:border-slate-700'
                }`}
              >
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[10px] font-mono text-emerald-400 truncate font-semibold">
                      {site.orgName}
                    </span>

                    <div className="flex items-center gap-1 flex-shrink-0">
                      <span
                        className={`px-1.5 py-0.2 rounded text-[9px] font-mono font-bold ${
                          site.status === 'ONLINE'
                            ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                            : 'bg-amber-950 text-amber-300 border border-amber-800'
                        }`}
                      >
                        {site.status}
                      </span>

                      <button
                        type="button"
                        onClick={(e) => startEditingSite(site, e)}
                        className="p-1 rounded bg-slate-900 hover:bg-amber-950/80 text-slate-400 hover:text-amber-300 border border-slate-800 transition"
                        title="Éditer ce site / passerelle"
                      >
                        <Pencil className="w-3 h-3" />
                      </button>

                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          setConfirmDeleteSiteId(
                            isConfirmingSiteDelete ? null : site.siteId
                          );
                        }}
                        className="p-1 rounded bg-slate-900 hover:bg-red-950/80 text-slate-400 hover:text-red-300 border border-slate-800 transition"
                        title="Effacer / Supprimer ce site"
                      >
                        <Trash2 className="w-3 h-3" />
                      </button>
                    </div>
                  </div>

                  <h5 className="text-xs font-bold text-white truncate" title={site.siteName}>
                    {site.siteName}
                  </h5>

                  <p className="text-[11px] font-mono text-cyan-300 truncate">
                    {site.gatewayModel} • {site.wanIp}
                  </p>
                </div>

                {/* Inline Site Delete Confirmation */}
                {isConfirmingSiteDelete && (
                  <div className="p-2 rounded-xl bg-red-950/60 border border-red-700 flex items-center justify-between gap-2 text-[10px] font-mono">
                    <span className="text-red-200">Effacer ce site ?</span>
                    <div className="flex items-center gap-1">
                      <button
                        type="button"
                        onClick={(e) => handleDeleteSite(site.siteId, site.siteName, e)}
                        className="px-2 py-0.5 rounded bg-red-600 hover:bg-red-500 text-white font-bold"
                      >
                        Oui
                      </button>
                      <button
                        type="button"
                        onClick={() => setConfirmDeleteSiteId(null)}
                        className="px-2 py-0.5 rounded bg-slate-800 text-slate-300"
                      >
                        Non
                      </button>
                    </div>
                  </div>
                )}

                {/* Mini Telemetry */}
                <div className="grid grid-cols-3 gap-1.5 p-2 rounded-xl bg-slate-900/90 border border-slate-800/80 text-[10px] font-mono">
                  <div>
                    <span className="text-slate-500 block">CPU</span>
                    <strong className={site.cpuUsage > 70 ? 'text-amber-400' : 'text-white'}>
                      {site.cpuUsage}%
                    </strong>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Sessions</span>
                    <strong className="text-cyan-300">{site.activeSessions}</strong>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Alertes</span>
                    <strong className="text-red-400">{site.threatsBlocked24h}</strong>
                  </div>
                </div>

                {/* Connect & Monitor Action */}
                <div className="flex items-center gap-1.5 pt-1">
                  <button
                    type="button"
                    onClick={() => handlePingSite(site)}
                    disabled={isPinging}
                    className="p-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 transition"
                    title="Tester le heartbeat de la passerelle"
                  >
                    <Activity
                      className={`w-3.5 h-3.5 text-emerald-400 ${
                        isPinging ? 'animate-spin' : ''
                      }`}
                    />
                  </button>

                  <button
                    type="button"
                    onClick={() => handleConnectAndMonitorSite(site)}
                    disabled={isSwitching}
                    className={`flex-1 inline-flex items-center justify-center gap-1.5 px-3 py-2 rounded-xl text-[11px] font-mono font-bold transition ${
                      isMonitored
                        ? 'bg-emerald-950/90 text-emerald-300 border border-emerald-700'
                        : 'bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white shadow-sm'
                    }`}
                  >
                    <Radio className={`w-3 h-3 ${isSwitching || isMonitored ? 'animate-pulse' : ''}`} />
                    <span>
                      {isSwitching
                        ? 'Connexion...'
                        : isMonitored
                        ? 'Site Surveillé'
                        : 'Surveiller en Direct'}
                    </span>
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
