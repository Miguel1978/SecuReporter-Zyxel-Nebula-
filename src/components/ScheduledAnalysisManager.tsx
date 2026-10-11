import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  Clock,
  CalendarClock,
  Play,
  Pause,
  Plus,
  Trash2,
  Edit3,
  CheckCircle2,
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  RefreshCw,
  Zap,
  Server,
  Building2,
  Bell,
  History,
  Terminal,
  Sliders,
  Check,
  X,
  Timer,
  ArrowUpRight,
} from 'lucide-react';
import {
  ScheduleFrequency,
  ScheduledAnalysisJob,
  ScheduledRunLog,
  NebulaOrganization,
  NebulaSiteGateway,
} from '../types';

interface ScheduledAnalysisManagerProps {
  onSelectSiteLogs?: (rawLogs: string, siteLabel: string) => void;
  onDefenseApplied?: () => void;
}

const FREQUENCY_OPTIONS: {
  value: ScheduleFrequency;
  label: string;
  shortDesc: string;
  cronPreview: string;
}[] = [
  {
    value: 'HOURLY',
    label: 'Toutes les heures',
    shortDesc: 'Exécution continue à chaque heure pile (24x / jour)',
    cronPreview: '0 * * * *',
  },
  {
    value: 'DAILY',
    label: 'Tous les jours',
    shortDesc: 'Audit quotidien complet à heure fixe',
    cronPreview: '0 HH * * *',
  },
  {
    value: '15_MIN',
    label: 'Toutes les 15 min',
    shortDesc: 'Haute fréquence pour passerelles critiques',
    cronPreview: '*/15 * * * *',
  },
  {
    value: 'EVERY_6H',
    label: 'Toutes les 6 heures',
    shortDesc: '4 analyses complètes par tranche de 24h',
    cronPreview: '0 */6 * * *',
  },
  {
    value: 'WEEKLY',
    label: 'Hebdomadaire',
    shortDesc: 'Consolidation hebdomadaire chaque lundi',
    cronPreview: '0 HH * * 1',
  },
];

const formatFrequencyLabel = (freq: ScheduleFrequency, preferredTime = '06:00'): string => {
  switch (freq) {
    case '15_MIN':
      return 'Toutes les 15 minutes';
    case 'HOURLY':
      return 'Toutes les heures';
    case 'EVERY_6H':
      return 'Toutes les 6 heures';
    case 'DAILY':
      return `Tous les jours à ${preferredTime}`;
    case 'WEEKLY':
      return `Chaque lundi à ${preferredTime}`;
    default:
      return 'Toutes les heures';
  }
};

const formatRelativeTime = (isoString: string | null): string => {
  if (!isoString) return 'Jamais exécuté';
  const diffSec = Math.round((new Date(isoString).getTime() - Date.now()) / 1000);
  const absSec = Math.abs(diffSec);

  if (absSec < 60) {
    return diffSec >= 0 ? `dans ${absSec}s` : `il y a ${absSec}s`;
  }
  const mins = Math.round(absSec / 60);
  if (mins < 60) {
    return diffSec >= 0 ? `dans ${mins} min` : `il y a ${mins} min`;
  }
  const hours = Math.floor(mins / 60);
  const remMins = mins % 60;
  if (hours < 24) {
    return diffSec >= 0
      ? `dans ${hours}h${remMins > 0 ? ` ${remMins}m` : ''}`
      : `il y a ${hours}h${remMins > 0 ? ` ${remMins}m` : ''}`;
  }
  const days = Math.floor(hours / 24);
  return diffSec >= 0 ? `dans ${days}j` : `il y a ${days}j`;
};

export const ScheduledAnalysisManager: React.FC<ScheduledAnalysisManagerProps> = ({
  onSelectSiteLogs,
  onDefenseApplied,
}) => {
  const [schedules, setSchedules] = useState<ScheduledAnalysisJob[]>([]);
  const [runLogs, setRunLogs] = useState<ScheduledRunLog[]>([]);
  const [organizations, setOrganizations] = useState<NebulaOrganization[]>([]);
  const [allSites, setAllSites] = useState<NebulaSiteGateway[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [runningJobId, setRunningJobId] = useState<string | null>(null);
  const [feedbackBanner, setFeedbackBanner] = useState<{
    type: 'success' | 'warning';
    text: string;
  } | null>(null);

  // Live continuous daemon simulation toggle (triggers an automatic scheduled cycle every 30s when activated)
  const [liveDaemonSimActive, setLiveDaemonSimActive] = useState<boolean>(false);
  const [daemonCountdownSec, setDaemonCountdownSec] = useState<number>(30);
  const schedulesRef = useRef<ScheduledAnalysisJob[]>([]);
  schedulesRef.current = schedules;

  // Create / Edit Form State
  const [isFormOpen, setIsFormOpen] = useState<boolean>(false);
  const [editingJobId, setEditingJobId] = useState<string | null>(null);
  const [formName, setFormName] = useState<string>('');
  const [formSiteId, setFormSiteId] = useState<string>('site-paris-hq');
  const [formFrequency, setFormFrequency] = useState<ScheduleFrequency>('HOURLY');
  const [formPreferredTime, setFormPreferredTime] = useState<string>('06:00');
  const [formAutoEnforce, setFormAutoEnforce] = useState<boolean>(true);
  const [formThresholdScore, setFormThresholdScore] = useState<number>(70);
  const [formNotifyDesktop, setFormNotifyDesktop] = useState<boolean>(true);
  const [isSavingForm, setIsSavingForm] = useState<boolean>(false);

  // Filter state
  const [frequencyFilter, setFrequencyFilter] = useState<'ALL' | 'HOURLY' | 'DAILY' | 'FAST'>('ALL');

  const showBanner = (text: string, type: 'success' | 'warning' = 'success') => {
    setFeedbackBanner({ text, type });
    setTimeout(() => setFeedbackBanner(null), 5000);
  };

  const fetchSchedulerData = useCallback(async () => {
    try {
      const [schedRes, nebulaRes] = await Promise.all([
        fetch('/api/schedules'),
        fetch('/api/nebula/status'),
      ]);

      if (schedRes.ok) {
        const data = await schedRes.json();
        setSchedules(data.schedules || []);
        setRunLogs(data.runLogs || []);
      }

      if (nebulaRes.ok) {
        const nebData = await nebulaRes.json();
        const orgs: NebulaOrganization[] = nebData.organizations || [];
        const sites: NebulaSiteGateway[] = nebData.sites || [];
        setOrganizations(orgs);
        setAllSites(sites);
        if (sites.length > 0 && !formSiteId) {
          setFormSiteId(sites[0].siteId);
        }
      }
    } catch (err) {
      console.error('Error loading scheduler data:', err);
    } finally {
      setIsLoading(false);
    }
  }, [formSiteId]);

  useEffect(() => {
    fetchSchedulerData();
  }, [fetchSchedulerData]);

  // Execute a schedule job right now (manual or daemon-triggered)
  const handleRunScheduleNow = useCallback(
    async (
      job: ScheduledAnalysisJob,
      triggerType: 'MANUAL_FORCE' | 'CONTINUOUS_DAEMON' = 'MANUAL_FORCE',
      syncToDashboard = true
    ) => {
      setRunningJobId(job.id);
      try {
        const res = await fetch(`/api/schedules/${job.id}/run-now`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ triggerType }),
        });

        if (res.ok) {
          const data = await res.json();
          await fetchSchedulerData();

          if (data.autoEnforcedDefenses && data.autoEnforcedDefenses.length > 0 && onDefenseApplied) {
            onDefenseApplied();
          }

          if (syncToDashboard && data.rawLogs && onSelectSiteLogs) {
            onSelectSiteLogs(
              data.rawLogs,
              `${job.siteName} (${job.gatewayModel}) [Scan Planifié]`
            );
          }

          const blockedText =
            data.autoEnforcedDefenses?.length > 0
              ? ` · ${data.autoEnforcedDefenses.length} règle(s) pare-feu déployée(s)`
              : '';

          showBanner(
            `Analyse planifiée exécutée sur ${job.siteName} — Score de risque : ${data.analysis?.riskScore}/100${blockedText}`,
            data.analysis?.riskScore >= job.alertThresholdScore ? 'warning' : 'success'
          );
        }
      } catch (err) {
        console.error('Failed to run schedule:', err);
      } finally {
        setRunningJobId(null);
      }
    },
    [fetchSchedulerData, onDefenseApplied, onSelectSiteLogs]
  );

  // Continuous surveillance daemon timer (when live simulation is enabled)
  useEffect(() => {
    if (!liveDaemonSimActive) {
      setDaemonCountdownSec(30);
      return;
    }

    const timer = setInterval(() => {
      setDaemonCountdownSec((prev) => {
        if (prev <= 1) {
          const enabledJobs = schedulesRef.current.filter((j) => j.enabled);
          if (enabledJobs.length > 0) {
            const randomJob = enabledJobs[Math.floor(Math.random() * enabledJobs.length)];
            handleRunScheduleNow(randomJob, 'CONTINUOUS_DAEMON', true);
          }
          return 30;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, [liveDaemonSimActive, handleRunScheduleNow]);

  // Open form for creating a new schedule
  const openCreateForm = (presetFrequency?: ScheduleFrequency) => {
    setEditingJobId(null);
    const freq = presetFrequency || 'HOURLY';
    setFormFrequency(freq);
    const defaultSite = allSites[0]?.siteId || 'site-paris-hq';
    const siteObj = allSites.find((s) => s.siteId === defaultSite);
    setFormSiteId(defaultSite);
    setFormPreferredTime('06:00');
    setFormName(
      freq === 'HOURLY'
        ? `Surveillance Horaire Continue — ${siteObj?.siteName || 'Passerelle Nebula'}`
        : freq === 'DAILY'
        ? `Audit Quotidien Complet — ${siteObj?.siteName || 'Passerelle Nebula'}`
        : `Scan Automatique (${formatFrequencyLabel(freq)}) — ${siteObj?.siteName || 'Passerelle Nebula'}`
    );
    setFormAutoEnforce(true);
    setFormThresholdScore(70);
    setFormNotifyDesktop(true);
    setIsFormOpen(true);
  };

  // Open form for editing an existing schedule
  const openEditForm = (job: ScheduledAnalysisJob) => {
    setEditingJobId(job.id);
    setFormName(job.name);
    setFormSiteId(job.siteId);
    setFormFrequency(job.frequency);
    setFormPreferredTime(job.preferredTime || '06:00');
    setFormAutoEnforce(job.autoEnforceFirewall);
    setFormThresholdScore(job.alertThresholdScore);
    setFormNotifyDesktop(job.notifyDesktop);
    setIsFormOpen(true);
  };

  // Save (Create or Update) schedule
  const handleSaveSchedule = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSavingForm(true);
    try {
      const payload = {
        name: formName.trim(),
        siteId: formSiteId,
        frequency: formFrequency,
        preferredTime: formPreferredTime,
        autoEnforceFirewall: formAutoEnforce,
        alertThresholdScore: formThresholdScore,
        notifyDesktop: formNotifyDesktop,
      };

      const url = editingJobId ? `/api/schedules/${editingJobId}` : '/api/schedules';
      const method = editingJobId ? 'PUT' : 'POST';

      const res = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (res.ok) {
        await fetchSchedulerData();
        setIsFormOpen(false);
        setEditingJobId(null);
        showBanner(
          editingJobId
            ? 'Planification automatique mise à jour avec succès.'
            : `Nouvelle analyse planifiée (${formatFrequencyLabel(formFrequency, formPreferredTime)}) activée.`
        );
      }
    } catch (err) {
      console.error('Error saving schedule:', err);
    } finally {
      setIsSavingForm(false);
    }
  };

  // Toggle enabled / paused state
  const handleToggleEnabled = async (job: ScheduledAnalysisJob) => {
    try {
      const res = await fetch(`/api/schedules/${job.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: !job.enabled }),
      });
      if (res.ok) {
        await fetchSchedulerData();
        showBanner(
          !job.enabled
            ? `Surveillance automatique réactivée : "${job.name}"`
            : `Surveillance mise en pause : "${job.name}"`
        );
      }
    } catch (err) {
      console.error('Error toggling schedule:', err);
    }
  };

  // Delete schedule
  const handleDeleteSchedule = async (job: ScheduledAnalysisJob) => {
    try {
      const res = await fetch(`/api/schedules/${job.id}`, {
        method: 'DELETE',
      });
      if (res.ok) {
        await fetchSchedulerData();
        showBanner(`Planification "${job.name}" supprimée.`);
      }
    } catch (err) {
      console.error('Error deleting schedule:', err);
    }
  };

  // Filtered schedules
  const filteredSchedules = schedules.filter((job) => {
    if (frequencyFilter === 'ALL') return true;
    if (frequencyFilter === 'HOURLY') return job.frequency === 'HOURLY';
    if (frequencyFilter === 'DAILY') return job.frequency === 'DAILY' || job.frequency === 'WEEKLY';
    if (frequencyFilter === 'FAST') return job.frequency === '15_MIN' || job.frequency === 'EVERY_6H';
    return true;
  });

  const activeSchedulesCount = schedules.filter((s) => s.enabled).length;
  const hourlyCount = schedules.filter((s) => s.frequency === 'HOURLY' && s.enabled).length;
  const dailyCount = schedules.filter((s) => s.frequency === 'DAILY' && s.enabled).length;
  const totalAutoRuns = schedules.reduce((acc, s) => acc + s.totalRunsCount, 0);
  const totalAutoNeutralized = schedules.reduce((acc, s) => acc + s.threatsNeutralizedCount, 0);

  return (
    <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-6">
      {/* Header & Continuous Surveillance Daemon Controls */}
      <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-4 border-b border-slate-800/80 pb-5">
        <div className="space-y-1.5">
          <div className="flex items-center flex-wrap gap-2.5">
            <div className="w-9 h-9 rounded-xl bg-cyan-950 border border-cyan-700/70 flex items-center justify-center text-cyan-400">
              <CalendarClock className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center flex-wrap gap-2 text-xs font-mono text-slate-400">
                <span className="text-cyan-400 font-bold uppercase tracking-wider">
                  Surveillance Continue SOC 24/7
                </span>
                <span aria-hidden="true">·</span>
                <span>
                  {activeSchedulesCount}/{schedules.length} tâches actives
                </span>
                <span aria-hidden="true">·</span>
                <span>{hourlyCount} horaire(s)</span>
                <span aria-hidden="true">·</span>
                <span>{dailyCount} quotidienne(s)</span>
              </div>
              <h3 className="text-base sm:text-lg font-bold text-white tracking-tight">
                Planificateur d’Analyses Automatiques des Logs Nebula
              </h3>
            </div>
          </div>
          <p className="text-xs text-slate-400 font-mono">
            Programmez l’extraction SecuReporter et l’analyse IA des menaces à intervalles réguliers (toutes les heures, tous les jours, 15 min) avec blocage pare-feu autonome.
          </p>
        </div>

        {/* Right Action Toolbar */}
        <div className="flex flex-wrap items-center gap-2.5">
          {/* Live Daemon Accelerated Simulation Toggle */}
          <button
            onClick={() => setLiveDaemonSimActive(!liveDaemonSimActive)}
            className={`inline-flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-mono font-bold transition border ${
              liveDaemonSimActive
                ? 'bg-emerald-950/90 text-emerald-300 border-emerald-600 shadow-lg shadow-emerald-950/50'
                : 'bg-slate-800/90 hover:bg-slate-700 text-slate-300 border-slate-700'
            }`}
            title="Activer le démon d'exécution automatique accélérée (déclenche une analyse planifiée toutes les 30 secondes)"
          >
            <Timer className={`w-4 h-4 ${liveDaemonSimActive ? 'text-emerald-400 animate-spin' : 'text-cyan-400'}`} />
            <span>
              {liveDaemonSimActive
                ? `Démon Auto Actif (${daemonCountdownSec}s)`
                : 'Mode Cadence Temps Réel (30s)'}
            </span>
          </button>

          {/* Quick Preset: New Hourly Schedule */}
          <button
            onClick={() => openCreateForm('HOURLY')}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-cyan-800/60 text-xs font-mono font-semibold transition"
          >
            <Clock className="w-3.5 h-3.5 text-cyan-400" />
            <span>+ Toutes les heures</span>
          </button>

          {/* Quick Preset: New Daily Schedule */}
          <button
            onClick={() => openCreateForm('DAILY')}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-indigo-300 border border-indigo-800/60 text-xs font-mono font-semibold transition"
          >
            <CalendarClock className="w-3.5 h-3.5 text-indigo-400" />
            <span>+ Tous les jours</span>
          </button>

          {/* Main Create Schedule CTA */}
          <button
            onClick={() => openCreateForm('HOURLY')}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono font-bold transition shadow-lg shadow-cyan-950/50"
          >
            <Plus className="w-4 h-4" />
            <span>Nouvelle Planification</span>
          </button>
        </div>
      </div>

      {/* Feedback Banner */}
      {feedbackBanner && (
        <div
          className={`flex items-center justify-between gap-3 px-4 py-3 rounded-xl border text-xs font-mono ${
            feedbackBanner.type === 'warning'
              ? 'bg-amber-950/60 border-amber-700/80 text-amber-200'
              : 'bg-emerald-950/60 border-emerald-700/80 text-emerald-200'
          }`}
        >
          <div className="flex items-center gap-2">
            {feedbackBanner.type === 'warning' ? (
              <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0" />
            ) : (
              <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
            )}
            <span>{feedbackBanner.text}</span>
          </div>
          <button
            onClick={() => setFeedbackBanner(null)}
            className="text-slate-400 hover:text-white p-1"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Summary KPI Strip */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3.5">
        <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800/90 space-y-1">
          <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
            <span>Statut Moteur Cron SOC</span>
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          </div>
          <div className="text-xl font-bold font-mono text-emerald-400">
            {activeSchedulesCount > 0 ? 'SURVEILLANCE ACTIVE' : 'EN PAUSE'}
          </div>
          <div className="text-[11px] font-mono text-slate-500">
            {activeSchedulesCount} planification(s) en exécution continue
          </div>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800/90 space-y-1">
          <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
            <span>Cadences Configurées</span>
            <Clock className="w-3.5 h-3.5 text-cyan-400" />
          </div>
          <div className="text-xl font-bold font-mono text-white">
            {hourlyCount} Horaire · {dailyCount} Jour
          </div>
          <div className="text-[11px] font-mono text-slate-500">
            Synchronisé via API Zyxel Nebula NCC
          </div>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800/90 space-y-1">
          <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
            <span>Analyses Automatisées</span>
            <RefreshCw className="w-3.5 h-3.5 text-indigo-400" />
          </div>
          <div className="text-xl font-bold font-mono text-cyan-300">
            {totalAutoRuns} cycles
          </div>
          <div className="text-[11px] font-mono text-slate-500">
            Inspection continue IDP / Anti-Malware / CDR
          </div>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800/90 space-y-1">
          <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
            <span>Menaces Auto-Bloquées</span>
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div className="text-xl font-bold font-mono text-emerald-400">
            {totalAutoNeutralized} ripostes
          </div>
          <div className="text-[11px] font-mono text-slate-500">
            Règles ACL WAN appliquées sans délai humain
          </div>
        </div>
      </div>

      {/* Create / Edit Schedule Modal Drawer */}
      {isFormOpen && (
        <form
          onSubmit={handleSaveSchedule}
          className="p-5 rounded-2xl bg-slate-950 border-2 border-cyan-700/70 shadow-2xl space-y-5"
        >
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2.5">
              <Sliders className="w-4 h-4 text-cyan-400" />
              <h4 className="text-sm font-bold text-white font-mono">
                {editingJobId
                  ? 'Modifier la Planification d’Analyse Automatique'
                  : 'Configurer une Nouvelle Analyse Automatique des Logs'}
              </h4>
            </div>
            <button
              type="button"
              onClick={() => {
                setIsFormOpen(false);
                setEditingJobId(null);
              }}
              className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Schedule Name */}
            <div className="space-y-1.5">
              <label className="block text-xs font-mono font-semibold text-slate-300">
                Nom de la tâche planifiée
              </label>
              <input
                type="text"
                required
                value={formName}
                onChange={(e) => setFormName(e.target.value)}
                placeholder="Ex: Surveillance Horaire — Siège Paris ATP800"
                className="w-full px-3.5 py-2 rounded-xl bg-slate-900 border border-slate-700 text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
              />
            </div>

            {/* Target Site Gateway */}
            <div className="space-y-1.5">
              <label className="block text-xs font-mono font-semibold text-slate-300">
                Organisation & Site Zyxel Nebula à surveiller
              </label>
              <select
                value={formSiteId}
                onChange={(e) => {
                  const newSiteId = e.target.value;
                  setFormSiteId(newSiteId);
                  const found = allSites.find((s) => s.siteId === newSiteId);
                  if (found && !editingJobId) {
                    setFormName(
                      `Surveillance ${formatFrequencyLabel(formFrequency, formPreferredTime)} — ${found.siteName}`
                    );
                  }
                }}
                className="w-full px-3.5 py-2 rounded-xl bg-slate-900 border border-slate-700 text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
              >
                {organizations.length > 0
                  ? organizations.map((org) => (
                      <optgroup key={org.id} label={`Organisation : ${org.name}`}>
                        {org.sites.map((site) => (
                          <option key={site.siteId} value={site.siteId}>
                            {site.siteName} — {site.gatewayModel} ({site.wanIp})
                          </option>
                        ))}
                      </optgroup>
                    ))
                  : allSites.map((site) => (
                      <option key={site.siteId} value={site.siteId}>
                        {site.siteName} — {site.gatewayModel}
                      </option>
                    ))}
              </select>
            </div>
          </div>

          {/* Frequency Selector Cards */}
          <div className="space-y-2">
            <label className="block text-xs font-mono font-semibold text-slate-300">
              Fréquence d’analyse automatique (Intervalle de surveillance)
            </label>
            <div className="grid grid-cols-1 sm:grid-cols-3 lg:grid-cols-5 gap-2.5">
              {FREQUENCY_OPTIONS.map((opt) => {
                const isSelected = formFrequency === opt.value;
                return (
                  <button
                    key={opt.value}
                    type="button"
                    onClick={() => {
                      setFormFrequency(opt.value);
                      const found = allSites.find((s) => s.siteId === formSiteId);
                      if (found && !editingJobId) {
                        setFormName(
                          `Surveillance ${formatFrequencyLabel(opt.value, formPreferredTime)} — ${found.siteName}`
                        );
                      }
                    }}
                    className={`p-3 rounded-xl border text-left transition flex flex-col justify-between gap-1.5 ${
                      isSelected
                        ? 'bg-cyan-950/90 border-cyan-500 text-white ring-1 ring-cyan-500/40'
                        : 'bg-slate-900/90 border-slate-800 text-slate-300 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-1">
                      <span className="text-xs font-bold font-mono">{opt.label}</span>
                      {isSelected && <Check className="w-3.5 h-3.5 text-cyan-400 flex-shrink-0" />}
                    </div>
                    <p className="text-[10px] text-slate-400 leading-snug">{opt.shortDesc}</p>
                    <span className="text-[10px] font-mono text-cyan-400">
                      Cron : {opt.cronPreview}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Time of day & Automated Response Threshold */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-1">
            {(formFrequency === 'DAILY' || formFrequency === 'WEEKLY') && (
              <div className="space-y-1.5">
                <label className="block text-xs font-mono font-semibold text-slate-300">
                  Heure d’exécution programmée
                </label>
                <input
                  type="time"
                  value={formPreferredTime}
                  onChange={(e) => setFormPreferredTime(e.target.value)}
                  className="w-full px-3.5 py-2 rounded-xl bg-slate-900 border border-slate-700 text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
                />
                <p className="text-[10px] font-mono text-slate-500">
                  Exécution automatique chaque jour à {formPreferredTime}
                </p>
              </div>
            )}

            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-xs font-mono">
                <label className="font-semibold text-slate-300">
                  Seuil de Risque Critique (Auto-Alerte)
                </label>
                <span className="font-bold text-cyan-400">{formThresholdScore} / 100</span>
              </div>
              <input
                type="range"
                min={35}
                max={95}
                step={5}
                value={formThresholdScore}
                onChange={(e) => setFormThresholdScore(Number(e.target.value))}
                className="w-full accent-cyan-500 cursor-pointer"
              />
              <p className="text-[10px] font-mono text-slate-500">
                Déclenche une alerte SOC si le score dépasse {formThresholdScore}/100
              </p>
            </div>

            <div className="space-y-2 flex flex-col justify-center">
              <label className="flex items-center gap-2.5 text-xs font-mono text-slate-200 cursor-pointer">
                <input
                  type="checkbox"
                  checked={formAutoEnforce}
                  onChange={(e) => setFormAutoEnforce(e.target.checked)}
                  className="rounded border-slate-700 text-cyan-500 focus:ring-cyan-500"
                />
                <span>
                  <strong>Riposte Pare-Feu Automatique</strong> (DROP WAN / CDR si seuil franchi)
                </span>
              </label>

              <label className="flex items-center gap-2.5 text-xs font-mono text-slate-200 cursor-pointer">
                <input
                  type="checkbox"
                  checked={formNotifyDesktop}
                  onChange={(e) => setFormNotifyDesktop(e.target.checked)}
                  className="rounded border-slate-700 text-cyan-500 focus:ring-cyan-500"
                />
                <span>Activer les notifications système temps réel</span>
              </label>
            </div>
          </div>

          <div className="flex items-center justify-end gap-2.5 pt-3 border-t border-slate-800">
            <button
              type="button"
              onClick={() => {
                setIsFormOpen(false);
                setEditingJobId(null);
              }}
              className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono font-semibold transition"
            >
              Annuler
            </button>
            <button
              type="submit"
              disabled={isSavingForm}
              className="inline-flex items-center gap-2 px-5 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono font-bold transition shadow-lg"
            >
              <CheckCircle2 className="w-4 h-4" />
              <span>
                {isSavingForm
                  ? 'Enregistrement...'
                  : editingJobId
                  ? 'Enregistrer les modifications'
                  : 'Activer la Planification'}
              </span>
            </button>
          </div>
        </form>
      )}

      {/* Filter Tabs & Scheduled Jobs List */}
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-1 p-1 bg-slate-950 rounded-xl border border-slate-800 w-fit">
            <button
              onClick={() => setFrequencyFilter('ALL')}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition ${
                frequencyFilter === 'ALL'
                  ? 'bg-slate-800 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Toutes ({schedules.length})
            </button>
            <button
              onClick={() => setFrequencyFilter('HOURLY')}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition ${
                frequencyFilter === 'HOURLY'
                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/60'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Toutes les heures ({schedules.filter((s) => s.frequency === 'HOURLY').length})
            </button>
            <button
              onClick={() => setFrequencyFilter('DAILY')}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition ${
                frequencyFilter === 'DAILY'
                  ? 'bg-indigo-950 text-indigo-300 border border-indigo-800/60'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Tous les jours ({schedules.filter((s) => s.frequency === 'DAILY' || s.frequency === 'WEEKLY').length})
            </button>
            <button
              onClick={() => setFrequencyFilter('FAST')}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition ${
                frequencyFilter === 'FAST'
                  ? 'bg-emerald-950 text-emerald-300 border border-emerald-800/60'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              15 min / 6h ({schedules.filter((s) => s.frequency === '15_MIN' || s.frequency === 'EVERY_6H').length})
            </button>
          </div>

          <div className="text-xs font-mono text-slate-400">
            Cliquez sur <strong className="text-cyan-300">Analyser maintenant</strong> pour forcer l’exécution immédiate d’une tâche planifiée.
          </div>
        </div>

        {isLoading ? (
          <div className="p-8 text-center text-xs font-mono text-slate-400">
            Chargement des planifications de surveillance...
          </div>
        ) : filteredSchedules.length === 0 ? (
          <div className="p-8 rounded-xl bg-slate-950/60 border border-slate-800 text-center space-y-3">
            <CalendarClock className="w-8 h-8 text-slate-500 mx-auto" />
            <p className="text-xs font-mono text-slate-400">
              Aucune tâche planifiée dans cette catégorie.
            </p>
            <button
              onClick={() => openCreateForm('HOURLY')}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono font-bold transition"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Créer une analyse horaire ou quotidienne</span>
            </button>
          </div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {filteredSchedules.map((job) => {
              const isRunning = runningJobId === job.id;
              const isHighRisk = (job.lastRiskScore || 0) >= job.alertThresholdScore;

              return (
                <div
                  key={job.id}
                  className={`p-4 rounded-xl border transition flex flex-col justify-between gap-4 ${
                    !job.enabled
                      ? 'bg-slate-950/40 border-slate-800/60 opacity-75'
                      : isHighRisk
                      ? 'bg-slate-950/90 border-red-900/60 hover:border-red-700/70'
                      : 'bg-slate-950/90 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="space-y-2.5">
                    {/* Top Metadata Line (Zero-pill discipline: clean unboxed text with separators) */}
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center flex-wrap gap-1.5 text-[11px] font-mono">
                        <span
                          className={`w-2 h-2 rounded-full ${
                            !job.enabled
                              ? 'bg-slate-600'
                              : isRunning
                              ? 'bg-cyan-400 animate-ping'
                              : 'bg-emerald-400'
                          }`}
                        />
                        <span
                          className={
                            job.enabled ? 'text-emerald-400 font-bold' : 'text-slate-500 font-bold'
                          }
                        >
                          {job.enabled ? 'ACTIF' : 'EN PAUSE'}
                        </span>
                        <span aria-hidden="true" className="text-slate-600">
                          ·
                        </span>
                        <span className="text-cyan-400 font-bold">
                          {formatFrequencyLabel(job.frequency, job.preferredTime)}
                        </span>
                        <span aria-hidden="true" className="text-slate-600">
                          ·
                        </span>
                        <span className="text-slate-400">Cron {job.cronExpression}</span>
                      </div>

                      {/* Toggle Active / Pause Button */}
                      <button
                        onClick={() => handleToggleEnabled(job)}
                        className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-[11px] font-mono font-semibold border transition ${
                          job.enabled
                            ? 'bg-slate-900 hover:bg-slate-800 text-emerald-300 border-emerald-800/70'
                            : 'bg-slate-900 hover:bg-slate-800 text-slate-400 border-slate-700'
                        }`}
                        title={
                          job.enabled
                            ? 'Mettre en pause cette surveillance automatique'
                            : 'Réactiver cette surveillance automatique'
                        }
                      >
                        {job.enabled ? (
                          <>
                            <Pause className="w-3 h-3" />
                            <span>Actif</span>
                          </>
                        ) : (
                          <>
                            <Play className="w-3 h-3" />
                            <span>Réactiver</span>
                          </>
                        )}
                      </button>
                    </div>

                    {/* Title & Site info */}
                    <div>
                      <h4 className="text-sm font-bold text-white leading-snug">{job.name}</h4>
                      <div className="flex items-center flex-wrap gap-2 mt-1 text-xs font-mono text-slate-400">
                        <span className="inline-flex items-center gap-1 text-slate-300">
                          <Building2 className="w-3.5 h-3.5 text-cyan-400" />
                          {job.organizationName}
                        </span>
                        <span aria-hidden="true">·</span>
                        <span className="inline-flex items-center gap-1 text-cyan-300">
                          <Server className="w-3.5 h-3.5" />
                          {job.siteName} ({job.gatewayModel})
                        </span>
                      </div>
                    </div>

                    {/* Timing & Defense Parameters */}
                    <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 pt-2 border-t border-slate-800/80 text-[11px] font-mono">
                      <div>
                        <span className="text-slate-500 block">Dernière analyse :</span>
                        <span className="text-slate-200 font-semibold">
                          {formatRelativeTime(job.lastRunAt)}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-500 block">Prochaine exécution :</span>
                        <span className="text-cyan-300 font-semibold">
                          {job.enabled ? formatRelativeTime(job.nextRunAt) : 'Suspendue'}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-500 block">Dernier Score Risque :</span>
                        {job.lastRiskScore !== undefined ? (
                          <span
                            className={`font-bold ${
                              job.lastRiskScore >= 75
                                ? 'text-red-400'
                                : job.lastRiskScore >= 50
                                ? 'text-amber-400'
                                : 'text-emerald-400'
                            }`}
                          >
                            {job.lastRiskScore}/100 (Seuil {job.alertThresholdScore})
                          </span>
                        ) : (
                          <span className="text-slate-400">En attente</span>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Bottom Action Bar */}
                  <div className="flex flex-wrap items-center justify-between gap-2 pt-2.5 border-t border-slate-800/80 text-[11px] font-mono">
                    <div className="flex items-center gap-2 text-slate-400">
                      <span>
                        Riposte Auto :{' '}
                        <strong className={job.autoEnforceFirewall ? 'text-emerald-400' : 'text-slate-500'}>
                          {job.autoEnforceFirewall ? 'Activée' : 'Désactivée'}
                        </strong>
                      </span>
                      <span aria-hidden="true">·</span>
                      <span>{job.totalRunsCount} exécutions</span>
                    </div>

                    <div className="flex items-center gap-1.5">
                      <button
                        onClick={() => handleRunScheduleNow(job, 'MANUAL_FORCE', true)}
                        disabled={isRunning}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-bold transition shadow-sm"
                        title="Exécuter immédiatement l'analyse des logs pour ce site et mettre à jour le Dashboard"
                      >
                        <RefreshCw className={`w-3.5 h-3.5 ${isRunning ? 'animate-spin' : ''}`} />
                        <span>{isRunning ? 'Analyse...' : 'Analyser maintenant'}</span>
                      </button>

                      <button
                        onClick={() => openEditForm(job)}
                        className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition"
                        title="Modifier l'intervalle ou les paramètres"
                      >
                        <Edit3 className="w-3.5 h-3.5" />
                      </button>

                      <button
                        onClick={() => handleDeleteSchedule(job)}
                        className="p-1.5 rounded-lg bg-slate-800 hover:bg-red-950/70 text-slate-400 hover:text-red-400 transition"
                        title="Supprimer cette planification"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Automated Execution Log History */}
      <div className="pt-4 border-t border-slate-800/90 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <History className="w-4 h-4 text-cyan-400" />
            <h4 className="text-xs font-mono font-bold text-white uppercase tracking-wider">
              Journal des Analyses Automatiques Exécutées ({runLogs.length})
            </h4>
          </div>
          <span className="text-[11px] font-mono text-slate-400">
            Synchronisation continue SecuReporter & Passerelles ATP / USG FLEX
          </span>
        </div>

        <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
          {runLogs.map((log) => {
            const timeFormatted = new Date(log.executedAt).toLocaleString('fr-FR', {
              day: '2-digit',
              month: '2-digit',
              hour: '2-digit',
              minute: '2-digit',
              second: '2-digit',
            });

            return (
              <div
                key={log.id}
                className="p-3 rounded-xl bg-slate-950/80 border border-slate-800/80 hover:border-slate-700 transition flex flex-col lg:flex-row lg:items-center justify-between gap-3 text-xs font-mono"
              >
                <div className="space-y-1">
                  <div className="flex items-center flex-wrap gap-2 text-[11px]">
                    <span className="text-slate-400">{timeFormatted}</span>
                    <span aria-hidden="true" className="text-slate-600">
                      ·
                    </span>
                    <span className="font-bold text-white">{log.siteName}</span>
                    <span className="text-slate-400">({log.gatewayModel})</span>
                    <span aria-hidden="true" className="text-slate-600">
                      ·
                    </span>
                    <span className="text-cyan-400">{log.frequencyLabel}</span>
                    <span aria-hidden="true" className="text-slate-600">
                      ·
                    </span>
                    <span
                      className={`font-bold ${
                        log.riskScore >= 75
                          ? 'text-red-400'
                          : log.riskScore >= 50
                          ? 'text-amber-400'
                          : 'text-emerald-400'
                      }`}
                    >
                      Score {log.riskScore}/100 ({log.threatLevel})
                    </span>
                    {log.autoBlockedCount > 0 && (
                      <>
                        <span aria-hidden="true" className="text-slate-600">
                          ·
                        </span>
                        <span className="text-emerald-400 font-bold">
                          {log.autoBlockedCount} menace(s) bloquée(s)
                        </span>
                      </>
                    )}
                  </div>
                  <p className="text-[11px] text-slate-300 leading-relaxed">{log.summary}</p>
                </div>

                {log.rawLogsSnapshot && onSelectSiteLogs && (
                  <button
                    onClick={() =>
                      onSelectSiteLogs(
                        log.rawLogsSnapshot!,
                        `${log.siteName} (${log.gatewayModel}) [Rapport Planifié]`
                      )
                    }
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 text-[11px] font-semibold transition flex-shrink-0 self-start lg:self-center"
                  >
                    <span>Inspecter dans le Dashboard</span>
                    <ArrowUpRight className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
