import React, { useState, useEffect, useCallback } from 'react';
import {
  LayoutDashboard,
  ShieldAlert,
  Zap,
  FileSearch,
  MessageSquare,
  FileCheck,
  CheckCircle,
  AlertTriangle,
  Cloud,
  CalendarClock,
  Radio,
} from 'lucide-react';
import { Header } from './components/Header';
import { DashboardView } from './components/DashboardView';
import { CountermeasuresView } from './components/CountermeasuresView';
import { DeepAnalysisView } from './components/DeepAnalysisView';
import { LogExplorerView } from './components/LogExplorerView';
import { CopilotView } from './components/CopilotView';
import { IncidentReportView } from './components/IncidentReportView';
import { NebulaApiView } from './components/NebulaApiView';
import { ScheduledAnalysisManager } from './components/ScheduledAnalysisManager';
import { SyslogCollectorView } from './components/SyslogCollectorView';
import { LogUploadModal } from './components/LogUploadModal';
import { SAMPLE_REPORTS } from './data/sampleReports';
import { parseNebulaLogs } from './utils/logParser';
import {
  getStoredAnalysisHistory,
  saveAnalysisToHistory,
  deleteHistoryItem,
  clearAnalysisHistory,
} from './utils/historyStorage';
import {
  SystemNotificationPayload,
  triggerWebNotification,
} from './utils/systemNotification';
import { SystemNotificationBanner } from './components/SystemNotificationBanner';
import { CommandPaletteModal } from './components/CommandPaletteModal';
import { FooterStatusBar } from './components/FooterStatusBar';
import { AutoRefreshNavbarSwitch } from './components/AutoRefreshNavbarSwitch';
import {
  ActiveDefense,
  LogEntry,
  SampleReport,
  StopAction,
  ThreatAnalysisResult,
  AnalysisHistoryItem,
} from './types';

export default function App() {
  const [activeTab, setActiveTab] = useState<
    | 'dashboard'
    | 'scheduler'
    | 'countermeasures'
    | 'deep-analysis'
    | 'logs'
    | 'syslog-server'
    | 'copilot'
    | 'report'
    | 'nebula-api'
  >('dashboard');

  const [currentScenario, setCurrentScenario] = useState<SampleReport | null>(SAMPLE_REPORTS[0]);
  const [rawLogs, setRawLogs] = useState<string>(SAMPLE_REPORTS[0].rawLogs);
  const [parsedLogs, setParsedLogs] = useState<LogEntry[]>([]);
  const [analysis, setAnalysis] = useState<ThreatAnalysisResult | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [activeDefenses, setActiveDefenses] = useState<ActiveDefense[]>([]);
  const [isEnforcing, setIsEnforcing] = useState<boolean>(false);
  const [isUploadOpen, setIsUploadOpen] = useState<boolean>(false);
  const [copilotInitialQuery, setCopilotInitialQuery] = useState<string | undefined>(undefined);
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const [historyList, setHistoryList] = useState<AnalysisHistoryItem[]>(() => getStoredAnalysisHistory());
  const [systemNotification, setSystemNotification] = useState<SystemNotificationPayload | null>(null);
  const [isCommandPaletteOpen, setIsCommandPaletteOpen] = useState<boolean>(false);

  // Auto-refresh state (every 30 seconds via Nebula API)
  const [isAutoRefreshEnabled, setIsAutoRefreshEnabled] = useState<boolean>(() => {
    return localStorage.getItem('nebula_auto_refresh_active') === 'true';
  });
  const [autoRefreshCountdown, setAutoRefreshCountdown] = useState<number>(30);
  const [isAutoRefreshing, setIsAutoRefreshing] = useState<boolean>(false);
  const [lastAutoRefreshTime, setLastAutoRefreshTime] = useState<Date | null>(null);

  // Global Keyboard Shortcut: Cmd+K / Ctrl+K for Command Palette
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setIsCommandPaletteOpen((prev) => !prev);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 4000);
  };

  // Fetch active defenses from server
  const fetchActiveDefenses = async () => {
    try {
      const res = await fetch('/api/active-defenses');
      if (res.ok) {
        const data = await res.json();
        setActiveDefenses(data.defenses || []);
      }
    } catch (e) {
      console.warn('Could not fetch active defenses:', e);
    }
  };

  // Trigger AI Analysis
  const runAnalysis = useCallback(async (textToAnalyze: string, deviceContext?: string) => {
    if (!textToAnalyze.trim()) return;

    setIsAnalyzing(true);
    const parsed = parseNebulaLogs(textToAnalyze);
    setParsedLogs(parsed);

    try {
      const res = await fetch('/api/analyze-nebula-logs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          logsText: textToAnalyze,
          context: deviceContext || currentScenario?.device || 'Nebula Gateway',
        }),
      });

      if (!res.ok) throw new Error('Erreur d\'analyse');
      const data: ThreatAnalysisResult = await res.json();
      setAnalysis(data);

      // Trigger Web Notifications API & UI alert simulation if threat is CRITICAL
      const isCritical =
        data.threatLevel === 'CRITICAL' ||
        data.riskScore >= 70 ||
        data.attackVectors.some((v) => v.severity === 'CRITICAL');

      if (isCritical) {
        const primaryVector = data.attackVectors[0];
        const topIoc = data.iocList.find((i) => i.type === 'IP')?.value;
        const devName = deviceContext || currentScenario?.device || 'Passerelle Nebula ATP';

        const notifPayload: SystemNotificationPayload = {
          title: `Menace Critique Détectée : ${primaryVector?.name || 'Attaque Cyber Active'}`,
          body: `Score de risque : ${data.riskScore}/100 sur ${devName}. Attaque active identifiée par Secure Reporter. Riposte pare-feu prête à être appliquée.`,
          threatLevel: 'CRITICAL',
          riskScore: data.riskScore,
          attackerIp: topIoc || primaryVector?.attackerIps?.[0],
          threatName: primaryVector?.name || 'Ransomware / C2 Beaconing',
          timestamp: new Date().toISOString(),
        };

        setSystemNotification(notifPayload);
        triggerWebNotification(notifPayload);
      }

      // Save to localStorage history (max 10)
      const updatedHistory = saveAnalysisToHistory({
        deviceName: deviceContext || currentScenario?.device || 'Passerelle Nebula',
        title: currentScenario?.title || 'Analyse Nebula Secure Report',
        riskScore: data.riskScore,
        threatLevel: data.threatLevel,
        attacksCount: data.attackVectors.length,
        logCount: parsed.length,
        analysis: data,
        rawLogs: textToAnalyze,
      });
      setHistoryList(updatedHistory);
    } catch (err) {
      console.error('Analysis failed:', err);
    } finally {
      setIsAnalyzing(false);
    }
  }, [currentScenario]);

  // Auto-refresh logs every 30 seconds via Nebula API
  const handleAutoRefreshNebulaLogs = useCallback(
    async (siteId?: string, isManual = false) => {
      setIsAutoRefreshing(true);
      const targetSiteId =
        siteId ||
        (currentScenario?.id && currentScenario.id.startsWith('SITE-')
          ? currentScenario.id
          : 'SITE-PARIS-ATP700');

      try {
        const res = await fetch('/api/nebula/pull-logs', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            siteId: targetSiteId,
          }),
        });

        if (res.ok) {
          const data = await res.json();
          const freshLogs: string = data.rawLogs || '';
          const siteLabel =
            data.site?.siteName || data.site?.gatewayModel || 'Zyxel Nebula ATP700';

          if (freshLogs) {
            setRawLogs(freshLogs);
            const parsed = parseNebulaLogs(freshLogs);
            setParsedLogs(parsed);

            setCurrentScenario((prev) => ({
              id: data.site?.siteId || prev?.id || 'SITE-PARIS-ATP700',
              title: `Flux Temps Réel Nebula • ${siteLabel}`,
              description: `Synchronisé via l'API Zyxel Nebula Control Center à ${new Date().toLocaleTimeString(
                'fr-FR'
              )}`,
              device: data.site?.gatewayModel || prev?.device || 'Zyxel Nebula ATP700',
              severity:
                data.attackSummary?.criticalThreats > 0 ? 'CRITICAL' : 'HIGH',
              logCount: parsed.length,
              primaryThreat:
                data.attackSummary?.activeVectors?.[0] || 'Attaques Détectées',
              rawLogs: freshLogs,
            }));

            await runAnalysis(freshLogs, siteLabel);
            setLastAutoRefreshTime(new Date());

            showToast(
              isManual
                ? `Synchronisation manuelle Nebula réussie : ${parsed.length} événements analysés.`
                : `Auto-rafraîchissement (30s) : ${parsed.length} événements Nebula actualisés.`
            );
          }
        }
      } catch (err) {
        console.warn('Nebula auto-refresh failed:', err);
      } finally {
        setIsAutoRefreshing(false);
        setAutoRefreshCountdown(30);
      }
    },
    [currentScenario, runAnalysis]
  );

  // 30s Auto-refresh timer effect
  useEffect(() => {
    localStorage.setItem('nebula_auto_refresh_active', String(isAutoRefreshEnabled));

    if (!isAutoRefreshEnabled) {
      setAutoRefreshCountdown(30);
      return;
    }

    const timer = setInterval(() => {
      setAutoRefreshCountdown((prev) => {
        if (prev <= 1) {
          handleAutoRefreshNebulaLogs();
          return 30;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, [isAutoRefreshEnabled, handleAutoRefreshNebulaLogs]);

  // Manually trigger test notification (Web Notifications API simulation)
  const handleTriggerTestNotification = () => {
    const currentRisk = analysis?.riskScore || 94;
    const primaryVector = analysis?.attackVectors?.[0];
    const topIoc = analysis?.iocList.find((i) => i.type === 'IP')?.value || '91.240.118.172';

    const testPayload: SystemNotificationPayload = {
      title: `ALERTE CRITIQUE : ${primaryVector?.name || 'Campagne Ransomware LockBit & C2 Cobalt Strike'}`,
      body: `Score de risque : ${currentRisk}/100. Passerelle Nebula ATP700 en état d'alerte. Flux suspect vers ${topIoc}. Riposte pare-feu WAN recommandée.`,
      threatLevel: 'CRITICAL',
      riskScore: currentRisk,
      attackerIp: topIoc,
      threatName: primaryVector?.name || 'Trojan.Win32.CobaltStrike.Beacon',
      timestamp: new Date().toISOString(),
    };

    setSystemNotification(testPayload);
    triggerWebNotification(testPayload);
    showToast('Simulation de notification système (Web Notifications API) déclenchée !');
  };

  // Initial load
  useEffect(() => {
    fetchActiveDefenses();
    if (SAMPLE_REPORTS[0]) {
      runAnalysis(SAMPLE_REPORTS[0].rawLogs, SAMPLE_REPORTS[0].device);
    }
  }, []);

  // Handle Scenario Change
  const handleSelectScenario = (scenario: SampleReport) => {
    setCurrentScenario(scenario);
    setRawLogs(scenario.rawLogs);
    runAnalysis(scenario.rawLogs, scenario.device);
    showToast(`Rapport "${scenario.title}" chargé avec succès.`);
  };

  // Handle User Log Upload
  const handleUploadSubmit = (content: string, device: string) => {
    setCurrentScenario({
      id: `custom-${Date.now()}`,
      title: `Logs Personnalisés : ${device}`,
      description: 'Logs importés manuellement par l\'utilisateur',
      device,
      severity: 'HIGH',
      logCount: content.split('\n').filter((l) => l.trim()).length,
      primaryThreat: 'Analyse en cours...',
      rawLogs: content,
    });
    setRawLogs(content);
    runAnalysis(content, device);
    showToast(`Logs importés pour ${device}. Lancement de l'analyse...`);
  };

  // Enforce single defense
  const handleEnforceDefense = async (action: StopAction) => {
    setIsEnforcing(true);
    try {
      const res = await fetch('/api/enforce-defense', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: action.type === 'HOST_QUARANTINE' ? 'HOST_QUARANTINE' : 'IP_BLOCK',
          target: action.target,
          reason: action.rationale,
          policyName: action.zyxelNebulaRule.ruleName,
        }),
      });

      if (res.ok) {
        await fetchActiveDefenses();
        showToast(`Règle de riposte déployée avec succès pour ${action.target} sur Nebula !`);
      }
    } catch (e) {
      console.error('Failed to enforce defense:', e);
      showToast(`Erreur lors de l'application de la règle pour ${action.target}`);
    } finally {
      setIsEnforcing(false);
    }
  };

  // Enforce all stop actions
  const handleEnforceAll = async () => {
    if (!analysis || analysis.stopActions.length === 0) return;
    setIsEnforcing(true);
    try {
      for (const action of analysis.stopActions) {
        await fetch('/api/enforce-defense', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            type: action.type === 'HOST_QUARANTINE' ? 'HOST_QUARANTINE' : 'IP_BLOCK',
            target: action.target,
            reason: action.rationale,
            policyName: action.zyxelNebulaRule.ruleName,
          }),
        });
      }
      await fetchActiveDefenses();
      showToast(`Riposte Totale Déployée : ${analysis.stopActions.length} règles appliquées sur Nebula Gateway !`);
    } catch (e) {
      console.error('Failed to enforce all:', e);
    } finally {
      setIsEnforcing(false);
    }
  };

  // Revoke defense
  const handleRevokeDefense = async (id: string) => {
    try {
      const res = await fetch('/api/revoke-defense', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id }),
      });
      if (res.ok) {
        await fetchActiveDefenses();
        showToast('Règle révoquée avec succès.');
      }
    } catch (e) {
      console.error('Failed to revoke defense:', e);
    }
  };

  // Restore analysis from localStorage history
  const handleRestoreAnalysis = (item: AnalysisHistoryItem) => {
    setAnalysis(item.analysis);
    setRawLogs(item.rawLogs);
    setParsedLogs(parseNebulaLogs(item.rawLogs));
    setCurrentScenario({
      id: item.id,
      title: item.title,
      description: 'Analyse restaurée depuis l\'historique local',
      device: item.deviceName,
      severity: item.threatLevel,
      logCount: item.logCount,
      primaryThreat: item.analysis.attackVectors[0]?.name || 'Menace analysée',
      rawLogs: item.rawLogs,
    });
    setActiveTab('dashboard');
    showToast(`Analyse "${item.title}" restaurée depuis l'historique.`);
  };

  // Delete single history item
  const handleDeleteHistoryItem = (id: string) => {
    const updated = deleteHistoryItem(id);
    setHistoryList(updated);
    showToast('Entrée supprimée de l\'historique local.');
  };

  // Clear entire history
  const handleClearHistory = () => {
    clearAnalysisHistory();
    setHistoryList([]);
    showToast('Historique local des analyses effacé.');
  };

  // Ask AI about specific log
  const handleAskAiAboutLog = (log: LogEntry) => {
    setCopilotInitialQuery(
      `Peux-tu analyser en détail ce log Nebula et m'expliquer si l'attaque a réussi ou a été arrêtée, et quelle action précise je dois entreprendre ?\n\nLog: ${log.raw}`
    );
    setActiveTab('copilot');
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500 selection:text-white">
      {/* Toast Notification */}
      {toastMessage && (
        <div className="fixed bottom-6 right-6 z-50 flex items-center gap-2.5 px-4 py-3 rounded-2xl bg-cyan-950/95 text-cyan-200 border border-cyan-700 shadow-2xl backdrop-blur-md animate-bounce">
          <CheckCircle className="w-5 h-5 text-cyan-400 flex-shrink-0" />
          <span className="text-xs font-semibold">{toastMessage}</span>
        </div>
      )}

      {/* Top Header */}
      <Header
        currentScenario={currentScenario}
        onSelectScenario={handleSelectScenario}
        onOpenUpload={() => setIsUploadOpen(true)}
        onAnalyze={() => runAnalysis(rawLogs, currentScenario?.device)}
        isAnalyzing={isAnalyzing}
        threatLevel={analysis?.threatLevel}
        activeDefensesCount={activeDefenses.filter((d) => d.status === 'ACTIVE').length}
        onTestNotification={handleTriggerTestNotification}
        onOpenNebulaApi={() => setActiveTab('nebula-api')}
        onOpenCommandPalette={() => setIsCommandPaletteOpen(true)}
        isAutoRefreshEnabled={isAutoRefreshEnabled}
        onToggleAutoRefresh={(enabled) => {
          setIsAutoRefreshEnabled(enabled);
          if (enabled) {
            showToast("Auto-rafraîchissement activé : mise à jour toutes les 30s via l'API Nebula");
            handleAutoRefreshNebulaLogs(undefined, false);
          } else {
            showToast("Auto-rafraîchissement désactivé");
          }
        }}
        autoRefreshCountdown={autoRefreshCountdown}
        isAutoRefreshing={isAutoRefreshing}
        onManualRefresh={() => handleAutoRefreshNebulaLogs(undefined, true)}
        lastAutoRefreshTime={lastAutoRefreshTime}
      />

      {/* Navigation Tabs Bar with Auto-Refresh Switch */}
      <div className="bg-slate-900/80 border-b border-slate-800/80 sticky top-[69px] z-30 backdrop-blur-md">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-2.5 py-2">
            <nav className="flex space-x-1 sm:space-x-2.5 overflow-x-auto py-0.5 no-scrollbar flex-1 min-w-0">
              <button
                onClick={() => setActiveTab('dashboard')}
                className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold transition whitespace-nowrap ${
                  activeTab === 'dashboard'
                    ? 'bg-cyan-950 text-cyan-300 border border-cyan-800 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
              >
                <LayoutDashboard className="w-4 h-4" />
                <span>Tableau de Bord</span>
              </button>

              <button
                onClick={() => setActiveTab('scheduler')}
                className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold transition whitespace-nowrap ${
                  activeTab === 'scheduler'
                    ? 'bg-cyan-950 text-cyan-300 border border-cyan-800 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
              >
                <CalendarClock className="w-4 h-4 text-cyan-400" />
                <span>Planification & Tâches</span>
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              </button>

              <button
                onClick={() => setActiveTab('countermeasures')}
                className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold transition whitespace-nowrap ${
                  activeTab === 'countermeasures'
                    ? 'bg-red-950 text-red-300 border border-red-800 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
              >
                <Zap className="w-4 h-4 text-red-400" />
                <span>Centre de Riposte</span>
                {analysis && analysis.stopActions.length > 0 && (
                  <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-red-600 text-white font-mono font-bold">
                    {analysis.stopActions.length}
                  </span>
                )}
              </button>

              <button
                onClick={() => setActiveTab('deep-analysis')}
                className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold transition whitespace-nowrap ${
                  activeTab === 'deep-analysis'
                    ? 'bg-cyan-950 text-cyan-300 border border-cyan-800 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
              >
                <ShieldAlert className="w-4 h-4" />
                <span>Analyse Détaillée MITRE</span>
              </button>

              <button
                onClick={() => setActiveTab('logs')}
                className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold transition whitespace-nowrap ${
                  activeTab === 'logs'
                    ? 'bg-cyan-950 text-cyan-300 border border-cyan-800 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
              >
                <FileSearch className="w-4 h-4" />
                <span>Explorateur de Logs</span>
                <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-slate-800 text-slate-300 font-mono">
                  {parsedLogs.length}
                </span>
              </button>

              <button
                onClick={() => setActiveTab('copilot')}
                className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold transition whitespace-nowrap ${
                  activeTab === 'copilot'
                    ? 'bg-cyan-950 text-cyan-300 border border-cyan-800 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
              >
                <MessageSquare className="w-4 h-4" />
                <span>Copilote IA SOC</span>
              </button>

              <button
                onClick={() => setActiveTab('report')}
                className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold transition whitespace-nowrap ${
                  activeTab === 'report'
                    ? 'bg-cyan-950 text-cyan-300 border border-cyan-800 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
              >
                <FileCheck className="w-4 h-4" />
                <span>Rapport Certifié</span>
              </button>

              <button
                onClick={() => setActiveTab('syslog-server')}
                className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold transition whitespace-nowrap ${
                  activeTab === 'syslog-server'
                    ? 'bg-cyan-950 text-cyan-300 border border-cyan-800 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
              >
                <Radio className="w-4 h-4 text-cyan-400" />
                <span>Serveur Syslog UDP</span>
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
              </button>

              <button
                onClick={() => setActiveTab('nebula-api')}
                className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold transition whitespace-nowrap ${
                  activeTab === 'nebula-api'
                    ? 'bg-emerald-950 text-emerald-300 border border-emerald-700 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
              >
                <Cloud className="w-4 h-4 text-emerald-400" />
                <span>API Nebula Zyxel</span>
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              </button>
            </nav>

            {/* Interrupteur Auto-rafraîchissement dans la barre de navigation */}
            <div className="flex items-center justify-end flex-shrink-0 pt-1 lg:pt-0">
              <AutoRefreshNavbarSwitch
                isEnabled={isAutoRefreshEnabled}
                onToggle={(enabled) => {
                  setIsAutoRefreshEnabled(enabled);
                  if (enabled) {
                    showToast("Auto-rafraîchissement activé : mise à jour toutes les 30s via l'API Nebula");
                    handleAutoRefreshNebulaLogs(undefined, false);
                  } else {
                    showToast("Auto-rafraîchissement désactivé");
                  }
                }}
                secondsRemaining={autoRefreshCountdown}
                isRefreshing={isAutoRefreshing}
                onManualRefresh={() => handleAutoRefreshNebulaLogs(undefined, true)}
                lastRefreshedAt={lastAutoRefreshTime}
                targetSiteName={currentScenario?.device || 'Passerelle Nebula ATP'}
              />
            </div>
          </div>
        </div>

        {/* Enterprise SOC Active Context Strip */}
        <div className="bg-slate-950/70 border-t border-slate-800/60 px-4 sm:px-6 lg:px-8 py-2 text-xs font-mono">
          <div className="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-3 text-slate-400">
            <div className="flex flex-wrap items-center gap-2 sm:gap-4">
              <span className="flex items-center gap-1.5 text-slate-300">
                <span className="w-2 h-2 rounded-full bg-cyan-400" />
                <span>Passerelle :</span>
                <strong className="text-white">{currentScenario?.device || 'ATP700'}</strong>
              </span>

              <span className="text-slate-600 hidden sm:inline">•</span>

              <span className="flex items-center gap-1 text-slate-300">
                <span>Scénario :</span>
                <strong className="text-cyan-300 truncate max-w-[200px] sm:max-w-none">
                  {currentScenario?.title}
                </strong>
              </span>

              <span className="text-slate-600 hidden md:inline">•</span>

              <span className="hidden md:inline text-slate-400">
                Menace principale : <strong className="text-rose-400">{currentScenario?.primaryThreat}</strong>
              </span>
            </div>

            <div className="flex items-center gap-3">
              {isAutoRefreshEnabled ? (
                <span className="inline-flex items-center gap-1.5 text-emerald-400 text-[11px] font-mono">
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
                  <span>Auto-sync Nebula (30s) : tick dans {autoRefreshCountdown}s</span>
                </span>
              ) : (
                <span className="hidden sm:inline-flex items-center gap-1.5 text-slate-500 text-[11px] font-mono">
                  <span className="w-1.5 h-1.5 rounded-full bg-slate-600" />
                  <span>Auto-sync : En pause</span>
                </span>
              )}

              <button
                onClick={() => setIsCommandPaletteOpen(true)}
                className="inline-flex items-center gap-1 text-[11px] text-slate-400 hover:text-cyan-300 transition"
                title="Ouvrir la palette de commandes (Ctrl+K)"
              >
                <kbd className="px-1 py-0.5 rounded bg-slate-900 border border-slate-800 text-[10px]">Ctrl+K</kbd>
                <span>Commandes</span>
              </button>

              {analysis && (
                <button
                  onClick={() => setActiveTab('countermeasures')}
                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-red-950/80 hover:bg-red-900 text-red-300 border border-red-800 text-[11px] font-bold transition shadow-sm"
                  title="Accéder directement aux règles de riposte pare-feu"
                >
                  <Zap className="w-3 h-3 text-red-400" />
                  <span>Riposte ({analysis.stopActions.length})</span>
                </button>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 pt-6 pb-24">
        {isAnalyzing && !analysis && (
          <div className="py-24 text-center space-y-4">
            <div className="w-14 h-14 rounded-2xl bg-cyan-950 border border-cyan-700 mx-auto flex items-center justify-center animate-spin">
              <Zap className="w-7 h-7 text-cyan-400" />
            </div>
            <h3 className="text-base font-bold text-white">
              Analyse en temps réel des logs Nebula avec l'IA...
            </h3>
            <p className="text-xs text-slate-400 max-w-md mx-auto font-mono">
              Extraction des signatures d'attaques, cartographie MITRE ATT&CK et génération des règles de riposte pare-feu.
            </p>
          </div>
        )}

        {analysis && (
          <>
            {activeTab === 'dashboard' && (
              <DashboardView
                analysis={analysis}
                logs={parsedLogs}
                activeDefenses={activeDefenses}
                onNavigateToCountermeasures={() => setActiveTab('countermeasures')}
                onEnforceDefense={handleEnforceDefense}
                onInspectLog={handleAskAiAboutLog}
                historyList={historyList}
                onRestoreAnalysis={handleRestoreAnalysis}
                onDeleteHistoryItem={handleDeleteHistoryItem}
                onClearHistory={handleClearHistory}
                deviceName={currentScenario?.device || 'Passerelle Zyxel Nebula ATP'}
                onSelectSiteLogs={(pulledRawLogs, siteLabel) => {
                  setCurrentScenario({
                    id: `site-${Date.now()}`,
                    title: `Flux SecuReporter : ${siteLabel}`,
                    description: 'Surveillance Multi-Organisations & Multi-Sites en direct',
                    device: siteLabel,
                    severity: 'CRITICAL',
                    logCount: pulledRawLogs.split('\n').filter((l) => l.trim()).length,
                    primaryThreat: 'Synchronisation Nebula Cloud',
                    rawLogs: pulledRawLogs,
                  });
                  setRawLogs(pulledRawLogs);
                  runAnalysis(pulledRawLogs, siteLabel);
                  showToast(`Connecté à ${siteLabel} — Analyse SOC mise à jour`);
                }}
                onAppendLiveLog={(newRawLine) => {
                  setRawLogs((prev) => `${newRawLine}\n${prev}`);
                }}
                onNavigateToTab={(tab) => setActiveTab(tab)}
              />
            )}

            {activeTab === 'scheduler' && (
              <ScheduledAnalysisManager
                onSelectSiteLogs={(pulledRawLogs, siteLabel) => {
                  setCurrentScenario({
                    id: `sched-site-${Date.now()}`,
                    title: `Analyse Planifiée : ${siteLabel}`,
                    description: 'Exécution issue du planificateur de surveillance continue SOC',
                    device: siteLabel,
                    severity: 'CRITICAL',
                    logCount: pulledRawLogs.split('\n').filter((l) => l.trim()).length,
                    primaryThreat: 'Surveillance Automatique Nebula',
                    rawLogs: pulledRawLogs,
                  });
                  setRawLogs(pulledRawLogs);
                  runAnalysis(pulledRawLogs, siteLabel);
                  showToast(`Analyse planifiée synchronisée : ${siteLabel}`);
                }}
                onDefenseApplied={fetchActiveDefenses}
              />
            )}

            {activeTab === 'countermeasures' && (
              <CountermeasuresView
                stopActions={analysis.stopActions}
                activeDefenses={activeDefenses}
                onEnforceDefense={handleEnforceDefense}
                onRevokeDefense={handleRevokeDefense}
                onEnforceAll={handleEnforceAll}
                isEnforcing={isEnforcing}
              />
            )}

            {activeTab === 'deep-analysis' && <DeepAnalysisView analysis={analysis} />}

            {activeTab === 'logs' && (
              <LogExplorerView logs={parsedLogs} onAskAiAboutLog={handleAskAiAboutLog} />
            )}

            {activeTab === 'copilot' && (
              <CopilotView
                analysis={analysis}
                initialQuery={copilotInitialQuery}
                onClearInitialQuery={() => setCopilotInitialQuery(undefined)}
              />
            )}

            {activeTab === 'report' && (
              <IncidentReportView
                analysis={analysis}
                activeDefenses={activeDefenses}
                deviceName={currentScenario?.device}
              />
            )}

            {activeTab === 'syslog-server' && (
              <SyslogCollectorView
                onAnalyzeSyslogLogs={(rawLogsText, deviceContext) => {
                  setRawLogs(rawLogsText);
                  runAnalysis(rawLogsText, deviceContext);
                  setActiveTab('dashboard');
                  showToast(
                    `Logs Syslog UDP reçus transférés vers l'Analyseur IA SOC (${
                      rawLogsText.split('\n').filter((l) => l.trim()).length
                    } événements)`
                  );
                }}
                onNavigateToTab={(tab) => setActiveTab(tab as any)}
                onDefenseApplied={fetchActiveDefenses}
              />
            )}

            {activeTab === 'nebula-api' && (
              <NebulaApiView
                stopActions={analysis.stopActions}
                activeDefenses={activeDefenses}
                onNavigateToDashboard={() => setActiveTab('dashboard')}
                onPullSiteLogs={(pulledRawLogs, siteLabel) => {
                  setRawLogs(pulledRawLogs);
                  runAnalysis(pulledRawLogs, siteLabel);
                  showToast(`Logs synchronisés depuis ${siteLabel} via Zyxel Nebula API`);
                }}
                onRulePushed={(newDefense, msg) => {
                  setActiveDefenses((prev) => [
                    newDefense,
                    ...prev.filter((d) => d.id !== newDefense.id),
                  ]);
                  showToast(msg);
                }}
              />
            )}
          </>
        )}
      </main>

      {/* Command Palette Modal (Ctrl+K / Cmd+K) */}
      <CommandPaletteModal
        isOpen={isCommandPaletteOpen}
        onClose={() => setIsCommandPaletteOpen(false)}
        onNavigateTab={(tab) => setActiveTab(tab)}
        onSelectScenario={handleSelectScenario}
        onAnalyze={() => runAnalysis(rawLogs, currentScenario?.device)}
        onOpenUpload={() => setIsUploadOpen(true)}
        onTestNotification={handleTriggerTestNotification}
        onInspectIp={(ip) => {
          setActiveTab('logs');
          showToast(`Filtrage ciblé sur l'adresse IP ${ip} dans l'Explorateur de Logs`);
        }}
        analysis={analysis}
        logs={parsedLogs}
        activeDefensesCount={activeDefenses.filter((d) => d.status === 'ACTIVE').length}
        isAutoRefreshEnabled={isAutoRefreshEnabled}
        onToggleAutoRefresh={(enabled) => {
          setIsAutoRefreshEnabled(enabled);
          if (enabled) {
            showToast("Auto-rafraîchissement activé : mise à jour toutes les 30s via l'API Nebula");
            handleAutoRefreshNebulaLogs(undefined, false);
          } else {
            showToast("Auto-rafraîchissement désactivé");
          }
        }}
      />

      {/* Upload Modal */}
      <LogUploadModal
        isOpen={isUploadOpen}
        onClose={() => setIsUploadOpen(false)}
        onSubmitLogs={handleUploadSubmit}
        onSelectSample={handleSelectScenario}
      />

      {/* System Desktop Notification Banner (Web Notifications API Simulation) */}
      <SystemNotificationBanner
        notification={systemNotification}
        onClose={() => setSystemNotification(null)}
        onNavigateToCountermeasures={() => setActiveTab('countermeasures')}
      />

      {/* Global Enterprise SOC Bottom Status Bar */}
      <FooterStatusBar
        deviceName={currentScenario?.device || 'Passerelle Zyxel Nebula ATP'}
        logCount={parsedLogs.length}
        activeDefensesCount={activeDefenses.filter((d) => d.status === 'ACTIVE').length}
        threatLevel={analysis?.threatLevel}
        onOpenCommandPalette={() => setIsCommandPaletteOpen(true)}
        onOpenNebulaApi={() => setActiveTab('nebula-api')}
        isAnalyzing={isAnalyzing}
      />
    </div>
  );
}
