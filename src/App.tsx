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
  ArrowRight,
  X,
  Flame,
  Upload,
  Sparkles,
  HelpCircle,
} from 'lucide-react';
import { Header } from './components/Header';
import { HelpGuideModal } from './components/HelpGuideModal';
import { DashboardView } from './components/DashboardView';
import { CountermeasuresView } from './components/CountermeasuresView';
import { DeepAnalysisView } from './components/DeepAnalysisView';
import { LogExplorerView } from './components/LogExplorerView';
import { CopilotView } from './components/CopilotView';
import { IncidentReportView } from './components/IncidentReportView';
import { NebulaApiView } from './components/NebulaApiView';
import { ScheduledAnalysisManager } from './components/ScheduledAnalysisManager';
import { SyslogCollectorView } from './components/SyslogCollectorView';
import { KnownAttacksView } from './components/KnownAttacksView';
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
    | 'known-attacks'
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
  const [toasts, setToasts] = useState<
    Array<{ id: string; type: 'success' | 'warning' | 'error' | 'info'; message: string }>
  >([]);
  const [historyList, setHistoryList] = useState<AnalysisHistoryItem[]>(() => getStoredAnalysisHistory());
  const [systemNotification, setSystemNotification] = useState<SystemNotificationPayload | null>(null);
  const [isCommandPaletteOpen, setIsCommandPaletteOpen] = useState<boolean>(false);
  const [isHelpGuideOpen, setIsHelpGuideOpen] = useState<boolean>(false);

  // Auto-refresh state (every 30 seconds via Nebula API)
  const [isAutoRefreshEnabled, setIsAutoRefreshEnabled] = useState<boolean>(() => {
    return localStorage.getItem('nebula_auto_refresh_active') === 'true';
  });
  const [autoRefreshCountdown, setAutoRefreshCountdown] = useState<number>(30);
  const [isAutoRefreshing, setIsAutoRefreshing] = useState<boolean>(false);
  const [lastAutoRefreshTime, setLastAutoRefreshTime] = useState<Date | null>(null);

  // Global Keyboard Shortcuts: Cmd+K / Ctrl+K for Command Palette & 1-9 for Tab Switch
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement;
      const isInput =
        target.tagName === 'INPUT' ||
        target.tagName === 'TEXTAREA' ||
        target.tagName === 'SELECT' ||
        target.isContentEditable;

      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setIsCommandPaletteOpen((prev) => !prev);
        return;
      }

      if (!isInput && !e.metaKey && !e.ctrlKey && !e.altKey) {
        const tabs: Array<
          | 'dashboard'
          | 'scheduler'
          | 'countermeasures'
          | 'deep-analysis'
          | 'logs'
          | 'copilot'
          | 'report'
          | 'syslog-server'
          | 'nebula-api'
          | 'known-attacks'
        > = [
          'dashboard',
          'countermeasures',
          'deep-analysis',
          'logs',
          'known-attacks',
          'copilot',
          'report',
          'nebula-api',
          'syslog-server',
          'scheduler',
        ];
        if (e.key === '0') {
          e.preventDefault();
          setActiveTab('scheduler');
          return;
        }
        const num = parseInt(e.key, 10);
        if (num >= 1 && num <= 9) {
          e.preventDefault();
          setActiveTab(tabs[num - 1]);
        }
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const showToast = useCallback(
    (msg: string, type: 'success' | 'warning' | 'error' | 'info' = 'success') => {
      const id = `toast-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
      setToasts((prev) => [...prev, { id, type, message: msg }]);
      setTimeout(() => {
        setToasts((prev) => prev.filter((t) => t.id !== id));
      }, 4200);
    },
    []
  );

  const removeToast = (id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
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
        onOpenKnownAttacks={() => setActiveTab('known-attacks')}
        onOpenCommandPalette={() => setIsCommandPaletteOpen(true)}
        onOpenHelpGuide={() => setIsHelpGuideOpen(true)}
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

      {/* Clean & Professional SOC Navigation Bar */}
      <nav className="bg-slate-900/95 border-b border-slate-800/90 sticky top-[61px] z-30 backdrop-blur-md shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between overflow-x-auto no-scrollbar py-1.5 gap-2">
            {/* Primary SOC Workflow Tabs */}
            <div className="flex items-center space-x-1 min-w-max">
              {/* 1. Tableau de Bord */}
              <button
                type="button"
                onClick={() => setActiveTab('dashboard')}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold transition whitespace-nowrap ${
                  activeTab === 'dashboard'
                    ? 'bg-slate-800 text-white border-b-2 border-cyan-400 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
                title="Tableau de Bord SOC (Raccourci : 1)"
              >
                <LayoutDashboard className="w-4 h-4 text-cyan-400" />
                <span>Tableau de Bord</span>
              </button>

              {/* 2. Centre de Riposte */}
              <button
                type="button"
                onClick={() => setActiveTab('countermeasures')}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold transition whitespace-nowrap ${
                  activeTab === 'countermeasures'
                    ? 'bg-red-950/80 text-red-200 border-b-2 border-red-500 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
                title="Centre de Riposte & Pare-Feu (Raccourci : 2)"
              >
                <Zap className="w-4 h-4 text-red-400" />
                <span>Centre de Riposte</span>
                {analysis && analysis.stopActions.length > 0 && (
                  <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-red-600 text-white font-mono font-bold">
                    {analysis.stopActions.length}
                  </span>
                )}
              </button>

              {/* 3. Analyse MITRE */}
              <button
                type="button"
                onClick={() => setActiveTab('deep-analysis')}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold transition whitespace-nowrap ${
                  activeTab === 'deep-analysis'
                    ? 'bg-slate-800 text-white border-b-2 border-cyan-400 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
                title="Analyse Détaillée MITRE ATT&CK (Raccourci : 3)"
              >
                <ShieldAlert className="w-4 h-4 text-cyan-400" />
                <span>Analyse MITRE</span>
              </button>

              {/* 4. Explorateur de Logs */}
              <button
                type="button"
                onClick={() => setActiveTab('logs')}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold transition whitespace-nowrap ${
                  activeTab === 'logs'
                    ? 'bg-slate-800 text-white border-b-2 border-cyan-400 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
                title="Explorateur de Logs SecuReporter (Raccourci : 4)"
              >
                <FileSearch className="w-4 h-4 text-cyan-400" />
                <span>Logs</span>
                <span className="px-1.5 py-0.2 rounded text-[10px] bg-slate-800 text-slate-400 font-mono">
                  {parsedLogs.length}
                </span>
              </button>

              {/* 5. Attaques Connues (IA) */}
              <button
                type="button"
                onClick={() => setActiveTab('known-attacks')}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold transition whitespace-nowrap ${
                  activeTab === 'known-attacks'
                    ? 'bg-slate-800 text-white border-b-2 border-cyan-400 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
                title="Référentiel des Attaques Connues avec IA (Raccourci : 5)"
              >
                <Sparkles className="w-4 h-4 text-cyan-400" />
                <span>Attaques IA</span>
              </button>

              {/* 6. Copilote IA */}
              <button
                type="button"
                onClick={() => setActiveTab('copilot')}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold transition whitespace-nowrap ${
                  activeTab === 'copilot'
                    ? 'bg-slate-800 text-white border-b-2 border-cyan-400 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
                title="Copilote IA SOC (Raccourci : 6)"
              >
                <MessageSquare className="w-4 h-4 text-cyan-400" />
                <span>Copilote IA</span>
              </button>

              {/* 7. Rapport Certifié */}
              <button
                type="button"
                onClick={() => setActiveTab('report')}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold transition whitespace-nowrap ${
                  activeTab === 'report'
                    ? 'bg-slate-800 text-white border-b-2 border-cyan-400 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
                title="Rapport Certifié CISO & Export (Raccourci : 7)"
              >
                <FileCheck className="w-4 h-4 text-cyan-400" />
                <span>Rapport</span>
              </button>
            </div>

            {/* Secondary Connectors & Tools Group */}
            <div className="flex items-center space-x-1 min-w-max border-l border-slate-800 pl-2">
              {/* 8. API Nebula */}
              <button
                type="button"
                onClick={() => setActiveTab('nebula-api')}
                className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium transition whitespace-nowrap ${
                  activeTab === 'nebula-api'
                    ? 'bg-emerald-950 text-emerald-300 font-semibold border border-emerald-800 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
                title="Connecteur Zyxel Nebula API (Raccourci : 8)"
              >
                <Cloud className="w-3.5 h-3.5 text-emerald-400" />
                <span>API Nebula</span>
              </button>

              {/* 9. Syslog Server */}
              <button
                type="button"
                onClick={() => setActiveTab('syslog-server')}
                className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium transition whitespace-nowrap ${
                  activeTab === 'syslog-server'
                    ? 'bg-slate-800 text-cyan-300 font-semibold border border-cyan-800 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
                title="Serveur Syslog UDP (Raccourci : 9)"
              >
                <Radio className="w-3.5 h-3.5 text-cyan-400" />
                <span>Syslog UDP</span>
              </button>

              {/* 0. Planification & Tâches */}
              <button
                type="button"
                onClick={() => setActiveTab('scheduler')}
                className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium transition whitespace-nowrap ${
                  activeTab === 'scheduler'
                    ? 'bg-slate-800 text-cyan-300 font-semibold border border-cyan-800 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
                title="Planification & Tâches (Raccourci : 0)"
              >
                <CalendarClock className="w-3.5 h-3.5 text-cyan-400" />
                <span>Tâches</span>
              </button>
            </div>
          </div>
        </div>
      </nav>

      {/* Quick Attack Scenario Switcher Bar */}
      <div className="bg-slate-900/60 border-b border-slate-800/70 text-xs">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-2 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2 min-w-0">
            <span className="text-[11px] font-mono text-slate-400 flex items-center gap-1.5 flex-shrink-0">
              <Flame className="w-3.5 h-3.5 text-rose-400" />
              <span className="hidden sm:inline">Scénario actif :</span>
            </span>
            <span className="text-white font-semibold text-xs truncate max-w-xs sm:max-w-sm">
              {currentScenario?.title || 'Analyse en direct'}
            </span>
            <span
              className={`text-[9px] font-mono font-bold px-1.5 py-0.2 rounded uppercase flex-shrink-0 ${
                currentScenario?.severity === 'CRITICAL'
                  ? 'bg-rose-950 text-rose-300 border border-rose-800'
                  : 'bg-amber-950 text-amber-300 border border-amber-800'
              }`}
            >
              {currentScenario?.severity || 'CRITICAL'}
            </span>
          </div>

          <div className="flex items-center gap-1.5 flex-wrap">
            <span className="text-[10px] text-slate-500 font-mono hidden md:inline mr-1">
              Tester en 1-clic :
            </span>
            {SAMPLE_REPORTS.map((sc) => {
              const isActive = currentScenario?.id === sc.id;
              return (
                <button
                  key={sc.id}
                  type="button"
                  onClick={() => handleSelectScenario(sc)}
                  className={`px-2.5 py-1 rounded-lg text-[11px] font-mono transition flex items-center gap-1.5 ${
                    isActive
                      ? 'bg-cyan-950 text-cyan-300 border border-cyan-700 font-bold shadow-sm'
                      : 'bg-slate-850 hover:bg-slate-800 text-slate-300 border border-slate-800 hover:border-slate-700'
                  }`}
                  title={`Charger le scénario ${sc.title}`}
                >
                  <span className={`w-1.5 h-1.5 rounded-full ${sc.severity === 'CRITICAL' ? 'bg-rose-400' : 'bg-amber-400'}`} />
                  <span className="truncate max-w-[130px] sm:max-w-none">{sc.title.replace('Scénario : ', '')}</span>
                </button>
              );
            })}
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

        {!analysis && !isAnalyzing && activeTab === 'known-attacks' && (
          <KnownAttacksView
            onTestAttackScenario={(sampleLogs, attackTitle) => {
              const newSc = {
                id: `scenario-${Date.now()}`,
                title: `Test : ${attackTitle}`,
                description: `Scénario de test issu du Référentiel des Attaques Connues avec IA`,
                device: 'Passerelle Zyxel Nebula ATP700',
                severity: 'CRITICAL' as const,
                logCount: sampleLogs.split('\n').filter((l) => l.trim()).length,
                primaryThreat: attackTitle,
                rawLogs: sampleLogs,
              };
              setCurrentScenario(newSc);
              setRawLogs(sampleLogs);
              runAnalysis(sampleLogs, 'Passerelle Zyxel Nebula ATP700');
              setActiveTab('dashboard');
              showToast(`Scénario chargé : ${attackTitle}. Analyse SOC en cours...`);
            }}
            onDefenseApplied={fetchActiveDefenses}
            onNavigateToTab={(tab) => setActiveTab(tab as any)}
          />
        )}

        {!analysis && !isAnalyzing && activeTab !== 'known-attacks' && (
          <div className="py-8 space-y-8 animate-in fade-in duration-300">
            <div className="p-8 rounded-3xl bg-gradient-to-br from-slate-900 via-slate-900/90 to-cyan-950/40 border border-slate-800 shadow-2xl relative overflow-hidden">
              <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />
              <div className="max-w-3xl relative z-10">
                <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-950/80 border border-cyan-800 text-cyan-300 text-xs font-mono font-bold mb-4">
                  <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
                  Console SOC SecuReporter Prête
                </div>
                <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight mb-3">
                  Surveillance & Riposte Automatisée Zyxel Nebula
                </h2>
                <p className="text-sm text-slate-300 leading-relaxed font-sans mb-6">
                  Analysez les flux de télémétrie SecuReporter (IDP/IPS, Antivirus, Réputation IP, Anomalies de Trafic), corrélés en temps réel avec les techniques MITRE ATT&CK et générez instantanément les règles pare-feu Zyxel CLI et Nebula OpenAPI.
                </p>

                <div className="flex flex-wrap items-center gap-3">
                  <button
                    onClick={() => {
                      if (SAMPLE_REPORTS[0]) {
                        handleSelectScenario(SAMPLE_REPORTS[0]);
                      }
                    }}
                    className="inline-flex items-center gap-2 px-5 py-3 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-mono text-xs font-bold shadow-lg shadow-cyan-950 border border-cyan-400/40 transition"
                  >
                    <Zap className="w-4 h-4" />
                    <span>Lancer Analyse Scénario Ransomware</span>
                  </button>

                  <button
                    onClick={() => setIsUploadOpen(true)}
                    className="inline-flex items-center gap-2 px-4 py-3 rounded-xl bg-slate-800/80 hover:bg-slate-750 text-slate-200 font-mono text-xs font-semibold border border-slate-700 transition"
                  >
                    <Upload className="w-4 h-4 text-cyan-400" />
                    <span>Importer des Logs Personnalisés</span>
                  </button>

                  <button
                    onClick={() => setActiveTab('nebula-api')}
                    className="inline-flex items-center gap-2 px-4 py-3 rounded-xl bg-emerald-950/60 hover:bg-emerald-900/60 text-emerald-300 font-mono text-xs font-semibold border border-emerald-800/70 transition"
                  >
                    <Cloud className="w-4 h-4 text-emerald-400" />
                    <span>Tester Connecteur Zyxel Nebula NCC</span>
                  </button>
                </div>
              </div>
            </div>

            {/* Quick Scenario Cards */}
            <div>
              <h3 className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider mb-4 flex items-center gap-2">
                <Flame className="w-4 h-4 text-rose-400" />
                Scénarios d'Attaque Échantillons SecuReporter
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                {SAMPLE_REPORTS.map((sc) => (
                  <div
                    key={sc.id}
                    onClick={() => handleSelectScenario(sc)}
                    className="p-5 rounded-2xl bg-slate-900/80 hover:bg-slate-850 border border-slate-800 hover:border-cyan-500/50 transition cursor-pointer flex flex-col justify-between group shadow-lg"
                  >
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <span
                          className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded-full uppercase ${
                            sc.severity === 'CRITICAL'
                              ? 'bg-rose-950 text-rose-300 border border-rose-800'
                              : 'bg-amber-950 text-amber-300 border border-amber-800'
                          }`}
                        >
                          {sc.severity}
                        </span>
                        <span className="text-[10px] font-mono text-slate-500">
                          {sc.logCount} logs
                        </span>
                      </div>
                      <h4 className="text-sm font-bold text-white group-hover:text-cyan-300 transition">
                        {sc.title}
                      </h4>
                      <p className="text-xs text-slate-400 line-clamp-2">
                        {sc.description}
                      </p>
                    </div>

                    <div className="pt-4 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono text-cyan-400 font-semibold group-hover:translate-x-0.5 transition-transform">
                      <span>Charger Scénario</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {analysis && (
          <>
            {/* Enterprise SOC Emergency Threat Banner */}
            {(analysis.threatLevel === 'CRITICAL' || analysis.riskScore >= 75) && activeTab !== 'countermeasures' && (
              <div className="mb-6 p-4 sm:p-5 rounded-2xl bg-gradient-to-r from-rose-950/90 via-slate-900 to-slate-900 border border-rose-500/60 shadow-2xl flex flex-col md:flex-row md:items-center justify-between gap-4 animate-in fade-in">
                <div className="flex items-center gap-3.5">
                  <div className="w-11 h-11 rounded-xl bg-rose-900/60 border border-rose-500/70 flex items-center justify-center text-rose-400 flex-shrink-0 animate-pulse">
                    <AlertTriangle className="w-6 h-6" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-mono font-bold text-rose-300 uppercase tracking-wider">
                        Alerte Critique SOC (Score: {analysis.riskScore}/100)
                      </span>
                      <span className="text-slate-600 hidden sm:inline">•</span>
                      <span className="text-xs font-semibold text-white truncate max-w-sm sm:max-w-none">
                        {analysis.attackVectors[0]?.name || 'Attaque active en cours'}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 font-mono mt-0.5">
                      {analysis.stopActions.length} règle(s) de riposte prête(s) pour neutraliser les flux malveillants et isoler les postes infectés.
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-2.5 flex-shrink-0 self-start md:self-auto">
                  <button
                    type="button"
                    onClick={handleEnforceAll}
                    disabled={isEnforcing || analysis.stopActions.length === 0}
                    className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-rose-600 to-red-600 hover:from-rose-500 hover:to-red-500 text-white font-mono text-xs font-bold shadow-lg shadow-rose-950/70 border border-rose-400/40 transition disabled:opacity-50"
                  >
                    <Zap className={`w-3.5 h-3.5 ${isEnforcing ? 'animate-spin' : ''}`} />
                    <span>{isEnforcing ? 'Riposte en cours...' : 'Déclencher Riposte Totale'}</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => setActiveTab('countermeasures')}
                    className="inline-flex items-center gap-1.5 px-3 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono font-semibold border border-slate-700 transition"
                  >
                    <span>Inspecter</span>
                    <ArrowRight className="w-3.5 h-3.5 text-rose-400" />
                  </button>
                </div>
              </div>
            )}

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

            {activeTab === 'deep-analysis' && (
              <DeepAnalysisView
                analysis={analysis}
                onEnforceDefense={handleEnforceDefense}
                onNavigateToCountermeasures={() => setActiveTab('countermeasures')}
                activeDefenses={activeDefenses}
              />
            )}

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

            {activeTab === 'known-attacks' && (
              <KnownAttacksView
                onTestAttackScenario={(sampleLogs, attackTitle) => {
                  const newSc = {
                    id: `scenario-${Date.now()}`,
                    title: `Test : ${attackTitle}`,
                    description: `Scénario de test issu du Référentiel des Attaques Connues avec IA`,
                    device: 'Passerelle Zyxel Nebula ATP700',
                    severity: 'CRITICAL' as const,
                    logCount: sampleLogs.split('\n').filter((l) => l.trim()).length,
                    primaryThreat: attackTitle,
                    rawLogs: sampleLogs,
                  };
                  setCurrentScenario(newSc);
                  setRawLogs(sampleLogs);
                  runAnalysis(sampleLogs, 'Passerelle Zyxel Nebula ATP700');
                  setActiveTab('dashboard');
                  showToast(`Scénario chargé : ${attackTitle}. Analyse SOC en cours...`);
                }}
                onDefenseApplied={fetchActiveDefenses}
                onNavigateToTab={(tab) => setActiveTab(tab as any)}
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

      {/* Interactive Quick Help & Onboarding Guide Modal */}
      <HelpGuideModal
        isOpen={isHelpGuideOpen}
        onClose={() => setIsHelpGuideOpen(false)}
        onNavigateToTab={(tab) => setActiveTab(tab as any)}
      />

      {/* System Desktop Notification Banner (Web Notifications API Simulation) */}
      <SystemNotificationBanner
        notification={systemNotification}
        onClose={() => setSystemNotification(null)}
        onNavigateToCountermeasures={() => setActiveTab('countermeasures')}
      />

      {/* Real-Time SOC Toast Notification Container */}
      <div className="fixed bottom-14 right-4 z-50 flex flex-col gap-2.5 max-w-sm w-full pointer-events-none">
        {toasts.map((toast) => (
          <div
            key={toast.id}
            className={`pointer-events-auto p-3.5 rounded-2xl shadow-2xl border backdrop-blur-xl flex items-start gap-3 transition-all duration-300 animate-in slide-in-from-bottom-3 ${
              toast.type === 'success'
                ? 'bg-slate-950/95 border-emerald-500/70 text-emerald-200 shadow-emerald-950/50'
                : toast.type === 'error'
                ? 'bg-slate-950/95 border-rose-500/70 text-rose-200 shadow-rose-950/50'
                : toast.type === 'warning'
                ? 'bg-slate-950/95 border-amber-500/70 text-amber-200 shadow-amber-950/50'
                : 'bg-slate-950/95 border-cyan-500/70 text-cyan-200 shadow-cyan-950/50'
            }`}
          >
            <div className="mt-0.5 flex-shrink-0">
              {toast.type === 'success' ? (
                <CheckCircle className="w-4 h-4 text-emerald-400" />
              ) : toast.type === 'error' ? (
                <AlertTriangle className="w-4 h-4 text-rose-400" />
              ) : toast.type === 'warning' ? (
                <AlertTriangle className="w-4 h-4 text-amber-400" />
              ) : (
                <Zap className="w-4 h-4 text-cyan-400" />
              )}
            </div>
            <div className="flex-1 text-xs font-mono font-medium leading-relaxed">
              {toast.message}
            </div>
            <button
              type="button"
              onClick={() => removeToast(toast.id)}
              className="text-slate-400 hover:text-white p-0.5 rounded transition"
              title="Fermer la notification"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        ))}
      </div>

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
