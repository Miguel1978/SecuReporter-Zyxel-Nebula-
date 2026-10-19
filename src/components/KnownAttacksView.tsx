import React, { useState, useEffect, useMemo } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Zap,
  Sparkles,
  Search,
  Filter,
  RefreshCw,
  Terminal,
  Copy,
  Check,
  ExternalLink,
  Flame,
  Globe,
  Lock,
  ArrowRight,
  ChevronDown,
  Layers,
  Database,
  Radio,
  FileText,
  AlertTriangle,
  Play,
  RotateCcw,
  SlidersHorizontal,
  Info,
  X,
  Cpu,
  Laptop,
} from 'lucide-react';
import { KnownAttackItem, KnownAttackCategory, SeverityLevel, ActiveDefense } from '../types';

interface KnownAttacksViewProps {
  onTestAttackScenario: (sampleLogs: string, attackTitle: string) => void;
  onDefenseApplied?: () => void;
  onNavigateToTab?: (tab: string) => void;
}

const CATEGORIES: Array<{ id: KnownAttackCategory | 'ALL'; label: string; icon: string }> = [
  { id: 'ALL', label: 'Toutes les Attaques', icon: '🌐' },
  { id: 'Ransomware', label: 'Ransomware & Extorsion', icon: '🔒' },
  { id: 'VPN & Gateway Exploit', label: 'Failles VPN & Pare-feu', icon: '🛡️' },
  { id: 'RCE & Exploitation', label: 'Exploits RCE', icon: '💥' },
  { id: 'C2 & Post-Exploitation', label: 'Balises C2 & Mouvement Latéral', icon: '📡' },
  { id: 'DDoS & Botnet', label: 'Botnets & DDoS', icon: '🤖' },
  { id: 'Credential Access', label: 'Vol d\'Identifiants & MFA', icon: '🔑' },
  { id: 'Supply Chain', label: 'Supply Chain & Zero-Days', icon: '⛓️' },
  { id: 'Phishing & Stealer', label: 'Phishing & InfoStealers', icon: '🎣' },
];

export const KnownAttacksView: React.FC<KnownAttacksViewProps> = ({
  onTestAttackScenario,
  onDefenseApplied,
  onNavigateToTab,
}) => {
  const [attacks, setAttacks] = useState<KnownAttackItem[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isUpdatingAi, setIsUpdatingAi] = useState<boolean>(false);
  const [lastAiUpdate, setLastAiUpdate] = useState<string>('');
  const [sourceInfo, setSourceInfo] = useState<string>('SecuReporter Threat Cloud');
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [selectedCategory, setSelectedCategory] = useState<KnownAttackCategory | 'ALL'>('ALL');
  const [selectedSeverity, setSelectedSeverity] = useState<SeverityLevel | 'ALL'>('ALL');
  const [aiFocusCategory, setAiFocusCategory] = useState<string>('ALL');
  const [customAiPrompt, setCustomAiPrompt] = useState<string>('');
  const [showAiControls, setShowAiControls] = useState<boolean>(false);
  const [inspectAttack, setInspectAttack] = useState<KnownAttackItem | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const [deployingId, setDeployingId] = useState<string | null>(null);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3800);
  };

  // Fetch attacks from backend
  const fetchAttacks = async () => {
    setIsLoading(true);
    try {
      const res = await fetch('/api/known-attacks');
      if (res.ok) {
        const data = await res.json();
        setAttacks(data.attacks || []);
        setLastAiUpdate(data.lastAiUpdate || '');
      }
    } catch (e) {
      console.error('Failed to fetch known attacks:', e);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchAttacks();
  }, []);

  // Update attacks with Gemini AI
  const handleUpdateWithAi = async () => {
    setIsUpdatingAi(true);
    try {
      const res = await fetch('/api/known-attacks/update-with-ai', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          focusCategory: aiFocusCategory !== 'ALL' ? aiFocusCategory : undefined,
          customPrompt: customAiPrompt.trim() ? customAiPrompt.trim() : undefined,
          replaceExisting: false,
        }),
      });

      if (!res.ok) throw new Error('Erreur lors de la mise à jour IA');
      const data = await res.json();

      setAttacks(data.attacks || []);
      setLastAiUpdate(data.lastAiUpdate || new Date().toISOString());
      setSourceInfo(data.source || 'Gemini AI Threat Intelligence');
      showToast(data.message || 'Référentiel des attaques enrichi avec l\'IA.');
      setCustomAiPrompt('');
    } catch (err: any) {
      console.error('AI update error:', err);
      showToast('Erreur lors de l\'interrogation de l\'IA. Mode de secours activé.');
    } finally {
      setIsUpdatingAi(false);
    }
  };

  // Reset to default
  const handleReset = async () => {
    if (!window.confirm('Réinitialiser le référentiel aux attaques de référence SecuReporter ?')) return;
    try {
      const res = await fetch('/api/known-attacks/reset', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setAttacks(data.attacks || []);
        showToast('Référentiel réinitialisé avec succès.');
      }
    } catch (e) {
      console.error(e);
    }
  };

  // Deploy mitigation rule for attack
  const handleDeployMitigation = async (attack: KnownAttackItem) => {
    setDeployingId(attack.id);
    try {
      const res = await fetch('/api/known-attacks/deploy-mitigation', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ attackId: attack.id }),
      });

      if (res.ok) {
        const data = await res.json();
        showToast(`Règle pare-feu Zyxel déployée : ${attack.zyxelMitigation.ruleName}`);
        if (onDefenseApplied) onDefenseApplied();
      }
    } catch (e) {
      console.error(e);
      showToast('Échec du déploiement de la riposte.');
    } finally {
      setDeployingId(null);
    }
  };

  // Copy text to clipboard
  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Filtered attacks
  const filteredAttacks = useMemo(() => {
    return attacks.filter((attack) => {
      // Category filter
      if (selectedCategory !== 'ALL' && attack.category !== selectedCategory) {
        return false;
      }
      // Severity filter
      if (selectedSeverity !== 'ALL' && attack.severity !== selectedSeverity) {
        return false;
      }
      // Search term
      if (searchTerm.trim()) {
        const term = searchTerm.toLowerCase();
        const inName = attack.name.toLowerCase().includes(term);
        const inAlias = attack.alias?.toLowerCase().includes(term);
        const inCve = attack.cveList.some((c) => c.toLowerCase().includes(term));
        const inMitre = attack.mitreTechniqueId.toLowerCase().includes(term) || attack.mitreTactic.toLowerCase().includes(term);
        const inActor = attack.threatActor?.toLowerCase().includes(term);
        const inDesc = attack.description.toLowerCase().includes(term);
        const inProto = attack.targetProtocols.some((p) => p.toLowerCase().includes(term));
        if (!inName && !inAlias && !inCve && !inMitre && !inActor && !inDesc && !inProto) {
          return false;
        }
      }
      return true;
    });
  }, [attacks, selectedCategory, selectedSeverity, searchTerm]);

  // Statistics
  const criticalCount = attacks.filter((a) => a.severity === 'CRITICAL').length;
  const cveCount = attacks.reduce((acc, a) => acc + (a.cveList?.length || 0), 0);
  const vpnExploitsCount = attacks.filter((a) => a.category === 'VPN & Gateway Exploit').length;

  return (
    <div className="space-y-6">
      {/* Toast Notification */}
      {toastMessage && (
        <div className="fixed bottom-16 right-6 z-50 flex items-center gap-2.5 px-4 py-3 rounded-2xl bg-cyan-950/95 text-cyan-200 border border-cyan-600 shadow-2xl backdrop-blur-md animate-in slide-in-from-bottom-2">
          <Check className="w-4 h-4 text-cyan-400" />
          <span className="text-xs font-mono font-semibold">{toastMessage}</span>
        </div>
      )}

      {/* Top Banner & KPI Metrics */}
      <div className="p-6 rounded-3xl bg-gradient-to-br from-slate-900 via-slate-900/95 to-cyan-950/40 border border-slate-800 shadow-2xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 relative z-10">
          <div className="space-y-2 max-w-2xl">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-cyan-950/90 border border-cyan-800 text-cyan-300 text-xs font-mono font-bold">
                <Sparkles className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
                Moteur Cyber Threat Intelligence IA
              </span>
              <span className="text-xs font-mono text-slate-400">
                SecuReporter & Gemini 3.8 Flash
              </span>
            </div>
            <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight flex items-center gap-3">
              Référentiel des Attaques Connues & Vulnérabilités Majeures
            </h2>
            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed font-sans">
              Base de connaissances active des cyberattaques les plus redoutables (Ransomware, failles VPN/Gateways, CVEs RCE, botnets IoT). Chaque menace intègre sa signature Zyxel IDP/IPS, sa commande pare-feu ZySH et un scénario de test SecuReporter.
            </p>
          </div>

          {/* Quick AI Update Button */}
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3 flex-shrink-0">
            <button
              onClick={handleUpdateWithAi}
              disabled={isUpdatingAi}
              className="inline-flex items-center justify-center gap-2 px-5 py-3.5 rounded-2xl bg-gradient-to-r from-cyan-600 via-blue-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-white font-mono text-xs font-bold shadow-xl shadow-cyan-950 border border-cyan-400/40 transition disabled:opacity-50"
            >
              <Sparkles className={`w-4 h-4 text-cyan-200 ${isUpdatingAi ? 'animate-spin' : ''}`} />
              <span>{isUpdatingAi ? 'Génération IA en cours...' : 'Mettre à jour avec l\'IA'}</span>
            </button>

            <button
              onClick={() => setShowAiControls(!showAiControls)}
              className={`inline-flex items-center justify-center gap-2 px-3.5 py-3.5 rounded-2xl text-xs font-mono font-semibold border transition ${
                showAiControls
                  ? 'bg-cyan-950 text-cyan-300 border-cyan-700'
                  : 'bg-slate-800/80 hover:bg-slate-700 text-slate-300 border-slate-700'
              }`}
              title="Options d'actualisation ciblée de l'IA"
            >
              <SlidersHorizontal className="w-4 h-4 text-cyan-400" />
              <span className="hidden sm:inline">Options IA</span>
            </button>
          </div>
        </div>

        {/* AI Options Drawer */}
        {showAiControls && (
          <div className="mt-6 pt-5 border-t border-slate-800/80 grid grid-cols-1 md:grid-cols-3 gap-4 animate-in fade-in">
            <div>
              <label className="text-xs font-mono text-slate-400 mb-1.5 block">
                Cibler une Catégorie de Menaces
              </label>
              <select
                value={aiFocusCategory}
                onChange={(e) => setAiFocusCategory(e.target.value)}
                className="w-full bg-slate-950 text-slate-200 text-xs font-mono rounded-xl px-3 py-2.5 border border-slate-700 focus:outline-none focus:ring-1 focus:ring-cyan-500"
              >
                <option value="ALL">Toutes les menaces mondiales (Global CTI)</option>
                <option value="Ransomware">Campagnes Ransomware & Extorsion 2024-2026</option>
                <option value="VPN & Gateway Exploit">Failles Zéro-Day Pare-feu & Passerelles VPN</option>
                <option value="RCE & Exploitation">Exploitation de Code à Distance (RCE)</option>
                <option value="DDoS & Botnet">Botnets IoT & Attaques DDoS distribuées</option>
                <option value="Credential Access">Vol d'Identifiants & Contournement MFA</option>
                <option value="Supply Chain">Attaques Chaîne d'Approvisionnement (Supply Chain)</option>
              </select>
            </div>

            <div>
              <label className="text-xs font-mono text-slate-400 mb-1.5 block">
                Consigne Spécifique pour l'IA (Optionnel)
              </label>
              <input
                type="text"
                placeholder="Ex: Menaces récentes ciblant les routeurs industriels..."
                value={customAiPrompt}
                onChange={(e) => setCustomAiPrompt(e.target.value)}
                className="w-full bg-slate-950 text-slate-200 text-xs font-mono rounded-xl px-3 py-2.5 border border-slate-700 focus:outline-none focus:ring-1 focus:ring-cyan-500 placeholder-slate-600"
              />
            </div>

            <div className="flex items-end gap-2">
              <button
                onClick={handleUpdateWithAi}
                disabled={isUpdatingAi}
                className="flex-1 inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-mono text-xs font-bold transition disabled:opacity-50"
              >
                <Sparkles className="w-3.5 h-3.5" />
                <span>Lancer Actualisation Ciblée</span>
              </button>

              <button
                onClick={handleReset}
                className="p-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white border border-slate-700 transition"
                title="Réinitialiser le référentiel"
              >
                <RotateCcw className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}

        {/* 4 Stat Badges */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-6 pt-5 border-t border-slate-800/80">
          <div className="p-3 rounded-2xl bg-slate-950/60 border border-slate-800">
            <span className="text-[10px] font-mono text-slate-400 block uppercase">Total Attaques Répertoriées</span>
            <div className="text-xl font-bold font-mono text-white mt-0.5 flex items-center gap-2">
              <Database className="w-4 h-4 text-cyan-400" />
              <span>{attacks.length}</span>
            </div>
          </div>

          <div className="p-3 rounded-2xl bg-slate-950/60 border border-slate-800">
            <span className="text-[10px] font-mono text-slate-400 block uppercase">Attaques Critiques (CVSS &ge; 9.0)</span>
            <div className="text-xl font-bold font-mono text-rose-400 mt-0.5 flex items-center gap-2">
              <Flame className="w-4 h-4 text-rose-500" />
              <span>{criticalCount}</span>
            </div>
          </div>

          <div className="p-3 rounded-2xl bg-slate-950/60 border border-slate-800">
            <span className="text-[10px] font-mono text-slate-400 block uppercase">Failles Passereaux & VPN</span>
            <div className="text-xl font-bold font-mono text-amber-300 mt-0.5 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-amber-400" />
              <span>{vpnExploitsCount}</span>
            </div>
          </div>

          <div className="p-3 rounded-2xl bg-slate-950/60 border border-slate-800">
            <span className="text-[10px] font-mono text-slate-400 block uppercase">Dernière Synthèse IA</span>
            <div className="text-xs font-mono text-emerald-400 mt-1 truncate" title={lastAiUpdate}>
              {lastAiUpdate ? new Date(lastAiUpdate).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' }) : 'Actif'} · {sourceInfo.split(' ')[0]}
            </div>
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="space-y-3">
        <div className="flex flex-col md:flex-row gap-3">
          {/* Search Input */}
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-3" />
            <input
              type="text"
              placeholder="Rechercher par CVE (ex: CVE-2024-21762), nom, technique MITRE (T1190), protocole..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2.5 rounded-2xl bg-slate-900 border border-slate-800 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 text-xs font-mono text-white placeholder-slate-500 transition"
            />
            {searchTerm && (
              <button
                onClick={() => setSearchTerm('')}
                className="absolute right-3 top-3 text-slate-500 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            )}
          </div>

          {/* Severity selector */}
          <div className="flex items-center gap-2 flex-shrink-0">
            <span className="text-xs font-mono text-slate-400 hidden sm:inline">Sévérité :</span>
            {(['ALL', 'CRITICAL', 'HIGH'] as const).map((sev) => (
              <button
                key={sev}
                onClick={() => setSelectedSeverity(sev)}
                className={`px-3 py-2 rounded-xl text-xs font-mono font-semibold transition ${
                  selectedSeverity === sev
                    ? sev === 'CRITICAL'
                      ? 'bg-rose-950 text-rose-300 border border-rose-800'
                      : sev === 'HIGH'
                      ? 'bg-amber-950 text-amber-300 border border-amber-800'
                      : 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                    : 'bg-slate-900 text-slate-400 hover:text-white border border-slate-800'
                }`}
              >
                {sev === 'ALL' ? 'Tous' : sev}
              </button>
            ))}
          </div>
        </div>

        {/* Category Pills Bar */}
        <div className="flex items-center gap-2 overflow-x-auto py-1 no-scrollbar">
          {CATEGORIES.map((cat) => {
            const isSelected = selectedCategory === cat.id;
            const count =
              cat.id === 'ALL'
                ? attacks.length
                : attacks.filter((a) => a.category === cat.id).length;

            return (
              <button
                key={cat.id}
                onClick={() => setSelectedCategory(cat.id)}
                className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-mono whitespace-nowrap transition border ${
                  isSelected
                    ? 'bg-cyan-950 text-cyan-300 border-cyan-700 shadow-sm'
                    : 'bg-slate-900/80 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border-slate-800'
                }`}
              >
                <span>{cat.icon}</span>
                <span>{cat.label}</span>
                <span
                  className={`text-[10px] px-1.5 py-0.2 rounded-full font-bold ${
                    isSelected ? 'bg-cyan-800 text-white' : 'bg-slate-800 text-slate-400'
                  }`}
                >
                  {count}
                </span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Attacks Grid */}
      {isLoading ? (
        <div className="py-20 text-center space-y-3">
          <RefreshCw className="w-8 h-8 text-cyan-400 mx-auto animate-spin" />
          <p className="text-xs font-mono text-slate-400">
            Chargement du référentiel des attaques...
          </p>
        </div>
      ) : filteredAttacks.length === 0 ? (
        <div className="p-12 rounded-3xl bg-slate-900/60 border border-slate-800 text-center space-y-3">
          <Info className="w-8 h-8 text-slate-500 mx-auto" />
          <h4 className="text-sm font-bold text-white">Aucune attaque trouvée</h4>
          <p className="text-xs font-mono text-slate-400 max-w-md mx-auto">
            Aucune menace ne correspond à vos filtres actuels. Réinitialisez la recherche ou lancez une actualisation avec l'IA.
          </p>
          <button
            onClick={() => {
              setSearchTerm('');
              setSelectedCategory('ALL');
              setSelectedSeverity('ALL');
            }}
            className="px-4 py-2 rounded-xl bg-slate-800 text-cyan-300 text-xs font-mono font-semibold border border-slate-700 hover:bg-slate-700 transition"
          >
            Réinitialiser les filtres
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filteredAttacks.map((attack) => {
            const isDeploying = deployingId === attack.id;

            return (
              <div
                key={attack.id}
                className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 hover:border-slate-700 transition flex flex-col justify-between group shadow-lg hover:shadow-cyan-950/20"
              >
                <div className="space-y-3">
                  {/* Top Badges */}
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <div className="flex items-center gap-1.5">
                      <span
                        className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded-full uppercase ${
                          attack.severity === 'CRITICAL'
                            ? 'bg-rose-950 text-rose-300 border border-rose-800'
                            : 'bg-amber-950 text-amber-300 border border-amber-800'
                        }`}
                      >
                        {attack.severity}
                      </span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-slate-800 text-cyan-300 font-bold border border-slate-700">
                        CVSS {attack.cvssScore.toFixed(1)}
                      </span>
                    </div>

                    <span className="text-[10px] font-mono text-slate-400 bg-slate-950 px-2 py-0.5 rounded-lg border border-slate-800 truncate max-w-[140px]">
                      {attack.category}
                    </span>
                  </div>

                  {/* Title & Alias */}
                  <div>
                    <h3 className="text-sm font-bold text-white group-hover:text-cyan-300 transition leading-snug">
                      {attack.name}
                    </h3>
                    {attack.alias && (
                      <p className="text-[11px] font-mono text-slate-400 mt-0.5">
                        Alias : {attack.alias}
                      </p>
                    )}
                  </div>

                  {/* CVE & MITRE tags */}
                  <div className="flex flex-wrap items-center gap-1.5 pt-1">
                    {attack.cveList.map((cve) => (
                      <span
                        key={cve}
                        className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-rose-950/70 text-rose-300 border border-rose-800/80"
                      >
                        {cve}
                      </span>
                    ))}
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                      {attack.mitreTechniqueId}
                    </span>
                    {attack.threatActor && (
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800">
                        {attack.threatActor}
                      </span>
                    )}
                  </div>

                  {/* Description */}
                  <p className="text-xs text-slate-300 line-clamp-3 leading-relaxed">
                    {attack.description}
                  </p>

                  {/* Zyxel Signature snippet */}
                  <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800/80 space-y-1 text-[11px] font-mono">
                    <div className="text-slate-400 text-[10px] uppercase font-bold flex items-center justify-between">
                      <span>Signature Zyxel IDP/IPS</span>
                      <span className="text-emerald-400">Actif</span>
                    </div>
                    <div className="text-slate-200 truncate" title={attack.zyxelDetectionSignature}>
                      {attack.zyxelDetectionSignature}
                    </div>
                  </div>
                </div>

                {/* Bottom Actions */}
                <div className="pt-4 mt-4 border-t border-slate-800/80 flex flex-col gap-2">
                  <div className="grid grid-cols-2 gap-2">
                    {/* Test with AI SOC */}
                    <button
                      onClick={() => onTestAttackScenario(attack.sampleSecuReporterLog, attack.name)}
                      className="inline-flex items-center justify-center gap-1.5 px-3 py-2 rounded-xl bg-cyan-600/90 hover:bg-cyan-500 text-white font-mono text-[11px] font-bold shadow-sm transition"
                      title="Charger ce scénario de log dans l'analyseur SOC pour générer la riposte"
                    >
                      <Play className="w-3 h-3" />
                      <span>Tester Scénario</span>
                    </button>

                    {/* Deploy Zyxel Defense */}
                    <button
                      onClick={() => handleDeployMitigation(attack)}
                      disabled={isDeploying}
                      className="inline-flex items-center justify-center gap-1.5 px-3 py-2 rounded-xl bg-red-950/80 hover:bg-red-900 text-red-200 border border-red-800 font-mono text-[11px] font-bold transition disabled:opacity-50"
                      title="Activer immédiatement la règle de riposte sur Nebula"
                    >
                      <Zap className={`w-3 h-3 text-red-400 ${isDeploying ? 'animate-spin' : ''}`} />
                      <span>{isDeploying ? 'Déploiement...' : 'Déployer Riposte'}</span>
                    </button>
                  </div>

                  {/* Inspect Details & CLI Modal button */}
                  <div className="flex items-center justify-between pt-1">
                    <button
                      onClick={() => setInspectAttack(attack)}
                      className="text-xs font-mono text-slate-400 hover:text-cyan-300 transition flex items-center gap-1"
                    >
                      <Terminal className="w-3.5 h-3.5" />
                      <span>Détails & Script ZySH</span>
                    </button>

                    <button
                      onClick={() => handleCopy(attack.sampleSecuReporterLog, `log-${attack.id}`)}
                      className="text-[10px] font-mono text-slate-500 hover:text-slate-300 transition flex items-center gap-1"
                      title="Copier le log de test"
                    >
                      {copiedId === `log-${attack.id}` ? (
                        <>
                          <Check className="w-3 h-3 text-emerald-400" />
                          <span className="text-emerald-400">Copié</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3 h-3" />
                          <span>Copier Log</span>
                        </>
                      )}
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Attack Detail Modal */}
      {inspectAttack && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in">
          <div className="bg-slate-900 border border-slate-700 rounded-3xl max-w-2xl w-full max-h-[90vh] overflow-y-auto p-6 space-y-5 shadow-2xl relative">
            <button
              onClick={() => setInspectAttack(null)}
              className="absolute top-5 right-5 text-slate-400 hover:text-white p-1 rounded-xl bg-slate-800 hover:bg-slate-700 transition"
            >
              <X className="w-5 h-5" />
            </button>

            {/* Modal Header */}
            <div className="space-y-1.5 pr-8">
              <div className="flex items-center gap-2">
                <span
                  className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded-full uppercase ${
                    inspectAttack.severity === 'CRITICAL'
                      ? 'bg-rose-950 text-rose-300 border border-rose-800'
                      : 'bg-amber-950 text-amber-300 border border-amber-800'
                  }`}
                >
                  {inspectAttack.severity}
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-slate-800 text-cyan-300 font-bold border border-slate-700">
                  CVSS {inspectAttack.cvssScore.toFixed(1)}
                </span>
                <span className="text-xs font-mono text-slate-400">
                  {inspectAttack.category}
                </span>
              </div>
              <h3 className="text-xl font-extrabold text-white">
                {inspectAttack.name}
              </h3>
              {inspectAttack.alias && (
                <p className="text-xs font-mono text-slate-400">
                  Alias : {inspectAttack.alias} · Acteur : {inspectAttack.threatActor || 'Non spécifié'}
                </p>
              )}
            </div>

            {/* Technical Impact */}
            <div className="space-y-1.5">
              <h4 className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider">
                Description & Impact Technique
              </h4>
              <p className="text-xs text-slate-300 leading-relaxed font-sans">
                {inspectAttack.description}
              </p>
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-xs text-amber-300 font-mono">
                Impact : {inspectAttack.technicalImpact}
              </div>
            </div>

            {/* MITRE & CVEs */}
            <div className="grid grid-cols-2 gap-3 text-xs font-mono">
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1">
                <span className="text-slate-400 text-[10px] uppercase font-bold block">Technique MITRE ATT&CK</span>
                <span className="text-cyan-300 font-bold">{inspectAttack.mitreTechniqueId}</span>
                <div className="text-[11px] text-slate-400 truncate">{inspectAttack.mitreTactic}</div>
              </div>

              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1">
                <span className="text-slate-400 text-[10px] uppercase font-bold block">Protocoles Cibles</span>
                <span className="text-white font-bold">{inspectAttack.targetProtocols.join(', ')}</span>
                <div className="text-[11px] text-rose-300 truncate">
                  {inspectAttack.cveList.join(', ') || 'Attaque sans CVE spécifique'}
                </div>
              </div>
            </div>

            {/* Zyxel CLI Command */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <h4 className="text-xs font-mono font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5" />
                  Script de Riposte Pare-feu Zyxel ZySH CLI
                </h4>
                <button
                  onClick={() => handleCopy(inspectAttack.zyxelMitigation.cliCommand, 'cli-modal')}
                  className="inline-flex items-center gap-1 text-[11px] font-mono text-cyan-400 hover:text-cyan-300"
                >
                  {copiedId === 'cli-modal' ? (
                    <>
                      <Check className="w-3 h-3 text-emerald-400" />
                      <span className="text-emerald-400">Copié</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3 h-3" />
                      <span>Copier CLI</span>
                    </>
                  )}
                </button>
              </div>
              <pre className="p-3.5 rounded-xl bg-black/90 border border-slate-800 text-emerald-300 text-xs font-mono overflow-x-auto leading-relaxed">
                {inspectAttack.zyxelMitigation.cliCommand}
              </pre>
            </div>

            {/* Recommendation */}
            <div className="p-3.5 rounded-xl bg-cyan-950/40 border border-cyan-800/60 text-xs font-mono text-cyan-200 space-y-1">
              <strong className="text-cyan-300 block font-bold">Conseil Opérationnel SOC :</strong>
              <p>{inspectAttack.zyxelMitigation.recommendation}</p>
            </div>

            {/* Modal Actions */}
            <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
              <button
                onClick={() => {
                  onTestAttackScenario(inspectAttack.sampleSecuReporterLog, inspectAttack.name);
                  setInspectAttack(null);
                }}
                className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-mono text-xs font-bold transition shadow-lg"
              >
                <Play className="w-3.5 h-3.5" />
                <span>Tester dans l'Analyseur SOC</span>
              </button>

              <button
                onClick={() => {
                  handleDeployMitigation(inspectAttack);
                  setInspectAttack(null);
                }}
                className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-red-600 hover:bg-red-500 text-white font-mono text-xs font-bold transition"
              >
                <Zap className="w-3.5 h-3.5" />
                <span>Déployer Règle Pare-feu</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
