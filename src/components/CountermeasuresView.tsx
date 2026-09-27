import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Zap,
  Terminal,
  Copy,
  Check,
  Lock,
  Radio,
  Send,
  Trash2,
  AlertOctagon,
  RefreshCw,
  Sliders,
  ExternalLink,
  Laptop,
  Globe,
} from 'lucide-react';
import { ActiveDefense, StopAction } from '../types';

interface CountermeasuresViewProps {
  stopActions: StopAction[];
  activeDefenses: ActiveDefense[];
  onEnforceDefense: (action: StopAction) => Promise<void>;
  onRevokeDefense: (id: string) => Promise<void>;
  onEnforceAll: () => Promise<void>;
  isEnforcing: boolean;
}

export const CountermeasuresView: React.FC<CountermeasuresViewProps> = ({
  stopActions,
  activeDefenses,
  onEnforceDefense,
  onRevokeDefense,
  onEnforceAll,
  isEnforcing,
}) => {
  const [selectedFormat, setSelectedFormat] = useState<Record<string, 'cli' | 'nebula' | 'iptables' | 'pfsense'>>({});
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [customTarget, setCustomTarget] = useState('');
  const [customType, setCustomType] = useState<'IP_BLOCK' | 'HOST_QUARANTINE'>('IP_BLOCK');
  const [customReason, setCustomReason] = useState('');
  const [apiSimulationLog, setApiSimulationLog] = useState<string[]>([]);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const getFormatForAction = (id: string) => selectedFormat[id] || 'cli';

  const setFormatForAction = (id: string, format: 'cli' | 'nebula' | 'iptables' | 'pfsense') => {
    setSelectedFormat((prev) => ({ ...prev, [id]: format }));
  };

  const isAlreadyEnforced = (target: string) => {
    return activeDefenses.some((d) => d.target === target && d.status === 'ACTIVE');
  };

  const handleCustomEnforce = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!customTarget.trim()) return;

    const fakeAction: StopAction = {
      id: `custom-${Date.now()}`,
      title: customType === 'IP_BLOCK' ? `Blocage WAN Manuel : ${customTarget}` : `Mise en quarantaine CDR : ${customTarget}`,
      type: customType === 'IP_BLOCK' ? 'FIREWALL_BLOCK' : 'HOST_QUARANTINE',
      target: customTarget.trim(),
      priority: 'IMMEDIATE',
      rationale: customReason || 'Règle de blocage manuelle ajoutée par l\'administrateur SOC',
      zyxelNebulaRule: {
        ruleName: `CUSTOM_DROP_${customTarget.replace(/[^a-zA-Z0-9]/g, '_')}`,
        direction: 'WAN to LAN',
        action: 'DROP',
        sourceObject: `Host_${customTarget.replace(/[^a-zA-Z0-9]/g, '_')}`,
        destinationObject: 'Any',
      },
      zyxelCliCommand: `configure terminal\naddress-object Host_${customTarget.replace(/[^a-zA-Z0-9]/g, '_')} host ${customTarget}\nfirewall rule 100\n  name CUSTOM_DROP_${customTarget.replace(/[^a-zA-Z0-9]/g, '_')}\n  from WAN to Any\n  source-address Host_${customTarget.replace(/[^a-zA-Z0-9]/g, '_')}\n  action drop\n  log alert\nexit\nwrite memory`,
      iptablesCommand: `sudo iptables -I INPUT -s ${customTarget} -j DROP\nsudo iptables -I FORWARD -s ${customTarget} -j DROP`,
      nftablesCommand: `sudo nft add rule inet filter input ip saddr ${customTarget} drop`,
      pfSenseRule: `<rule><type>block</type><interface>wan</interface><source><address>${customTarget}</address></source><descr>Custom Block</descr></rule>`,
    };

    await onEnforceDefense(fakeAction);
    setApiSimulationLog((prev) => [
      `[${new Date().toLocaleTimeString()}] Nebula API: Règle de blocage déployée avec succès pour ${customTarget}`,
      ...prev,
    ]);
    setCustomTarget('');
    setCustomReason('');
  };

  return (
    <div className="space-y-8">
      {/* Top Banner: Emergency Kill-Switch & Overview */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 border border-slate-700/80 shadow-2xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-red-600/10 rounded-full blur-3xl pointer-events-none" />

        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6 relative z-10">
          <div className="space-y-2 max-w-2xl">
            <div className="flex items-center gap-2">
              <span className="p-2 rounded-xl bg-red-950/80 text-red-400 border border-red-800 flex items-center justify-center">
                <AlertOctagon className="w-6 h-6 animate-pulse" />
              </span>
              <div>
                <h2 className="text-xl font-bold text-white tracking-tight">
                  Centre de Riposte & Neutralisation des Attaques
                </h2>
                <p className="text-xs text-slate-400 font-mono">
                  Génération et application instantanée des politiques de blocage Zyxel Nebula Cloud & Firewalls
                </p>
              </div>
            </div>
            <p className="text-sm text-slate-300 leading-relaxed pt-1">
              Les attaques repérées dans vos logs Nebula peuvent être bloquées immédiatement. Cliquez sur{' '}
              <strong className="text-white">"Déclencher Riposte Totale"</strong> pour appliquer l'ensemble des règles de filtrage WAN et isoler les hôtes internes compromis (quarantaine CDR).
            </p>
          </div>

          <div className="flex flex-col sm:flex-row gap-3">
            <button
              onClick={onEnforceAll}
              disabled={isEnforcing || stopActions.length === 0}
              className="inline-flex items-center justify-center gap-2.5 px-6 py-3.5 rounded-xl bg-gradient-to-r from-red-600 via-rose-600 to-red-700 hover:from-red-500 hover:to-rose-500 text-white font-bold text-sm shadow-xl shadow-red-900/40 border border-red-400/30 transition transform hover:-translate-y-0.5 active:translate-y-0 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <Zap className={`w-5 h-5 ${isEnforcing ? 'animate-spin' : ''}`} />
              <span>{isEnforcing ? 'Application en cours...' : 'Déclencher Riposte Totale (Tout Bloquer)'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Grid: Actions to Stop Attacks & Active Defenses */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Left Column: Recommended Stop Actions List (2 Cols on lg) */}
        <div className="lg:col-span-2 space-y-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-cyan-400" />
              <h3 className="text-base font-bold text-white">
                Contre-Mesures Recommandées par l'IA ({stopActions.length})
              </h3>
            </div>
            <span className="text-xs text-slate-400 font-mono">
              Priorisées par criticité d'impact
            </span>
          </div>

          {stopActions.length === 0 ? (
            <div className="p-8 rounded-2xl bg-slate-900/60 border border-slate-800 text-center space-y-3">
              <ShieldCheck className="w-12 h-12 text-emerald-400 mx-auto" />
              <h4 className="text-sm font-semibold text-slate-300">Aucune attaque non bloquée détectée</h4>
              <p className="text-xs text-slate-500 max-w-md mx-auto">
                Chargez un rapport d'attaque ou lancez l'analyse IA pour générer les règles de blocage.
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              {stopActions.map((action, idx) => {
                const isEnforced = isAlreadyEnforced(action.target);
                const format = getFormatForAction(action.id);

                return (
                  <div
                    key={action.id || idx}
                    className={`rounded-2xl border transition-all ${
                      isEnforced
                        ? 'bg-slate-900/40 border-emerald-800/40'
                        : 'bg-slate-900/90 border-slate-800 hover:border-slate-700 shadow-xl'
                    } overflow-hidden`}
                  >
                    {/* Header */}
                    <div className="p-5 border-b border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                      <div className="flex items-start gap-3">
                        <span
                          className={`p-2 rounded-xl mt-0.5 ${
                            action.type === 'HOST_QUARANTINE'
                              ? 'bg-purple-950/80 text-purple-400 border border-purple-800'
                              : 'bg-red-950/80 text-red-400 border border-red-800'
                          }`}
                        >
                          {action.type === 'HOST_QUARANTINE' ? (
                            <Laptop className="w-4 h-4" />
                          ) : (
                            <Lock className="w-4 h-4" />
                          )}
                        </span>
                        <div>
                          <div className="flex flex-wrap items-center gap-2">
                            <h4 className="text-sm font-bold text-white">{action.title}</h4>
                            <span
                              className={`text-[10px] font-mono px-2 py-0.5 rounded font-semibold ${
                                action.priority === 'IMMEDIATE'
                                  ? 'bg-red-950 text-red-400 border border-red-800'
                                  : 'bg-amber-950 text-amber-400 border border-amber-800'
                              }`}
                            >
                              {action.priority}
                            </span>
                            {isEnforced && (
                              <span className="inline-flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
                                <Check className="w-3 h-3" /> ACTIVE SUR NEBULA
                              </span>
                            )}
                          </div>
                          <p className="text-xs text-slate-400 mt-1 font-mono">
                            Cible : <span className="text-cyan-300 font-bold">{action.target}</span> • Type :{' '}
                            {action.type === 'HOST_QUARANTINE' ? 'Isolation CDR (VLAN Quarantaine)' : 'Règle Firewall WAN Drop'}
                          </p>
                        </div>
                      </div>

                      {/* Enforce Button */}
                      <button
                        onClick={() => onEnforceDefense(action)}
                        disabled={isEnforced || isEnforcing}
                        className={`inline-flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition shadow-md ${
                          isEnforced
                            ? 'bg-emerald-950 text-emerald-300 border border-emerald-800 cursor-default'
                            : 'bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 text-white shadow-red-900/30'
                        }`}
                      >
                        {isEnforced ? (
                          <>
                            <Check className="w-3.5 h-3.5" /> Règle Appliquée
                          </>
                        ) : (
                          <>
                            <Zap className="w-3.5 h-3.5" /> Appliquer la Règle
                          </>
                        )}
                      </button>
                    </div>

                    {/* Body & Rationale */}
                    <div className="p-5 space-y-4">
                      <p className="text-xs text-slate-300 leading-relaxed bg-slate-800/40 p-3 rounded-xl border border-slate-700/40">
                        <strong className="text-slate-200">Justification IA : </strong>
                        {action.rationale}
                      </p>

                      {/* Code Snippet Tabs */}
                      <div className="space-y-2">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-1.5 p-1 rounded-lg bg-slate-950 border border-slate-800 text-[11px] font-mono">
                            <button
                              onClick={() => setFormatForAction(action.id, 'cli')}
                              className={`px-2.5 py-1 rounded transition ${
                                format === 'cli'
                                  ? 'bg-cyan-900/50 text-cyan-300 border border-cyan-700 font-bold'
                                  : 'text-slate-400 hover:text-slate-200'
                              }`}
                            >
                              Zyxel ZySH CLI
                            </button>
                            <button
                              onClick={() => setFormatForAction(action.id, 'nebula')}
                              className={`px-2.5 py-1 rounded transition ${
                                format === 'nebula'
                                  ? 'bg-cyan-900/50 text-cyan-300 border border-cyan-700 font-bold'
                                  : 'text-slate-400 hover:text-slate-200'
                              }`}
                            >
                              Nebula Cloud GUI
                            </button>
                            <button
                              onClick={() => setFormatForAction(action.id, 'iptables')}
                              className={`px-2.5 py-1 rounded transition ${
                                format === 'iptables'
                                  ? 'bg-cyan-900/50 text-cyan-300 border border-cyan-700 font-bold'
                                  : 'text-slate-400 hover:text-slate-200'
                              }`}
                            >
                              Linux iptables
                            </button>
                            <button
                              onClick={() => setFormatForAction(action.id, 'pfsense')}
                              className={`px-2.5 py-1 rounded transition ${
                                format === 'pfsense'
                                  ? 'bg-cyan-900/50 text-cyan-300 border border-cyan-700 font-bold'
                                  : 'text-slate-400 hover:text-slate-200'
                              }`}
                            >
                              pfSense / OPNsense
                            </button>
                          </div>

                          <button
                            onClick={() => {
                              const text =
                                format === 'cli'
                                  ? action.zyxelCliCommand
                                  : format === 'nebula'
                                  ? JSON.stringify(action.zyxelNebulaRule, null, 2)
                                  : format === 'iptables'
                                  ? action.iptablesCommand
                                  : action.pfSenseRule;
                              handleCopy(text, `${action.id}-${format}`);
                            }}
                            className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs border border-slate-700 transition"
                          >
                            {copiedId === `${action.id}-${format}` ? (
                              <>
                                <Check className="w-3 h-3 text-emerald-400" />
                                <span className="text-emerald-400 font-mono text-[11px]">Copié !</span>
                              </>
                            ) : (
                              <>
                                <Copy className="w-3 h-3" />
                                <span className="font-mono text-[11px]">Copier le script</span>
                              </>
                            )}
                          </button>
                        </div>

                        {/* Code Display */}
                        <div className="relative rounded-xl bg-slate-950 p-3.5 border border-slate-800 font-mono text-xs text-slate-300 overflow-x-auto">
                          <pre className="text-cyan-400/90 leading-relaxed">
                            {format === 'cli' && action.zyxelCliCommand}
                            {format === 'nebula' && JSON.stringify(action.zyxelNebulaRule, null, 2)}
                            {format === 'iptables' && action.iptablesCommand}
                            {format === 'pfsense' && action.pfSenseRule}
                          </pre>
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Right Column: Active Defenses & Nebula Webhook Simulator (1 Col) */}
        <div className="space-y-6">
          {/* Active Defenses Panel */}
          <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-emerald-400" />
                <h3 className="text-sm font-bold text-white">Défenses Actives sur Passerelle</h3>
              </div>
              <span className="text-xs font-mono px-2 py-0.5 rounded-full bg-emerald-950 text-emerald-400 border border-emerald-800">
                {activeDefenses.filter((d) => d.status === 'ACTIVE').length} actives
              </span>
            </div>

            {activeDefenses.length === 0 ? (
              <p className="text-xs text-slate-500 py-4 text-center">Aucune règle de blocage active actuellement.</p>
            ) : (
              <div className="space-y-2.5 max-h-[360px] overflow-y-auto pr-1">
                {activeDefenses.map((def) => (
                  <div
                    key={def.id}
                    className={`p-3 rounded-xl border text-xs space-y-2 ${
                      def.status === 'ACTIVE'
                        ? 'bg-slate-800/60 border-slate-700/80'
                        : 'bg-slate-950/40 border-slate-800/40 opacity-60'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                        <span className="font-mono font-bold text-white">{def.target}</span>
                      </div>
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-700 text-slate-300">
                        {def.type}
                      </span>
                    </div>

                    <p className="text-[11px] text-slate-400">{def.reason}</p>

                    <div className="flex items-center justify-between pt-1 border-t border-slate-700/40 text-[10px] font-mono text-slate-400">
                      <span>Paquets rejetés : <strong className="text-emerald-400">{def.packetsBlocked}</strong></span>
                      {def.status === 'ACTIVE' && (
                        <button
                          onClick={() => onRevokeDefense(def.id)}
                          className="text-red-400 hover:text-red-300 flex items-center gap-1 font-semibold"
                        >
                          <Trash2 className="w-3 h-3" /> Révoquer
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Quick Manual Rule Injector */}
          <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-4">
            <div className="flex items-center gap-2">
              <Sliders className="w-5 h-5 text-cyan-400" />
              <h3 className="text-sm font-bold text-white">Ajout Manuel d'un Blocage</h3>
            </div>

            <form onSubmit={handleCustomEnforce} className="space-y-3">
              <div>
                <label className="text-[11px] font-mono text-slate-400 block mb-1">
                  Type d'Intervention
                </label>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    type="button"
                    onClick={() => setCustomType('IP_BLOCK')}
                    className={`py-1.5 text-xs font-semibold rounded-lg border transition ${
                      customType === 'IP_BLOCK'
                        ? 'bg-cyan-950 text-cyan-300 border-cyan-700'
                        : 'bg-slate-800 text-slate-400 border-slate-700'
                    }`}
                  >
                    Bloquer IP WAN
                  </button>
                  <button
                    type="button"
                    onClick={() => setCustomType('HOST_QUARANTINE')}
                    className={`py-1.5 text-xs font-semibold rounded-lg border transition ${
                      customType === 'HOST_QUARANTINE'
                        ? 'bg-purple-950 text-purple-300 border-purple-700'
                        : 'bg-slate-800 text-slate-400 border-slate-700'
                    }`}
                  >
                    Quarantaine CDR
                  </button>
                </div>
              </div>

              <div>
                <label className="text-[11px] font-mono text-slate-400 block mb-1">
                  Adresse IP / Sous-réseau ou MAC
                </label>
                <input
                  type="text"
                  placeholder="ex: 185.220.101.5 ou 192.168.1.105"
                  value={customTarget}
                  onChange={(e) => setCustomTarget(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono"
                  required
                />
              </div>

              <div>
                <label className="text-[11px] font-mono text-slate-400 block mb-1">
                  Motif du blocage (Optionnel)
                </label>
                <input
                  type="text"
                  placeholder="ex: Tentative de brute-force SSH repérée"
                  value={customReason}
                  onChange={(e) => setCustomReason(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                />
              </div>

              <button
                type="submit"
                className="w-full py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-xs shadow-md shadow-cyan-600/20 transition flex items-center justify-center gap-2"
              >
                <Send className="w-3.5 h-3.5" /> Déployer sur Passerelle Nebula
              </button>
            </form>
          </div>

          {/* Nebula API Simulator Status */}
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 font-mono text-[11px] space-y-2">
            <div className="flex items-center justify-between text-slate-400">
              <span className="flex items-center gap-1.5 text-cyan-400 font-semibold">
                <Radio className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
                Nebula API Endpoint:
              </span>
              <span className="text-[10px] text-emerald-400">CONNECTÉ</span>
            </div>
            <p className="text-slate-500 truncate">https://api.nebula.zyxel.com/v1/sites/hq/firewall</p>
            {apiSimulationLog.length > 0 && (
              <div className="pt-2 border-t border-slate-800 space-y-1 text-slate-400 max-h-28 overflow-y-auto">
                {apiSimulationLog.map((log, i) => (
                  <div key={i} className="text-emerald-400/90 text-[10px]">
                    {log}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
