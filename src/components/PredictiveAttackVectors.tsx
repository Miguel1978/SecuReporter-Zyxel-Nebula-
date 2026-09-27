import React, { useState, useEffect } from 'react';
import {
  Sparkles,
  TrendingUp,
  AlertOctagon,
  ShieldAlert,
  Clock,
  Target,
  Zap,
  CheckCircle2,
  RefreshCw,
  Lock,
  ChevronDown,
  ChevronUp,
  Flame,
  ShieldCheck,
  AlertTriangle,
  Radio,
} from 'lucide-react';
import { ThreatAnalysisResult, LogEntry, PredictiveAnalysisResult, StopAction } from '../types';

interface PredictiveAttackVectorsProps {
  analysis: ThreatAnalysisResult;
  logs: LogEntry[];
  deviceName?: string;
  onEnforceDefense?: (action: StopAction) => Promise<void>;
  onNavigateToCountermeasures?: () => void;
}

export const PredictiveAttackVectors: React.FC<PredictiveAttackVectorsProps> = ({
  analysis,
  logs,
  deviceName = 'Passerelle Zyxel Nebula ATP',
  onEnforceDefense,
  onNavigateToCountermeasures,
}) => {
  const [predictions, setPredictions] = useState<PredictiveAnalysisResult | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [enforcedRuleIds, setEnforcedRuleIds] = useState<Set<string>>(new Set());

  const fetchPredictions = async () => {
    setIsLoading(true);
    setError(null);

    try {
      const logsSummary = logs.slice(0, 35).map((l) => l.raw).join('\n');
      const res = await fetch('/api/predict-attacks', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          logsText: logsSummary,
          currentAnalysis: analysis,
          deviceName,
        }),
      });

      if (!res.ok) {
        throw new Error('Erreur lors de la modélisation prédictive');
      }

      const data: PredictiveAnalysisResult = await res.json();
      setPredictions(data);
      if (data.predictedAttackVectors.length > 0) {
        setExpandedId(data.predictedAttackVectors[0].id);
      }
    } catch (err: any) {
      console.warn('Fallback on prediction:', err);
      setError('Mode dégradé : utilisation des modèles heuristiques locaux.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchPredictions();
  }, [analysis.riskScore, analysis.threatLevel]);

  const handleApplyPreemptive = async (predId: string, ruleTitle: string, ruleCmd: string) => {
    if (onEnforceDefense) {
      const pseudoAction: StopAction = {
        id: `preempt-${Date.now()}`,
        title: `Protection Préemptive : ${ruleTitle}`,
        type: 'FIREWALL_BLOCK',
        target: 'Périmètre_Anticipé',
        priority: 'IMMEDIATE',
        rationale: `Règle de cyberdéfense prédictive IA pour contrer l'attaque imminente.`,
        zyxelNebulaRule: {
          ruleName: `PREEMPT_${predId.toUpperCase()}`,
          direction: 'WAN to LAN',
          action: 'DROP',
          sourceObject: 'Any',
          destinationObject: 'Any',
        },
        zyxelCliCommand: ruleCmd,
        iptablesCommand: `sudo iptables -I FORWARD -p tcp --dport 445 -j DROP`,
        nftablesCommand: `sudo nft add rule inet filter forward tcp dport 445 drop`,
        pfSenseRule: `<rule><descr>Preemptive Block</descr></rule>`,
      };

      await onEnforceDefense(pseudoAction);
      setEnforcedRuleIds((prev) => new Set([...prev, predId]));
    } else if (onNavigateToCountermeasures) {
      onNavigateToCountermeasures();
    }
  };

  if (!predictions && !isLoading) {
    return null;
  }

  return (
    <div className="rounded-3xl bg-slate-900/90 border border-slate-800 shadow-2xl p-6 sm:p-7 space-y-6 backdrop-blur-xl">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div className="flex items-center gap-3.5">
          <div className="w-11 h-11 rounded-2xl bg-gradient-to-br from-purple-950 via-slate-900 to-cyan-950 border border-purple-500/40 flex items-center justify-center text-purple-400 shadow-lg shadow-purple-950/50">
            <Sparkles className="w-5 h-5 animate-pulse text-purple-300" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-base sm:text-lg font-bold text-white flex items-center gap-2">
                <span>Prédiction IA des Vecteurs d'Attaques</span>
              </h3>
              <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-purple-950 text-purple-300 border border-purple-800">
                Threat Forecasting
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono">
              Anticipation des prochaines phases de la Kill Chain selon les tendances des logs Nebula.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          {predictions && (
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono">
              <Flame
                className={`w-3.5 h-3.5 ${
                  predictions.overallThreatVelocity === 'ACCELERATING'
                    ? 'text-red-400 animate-bounce'
                    : 'text-amber-400'
                }`}
              />
              <span className="text-slate-400">Vélocité :</span>
              <span
                className={`font-bold ${
                  predictions.overallThreatVelocity === 'ACCELERATING'
                    ? 'text-red-400'
                    : 'text-amber-400'
                }`}
              >
                {predictions.overallThreatVelocity === 'ACCELERATING' ? 'En Accélération' : 'Stable'}
              </span>
            </div>
          )}

          <button
            onClick={fetchPredictions}
            disabled={isLoading}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white text-xs font-mono border border-slate-700 transition disabled:opacity-50"
            title="Recalculer les prédictions IA"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-purple-400' : ''}`} />
            <span>{isLoading ? 'Calcul...' : 'Actualiser'}</span>
          </button>
        </div>
      </div>

      {isLoading && !predictions ? (
        <div className="py-12 text-center space-y-3">
          <div className="w-10 h-10 rounded-2xl bg-purple-950 border border-purple-800 mx-auto flex items-center justify-center animate-spin">
            <Radio className="w-5 h-5 text-purple-400" />
          </div>
          <p className="text-xs text-slate-400 font-mono">
            Modélisation des trajectoires d'attaques et analyse prédictive en cours...
          </p>
        </div>
      ) : predictions ? (
        <>
          {/* Executive Forecast Summary Banner */}
          <div className="p-4 rounded-2xl bg-gradient-to-r from-purple-950/30 via-slate-950/60 to-slate-900 border border-purple-900/50 space-y-2.5">
            <div className="flex flex-wrap items-center justify-between gap-2 text-xs font-mono">
              <span className="flex items-center gap-1.5 text-purple-300 font-bold">
                <Clock className="w-3.5 h-3.5 text-purple-400" />
                Horizon de Prévision : {predictions.forecastWindow}
              </span>
              <span className="text-slate-400 text-[11px]">
                Modélisé le {new Date(predictions.generatedAt).toLocaleTimeString('fr-FR')}
              </span>
            </div>
            <p className="text-xs text-slate-200 leading-relaxed font-sans">
              {predictions.threatTrendSummary}
            </p>

            {/* Early Warning Signals */}
            {predictions.earlyWarningSignals.length > 0 && (
              <div className="pt-2 border-t border-purple-900/40">
                <span className="text-[10px] font-mono uppercase text-slate-400 block mb-1.5 font-bold">
                  Signaux d'Alerte Précoces Observés :
                </span>
                <div className="flex flex-wrap gap-1.5">
                  {predictions.earlyWarningSignals.map((signal, idx) => (
                    <span
                      key={idx}
                      className="px-2.5 py-0.5 rounded-lg text-[11px] font-mono bg-purple-950/60 text-purple-200 border border-purple-800/80"
                    >
                      • {signal}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Predicted Attack Cards Grid */}
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h4 className="text-xs font-bold text-slate-300 font-mono uppercase tracking-wider">
                Vecteurs d'Attaques Anticipés ({predictions.predictedAttackVectors.length})
              </h4>
              <span className="text-[11px] text-slate-500 font-mono">
                Classés par probabilité décroissante
              </span>
            </div>

            <div className="grid grid-cols-1 gap-4">
              {predictions.predictedAttackVectors.map((pred) => {
                const isExpanded = expandedId === pred.id;
                const isEnforced = enforcedRuleIds.has(pred.id);

                return (
                  <div
                    key={pred.id}
                    className={`rounded-2xl border transition-all ${
                      pred.severity === 'CRITICAL'
                        ? 'bg-slate-950/80 border-red-900/60 hover:border-red-700/80'
                        : 'bg-slate-950/80 border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    {/* Card Header */}
                    <div className="p-4 sm:p-5 space-y-3">
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div className="flex items-center gap-2.5">
                          <div
                            className={`w-7 h-7 rounded-lg flex items-center justify-center font-mono font-bold text-xs ${
                              pred.probability >= 85
                                ? 'bg-red-950 text-red-300 border border-red-800'
                                : 'bg-amber-950 text-amber-300 border border-amber-800'
                            }`}
                          >
                            {pred.probability}%
                          </div>
                          <div>
                            <h5 className="text-sm font-bold text-white flex items-center gap-2">
                              <span>{pred.threatName}</span>
                            </h5>
                            <span className="text-[11px] font-mono text-cyan-400">
                              {pred.killChainStage}
                            </span>
                          </div>
                        </div>

                        <div className="flex items-center gap-2">
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 text-slate-300 border border-slate-800">
                            {pred.mitreTechniqueId}
                          </span>
                          <span
                            className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${
                              pred.severity === 'CRITICAL'
                                ? 'bg-red-950 text-red-400 border border-red-800'
                                : 'bg-amber-950 text-amber-400 border border-amber-800'
                            }`}
                          >
                            {pred.severity}
                          </span>
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-amber-300 flex items-center gap-1 font-semibold">
                            <Clock className="w-3 h-3" /> {pred.estimatedTimeToImpact}
                          </span>
                        </div>
                      </div>

                      {/* Probability Gauge Bar */}
                      <div className="space-y-1">
                        <div className="flex items-center justify-between text-[11px] font-mono">
                          <span className="text-slate-400">Probabilité d'Occurrence :</span>
                          <span className="font-bold text-white">{pred.probability}% (Indice {pred.confidence})</span>
                        </div>
                        <div className="w-full h-2 rounded-full bg-slate-900 overflow-hidden border border-slate-800">
                          <div
                            className={`h-full rounded-full transition-all duration-1000 ${
                              pred.probability >= 85
                                ? 'bg-gradient-to-r from-amber-500 via-red-500 to-rose-600'
                                : 'bg-gradient-to-r from-blue-500 to-amber-500'
                            }`}
                            style={{ width: `${pred.probability}%` }}
                          />
                        </div>
                      </div>

                      {/* Rationale */}
                      <p className="text-xs text-slate-300 font-sans leading-relaxed">
                        {pred.rationale}
                      </p>

                      {/* Expand / Details Toggle Button */}
                      <div className="flex items-center justify-between pt-2 border-t border-slate-800/80">
                        <button
                          onClick={() => setExpandedId(isExpanded ? null : pred.id)}
                          className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition"
                        >
                          <span>{isExpanded ? 'Masquer détails' : 'Afficher cibles & contre-mesures préemptives'}</span>
                          {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                        </button>

                        <button
                          onClick={() =>
                            handleApplyPreemptive(
                              pred.id,
                              pred.proactiveDefense.title,
                              pred.proactiveDefense.preemptiveRule
                            )
                          }
                          disabled={isEnforced}
                          className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-mono font-bold transition shadow-sm ${
                            isEnforced
                              ? 'bg-emerald-950 text-emerald-300 border border-emerald-800 cursor-default'
                              : 'bg-gradient-to-r from-purple-600 to-cyan-600 hover:from-purple-500 hover:to-cyan-500 text-white shadow-purple-900/30'
                          }`}
                        >
                          {isEnforced ? (
                            <>
                              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                              <span>Protection Préemptive Active</span>
                            </>
                          ) : (
                            <>
                              <ShieldAlert className="w-3.5 h-3.5" />
                              <span>Déployer la Défense Préemptive</span>
                            </>
                          )}
                        </button>
                      </div>

                      {/* Expanded Section: Precursors, Target Assets, Rules */}
                      {isExpanded && (
                        <div className="pt-3 border-t border-slate-800/80 space-y-3 text-xs animate-in fade-in slide-in-from-top-1 font-mono">
                          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800/80">
                              <span className="text-[10px] text-slate-500 uppercase block mb-1">
                                Cibles Potentielles Menacées
                              </span>
                              <div className="flex flex-wrap gap-1">
                                {pred.potentialTargetAssets.map((asset, i) => (
                                  <span
                                    key={i}
                                    className="px-2 py-0.5 rounded bg-slate-800 text-slate-200 border border-slate-700 text-[11px]"
                                  >
                                    {asset}
                                  </span>
                                ))}
                              </div>
                            </div>

                            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800/80">
                              <span className="text-[10px] text-slate-500 uppercase block mb-1">
                                Signaux Précurseurs dans les Logs
                              </span>
                              <ul className="space-y-0.5 text-[11px] text-slate-300 list-disc list-inside">
                                {pred.precursorIndicators.map((ind, i) => (
                                  <li key={i}>{ind}</li>
                                ))}
                              </ul>
                            </div>
                          </div>

                          {/* Preemptive Defense Details */}
                          <div className="p-3.5 rounded-xl bg-purple-950/20 border border-purple-900/60 space-y-1.5 font-sans">
                            <span className="text-[10px] font-mono uppercase text-purple-400 font-bold block">
                              Contre-Mesure Préemptive Recommandée (Zyxel Nebula) :
                            </span>
                            <h6 className="font-bold text-white text-xs">{pred.proactiveDefense.title}</h6>
                            <p className="text-slate-300 text-xs">
                              {pred.proactiveDefense.recommendedAction}
                            </p>
                            <div className="mt-2 p-2 rounded-lg bg-slate-950 border border-slate-800 font-mono text-[11px] text-cyan-300 select-all overflow-x-auto">
                              <code>{pred.proactiveDefense.preemptiveRule}</code>
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Recommended Preemptive Actions Summary */}
          {predictions.recommendedPreemptiveActions.length > 0 && (
            <div className="p-4 rounded-2xl bg-slate-950/70 border border-slate-800 space-y-2">
              <span className="text-[10px] font-mono uppercase text-cyan-400 font-bold block">
                Recommandations d'Anticipation SOC :
              </span>
              <ul className="space-y-1.5 text-xs font-mono text-slate-300">
                {predictions.recommendedPreemptiveActions.map((action, i) => (
                  <li key={i} className="flex items-start gap-2">
                    <span className="text-cyan-400 font-bold flex-shrink-0">›</span>
                    <span>{action}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </>
      ) : null}
    </div>
  );
};
