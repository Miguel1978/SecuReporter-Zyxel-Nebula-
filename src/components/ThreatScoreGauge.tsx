import React from 'react';
import { AlertTriangle, Flame, Shield, ShieldCheck } from 'lucide-react';
import { SeverityLevel } from '../types';

interface ThreatScoreGaugeProps {
  score: number; // 0 - 100
  threatLevel: SeverityLevel;
  activeAttacks: number;
}

export const ThreatScoreGauge: React.FC<ThreatScoreGaugeProps> = ({
  score,
  threatLevel,
  activeAttacks,
}) => {
  // SVG circular gauge math
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  const getColor = () => {
    if (score >= 80) return { stroke: '#ef4444', text: 'text-red-400', bg: 'bg-red-950/40', border: 'border-red-800/60' };
    if (score >= 60) return { stroke: '#f97316', text: 'text-orange-400', bg: 'bg-orange-950/40', border: 'border-orange-800/60' };
    if (score >= 35) return { stroke: '#eab308', text: 'text-yellow-400', bg: 'bg-yellow-950/40', border: 'border-yellow-800/60' };
    return { stroke: '#10b981', text: 'text-emerald-400', bg: 'bg-emerald-950/40', border: 'border-emerald-800/60' };
  };

  const colors = getColor();

  return (
    <div className={`p-5 rounded-2xl bg-slate-900/90 border ${colors.border} relative overflow-hidden backdrop-blur-sm shadow-xl`}>
      {/* Background glow */}
      <div
        className="absolute -top-12 -right-12 w-44 h-44 rounded-full blur-3xl opacity-20 pointer-events-none"
        style={{ backgroundColor: colors.stroke }}
      />

      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Flame className={`w-5 h-5 ${colors.text}`} />
          <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-300">
            Niveau de Menace Global
          </h3>
        </div>
        <span className="text-xs font-mono text-slate-400 px-2 py-0.5 rounded bg-slate-800 border border-slate-700">
          Zyxel Nebula ATP / IDP
        </span>
      </div>

      <div className="flex flex-col sm:flex-row items-center justify-between gap-6">
        {/* Circular Gauge */}
        <div className="relative flex items-center justify-center">
          <svg className="w-36 h-36 transform -rotate-90">
            {/* Background ring */}
            <circle
              cx="72"
              cy="72"
              r={radius}
              stroke="currentColor"
              strokeWidth="10"
              fill="transparent"
              className="text-slate-800"
            />
            {/* Progress ring */}
            <circle
              cx="72"
              cy="72"
              r={radius}
              stroke={colors.stroke}
              strokeWidth="10"
              strokeDasharray={circumference}
              strokeDashoffset={strokeDashoffset}
              strokeLinecap="round"
              fill="transparent"
              className="transition-all duration-1000 ease-out"
            />
          </svg>
          <div className="absolute flex flex-col items-center justify-center text-center">
            <span className={`text-3xl font-extrabold font-mono tracking-tight ${colors.text}`}>
              {score}
            </span>
            <span className="text-[10px] font-mono text-slate-400 uppercase tracking-widest">
              / 100
            </span>
          </div>
        </div>

        {/* Breakdown Stats */}
        <div className="flex-1 space-y-3 w-full">
          <div className="flex items-center justify-between p-2.5 rounded-xl bg-slate-800/60 border border-slate-700/50">
            <span className="text-xs text-slate-400">Évaluation Criticité</span>
            <span className={`text-xs font-bold font-mono px-2 py-0.5 rounded ${colors.bg} ${colors.text} border ${colors.border}`}>
              {threatLevel}
            </span>
          </div>

          <div className="flex items-center justify-between p-2.5 rounded-xl bg-slate-800/60 border border-slate-700/50">
            <span className="text-xs text-slate-400">Vecteurs d'Attaques Actifs</span>
            <span className="text-xs font-bold font-mono text-white px-2 py-0.5 rounded bg-slate-700">
              {activeAttacks} vecteurs
            </span>
          </div>

          <div className="flex items-center justify-between p-2.5 rounded-xl bg-slate-800/60 border border-slate-700/50">
            <span className="text-xs text-slate-400">Posture de Défense</span>
            <span className="text-xs font-bold font-mono text-cyan-400 flex items-center gap-1">
              <Shield className="w-3.5 h-3.5" /> Riposte Prête
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
