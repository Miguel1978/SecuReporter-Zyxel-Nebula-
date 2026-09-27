import React, { useState, useEffect, useRef, useMemo } from 'react';
import {
  Volume2,
  VolumeX,
  Play,
  Pause,
  Square,
  Sparkles,
  Radio,
  Sliders,
  ChevronDown,
  ChevronUp,
  Headphones,
  Check,
  AlertTriangle,
} from 'lucide-react';
import { ThreatAnalysisResult, ActiveDefense } from '../types';

interface ThreatAudioBriefingProps {
  analysis: ThreatAnalysisResult;
  deviceName?: string;
  activeDefensesCount?: number;
}

export const ThreatAudioBriefing: React.FC<ThreatAudioBriefingProps> = ({
  analysis,
  deviceName = 'Passerelle Zyxel Nebula ATP',
  activeDefensesCount = 0,
}) => {
  const [isPlaying, setIsPlaying] = useState<boolean>(false);
  const [isPaused, setIsPaused] = useState<boolean>(false);
  const [isSupported, setIsSupported] = useState<boolean>(true);
  const [rate, setRate] = useState<number>(1.0);
  const [showScript, setShowScript] = useState<boolean>(false);
  const [voices, setVoices] = useState<SpeechSynthesisVoice[]>([]);
  const [selectedVoiceURI, setSelectedVoiceURI] = useState<string>('');

  const utteranceRef = useRef<SpeechSynthesisUtterance | null>(null);

  // Generate clear and professional French briefing text
  const scriptText = useMemo(() => {
    const isCritical = analysis.threatLevel === 'CRITICAL' || analysis.riskScore >= 75;
    const vectorsText = analysis.attackVectors
      .slice(0, 3)
      .map((v, i) => `Numéro ${i + 1}, ${v.name}, tactique ${v.mitreTactic}, sévérité ${v.severity}.`)
      .join(' ');

    const topAttackerIps = Array.from(
      new Set(analysis.attackVectors.flatMap((v) => v.attackerIps))
    ).slice(0, 3);

    const ipsText =
      topAttackerIps.length > 0
        ? `Adresses I P assaillantes identifiées : ${topAttackerIps.join(', ')}.`
        : '';

    const compromisedCount = analysis.compromisedHosts.length;
    const hostsText =
      compromisedCount > 0
        ? `Alerte de confinement : ${compromisedCount} hôte interne présente des signes d'infection et nécessite un isolement VLAN immédiat.`
        : 'Aucun hôte interne compromis détecté.';

    const actionsCount = analysis.stopActions.length;
    const actionsText =
      actionsCount > 0
        ? `${actionsCount} contre-mesure de blocage pare-feu générée pour neutraliser les flux malveillants.`
        : '';

    const intro = isCritical
      ? `Alerte critique de sécurité Nebula SOC.`
      : `Synthèse de surveillance Nebula SOC.`;

    return `${intro} Équipement surveillé : ${deviceName}. Score de risque global : ${analysis.riskScore} sur 100, niveau de gravité : ${analysis.threatLevel}. ${analysis.activeAttacksDetected} événement(s) de sécurité détecté(s). Vecteurs d'attaques principaux : ${vectorsText} ${ipsText} ${hostsText} ${actionsText} Fin du briefing vocal de sécurité.`;
  }, [analysis, deviceName]);

  // Check speech synthesis support and load voices
  useEffect(() => {
    if (typeof window === 'undefined' || !('speechSynthesis' in window)) {
      setIsSupported(false);
      return;
    }

    const updateVoices = () => {
      const availVoices = window.speechSynthesis.getVoices();
      setVoices(availVoices);
      // Prefer French voice
      const frVoice = availVoices.find(
        (v) => v.lang.startsWith('fr') || v.lang.includes('FR')
      );
      if (frVoice && !selectedVoiceURI) {
        setSelectedVoiceURI(frVoice.voiceURI);
      }
    };

    updateVoices();
    window.speechSynthesis.onvoiceschanged = updateVoices;

    return () => {
      if (typeof window !== 'undefined' && 'speechSynthesis' in window) {
        window.speechSynthesis.cancel();
      }
    };
  }, [selectedVoiceURI]);

  // Stop audio on unmount or report change
  useEffect(() => {
    return () => {
      if (typeof window !== 'undefined' && 'speechSynthesis' in window) {
        window.speechSynthesis.cancel();
      }
    };
  }, [analysis]);

  const handleStartSpeaking = () => {
    if (!isSupported) return;

    window.speechSynthesis.cancel(); // Clear any previous

    const utterance = new SpeechSynthesisUtterance(scriptText);
    utterance.lang = 'fr-FR';
    utterance.rate = rate;
    utterance.pitch = 1.0;

    if (selectedVoiceURI) {
      const selected = voices.find((v) => v.voiceURI === selectedVoiceURI);
      if (selected) {
        utterance.voice = selected;
      }
    }

    utterance.onstart = () => {
      setIsPlaying(true);
      setIsPaused(false);
    };

    utterance.onend = () => {
      setIsPlaying(false);
      setIsPaused(false);
    };

    utterance.onerror = (e) => {
      console.warn('Speech synthesis error:', e);
      setIsPlaying(false);
      setIsPaused(false);
    };

    utteranceRef.current = utterance;
    window.speechSynthesis.speak(utterance);
  };

  const handlePause = () => {
    if (!isSupported) return;
    if (isPlaying && !isPaused) {
      window.speechSynthesis.pause();
      setIsPaused(true);
    } else if (isPlaying && isPaused) {
      window.speechSynthesis.resume();
      setIsPaused(false);
    }
  };

  const handleStop = () => {
    if (!isSupported) return;
    window.speechSynthesis.cancel();
    setIsPlaying(false);
    setIsPaused(false);
  };

  const handleRateChange = (newRate: number) => {
    setRate(newRate);
    if (isPlaying) {
      handleStop();
      setTimeout(handleStartSpeaking, 100);
    }
  };

  if (!isSupported) {
    return null;
  }

  return (
    <div className="rounded-2xl bg-gradient-to-r from-slate-900 via-slate-900/95 to-slate-950 border border-cyan-800/50 shadow-xl p-4 sm:p-5 backdrop-blur-md">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        {/* Left: Info & Soundwave Indicator */}
        <div className="flex items-center gap-3.5">
          <div
            className={`w-11 h-11 rounded-2xl flex items-center justify-center transition-all ${
              isPlaying
                ? 'bg-gradient-to-br from-cyan-500 to-blue-600 text-white shadow-lg shadow-cyan-500/30 ring-2 ring-cyan-400/50 animate-pulse'
                : 'bg-cyan-950/80 border border-cyan-800 text-cyan-400'
            }`}
          >
            {isPlaying ? (
              <Radio className="w-5 h-5 animate-spin" style={{ animationDuration: '4s' }} />
            ) : (
              <Headphones className="w-5 h-5" />
            )}
          </div>

          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
                <span>Synthèse Vocale des Menaces</span>
                <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-cyan-950 text-cyan-300 border border-cyan-800">
                  TTS SOC Mobilité
                </span>
              </span>
              {isPlaying && (
                <span className="flex items-center gap-1 text-[10px] font-mono text-cyan-400 font-bold animate-pulse">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                  Lecture audio en cours
                </span>
              )}
            </div>

            <p className="text-xs text-slate-400 font-sans mt-0.5">
              Écoutez un résumé audio concis des attaques critiques pour les analystes sur le terrain ou en astreinte.
            </p>
          </div>
        </div>

        {/* Right: Controls & Speed */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Animated sound equalizer bars when playing */}
          {isPlaying && !isPaused && (
            <div className="hidden sm:flex items-center gap-1 px-2.5 py-1.5 rounded-xl bg-slate-950 border border-slate-800">
              <span className="w-1 bg-cyan-400 rounded-full animate-bounce h-4" style={{ animationDuration: '450ms' }} />
              <span className="w-1 bg-cyan-300 rounded-full animate-bounce h-6" style={{ animationDuration: '300ms' }} />
              <span className="w-1 bg-cyan-500 rounded-full animate-bounce h-3" style={{ animationDuration: '550ms' }} />
              <span className="w-1 bg-cyan-400 rounded-full animate-bounce h-5" style={{ animationDuration: '400ms' }} />
            </div>
          )}

          {/* Rate Selector */}
          <div className="flex items-center bg-slate-950 border border-slate-800 rounded-xl p-0.5 text-[11px] font-mono">
            {[1.0, 1.25, 1.5].map((r) => (
              <button
                key={r}
                onClick={() => handleRateChange(r)}
                className={`px-2 py-1 rounded-lg transition ${
                  rate === r
                    ? 'bg-cyan-900/70 text-cyan-200 font-bold border border-cyan-700/60'
                    : 'text-slate-400 hover:text-white'
                }`}
                title={`Vitesse de lecture : ${r}x`}
              >
                {r}x
              </button>
            ))}
          </div>

          {/* Main Action Button */}
          {!isPlaying ? (
            <button
              onClick={handleStartSpeaking}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-600 via-cyan-500 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-bold font-mono shadow-lg shadow-cyan-900/40 border border-cyan-400/40 transition active:scale-95"
              title="Lancer la lecture vocale du rapport"
            >
              <Volume2 className="w-4 h-4" />
              <span>Écouter le Résumé</span>
            </button>
          ) : (
            <div className="flex items-center gap-1.5">
              <button
                onClick={handlePause}
                className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl bg-amber-600 hover:bg-amber-500 text-white text-xs font-bold font-mono shadow-md shadow-amber-900/40 transition"
                title={isPaused ? 'Reprendre la lecture' : 'Mettre en pause'}
              >
                {isPaused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
                <span>{isPaused ? 'Reprendre' : 'Pause'}</span>
              </button>

              <button
                onClick={handleStop}
                className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono border border-slate-700 transition"
                title="Arrêter la lecture"
              >
                <Square className="w-3.5 h-3.5 text-red-400" />
                <span>Stop</span>
              </button>
            </div>
          )}

          {/* Toggle Script Preview */}
          <button
            onClick={() => setShowScript(!showScript)}
            className="p-2 rounded-xl bg-slate-950 border border-slate-800 text-slate-400 hover:text-white transition"
            title="Afficher la transcription textuelle du résumé audio"
          >
            {showScript ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {/* Script Text Dropdown */}
      {showScript && (
        <div className="mt-4 pt-3.5 border-t border-slate-800/80 space-y-2 animate-in fade-in slide-in-from-top-1 text-xs">
          <div className="flex items-center justify-between text-slate-400 font-mono text-[11px]">
            <span>Transcription du briefing vocal :</span>
            <span className="text-cyan-400 font-semibold">{scriptText.length} caractères</span>
          </div>
          <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 text-slate-300 font-sans leading-relaxed">
            {scriptText}
          </div>
        </div>
      )}
    </div>
  );
};
