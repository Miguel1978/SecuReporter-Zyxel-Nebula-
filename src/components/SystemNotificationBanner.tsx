import React, { useEffect, useState } from 'react';
import {
  ShieldAlert,
  Bell,
  X,
  ArrowRight,
  Radio,
  ExternalLink,
  Volume2,
} from 'lucide-react';
import { SystemNotificationPayload, playAlertChime } from '../utils/systemNotification';

interface SystemNotificationBannerProps {
  notification: SystemNotificationPayload | null;
  onClose: () => void;
  onNavigateToCountermeasures: () => void;
}

export const SystemNotificationBanner: React.FC<SystemNotificationBannerProps> = ({
  notification,
  onClose,
  onNavigateToCountermeasures,
}) => {
  const [isHovered, setIsHovered] = useState(false);
  const [progress, setProgress] = useState(100);

  useEffect(() => {
    if (!notification) return;
    setProgress(100);
  }, [notification]);

  useEffect(() => {
    if (!notification) return;

    const duration = 9000; // 9 seconds
    const intervalTime = 100;
    const step = (intervalTime / duration) * 100;

    const timer = setInterval(() => {
      if (!isHovered) {
        setProgress((prev) => Math.max(0, prev - step));
      }
    }, intervalTime);

    return () => clearInterval(timer);
  }, [notification, isHovered]);

  useEffect(() => {
    if (notification && progress <= 0) {
      onClose();
    }
  }, [progress, notification, onClose]);

  if (!notification) return null;

  return (
    <div
      role="alert"
      aria-live="assertive"
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      className="fixed top-5 right-5 z-[9999] w-[92vw] sm:w-[420px] max-w-[420px] rounded-2xl bg-slate-900/95 border-2 border-red-600/80 shadow-[0_20px_50px_rgba(239,68,68,0.35)] backdrop-blur-xl transition-all duration-300 animate-in slide-in-from-top-4 fade-in overflow-hidden"
    >
      {/* Top OS Header Bar */}
      <div className="flex items-center justify-between px-4 py-2.5 bg-slate-950/80 border-b border-slate-800 text-[11px] font-mono text-slate-400">
        <div className="flex items-center gap-2">
          <div className="w-5 h-5 rounded-md bg-red-950 text-red-400 border border-red-800 flex items-center justify-center">
            <Bell className="w-3 h-3 animate-bounce" />
          </div>
          <span className="font-bold text-slate-200 uppercase tracking-wider">
            Web Notification • SOC System
          </span>
        </div>

        <div className="flex items-center gap-2.5">
          <span className="text-[10px] text-slate-500">À l'instant</span>
          <button
            onClick={() => playAlertChime(true)}
            className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-cyan-300 transition"
            title="Rejouer le carillon d'alerte sonore"
          >
            <Volume2 className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={onClose}
            className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-white transition"
            title="Fermer la notification"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Main Body */}
      <div className="p-4 space-y-3">
        <div className="flex items-start gap-3">
          <div className="w-10 h-10 rounded-xl bg-red-600/20 border border-red-500/50 text-red-400 flex items-center justify-center flex-shrink-0 mt-0.5">
            <ShieldAlert className="w-6 h-6 animate-pulse" />
          </div>

          <div className="space-y-1 min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-red-950 text-red-300 border border-red-800 animate-pulse">
                <Radio className="w-3 h-3" />
                SÉVÉRITÉ CRITIQUE
              </span>
              <span className="text-[11px] font-mono font-bold text-red-400">
                Score : {notification.riskScore}/100
              </span>
            </div>

            <h4 className="text-sm font-bold text-white leading-snug">
              {notification.title}
            </h4>

            <p className="text-xs text-slate-300 leading-relaxed font-sans line-clamp-2">
              {notification.body}
            </p>
          </div>
        </div>

        {/* Attack Specific Metadata Pills */}
        {(notification.attackerIp || notification.threatName) && (
          <div className="grid grid-cols-2 gap-2 pt-1 font-mono text-[11px]">
            {notification.attackerIp && (
              <div className="p-2 rounded-lg bg-slate-950/70 border border-slate-800 truncate">
                <span className="text-[9px] text-slate-500 uppercase block">IP Source</span>
                <span className="text-red-300 font-bold">{notification.attackerIp}</span>
              </div>
            )}
            {notification.threatName && (
              <div className="p-2 rounded-lg bg-slate-950/70 border border-slate-800 truncate">
                <span className="text-[9px] text-slate-500 uppercase block">Signature</span>
                <span className="text-cyan-300 font-bold truncate block">{notification.threatName}</span>
              </div>
            )}
          </div>
        )}

        {/* Action Buttons */}
        <div className="flex items-center gap-2 pt-2">
          <button
            onClick={() => {
              onClose();
              onNavigateToCountermeasures();
            }}
            className="flex-1 inline-flex items-center justify-center gap-1.5 px-4 py-2.5 rounded-xl bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 text-white font-bold text-xs shadow-lg shadow-red-900/40 transition"
          >
            <span>Riposte & Neutralisation</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>

          <button
            onClick={onClose}
            className="px-3 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono transition"
          >
            Ignorer
          </button>
        </div>
      </div>

      {/* Countdown Progress Bar */}
      <div className="w-full bg-slate-950 h-1">
        <div
          className="h-full bg-gradient-to-r from-red-500 to-rose-500 transition-all duration-100"
          style={{ width: `${progress}%` }}
        />
      </div>
    </div>
  );
};
