import React, { useState } from 'react';
import {
  Upload,
  FileText,
  FileCode,
  ShieldAlert,
  X,
  Sparkles,
  ArrowRight,
} from 'lucide-react';
import { SAMPLE_REPORTS } from '../data/sampleReports';
import { SampleReport } from '../types';

interface LogUploadModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmitLogs: (rawText: string, deviceName: string) => void;
  onSelectSample: (sample: SampleReport) => void;
}

export const LogUploadModal: React.FC<LogUploadModalProps> = ({
  isOpen,
  onClose,
  onSubmitLogs,
  onSelectSample,
}) => {
  const [pastedLogs, setPastedLogs] = useState('');
  const [deviceName, setDeviceName] = useState('Zyxel Nebula ATP700 Gateway');
  const [fileName, setFileName] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setFileName(file.name);
    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      if (content) {
        setPastedLogs(content);
      }
    };
    reader.readAsText(file);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    const file = e.dataTransfer.files?.[0];
    if (!file) return;

    setFileName(file.name);
    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      if (content) {
        setPastedLogs(content);
      }
    };
    reader.readAsText(file);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!pastedLogs.trim()) return;
    onSubmitLogs(pastedLogs, deviceName);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-800 rounded-3xl max-w-3xl w-full p-6 sm:p-8 space-y-6 shadow-2xl relative max-h-[92vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-cyan-600/20 text-cyan-400 border border-cyan-500/30 flex items-center justify-center">
              <Upload className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-white tracking-tight">
                Importer des Logs Nebula Secure Report
              </h3>
              <p className="text-xs text-slate-400 font-mono">
                Supporte Zyxel Nebula Syslog, CEF, export CSV ou JSON
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Quick Sample Selector */}
        <div className="space-y-2">
          <span className="text-xs font-mono uppercase text-slate-400 font-semibold block">
            Ou charger un rapport d'attaque prédéfini :
          </span>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
            {SAMPLE_REPORTS.map((sample) => (
              <button
                key={sample.id}
                type="button"
                onClick={() => {
                  onSelectSample(sample);
                  onClose();
                }}
                className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 hover:border-cyan-600 text-left transition group space-y-1"
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-white group-hover:text-cyan-400 transition truncate max-w-[200px]">
                    {sample.title}
                  </span>
                  <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-red-950 text-red-400 border border-red-900 font-bold">
                    {sample.severity}
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 line-clamp-1">{sample.description}</p>
              </button>
            ))}
          </div>
        </div>

        <div className="relative flex py-1 items-center">
          <div className="flex-grow border-t border-slate-800"></div>
          <span className="flex-shrink mx-4 text-xs font-mono text-slate-500 uppercase">
            OU importer vos propres logs
          </span>
          <div className="flex-grow border-t border-slate-800"></div>
        </div>

        {/* Upload Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="text-xs font-mono text-slate-300 block mb-1">
              Nom ou Modèle de la Passerelle Nebula
            </label>
            <input
              type="text"
              value={deviceName}
              onChange={(e) => setDeviceName(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono"
              placeholder="ex: Nebula ATP700 Gateway (Site Central)"
              required
            />
          </div>

          {/* Drag & drop zone */}
          <div
            onDragOver={handleDragOver}
            onDrop={handleDrop}
            className="border-2 border-dashed border-slate-700 hover:border-cyan-500 rounded-2xl p-6 text-center cursor-pointer transition bg-slate-950/40 relative"
          >
            <input
              type="file"
              accept=".csv,.txt,.log,.json"
              onChange={handleFileUpload}
              className="absolute inset-0 opacity-0 cursor-pointer w-full h-full"
            />
            <div className="flex flex-col items-center justify-center space-y-2 pointer-events-none">
              <FileCode className="w-8 h-8 text-cyan-400" />
              <div className="text-xs text-slate-300 font-medium">
                {fileName ? (
                  <span className="text-cyan-400 font-bold font-mono">Fichier sélectionné : {fileName}</span>
                ) : (
                  <>
                    Glissez votre fichier ici ou <span className="text-cyan-400 underline">parcourez vos dossiers</span>
                  </>
                )}
              </div>
              <p className="text-[10px] text-slate-500 font-mono">Fichiers acceptés : .csv, .log, .txt, .json</p>
            </div>
          </div>

          {/* Paste Textarea */}
          <div className="space-y-1">
            <label className="text-xs font-mono text-slate-300 block">
              Ou collez le texte brut des logs Nebula :
            </label>
            <textarea
              rows={6}
              value={pastedLogs}
              onChange={(e) => setPastedLogs(e.target.value)}
              placeholder="2026-09-25T08:14:22Z [ATP700] [IDP/IPS] PRIORITY=CRITICAL SIG_ID=1120489 NAME=&quot;Trojan.Win32.CobaltStrike&quot; SRC=192.168.1.105:49182 DST=91.240.118.172:443 ACTION=Dropped..."
              className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3.5 text-xs text-white placeholder-slate-600 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono leading-relaxed resize-none"
            />
          </div>

          {/* Buttons */}
          <div className="flex items-center justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition"
            >
              Annuler
            </button>
            <button
              type="submit"
              disabled={!pastedLogs.trim()}
              className="inline-flex items-center gap-2 px-6 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold text-xs shadow-lg shadow-cyan-600/30 transition disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <Sparkles className="w-4 h-4" />
              <span>Lancer l'Analyse IA & Arrêter les Attaques</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
