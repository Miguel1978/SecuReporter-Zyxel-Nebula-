import React, { useState } from 'react';
import {
  FileText,
  Download,
  Printer,
  Copy,
  Check,
  ShieldCheck,
  AlertTriangle,
  Lock,
  FileDown,
  Loader2,
} from 'lucide-react';
import { ActiveDefense, ThreatAnalysisResult } from '../types';
import { exportIncidentReportPdf } from '../utils/pdfExport';

interface IncidentReportViewProps {
  analysis: ThreatAnalysisResult;
  activeDefenses: ActiveDefense[];
  deviceName?: string;
}

export const IncidentReportView: React.FC<IncidentReportViewProps> = ({
  analysis,
  activeDefenses,
  deviceName = 'Passerelle Zyxel Nebula ATP / USG Flex',
}) => {
  const [copied, setCopied] = useState(false);
  const [isExportingPdf, setIsExportingPdf] = useState(false);
  const [pdfDownloaded, setPdfDownloaded] = useState(false);

  const reportId = `INC-NEBULA-${new Date().toISOString().slice(0, 10).replace(/-/g, '')}-001`;

  const generateMarkdown = () => {
    return `# RAPPORT OFFICIEL D'INCIDENT DE SÉCURITÉ - NEBULA SOC
**Référence :** ${reportId}
**Date :** ${new Date().toLocaleString('fr-FR')}
**Périmètre :** ${deviceName}
**Classification :** TLP:AMBER / RESTREINT
**Score de Risque :** ${analysis.riskScore}/100 (${analysis.threatLevel})

---

## 1. SYNTHÈSE EXÉCUTIVE
${analysis.cisoBriefing}

---

## 2. VECTEURS D'ATTAQUES & MAPPING MITRE ATT&CK
${analysis.attackVectors
  .map(
    (v, i) => `### ${i + 1}. ${v.name} [${v.mitreTechniqueId}]
- **Gravité :** ${v.severity}
- **Tactique MITRE :** ${v.mitreTactic}
- **Description :** ${v.description}
- **IPs Attaquantes :** ${v.attackerIps.join(', ') || 'N/A'}
- **Cibles :** ${v.targetAssets.join(', ') || 'Périmètre'}
`
  )
  .join('\n')}

---

## 3. INDICATEURS DE COMPROMISSION (IOC)
| Type | Valeur | Menace | Criticité |
| :--- | :--- | :--- | :--- |
${analysis.iocList.map((ioc) => `| ${ioc.type} | ${ioc.value} | ${ioc.threat} | ${ioc.severity} |`).join('\n')}

---

## 4. HÔTES INTERNES COMPROMIS / SOUS SURVEILLANCE
${
  analysis.compromisedHosts.length > 0
    ? analysis.compromisedHosts
        .map(
          (h) => `- **IP :** ${h.ip} ${h.hostname ? `(${h.hostname})` : ''} - **Statut :** ${h.status} - **Action CDR :** ${
            h.recommendedIsolation ? 'Isolement VLAN requis' : 'Sous surveillance'
          }\n  *Preuve :* ${h.evidence}`
        )
        .join('\n')
    : 'Aucun hôte interne compromis.'
}

---

## 5. CONTRE-MESURES ET RIPOSTES DÉPLOYÉES
${
  activeDefenses.length > 0
    ? activeDefenses
        .map(
          (d) => `- **Règle :** [${d.type}] ${d.target} - Statut : ${d.status} (Appliquée à ${d.appliedAt})\n  *Motif :* ${d.reason}`
        )
        .join('\n')
    : 'Aucune règle automatique active.'
}

---

## 6. PLAYBOOK ET PLAN D'ACTION RECOMMANDÉ
${analysis.incidentPlaybook.map((s) => `${s.step}. **${s.action}** (Cible : ${s.target})\n   ${s.details}`).join('\n')}

---
*Rapport certifié et généré par NebulaGuard AI SOC Engine.*
`;
  };

  const handleExportPdf = () => {
    setIsExportingPdf(true);
    try {
      exportIncidentReportPdf({
        analysis,
        activeDefenses,
        deviceName,
        reportId,
      });
      setPdfDownloaded(true);
      setTimeout(() => setPdfDownloaded(false), 3000);
    } catch (err) {
      console.error('Erreur export PDF:', err);
    } finally {
      setIsExportingPdf(false);
    }
  };

  const handleDownload = () => {
    const md = generateMarkdown();
    const blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Rapport_${reportId}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handlePrint = () => {
    window.print();
  };

  const handleCopyMd = () => {
    navigator.clipboard.writeText(generateMarkdown());
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Action Toolbar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl">
        <div className="flex items-center gap-2">
          <FileText className="w-5 h-5 text-cyan-400" />
          <div>
            <h3 className="text-sm font-bold text-white">Rapport Officiel d'Incident Cyber</h3>
            <p className="text-xs text-slate-400 font-mono">Format conforme aux normes CERT / CISO</p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={handleCopyMd}
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono font-medium border border-slate-700 transition"
          >
            {copied ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-400" />
                <span className="text-emerald-400">Copié !</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                <span>Copier Markdown</span>
              </>
            )}
          </button>

          <button
            onClick={handleDownload}
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono font-medium border border-slate-700 transition"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span>Markdown (.md)</span>
          </button>

          <button
            onClick={handlePrint}
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono font-medium border border-slate-700 transition"
            title="Ouvrir la boîte de dialogue d'impression navigateur"
          >
            <Printer className="w-3.5 h-3.5 text-slate-400" />
            <span>Imprimer</span>
          </button>

          {/* Bouton Exporter PDF Officiel */}
          <button
            onClick={handleExportPdf}
            disabled={isExportingPdf}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-red-600 via-rose-600 to-red-500 hover:from-red-500 hover:to-rose-400 text-white text-xs font-bold shadow-lg shadow-red-900/40 border border-red-500/40 transition disabled:opacity-50"
            title="Télécharger immédiatement le rapport complet au format PDF imprimable et certifié"
          >
            {isExportingPdf ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                <span>Génération du PDF...</span>
              </>
            ) : pdfDownloaded ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-300" />
                <span className="text-emerald-200">PDF Téléchargé !</span>
              </>
            ) : (
              <>
                <FileDown className="w-3.5 h-3.5 text-white" />
                <span>Exporter PDF</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Printable Report Document Sheet */}
      <div className="p-8 sm:p-12 rounded-3xl bg-slate-900/95 border border-slate-800 shadow-2xl text-slate-200 space-y-8 font-sans max-w-4xl mx-auto print:bg-white print:text-black print:border-none print:shadow-none print:p-0">
        {/* Document Header */}
        <div className="border-b border-slate-800 pb-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4 print:border-slate-300">
          <div>
            <div className="flex items-center gap-2">
              <span className="px-2.5 py-0.5 rounded text-[11px] font-mono font-bold bg-amber-950 text-amber-400 border border-amber-800 print:bg-amber-100 print:text-amber-800">
                TLP:AMBER / CONFIDENTIEL
              </span>
              <span className="text-xs font-mono text-slate-400 print:text-slate-600">
                Réf: {reportId}
              </span>
            </div>
            <h1 className="text-2xl font-extrabold text-white mt-2 print:text-black">
              Rapport d'Incident de Sécurité & Riposte Nebula
            </h1>
            <p className="text-xs text-slate-400 mt-1 font-mono print:text-slate-600">
              Système source : {deviceName} • Généré le {new Date().toLocaleString('fr-FR')}
            </p>
          </div>

          <div className="p-3.5 rounded-2xl bg-slate-950 border border-slate-800 text-right print:bg-slate-100 print:border-slate-300">
            <span className="text-[10px] font-mono uppercase text-slate-500 block">
              Score de Risque Évalué
            </span>
            <span
              className={`text-2xl font-extrabold font-mono ${
                analysis.riskScore >= 75 ? 'text-red-400 print:text-red-600' : 'text-amber-400 print:text-amber-600'
              }`}
            >
              {analysis.riskScore} / 100
            </span>
            <span className="text-[10px] font-mono block text-slate-400 print:text-slate-600">
              Niveau : {analysis.threatLevel}
            </span>
          </div>
        </div>

        {/* 1. Executive Summary */}
        <div className="space-y-3">
          <h2 className="text-sm font-bold text-cyan-400 uppercase tracking-wider font-mono print:text-cyan-800">
            1. Synthèse Exécutive (RSSI / Direction)
          </h2>
          <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800/80 text-sm leading-relaxed text-slate-300 print:bg-slate-50 print:border-slate-200 print:text-slate-800">
            {analysis.cisoBriefing}
          </div>
        </div>

        {/* 2. Attack Vectors */}
        <div className="space-y-3">
          <h2 className="text-sm font-bold text-cyan-400 uppercase tracking-wider font-mono print:text-cyan-800">
            2. Vecteurs d'Attaques & Techniques MITRE ATT&CK
          </h2>
          <div className="space-y-3">
            {analysis.attackVectors.map((vec, i) => (
              <div
                key={i}
                className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 text-xs space-y-1.5 print:bg-slate-50 print:border-slate-200 print:text-slate-800"
              >
                <div className="flex items-center justify-between">
                  <h4 className="font-bold text-white text-sm print:text-black">
                    {i + 1}. {vec.name}
                  </h4>
                  <span className="font-mono text-cyan-300 font-bold print:text-cyan-800">
                    {vec.mitreTechniqueId} ({vec.mitreTactic})
                  </span>
                </div>
                <p className="text-slate-300 print:text-slate-700">{vec.description}</p>
                <p className="font-mono text-[11px] text-slate-400 pt-1 print:text-slate-600">
                  IPs Attaquantes : <span className="text-red-400 print:text-red-600">{vec.attackerIps.join(', ') || 'N/A'}</span> • Cibles : {vec.targetAssets.join(', ') || 'Passerelle'}
                </p>
              </div>
            ))}
          </div>
        </div>

        {/* 3. IOCs */}
        <div className="space-y-3">
          <h2 className="text-sm font-bold text-cyan-400 uppercase tracking-wider font-mono print:text-cyan-800">
            3. Indicateurs de Compromission Relevés (IOC)
          </h2>
          <div className="overflow-x-auto rounded-xl border border-slate-800 print:border-slate-300">
            <table className="w-full text-left font-mono text-xs">
              <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 print:bg-slate-100 print:text-black print:border-slate-300">
                <tr>
                  <th className="p-2.5">Type</th>
                  <th className="p-2.5">Valeur</th>
                  <th className="p-2.5">Menace</th>
                  <th className="p-2.5">Gravité</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 print:divide-slate-200">
                {analysis.iocList.map((ioc, idx) => (
                  <tr key={idx}>
                    <td className="p-2.5 font-bold text-cyan-300 print:text-cyan-800">{ioc.type}</td>
                    <td className="p-2.5 font-bold text-white print:text-black">{ioc.value}</td>
                    <td className="p-2.5 text-slate-300 font-sans print:text-slate-700">{ioc.threat}</td>
                    <td className="p-2.5 text-red-400 font-bold print:text-red-600">{ioc.severity}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* 4. Active Riposte Rules */}
        <div className="space-y-3">
          <h2 className="text-sm font-bold text-cyan-400 uppercase tracking-wider font-mono print:text-cyan-800">
            4. Statut des Contre-Mesures Firewall & Quarantaine
          </h2>
          <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 space-y-2 text-xs font-mono print:bg-slate-50 print:border-slate-200 print:text-slate-800">
            {activeDefenses.length === 0 ? (
              <p className="text-slate-500">Aucune riposte active répertoriée dans la session.</p>
            ) : (
              activeDefenses.map((def, idx) => (
                <div key={idx} className="flex items-center justify-between pb-1 border-b border-slate-800/60 last:border-0 print:border-slate-200">
                  <span>
                    [{def.type}] <strong className="text-white print:text-black">{def.target}</strong> - {def.reason}
                  </span>
                  <span className="text-emerald-400 font-bold print:text-emerald-700">DÉPLOYÉE ({def.packetsBlocked} drops)</span>
                </div>
              ))
            )}
          </div>
        </div>

        {/* 5. Compromised Internal Hosts */}
        <div className="space-y-3">
          <h2 className="text-sm font-bold text-cyan-400 uppercase tracking-wider font-mono print:text-cyan-800">
            5. Hôtes Internes LAN Compromis & Isolement CDR
          </h2>
          <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 space-y-2 text-xs font-mono print:bg-slate-50 print:border-slate-200 print:text-slate-800">
            {analysis.compromisedHosts.length === 0 ? (
              <p className="text-slate-500">Aucun hôte interne compromis dans ce rapport.</p>
            ) : (
              analysis.compromisedHosts.map((host, idx) => (
                <div key={idx} className="p-2.5 rounded-lg bg-slate-900 border border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-2 print:bg-white print:border-slate-300">
                  <div>
                    <span className="font-bold text-red-400 print:text-red-700">{host.ip}</span>
                    {host.hostname && <span className="text-slate-400 font-sans ml-1">({host.hostname})</span>}
                    <p className="text-[11px] text-slate-400 font-sans mt-0.5">{host.evidence}</p>
                  </div>
                  <span className={`text-[10px] px-2 py-0.5 rounded font-bold self-start sm:self-auto ${
                    host.recommendedIsolation
                      ? 'bg-red-950 text-red-300 border border-red-800 print:bg-red-100 print:text-red-800'
                      : 'bg-slate-800 text-slate-300'
                  }`}>
                    {host.recommendedIsolation ? 'Isolement VLAN Requis' : 'Sous Surveillance'}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>

        {/* 6. Playbook Steps */}
        <div className="space-y-3">
          <h2 className="text-sm font-bold text-cyan-400 uppercase tracking-wider font-mono print:text-cyan-800">
            6. Playbook et Plan d'Action Recommandé (CERT)
          </h2>
          <div className="space-y-2 text-xs">
            {analysis.incidentPlaybook.map((step) => (
              <div
                key={step.step}
                className="p-3 rounded-xl bg-slate-950/70 border border-slate-800 flex items-start gap-3 print:bg-slate-50 print:border-slate-200"
              >
                <div className="w-6 h-6 rounded-lg bg-cyan-950 text-cyan-400 border border-cyan-800 flex items-center justify-center font-mono font-bold flex-shrink-0 text-xs print:bg-cyan-100 print:text-cyan-800">
                  {step.step}
                </div>
                <div>
                  <h4 className="font-bold text-white print:text-black">
                    {step.action} <span className="text-cyan-300 font-mono font-normal">({step.target})</span>
                  </h4>
                  <p className="text-slate-400 text-[11px] mt-0.5 print:text-slate-700 font-sans">
                    {step.details}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Footer */}
        <div className="pt-6 border-t border-slate-800 text-center text-xs font-mono text-slate-500 print:text-slate-600 print:border-slate-300">
          Ce rapport est un livrable d'analyse forensique automatisé généré par NebulaGuard AI SOC.
        </div>
      </div>
    </div>
  );
};
