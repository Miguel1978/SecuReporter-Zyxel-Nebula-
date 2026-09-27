import { jsPDF } from 'jspdf';
import { ThreatAnalysisResult, ActiveDefense } from '../types';

interface PdfExportOptions {
  analysis: ThreatAnalysisResult;
  activeDefenses: ActiveDefense[];
  deviceName?: string;
  reportId: string;
}

export function exportIncidentReportPdf({
  analysis,
  activeDefenses,
  deviceName = 'Passerelle Zyxel Nebula ATP / USG Flex',
  reportId,
}: PdfExportOptions): void {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4',
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 14;
  const contentWidth = pageWidth - margin * 2;
  let y = 18;

  const drawHeaderOnPage = () => {
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    doc.setTextColor(71, 85, 105); // slate-600
    doc.text('NEBULAGUARD AI SOC • RAPPORT OFFICIEL CERT / RSSI', margin, 10);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(148, 163, 184); // slate-400
    doc.text(`RÉF: ${reportId}  •  TLP:AMBER`, pageWidth - margin, 10, { align: 'right' });

    doc.setDrawColor(203, 213, 225); // slate-300
    doc.setLineWidth(0.3);
    doc.line(margin, 12, pageWidth - margin, 12);
  };

  const checkPageBreak = (neededHeight: number) => {
    if (y + neededHeight > pageHeight - 16) {
      doc.addPage();
      drawHeaderOnPage();
      y = 18;
    }
  };

  // First page top header
  drawHeaderOnPage();

  // Top Title Block
  doc.setFillColor(15, 23, 42); // slate-900
  doc.roundedRect(margin, y, contentWidth, 34, 3, 3, 'F');

  // Badge TLP
  doc.setFillColor(120, 53, 15); // amber-900
  doc.roundedRect(margin + 4, y + 4, 36, 5.5, 1.5, 1.5, 'F');
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(7.5);
  doc.setTextColor(253, 230, 138); // amber-200
  doc.text('TLP:AMBER / RESTREINT', margin + 6, y + 8);

  // Reference & Date
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.5);
  doc.setTextColor(148, 163, 184);
  doc.text(`Réf : ${reportId}`, margin + 44, y + 8);

  // Main Title
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(14);
  doc.setTextColor(255, 255, 255);
  doc.text("Rapport d'Incident de Sécurité & Riposte Nebula", margin + 4, y + 17);

  // Subtitle / Scope
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(203, 213, 225);
  doc.text(
    `Périmètre : ${deviceName}  •  Généré le : ${new Date().toLocaleString('fr-FR')}`,
    margin + 4,
    y + 23
  );
  doc.text('Moteur d\'analyse : NebulaGuard AI SOC Engine v2.4 (Zyxel ATP / USG Flex)', margin + 4, y + 28);

  // Risk Score Badge (Right box inside banner)
  const isCritical = analysis.riskScore >= 75 || analysis.threatLevel === 'CRITICAL';
  const badgeColor = isCritical ? [185, 28, 28] : [217, 119, 6]; // red-700 : amber-600
  doc.setFillColor(badgeColor[0], badgeColor[1], badgeColor[2]);
  doc.roundedRect(pageWidth - margin - 38, y + 4, 34, 26, 2, 2, 'F');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(7.5);
  doc.setTextColor(255, 255, 255);
  doc.text('SCORE DE RISQUE', pageWidth - margin - 21, y + 9, { align: 'center' });

  doc.setFontSize(16);
  doc.text(`${analysis.riskScore}/100`, pageWidth - margin - 21, y + 18, { align: 'center' });

  doc.setFontSize(8);
  doc.text(analysis.threatLevel, pageWidth - margin - 21, y + 25, { align: 'center' });

  y += 40;

  // Helper for Section Titles
  const drawSectionTitle = (number: string, title: string) => {
    checkPageBreak(12);
    doc.setFillColor(241, 245, 249); // slate-100
    doc.rect(margin, y, contentWidth, 7, 'F');

    doc.setFillColor(8, 145, 178); // cyan-600
    doc.rect(margin, y, 2.5, 7, 'F');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9.5);
    doc.setTextColor(15, 23, 42); // slate-900
    doc.text(`${number}. ${title.toUpperCase()}`, margin + 5, y + 5);
    y += 10;
  };

  // 1. Executive Summary
  drawSectionTitle('1', 'Synthèse Exécutive (RSSI / Direction)');
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(30, 41, 59);

  const briefingLines = doc.splitTextToSize(analysis.cisoBriefing, contentWidth - 4);
  checkPageBreak(briefingLines.length * 4.2 + 6);

  doc.setFillColor(248, 250, 252);
  doc.roundedRect(margin, y, contentWidth, briefingLines.length * 4.2 + 4, 1.5, 1.5, 'F');
  doc.text(briefingLines, margin + 3, y + 4);
  y += briefingLines.length * 4.2 + 9;

  // 2. Attack Vectors & MITRE ATT&CK Mapping
  drawSectionTitle('2', "Vecteurs d'Attaques & Techniques MITRE ATT&CK");
  analysis.attackVectors.forEach((vec, idx) => {
    const descLines = doc.splitTextToSize(vec.description, contentWidth - 8);
    const boxHeight = 16 + descLines.length * 3.8;
    checkPageBreak(boxHeight + 4);

    // Box container
    doc.setFillColor(248, 250, 252);
    doc.setDrawColor(226, 232, 240);
    doc.roundedRect(margin, y, contentWidth, boxHeight, 1.5, 1.5, 'FD');

    // Vector Header
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9);
    doc.setTextColor(15, 23, 42);
    doc.text(`${idx + 1}. ${vec.name}`, margin + 4, y + 5);

    // MITRE tag
    doc.setFont('courier', 'bold');
    doc.setFontSize(8);
    doc.setTextColor(8, 145, 178);
    doc.text(`[${vec.mitreTechniqueId}] ${vec.mitreTactic}`, pageWidth - margin - 4, y + 5, {
      align: 'right',
    });

    // Description
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(51, 65, 85);
    doc.text(descLines, margin + 4, y + 9.5);

    // Footer IPs and Target
    const footerY = y + 10 + descLines.length * 3.8;
    doc.setFont('courier', 'bold');
    doc.setFontSize(7.5);
    doc.setTextColor(185, 28, 28);
    doc.text(`IPs Attaquantes : ${vec.attackerIps.join(', ') || 'N/A'}`, margin + 4, footerY);

    doc.setFont('helvetica', 'normal');
    doc.setTextColor(100, 116, 139);
    doc.text(`Cibles : ${vec.targetAssets.join(', ') || 'Périmètre LAN/WAN'}`, margin + 85, footerY);

    y += boxHeight + 4;
  });

  y += 3;

  // 3. Indicators of Compromise (IOC)
  drawSectionTitle('3', 'Indicateurs de Compromission Relevés (IOC)');
  checkPageBreak(25);

  // Table Header
  doc.setFillColor(15, 23, 42);
  doc.rect(margin, y, contentWidth, 6, 'F');
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(7.5);
  doc.setTextColor(255, 255, 255);
  doc.text('TYPE', margin + 3, y + 4.2);
  doc.text('VALEUR / INDICATEUR', margin + 28, y + 4.2);
  doc.text('MENACE ASSOCIÉE', margin + 95, y + 4.2);
  doc.text('GRAVITÉ', pageWidth - margin - 4, y + 4.2, { align: 'right' });
  y += 6;

  analysis.iocList.forEach((ioc, i) => {
    checkPageBreak(6.5);
    doc.setFillColor(i % 2 === 0 ? 255 : 248, i % 2 === 0 ? 255 : 250, i % 2 === 0 ? 255 : 252);
    doc.rect(margin, y, contentWidth, 6, 'F');

    doc.setFont('courier', 'bold');
    doc.setFontSize(7.5);
    doc.setTextColor(8, 145, 178);
    doc.text(ioc.type, margin + 3, y + 4.2);

    doc.setTextColor(15, 23, 42);
    doc.text(ioc.value, margin + 28, y + 4.2);

    doc.setFont('helvetica', 'normal');
    doc.setTextColor(51, 65, 85);
    doc.text(ioc.threat.slice(0, 50), margin + 95, y + 4.2);

    doc.setFont('helvetica', 'bold');
    doc.setTextColor(ioc.severity === 'CRITICAL' ? 185 : 217, ioc.severity === 'CRITICAL' ? 28 : 119, ioc.severity === 'CRITICAL' ? 28 : 6);
    doc.text(ioc.severity, pageWidth - margin - 4, y + 4.2, { align: 'right' });

    y += 6;
  });

  y += 6;

  // 4. Compromised Internal Hosts & Isolation
  drawSectionTitle('4', 'Hôtes LAN Compromis & Actions CDR');
  if (analysis.compromisedHosts.length === 0) {
    checkPageBreak(10);
    doc.setFont('helvetica', 'italic');
    doc.setFontSize(8);
    doc.setTextColor(100, 116, 139);
    doc.text('Aucun hôte interne compromis détecté dans ce rapport.', margin + 4, y + 4);
    y += 8;
  } else {
    analysis.compromisedHosts.forEach((host) => {
      checkPageBreak(14);
      doc.setFillColor(254, 242, 242); // red-50
      doc.setDrawColor(254, 202, 202);
      doc.roundedRect(margin, y, contentWidth, 12, 1.5, 1.5, 'FD');

      doc.setFont('courier', 'bold');
      doc.setFontSize(8);
      doc.setTextColor(185, 28, 28);
      doc.text(`IP : ${host.ip} ${host.hostname ? `(${host.hostname})` : ''}`, margin + 4, y + 4.5);

      doc.setFont('helvetica', 'bold');
      doc.setTextColor(15, 23, 42);
      doc.text(`Statut : ${host.status}`, margin + 65, y + 4.5);

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7.5);
      doc.setTextColor(71, 85, 105);
      doc.text(`Preuve : ${host.evidence.slice(0, 95)}`, margin + 4, y + 9);

      doc.setFont('helvetica', 'bold');
      doc.setTextColor(host.recommendedIsolation ? 185 : 8, host.recommendedIsolation ? 28 : 145, host.recommendedIsolation ? 28 : 178);
      doc.text(
        host.recommendedIsolation ? 'Isolement VLAN Requis' : 'Sous Surveillance',
        pageWidth - margin - 4,
        y + 4.5,
        { align: 'right' }
      );

      y += 15;
    });
  }

  y += 3;

  // 5. Active Riposte Rules & Countermeasures
  drawSectionTitle('5', 'Ripostes Pare-Feu Déployées & Contre-Mesures');
  if (activeDefenses.length === 0) {
    checkPageBreak(10);
    doc.setFont('helvetica', 'italic');
    doc.setFontSize(8);
    doc.setTextColor(100, 116, 139);
    doc.text('Aucune règle pare-feu active enregistrée dans cette session.', margin + 4, y + 4);
    y += 8;
  } else {
    activeDefenses.forEach((def) => {
      checkPageBreak(12);
      doc.setFillColor(240, 253, 244); // emerald-50
      doc.setDrawColor(187, 247, 208);
      doc.roundedRect(margin, y, contentWidth, 10, 1.5, 1.5, 'FD');

      doc.setFont('courier', 'bold');
      doc.setFontSize(8);
      doc.setTextColor(21, 128, 61); // emerald-700
      doc.text(`[${def.type}] ${def.target}`, margin + 4, y + 4.5);

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7.5);
      doc.setTextColor(51, 65, 85);
      doc.text(`Motif : ${def.reason.slice(0, 75)}`, margin + 4, y + 8);

      doc.setFont('helvetica', 'bold');
      doc.setTextColor(21, 128, 61);
      doc.text(
        `ACTIVE (${def.packetsBlocked} paquets bloqués)`,
        pageWidth - margin - 4,
        y + 4.5,
        { align: 'right' }
      );

      y += 12;
    });
  }

  y += 3;

  // 6. Incident Playbook Steps
  drawSectionTitle('6', "Plan d'Action Recommandé (Playbook CERT)");
  analysis.incidentPlaybook.forEach((pb) => {
    checkPageBreak(12);
    doc.setFillColor(248, 250, 252);
    doc.setDrawColor(226, 232, 240);
    doc.roundedRect(margin, y, contentWidth, 10, 1.5, 1.5, 'FD');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    doc.setTextColor(15, 23, 42);
    doc.text(`Étape ${pb.step} : ${pb.action}`, margin + 4, y + 4.5);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(71, 85, 105);
    doc.text(`Cible : ${pb.target}  •  ${pb.details.slice(0, 90)}`, margin + 4, y + 8);

    y += 12;
  });

  // Footer on all pages (Page numbers and certification)
  const totalPages = doc.getNumberOfPages();
  for (let p = 1; p <= totalPages; p++) {
    doc.setPage(p);
    doc.setDrawColor(203, 213, 225);
    doc.setLineWidth(0.3);
    doc.line(margin, pageHeight - 12, pageWidth - margin, pageHeight - 12);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7);
    doc.setTextColor(148, 163, 184);
    doc.text(
      'Document certifié conforme • Généré par NebulaGuard AI SOC Engine pour Passerelle Zyxel Nebula ATP / USG FLEX',
      margin,
      pageHeight - 8
    );

    doc.text(`Page ${p} / ${totalPages}`, pageWidth - margin, pageHeight - 8, { align: 'right' });
  }

  // Trigger download
  doc.save(`Rapport_Incident_${reportId}.pdf`);
}
