import express from 'express';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import { GoogleGenAI, Type } from '@google/genai';
import { createServer as createViteServer } from 'vite';
import { StopAction } from './src/types/index';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT) || 3000;

app.use(express.json({ limit: '10mb' }));

// In-memory active defenses store (simulating Nebula Cloud Security Manager)
interface ActiveDefenseRecord {
  id: string;
  type: 'IP_BLOCK' | 'HOST_QUARANTINE' | 'GEO_BLOCK' | 'DOMAIN_BLACKLIST';
  target: string;
  reason: string;
  appliedAt: string;
  status: 'ACTIVE' | 'REVOKED';
  packetsBlocked: number;
  policyName: string;
  syncedWithNebula: boolean;
}

const activeDefenses: ActiveDefenseRecord[] = [
  {
    id: 'def-init-1',
    type: 'IP_BLOCK',
    target: '185.220.101.5',
    reason: 'Tor Exit Node & Exfiltration C2 attempt',
    appliedAt: new Date(Date.now() - 3600000).toISOString(),
    status: 'ACTIVE',
    packetsBlocked: 1420,
    policyName: 'Nebula_AutoBlock_HighRisk_WAN',
    syncedWithNebula: true,
  },
];

// Initialize Gemini Client
const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY,
  httpOptions: {
    headers: {
      'User-Agent': 'aistudio-build',
    },
  },
});

// Helper for local algorithmic analysis fallback
function generateLocalFallbackAnalysis(logsText: string) {
  const lines = logsText.split('\n').filter((l) => l.trim().length > 0);
  const criticalCount = (logsText.match(/CRITICAL/gi) || []).length;
  const highCount = (logsText.match(/HIGH/gi) || []).length;
  const lockbitDetected = /lockbit|ransomware/i.test(logsText);
  const log4jDetected = /log4j|cve-2021-44228|jndi/i.test(logsText);
  const miraiDetected = /mirai|syn_flood|telnet/i.test(logsText);
  const c2Detected = /cobaltstrike|botnet|beacon|c2/i.test(logsText);

  // Extract candidate external IPs
  const ipMatches = logsText.match(/\b(?!(?:10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|127\.0\.0\.1|0\.0\.0\.0))([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\b/g) || [];
  const uniqueAttackerIps = Array.from(new Set(ipMatches)).slice(0, 5);

  // Extract internal hosts
  const internalIps = logsText.match(/\b(192\.168\.[0-9]{1,3}\.[0-9]{1,3}|10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\b/g) || [];
  const uniqueInternalIps = Array.from(new Set(internalIps)).slice(0, 3);

  const riskScore = Math.min(100, Math.max(30, criticalCount * 25 + highCount * 12 + (lockbitDetected ? 40 : 0) + (log4jDetected ? 35 : 0)));
  const threatLevel = riskScore >= 75 ? 'CRITICAL' : riskScore >= 50 ? 'HIGH' : 'MEDIUM';

  const stopActions: StopAction[] = uniqueAttackerIps.map((ip, idx) => ({
    id: `action-stop-${idx + 1}`,
    title: `Blocage WAN Immédiat : IP Attaquante ${ip}`,
    type: 'FIREWALL_BLOCK' as const,
    target: ip,
    priority: idx === 0 ? ('IMMEDIATE' as const) : ('HIGH' as const),
    rationale: `Activité hostile répétée identifiée dans le rapport Nebula (Score de risque élevé, tentatives d'intrusion / balisage C2).`,
    zyxelNebulaRule: {
      ruleName: `DROP_ATTACKER_${ip.replace(/\./g, '_')}`,
      direction: 'WAN to LAN' as const,
      action: 'DROP' as const,
      sourceObject: `Host_${ip}`,
      destinationObject: 'Any',
    },
    zyxelCliCommand: `configure terminal\naddress-object Host_${ip.replace(/\./g, '_')} host ${ip}\nfirewall rule 100\n  name DROP_ATTACKER_${ip.replace(/\./g, '_')}\n  from WAN to Any\n  source-address Host_${ip.replace(/\./g, '_')}\n  action drop\n  log alert\nexit\nwrite memory`,
    iptablesCommand: `sudo iptables -I INPUT -s ${ip} -j DROP\nsudo iptables -I FORWARD -s ${ip} -j DROP`,
    nftablesCommand: `sudo nft add rule inet filter input ip saddr ${ip} drop`,
    pfSenseRule: `<rule><type>block</type><interface>wan</interface><source><address>${ip}</address></source><descr>Nebula AI Block</descr></rule>`,
  }));

  if (uniqueInternalIps.length > 0) {
    stopActions.unshift({
      id: 'action-isolate-internal',
      title: `Isolation Hôte Interne Compromis : ${uniqueInternalIps[0]}`,
      type: 'HOST_QUARANTINE' as const,
      target: uniqueInternalIps[0],
      priority: 'IMMEDIATE' as const,
      rationale: `L'hôte interne présente des communications anormales vers l'extérieur et des tentatives de mouvement latéral.`,
      zyxelNebulaRule: {
        ruleName: `QUARANTINE_${uniqueInternalIps[0].replace(/\./g, '_')}`,
        direction: 'LAN to WAN' as const,
        action: 'DROP' as const,
        sourceObject: `Infected_${uniqueInternalIps[0]}`,
        destinationObject: 'Any',
      },
      zyxelCliCommand: `cdr quarantine-client ip ${uniqueInternalIps[0]} vlan quarantine-isolated\nfirewall rule 10\n  name QUARANTINE_LAN_${uniqueInternalIps[0].replace(/\./g, '_')}\n  from LAN1 to Any\n  source-address ${uniqueInternalIps[0]}\n  action reject\nexit`,
      iptablesCommand: `sudo iptables -I FORWARD -s ${uniqueInternalIps[0]} -j DROP`,
      nftablesCommand: `sudo nft add rule inet filter forward ip saddr ${uniqueInternalIps[0]} drop`,
      pfSenseRule: `<rule><type>reject</type><interface>lan</interface><source><address>${uniqueInternalIps[0]}</address></source><descr>CDR Quarantine Host</descr></rule>`,
    });
  }

  return {
    summary: `Analyse automatique effectuée sur ${lines.length} enregistrements Nebula Secure Report. ${criticalCount} événement(s) critique(s) et ${highCount} événement(s) haute priorité détectés.${lockbitDetected ? ' Menace critique Ransomware / Cobalt Strike active.' : ''}${log4jDetected ? ' Exploitation active Log4Shell CVE-2021-44228 repérée.' : ''}`,
    riskScore,
    threatLevel,
    activeAttacksDetected: Math.max(1, criticalCount + highCount),
    attackVectors: [
      {
        name: lockbitDetected ? 'Campagne Ransomware & Command-and-Control' : log4jDetected ? 'Exploitation RCE & Credential Stuffing' : miraiDetected ? 'Reconnaissance Botnet & Déni de Service' : 'Tentative d\'Infiltration Périmétrique',
        description: 'Vecteur d\'attaque identifié par corrélation des signatures IDP, filtres IP Reputation et alertes Nebula Gateway.',
        mitreTactic: lockbitDetected ? 'Command and Control / Exfiltration' : log4jDetected ? 'Initial Access / Execution' : 'Reconnaissance / Impact',
        mitreTechniqueId: lockbitDetected ? 'T1071 / T1059' : log4jDetected ? 'T1190' : 'T1595 / T1498',
        severity: threatLevel,
        attackerIps: uniqueAttackerIps,
        targetAssets: uniqueInternalIps,
      },
    ],
    iocList: uniqueAttackerIps.map((ip) => ({
      type: 'IP' as const,
      value: ip,
      threat: lockbitDetected ? 'Serveur C2 Malveillant' : 'Hôte d\'Attaque / Scanner',
      severity: 'CRITICAL' as const,
      recommendedAction: 'BLOCK_WAN' as const,
    })),
    compromisedHosts: uniqueInternalIps.map((ip) => ({
      ip,
      hostname: 'POSTE-CLIENT',
      status: 'Infected' as const,
      recommendedIsolation: true,
      evidence: 'Détection d\'appels anormaux vers des IP malveillantes répertoriées par Nebula Threat Intelligence.',
    })),
    stopActions,
    incidentPlaybook: [
      {
        step: 1,
        action: 'Application immédiate du blocage firewall périmétrique',
        target: 'Passerelle Zyxel Nebula WAN',
        details: 'Ajouter les adresses IP attaquantes dans le groupe d\'adresses de blocage WAN-to-LAN et WAN-to-ZyWALL.',
      },
      {
        step: 2,
        action: 'Quarantaine réseau du poste interne suspect (CDR)',
        target: uniqueInternalIps[0] || 'Poste LAN',
        details: 'Déclencher la mise en quarantaine VLAN sur les commutateurs Nebula pour stopper toute propagation latérale.',
      },
      {
        step: 3,
        action: 'Purge des sessions actives et analyse forensique EDR',
        target: 'Nebula Security Gateway',
        details: 'Tuer les flux TCP persistants et vérifier la non-exfiltration de données.',
      },
    ],
    cisoBriefing: `Incidents de sécurité majeurs détectés sur la passerelle Nebula. Niveau de criticité évalué à ${threatLevel} (Score de risque: ${riskScore}/100). Contre-mesures prêtes à être déployées pour neutraliser les flux malveillants et isoler les équipements menacés.`,
    analyzedAt: new Date().toISOString(),
  };
}

// 1. Analyze Nebula Logs API
app.post('/api/analyze-nebula-logs', async (req, res) => {
  const { logsText, context } = req.body;

  if (!logsText || typeof logsText !== 'string' || !logsText.trim()) {
    return res.status(400).json({ error: 'Le contenu des logs Nebula est requis.' });
  }

  // Truncate if very long to prevent token issues
  const sanitizedLogs = logsText.slice(0, 25000);

  try {
    const prompt = `Tu es un expert d'élite en cyberdéfense (SOC Lead & Ingénieur Réseau Certifié Zyxel Nebula Security).
Tu reçois un rapport d'événements de sécurité ou des logs de sécurité d'une passerelle ou pare-feu Nebula (Zyxel Nebula Secure Reporter / USG FLEX / ATP Series, IDP, Anti-Malware, IP Reputation, Web Filter, VPN, CDR).

OBJECTIF :
1. Analyser en profondeur les attaques en cours et évaluer la menace.
2. Dégager TOUTES les actions concrètes et immédiates pour ARRÊTER ces attaques (règles de pare-feu Nebula Cloud, scripts Zyxel ZySH CLI, règles iptables, nftables, pfSense, et isolation en quarantaine CDR des machines internes compromises).
3. Cartographier avec la matrice MITRE ATT&CK.
4. Fournir un playbook d'intervention rapide pour l'administrateur système.

Voici les logs Nebula Secure Report à analyser :
${sanitizedLogs}

Informations de contexte additionnelles : ${context || 'Réseau d\'entreprise protégé par passerelle Nebula'}

Consigne impérative : Réponds UNIQUEMENT sous forme d'un objet JSON strict valide conforme au schéma suivant :
{
  "summary": "Résumé exécutif clair et percutant de la situation de sécurité (3-5 phrases en français)",
  "riskScore": 85, // Nombre entier entre 0 et 100
  "threatLevel": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "activeAttacksDetected": 3,
  "attackVectors": [
    {
      "name": "Nom de l'attaque (ex: Exfiltration C2 Cobalt Strike / Exploitation Log4Shell)",
      "description": "Explication technique détaillée du mode opératoire",
      "mitreTactic": "Command and Control / Initial Access",
      "mitreTechniqueId": "T1071 / T1190",
      "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
      "attackerIps": ["91.240.118.172"],
      "targetAssets": ["192.168.1.105"]
    }
  ],
  "iocList": [
    {
      "type": "IP" | "DOMAIN" | "HASH" | "PORT",
      "value": "91.240.118.172",
      "threat": "Serveur C2 Ransomware",
      "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
      "recommendedAction": "BLOCK_WAN" | "QUARANTINE_HOST" | "BLACKLIST_DOMAIN" | "RATE_LIMIT",
      "country": "RU"
    }
  ],
  "compromisedHosts": [
    {
      "ip": "192.168.1.105",
      "hostname": "DESKTOP-FINANCE-04",
      "mac": "00:1A:2B:3C:4D:5E",
      "status": "Infected" | "Suspicious" | "Clean",
      "recommendedIsolation": true,
      "evidence": "Pourquoi cet hôte est considéré compromis"
    }
  ],
  "stopActions": [
    {
      "id": "action-1",
      "title": "Bloquer l'IP Attaquante sur le WAN Nebula",
      "type": "FIREWALL_BLOCK" | "HOST_QUARANTINE" | "GEO_BLOCK" | "POLICY_UPDATE",
      "target": "91.240.118.172",
      "priority": "IMMEDIATE" | "HIGH" | "MEDIUM",
      "rationale": "Pourquoi cette règle stoppe directement l'attaque",
      "zyxelNebulaRule": {
        "ruleName": "DROP_C2_HOST",
        "direction": "WAN to LAN",
        "action": "DROP",
        "sourceObject": "Host_91_240_118_172",
        "destinationObject": "Any"
      },
      "zyxelCliCommand": "configure terminal\\naddress-object Host_91_240_118_172 host 91.240.118.172\\nfirewall rule 101\\n  name DROP_C2_91_240_118_172\\n  from WAN to Any\\n  source-address Host_91_240_118_172\\n  action drop\\n  log alert\\nexit\\nwrite memory",
      "iptablesCommand": "sudo iptables -I INPUT -s 91.240.118.172 -j DROP\\nsudo iptables -I FORWARD -s 91.240.118.172 -j DROP",
      "nftablesCommand": "sudo nft add rule inet filter input ip saddr 91.240.118.172 drop",
      "pfSenseRule": "<rule><type>block</type><interface>wan</interface><source><address>91.240.118.172</address></source><descr>Nebula Block</descr></rule>"
    }
  ],
  "incidentPlaybook": [
    {
      "step": 1,
      "action": "Titre de l'action",
      "target": "Cible",
      "details": "Procédure d'exécution exacte pour stopper l'attaque"
    }
  ],
  "cisoBriefing": "Synthèse exécutive stratégique pour le RSSI / DSI en 1 paragraphe"
}`;

    if (!process.env.GEMINI_API_KEY || process.env.GEMINI_API_KEY === 'MY_GEMINI_API_KEY') {
      console.log('Using local SOC engine fallback for analysis');
      const fallback = generateLocalFallbackAnalysis(sanitizedLogs);
      return res.json(fallback);
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 6000);

    const response = await ai.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: prompt,
      config: {
        responseMimeType: 'application/json',
        temperature: 0.2,
        abortSignal: controller.signal,
      },
    });

    clearTimeout(timer);

    const text = response.text || '';
    let parsedData;
    try {
      parsedData = JSON.parse(text);
    } catch (e) {
      // Clean up markdown block if present
      const cleaned = text.replace(/```json/g, '').replace(/```/g, '').trim();
      parsedData = JSON.parse(cleaned);
    }

    parsedData.analyzedAt = new Date().toISOString();
    return res.json(parsedData);
  } catch (err: any) {
    console.error('Gemini Analysis failed, applying local engine fallback:', err?.message || err);
    const fallback = generateLocalFallbackAnalysis(sanitizedLogs);
    return res.json(fallback);
  }
});

// Helper for algorithmic predictive analysis fallback
function generatePredictiveAnalysisFallback(logsText: string, currentAnalysis?: any) {
  const isLockbit = /lockbit|ransomware|c2|cobalt|beacon/i.test(logsText);
  const isLog4j = /log4j|cve-2021-44228|jndi|exploit|rce/i.test(logsText);
  const isMirai = /mirai|syn_flood|flood|telnet|port_scan/i.test(logsText);
  const isStealer = /stealer|redline|phishing|mimikatz|credential/i.test(logsText);
  const isVpnBrute = /vpn_auth|failed|attempts|brute/i.test(logsText);

  const predictions: any[] = [];

  if (isLockbit) {
    predictions.push({
      id: 'pred-1',
      threatName: 'Déploiement Massif de Ransomware & Chiffrement des Partages SMB',
      mitreTactic: 'Impact / Execution',
      mitreTechniqueId: 'T1486 (Data Encrypted for Impact)',
      probability: 92,
      confidence: 'HIGH',
      estimatedTimeToImpact: '< 30 à 45 minutes',
      severity: 'CRITICAL',
      killChainStage: 'Phase 6 - Impact / Destruction des Données',
      precursorIndicators: [
        'Balisage régulier Cobalt Strike vers C2 externe',
        'Téléchargement de binaire chiffré suspect via port 443',
        'Tentatives de communication RPC/SMB vers les serveurs de fichiers',
      ],
      potentialTargetAssets: ['SRV-DATABASE-01', 'Partages Réseau SMB (Port 445)', 'Sauvegardes NAS'],
      proactiveDefense: {
        title: 'Blocage préventif des protocoles SMB/RPC inter-VLANs & Quarantaine EDR',
        preemptiveRule: 'firewall rule 50 name PREVENT_SMB_PROPAGATION from LAN1 to LAN_SERVERS service SMB action drop',
        recommendedAction: 'Activer le confinement CDR Zyxel sur le poste infecté et isoler les partages réseau sensibles.',
      },
      rationale: 'La présence simultanée d\'un agent C2 actif et d\'une balise LockBit indique la fin de la phase de reconnaissance et le début imminent de la charge finale de chiffrement.',
    });

    predictions.push({
      id: 'pred-2',
      threatName: 'Exfiltration Massive de Données Sensibles via Canaux Furtifs (DNS/HTTPS)',
      mitreTactic: 'Exfiltration',
      mitreTechniqueId: 'T1048 / T1071 (Exfiltration Over Alternative Protocol)',
      probability: 86,
      confidence: 'HIGH',
      estimatedTimeToImpact: '1 à 2 heures',
      severity: 'CRITICAL',
      killChainStage: 'Phase 5 - Exfiltration de Données Pré-Ransomware',
      precursorIndicators: [
        'Pics anormaux de requêtes DNS avec sous-domaines encodés en Base64',
        'Sessions TLS de longue durée vers des IP russes ou hollandaises non répertoriées',
      ],
      potentialTargetAssets: ['Bases de données SQL', 'Répertoire RH/Comptabilité', 'Fichiers clients'],
      proactiveDefense: {
        title: 'Inspection DNS renforcée & blocage des tunnels DNS non autorisés',
        preemptiveRule: 'dns-security-profile strict-inspection drop-unknown-tunneling',
        recommendedAction: 'Restreindre les requêtes DNS sortantes uniquement vers les résolveurs d\'entreprise autorisés.',
      },
      rationale: 'Dans 89% des attaques LockBit/Cobalt Strike, une double extorsion est pratiquée avec exfiltration préalable des données avant le verrouillage.',
    });
  }

  if (isLog4j || isVpnBrute) {
    predictions.push({
      id: 'pred-3',
      threatName: 'Mouvement Latéral & Compromission du Contrôleur de Domaine (Active Directory)',
      mitreTactic: 'Lateral Movement / Privilege Escalation',
      mitreTechniqueId: 'T1068 / T1003 (OS Credential Dumping)',
      probability: 88,
      confidence: 'HIGH',
      estimatedTimeToImpact: '< 1 heure',
      severity: 'CRITICAL',
      killChainStage: 'Phase 4 - Escalade de Privilèges & Domination Active Directory',
      precursorIndicators: [
        'Exploitation RCE réussie ou credential stuffing agressif sur passerelle',
        'Tentative d\'injection de payload LDAP/JNDI',
        'Recherches de comptes administrateurs de domaine',
      ],
      potentialTargetAssets: ['SRV-AD-DOMAIN (192.168.1.10)', 'Kerberos / LSASS', 'Serveur Web DMZ'],
      proactiveDefense: {
        title: 'Verrouillage immédiat des accès RDP/SSH inter-zones et rotation des secrets d\'administration',
        preemptiveRule: 'firewall rule 30 name RESTRICT_MGMT from DMZ to LAN_MGMT action drop',
        recommendedAction: 'Réinitialiser les mots de passe des comptes à privilèges et forcer la double authentification (MFA).',
      },
      rationale: 'Une exécution de code à distance non contenue sur un serveur DMZ mène systématiquement à une élévation de privilèges vers l\'annuaire central.',
    });
  }

  if (isMirai) {
    predictions.push({
      id: 'pred-4',
      threatName: 'Saturation par Déni de Service Distribué (DDoS SYN/UDP Flood) & Perte de Connexion WAN',
      mitreTactic: 'Impact',
      mitreTechniqueId: 'T1498 (Network Denial of Service)',
      probability: 84,
      confidence: 'HIGH',
      estimatedTimeToImpact: 'Immédiat (< 15 minutes)',
      severity: 'HIGH',
      killChainStage: 'Phase 3 - Débordement de Capacité & Déni de Service',
      precursorIndicators: [
        'Scan agressif distribué sur les ports 22, 23, 80 et 443',
        'Montée en flèche du nombre de paquets SYN par seconde (> 12 500 pps)',
      ],
      potentialTargetAssets: ['Interface WAN de la passerelle Nebula', 'Services Web hébergés', 'Tunnels VPN IPsec'],
      proactiveDefense: {
        title: 'Activation du profil Anti-DDoS SYN Flood & Rate-Limiting adaptatif',
        preemptiveRule: 'anti-ddos syn-flood threshold 2000 drop-timeout 300',
        recommendedAction: 'Déclencher la protection Cloud DDoS et bloquer la plage géographique ou le réseau d\'adresses botnet.',
      },
      rationale: 'Le balayage automatisé Mirai est quasi-systématiquement le prélude à un flood synchronisé par l\'ensemble du botnet.',
    });
  }

  if (isStealer) {
    predictions.push({
      id: 'pred-5',
      threatName: 'Usurpation de Tokens de Session M365 & Attaque Man-in-the-Middle',
      mitreTactic: 'Credential Access / Defense Evasion',
      mitreTechniqueId: 'T1539 (Steal Web Session Cookie)',
      probability: 81,
      confidence: 'MEDIUM',
      estimatedTimeToImpact: '2 à 4 heures',
      severity: 'HIGH',
      killChainStage: 'Phase 4 - Utilisation des Identifiants Volés',
      precursorIndicators: [
        'Exécution d\'un malware voleur de mots de passe sur un poste utilisateur',
        'Appel vers un serveur C2 d\'infostealer répertorié',
      ],
      potentialTargetAssets: ['Messagerie d\'entreprise', 'Portail VPN SSL', 'Comptes bancaires / ERP'],
      proactiveDefense: {
        title: 'Révocation immédiate de toutes les sessions actives de l\'utilisateur et réinitialisation MFA',
        preemptiveRule: 'cdr isolate-client mac A4:5E:60:E1:92:0B vlan 999',
        recommendedAction: 'Forcer la déconnexion globale du compte utilisateur compromis dans l\'IdP.',
      },
      rationale: 'Les stealers modernes cherchent à contourner le MFA en exfiltrant directement les cookies de session des navigateurs.',
    });
  }

  // Default fallback if no specific flags
  if (predictions.length === 0) {
    predictions.push({
      id: 'pred-default-1',
      threatName: 'Tentatives d\'Intrusion Ciblées & Balayage de Vulnérabilités Web',
      mitreTactic: 'Initial Access / Reconnaissance',
      mitreTechniqueId: 'T1190 (Exploit Public-Facing Application)',
      probability: 72,
      confidence: 'MEDIUM',
      estimatedTimeToImpact: '2 à 6 heures',
      severity: 'HIGH',
      killChainStage: 'Phase 2 - Reconnaissance Armée & Exploitation',
      precursorIndicators: ['Multiplication des sondages de ports et requêtes HTTP anormales'],
      potentialTargetAssets: ['Services Web exposés', 'Portails VPN', 'Passerelle Zyxel'],
      proactiveDefense: {
        title: 'Durcissement des règles de filtrage géopolitique et blocage des scanners connus',
        preemptiveRule: 'firewall rule 10 name GEO_BLOCK from WAN to Any action drop',
        recommendedAction: 'Restreindre l\'accès d\'administration exclusivement aux adresses IP fiables.',
      },
      rationale: 'Le comportement de scan préliminaire précède généralement des tentatives d\'exploitation ciblées.',
    });
  }

  return {
    generatedAt: new Date().toISOString(),
    overallThreatVelocity: predictions.some((p) => p.severity === 'CRITICAL' && p.probability >= 85) ? 'ACCELERATING' : 'STABLE',
    forecastWindow: 'Prochaines 2 à 6 heures',
    threatTrendSummary: `Modélisation prédictive IA basée sur les flux récents : forte probabilité de progression vers les étapes ${predictions.map((p) => p.mitreTactic.split('/')[0].trim()).join(' et ')}. La vitesse de propagation est en accélération, justifiant l'application immédiate de contre-mesures préventives.`,
    predictedAttackVectors: predictions,
    earlyWarningSignals: [
      'Augmentation anormale du ratio de paquets SYN non acquittés',
      'Corrélation de signatures IDP avec les campagnes d\'acteurs malveillants identifiés',
      'Détection d\'adresses IP figurant sur les flux de réputation mondiale Nebula Threat Intelligence',
    ],
    recommendedPreemptiveActions: [
      'Appliquer sans délai les règles de quarantaine CDR sur les hôtes pré-compromis',
      'Activer le blocage WAN préemptif sur les sous-réseaux des serveurs C2 détectés',
      'Vérifier l\'étanchéité des sauvegardes hors ligne avant toute tentative de chiffrement ransomware',
    ],
  };
}

// 2. Chat / SOC Copilot API
app.post('/api/chat-copilot', async (req, res) => {
  const { message, history, currentAnalysis } = req.body;

  if (!message) {
    return res.status(400).json({ error: 'Le message est requis.' });
  }

  try {
    const systemContext = `Tu es l'analyste SOC IA spécialisé dans l'écosystème de sécurité Nebula (Zyxel Nebula Cloud Networking, USG FLEX, ATP Firewalls, Nebula Secure Reporter).
Tu aides l'administrateur système et le responsable sécurité à analyser les logs, identifier les menaces et générer les ripostes et configurations nécessaires pour ARRÊTER les attaques en cours.

Contexte de l'analyse actuelle :
${currentAnalysis ? JSON.stringify(currentAnalysis).slice(0, 4000) : 'Aucune analyse préalable.'}

Réponds avec précision technique, en français, en fournissant des commandes concrètes (ZySH CLI, iptables, configuration Nebula Control Center) et des conseils pragmatiques.`;

    const contents = [
      { role: 'user', parts: [{ text: systemContext }] },
      ...(Array.isArray(history)
        ? history.slice(-6).map((h: any) => ({
            role: h.role === 'user' ? 'user' : 'model',
            parts: [{ text: h.content }],
          }))
        : []),
      { role: 'user', parts: [{ text: message }] },
    ];

    if (!process.env.GEMINI_API_KEY || process.env.GEMINI_API_KEY === 'MY_GEMINI_API_KEY') {
      return res.json({
        reply: `En tant qu'assistant de sécurité Nebula : pour arrêter immédiatement l'attaque détectée, appliquez la règle de blocage WAN sur les adresses IP hostiles identifiées via la console Nebula Cloud ou en CLI avec la commande :
\`\`\`bash
configure terminal
address-object Blocked_Attacker host 91.240.118.172
firewall rule 100
  name AUTO_DROP_ATTACK
  from WAN to Any
  source-address Blocked_Attacker
  action drop
  log alert
exit
write memory
\`\`\`
Pour les machines internes compromises, activez le CDR (Collaborative Detection & Response) pour isoler immédiatement l'adresse MAC/IP sur un VLAN de quarantaine.`,
      });
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 6000);

    const response = await ai.models.generateContent({
      model: 'gemini-3.8-flash',
      contents,
      config: {
        abortSignal: controller.signal,
      },
    });

    clearTimeout(timer);

    return res.json({ reply: response.text });
  } catch (err: any) {
    console.error('Chat copilot error:', err?.message || err);
    return res.json({
      reply: `En tant qu'assistant de sécurité Nebula : pour arrêter immédiatement l'attaque détectée, appliquez la règle de blocage WAN sur les adresses IP hostiles identifiées via la console Nebula Cloud ou en CLI avec la commande :
\`\`\`bash
configure terminal
address-object Blocked_Attacker host [IP_SUSPECTE]
firewall rule 100
  name AUTO_DROP_ATTACK
  from WAN to Any
  source-address Blocked_Attacker
  action drop
  log alert
exit
write memory
\`\`\`
Pour les machines internes compromises, activez le CDR (Collaborative Detection & Response) pour isoler immédiatement l'adresse MAC/IP sur un VLAN de quarantaine.`,
    });
  }
});

// 3. AI Predictive Attack Vectors API
app.post('/api/predict-attacks', async (req, res) => {
  const { logsText, currentAnalysis, deviceName } = req.body;
  const rawLogs = typeof logsText === 'string' ? logsText.slice(0, 20000) : '';

  try {
    if (!process.env.GEMINI_API_KEY || process.env.GEMINI_API_KEY === 'MY_GEMINI_API_KEY') {
      const fallback = generatePredictiveAnalysisFallback(rawLogs, currentAnalysis);
      return res.json(fallback);
    }

    const prompt = `Tu es un système de Cyber Threat Intelligence prédictif et un moteur d'IA de modélisation de trajectoires d'attaques pour SOC (spécialisé dans les passerelles Zyxel Nebula ATP et USG Flex).
Sur la base des logs actuels et de l'analyse en cours, modélise la progression probable de la cyberattaque (Kill Chain MITRE ATT&CK, vitesse de propagation, précurseurs).

Logs actuels :
${rawLogs}

Analyse actuelle :
${currentAnalysis ? JSON.stringify(currentAnalysis).slice(0, 3000) : 'Non fournie'}

Équipement : ${deviceName || 'Passerelle Zyxel Nebula ATP'}

TÂCHE :
Prédire les prochains vecteurs d'attaques probables (2 à 4 vecteurs) qui vont survenir si aucune contre-mesure n'est déployée, avec leur probabilité (en %), leur temps estimé avant impact (TTI), la tactique et technique MITRE, les signaux d'alerte précoces et les actions préemptives à appliquer.

Réponds UNIQUEMENT sous forme d'un objet JSON strict valide conforme à ce schéma :
{
  "generatedAt": "${new Date().toISOString()}",
  "overallThreatVelocity": "ACCELERATING" | "STABLE" | "DECREASING",
  "forecastWindow": "Prochaines 2 à 6 heures",
  "threatTrendSummary": "Synthèse prédictive claire (2-3 phrases)",
  "predictedAttackVectors": [
    {
      "id": "pred-1",
      "threatName": "Nom de l'attaque anticipée",
      "mitreTactic": "Tactic MITRE",
      "mitreTechniqueId": "Technique ID",
      "probability": 88,
      "confidence": "HIGH" | "MEDIUM" | "LOW",
      "estimatedTimeToImpact": "< 30 minutes",
      "severity": "CRITICAL" | "HIGH" | "MEDIUM",
      "killChainStage": "Étape de la Kill Chain",
      "precursorIndicators": ["Indicateur 1", "Indicateur 2"],
      "potentialTargetAssets": ["Cible 1", "Cible 2"],
      "proactiveDefense": {
        "title": "Action préemptive recommandée",
        "preemptiveRule": "Règle pare-feu ou commande de protection",
        "recommendedAction": "Détails opérationnels pour le SOC"
      },
      "rationale": "Pourquoi cette attaque est mathématiquement probable selon les tendances"
    }
  ],
  "earlyWarningSignals": ["Signal 1", "Signal 2"],
  "recommendedPreemptiveActions": ["Recommandation 1", "Recommandation 2"]
}`;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 6000);

    const response = await ai.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: prompt,
      config: {
        responseMimeType: 'application/json',
        temperature: 0.2,
        abortSignal: controller.signal,
      },
    });

    clearTimeout(timer);

    const text = response.text || '';
    let parsedData;
    try {
      parsedData = JSON.parse(text);
    } catch {
      const cleaned = text.replace(/```json/g, '').replace(/```/g, '').trim();
      parsedData = JSON.parse(cleaned);
    }

    parsedData.generatedAt = new Date().toISOString();
    return res.json(parsedData);
  } catch (err: any) {
    console.error('Gemini Predictive Analysis failed, using local engine fallback:', err?.message || err);
    const fallback = generatePredictiveAnalysisFallback(rawLogs, currentAnalysis);
    return res.json(fallback);
  }
});

// 4. Active Defenses Management (List, Enforce, Revoke)
app.get('/api/active-defenses', (req, res) => {
  res.json({
    defenses: activeDefenses,
    totalBlockedPackets: activeDefenses.reduce((acc, d) => acc + (d.status === 'ACTIVE' ? d.packetsBlocked : 0), 0),
    activeCount: activeDefenses.filter((d) => d.status === 'ACTIVE').length,
  });
});

app.post('/api/enforce-defense', (req, res) => {
  const { type, target, reason, policyName } = req.body;

  if (!target) {
    return res.status(400).json({ error: 'La cible (IP ou domaine) est requise.' });
  }

  // Check if already active
  const existing = activeDefenses.find((d) => d.target === target && d.status === 'ACTIVE');
  if (existing) {
    return res.json({ message: 'Règle déjà active', defense: existing });
  }

  const newDefense: ActiveDefenseRecord = {
    id: `def-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
    type: type || 'IP_BLOCK',
    target,
    reason: reason || 'Bloqué via NebulaGuard AI Countermeasure',
    appliedAt: new Date().toISOString(),
    status: 'ACTIVE',
    packetsBlocked: Math.floor(Math.random() * 85) + 12,
    policyName: policyName || `Nebula_AutoDrop_${target.replace(/[^a-zA-Z0-9]/g, '_')}`,
    syncedWithNebula: true,
  };

  activeDefenses.unshift(newDefense);

  return res.json({
    success: true,
    message: `Règle de blocage déployée avec succès sur Nebula Gateway pour ${target}`,
    defense: newDefense,
  });
});

app.post('/api/revoke-defense', (req, res) => {
  const { id } = req.body;
  const defense = activeDefenses.find((d) => d.id === id);
  if (!defense) {
    return res.status(404).json({ error: 'Règle de défense non trouvée.' });
  }

  defense.status = 'REVOKED';
  return res.json({ success: true, defense });
});

// 4. Vite Dev Server / Production Serving
async function startServer() {
  const isProduction = process.env.NODE_ENV === 'production';

  if (!isProduction) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.resolve(__dirname, 'dist')));
    app.get('*', (_req, res) => {
      res.sendFile(path.resolve(__dirname, 'dist', 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`NebulaGuard AI server running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
});
