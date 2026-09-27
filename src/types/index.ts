export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type LogCategory =
  | 'IDP/IPS'
  | 'Anti-Malware'
  | 'IP_Reputation'
  | 'Content_Filter'
  | 'VPN_Auth'
  | 'Traffic_Anomaly'
  | 'CDR_Quarantine';

export interface LogEntry {
  id: string;
  timestamp: string;
  source: string;
  category: LogCategory;
  severity: SeverityLevel;
  srcIp: string;
  srcPort?: number;
  dstIp: string;
  dstPort?: number;
  protocol?: string;
  signature?: string;
  cve?: string;
  action: 'Blocked' | 'Dropped' | 'Alerted' | 'Quarantined' | 'Allowed';
  threatName: string;
  hostName?: string;
  hostMac?: string;
  country?: string;
  raw: string;
}

export interface AttackVector {
  name: string;
  description: string;
  mitreTactic: string;
  mitreTechniqueId: string;
  severity: SeverityLevel;
  attackerIps: string[];
  targetAssets: string[];
}

export interface IOCItem {
  type: 'IP' | 'DOMAIN' | 'HASH' | 'PORT';
  value: string;
  threat: string;
  severity: SeverityLevel;
  recommendedAction: 'BLOCK_WAN' | 'QUARANTINE_HOST' | 'BLACKLIST_DOMAIN' | 'RATE_LIMIT';
  country?: string;
  timesSeen?: number;
}

export interface CompromisedHost {
  ip: string;
  hostname?: string;
  mac?: string;
  status: 'Infected' | 'Suspicious' | 'Clean';
  recommendedIsolation: boolean;
  evidence: string;
}

export interface StopAction {
  id: string;
  title: string;
  type: 'FIREWALL_BLOCK' | 'HOST_QUARANTINE' | 'GEO_BLOCK' | 'POLICY_UPDATE';
  target: string;
  priority: 'IMMEDIATE' | 'HIGH' | 'MEDIUM';
  rationale: string;
  zyxelNebulaRule: {
    ruleName: string;
    direction: 'WAN to LAN' | 'WAN to ZyWALL' | 'LAN to WAN';
    action: 'DROP' | 'REJECT';
    sourceObject: string;
    destinationObject: string;
  };
  zyxelCliCommand: string;
  iptablesCommand: string;
  nftablesCommand: string;
  pfSenseRule: string;
}

export interface PlaybookStep {
  step: number;
  action: string;
  target: string;
  details: string;
}

export interface ThreatAnalysisResult {
  summary: string;
  riskScore: number; // 0 - 100
  threatLevel: SeverityLevel;
  activeAttacksDetected: number;
  attackVectors: AttackVector[];
  iocList: IOCItem[];
  compromisedHosts: CompromisedHost[];
  stopActions: StopAction[];
  incidentPlaybook: PlaybookStep[];
  cisoBriefing: string;
  analyzedAt: string;
}

export interface ActiveDefense {
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

export interface SampleReport {
  id: string;
  title: string;
  description: string;
  device: string;
  severity: SeverityLevel;
  logCount: number;
  primaryThreat: string;
  rawLogs: string;
}

export interface AnalysisHistoryItem {
  id: string;
  timestamp: string;
  deviceName: string;
  title: string;
  riskScore: number;
  threatLevel: SeverityLevel;
  attacksCount: number;
  logCount: number;
  analysis: ThreatAnalysisResult;
  rawLogs: string;
}

export interface AttackPrediction {
  id: string;
  threatName: string;
  mitreTactic: string;
  mitreTechniqueId: string;
  probability: number; // 0 to 100
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  estimatedTimeToImpact: string; // e.g. "< 30 minutes", "1 à 2 heures"
  severity: SeverityLevel;
  killChainStage: string;
  precursorIndicators: string[];
  potentialTargetAssets: string[];
  proactiveDefense: {
    title: string;
    preemptiveRule: string;
    recommendedAction: string;
  };
  rationale: string;
}

export interface PredictiveAnalysisResult {
  generatedAt: string;
  overallThreatVelocity: 'ACCELERATING' | 'STABLE' | 'DECREASING';
  forecastWindow: string;
  threatTrendSummary: string;
  predictedAttackVectors: AttackPrediction[];
  earlyWarningSignals: string[];
  recommendedPreemptiveActions: string[];
}
