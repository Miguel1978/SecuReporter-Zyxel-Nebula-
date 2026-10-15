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

export interface NebulaSiteGateway {
  siteId: string;
  organizationId?: string;
  siteName: string;
  location: string;
  gatewayModel: string;
  serialNumber: string;
  firmwareVersion: string;
  wanIp: string;
  status: 'ONLINE' | 'DEGRADED';
  cpuUsage: number;
  ramUsage: number;
  activeSessions: number;
  threatsBlocked24h: number;
  riskScore?: number;
  licenseTier: string;
  cdrEnabled: boolean;
  idpEnabled: boolean;
  lastHeartbeat: string;
}

export interface NebulaOrganization {
  id: string;
  name: string;
  sector: string;
  region: string;
  licenseTier: string;
  monitoringProfile: string;
  status: 'CONNECTED' | 'ALERT' | 'SYNCING';
  avgRiskScore: number;
  sites: NebulaSiteGateway[];
  createdAt: string;
}

export interface NebulaApiCallLog {
  id: string;
  timestamp: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  endpoint: string;
  statusCode: number;
  latencyMs: number;
  siteId: string;
  summary: string;
  payloadPreview?: string;
}

export interface NebulaConnectionStatus {
  connected: boolean;
  mode: 'LIVE_CLOUD_API' | 'NCC_TELEMETRY_BRIDGE';
  apiBaseUrl: string;
  organizationId: string;
  organizationName: string;
  latencyMs: number;
  lastSyncedAt: string;
  securityPackStatus: string;
  sites: NebulaSiteGateway[];
  organizations?: NebulaOrganization[];
  recentApiCalls: NebulaApiCallLog[];
}

export interface NebulaEnvVariablesConfig {
  ZYXEL_NEBULA_ORG_ID: string;
  ZYXEL_NEBULA_SITE_ID: string;
  ZYXEL_NEBULA_API_URL: string;
  organizationName: string;
  siteName: string;
  gatewayModel: string;
  serverAuthMode: 'SERVER_PROXY_AUTHENTICATED' | 'LIVE_CLOUD_API';
  lastSyncedAt: string;
}

export type ScheduleFrequency = '15_MIN' | 'HOURLY' | 'EVERY_6H' | 'DAILY' | 'WEEKLY';

export interface ScheduledAnalysisJob {
  id: string;
  name: string;
  organizationId: string;
  organizationName: string;
  siteId: string;
  siteName: string;
  gatewayModel: string;
  frequency: ScheduleFrequency;
  cronExpression: string;
  preferredTime?: string;
  enabled: boolean;
  autoEnforceFirewall: boolean;
  alertThresholdScore: number;
  notifyDesktop: boolean;
  lastRunAt: string | null;
  nextRunAt: string;
  lastStatus: 'SUCCESS' | 'CRITICAL_DETECTED' | 'PENDING' | 'PAUSED';
  lastRiskScore?: number;
  totalRunsCount: number;
  threatsNeutralizedCount: number;
}

export interface ScheduledRunLog {
  id: string;
  scheduleId: string;
  scheduleName: string;
  siteId: string;
  siteName: string;
  gatewayModel: string;
  executedAt: string;
  triggerType: 'SCHEDULED_AUTO' | 'MANUAL_FORCE' | 'CONTINUOUS_DAEMON';
  frequencyLabel: string;
  logsAnalyzedCount: number;
  riskScore: number;
  threatLevel: SeverityLevel;
  attacksDetected: number;
  autoBlockedCount: number;
  durationMs: number;
  summary: string;
  rawLogsSnapshot?: string;
}

export interface SyslogPacket {
  id: string;
  timestamp: string;
  raw: string;
  remoteAddress: string;
  remotePort: number;
  facility: number;
  facilityName: string;
  severity: SeverityLevel;
  category: string;
  sourceDevice: string;
  srcIp?: string;
  srcPort?: number;
  dstIp?: string;
  dstPort?: number;
  threatName?: string;
  action?: 'Blocked' | 'Dropped' | 'Alerted' | 'Quarantined' | 'Allowed';
  isBlocked?: boolean;
}

export interface SyslogServerStatus {
  isListening: boolean;
  port: number;
  host: string;
  protocol: 'UDP';
  packetsReceived: number;
  bytesReceived: number;
  lastPacketAt: string | null;
  activeSenders: { ip: string; count: number; lastSeen: string }[];
  error: string | null;
  eventsPerSecond: number;
}

