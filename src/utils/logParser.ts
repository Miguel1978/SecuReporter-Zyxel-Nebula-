import { LogCategory, LogEntry, SeverityLevel } from '../types';

export function parseNebulaLogs(rawText: string): LogEntry[] {
  if (!rawText || !rawText.trim()) return [];

  const lines = rawText.split('\n').map((l) => l.trim()).filter((l) => l.length > 0 && !l.startsWith('#'));
  const entries: LogEntry[] = [];

  // Check if CSV format
  const isCsv = lines[0]?.includes(',') && (lines[0].toLowerCase().includes('time') || lines[0].toLowerCase().includes('src') || lines[0].toLowerCase().includes('category'));

  if (isCsv && lines.length > 1) {
    const headers = lines[0].split(',').map((h) => h.trim().toLowerCase().replace(/['"]/g, ''));
    for (let i = 1; i < lines.length; i++) {
      const cols = parseCsvLine(lines[i]);
      if (cols.length < 3) continue;

      const record: Record<string, string> = {};
      headers.forEach((h, idx) => {
        record[h] = cols[idx] || '';
      });

      const entry = mapCsvToLogEntry(record, i, lines[i]);
      if (entry) entries.push(entry);
    }
    if (entries.length > 0) return entries;
  }

  // Parse Syslog / Key-Value / CEF format
  lines.forEach((line, index) => {
    try {
      const entry = parseSyslogLine(line, index);
      if (entry) entries.push(entry);
    } catch (e) {
      console.warn('Failed to parse line:', line, e);
    }
  });

  return entries;
}

function parseCsvLine(line: string): string[] {
  const result: string[] = [];
  let current = '';
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    if (char === '"') {
      inQuotes = !inQuotes;
    } else if (char === ',' && !inQuotes) {
      result.push(current.trim());
      current = '';
    } else {
      current += char;
    }
  }
  result.push(current.trim());
  return result;
}

function mapCsvToLogEntry(record: Record<string, string>, index: number, raw: string): LogEntry {
  const timestamp = record['timestamp'] || record['time'] || record['date'] || new Date().toISOString();
  const source = record['device'] || record['source'] || record['gateway'] || 'Nebula Gateway';
  const categoryRaw = record['category'] || record['type'] || record['module'] || 'IDP/IPS';
  const category = normalizeCategory(categoryRaw);
  const severityRaw = record['priority'] || record['severity'] || record['level'] || 'HIGH';
  const severity = normalizeSeverity(severityRaw);
  const src = record['src'] || record['source_ip'] || record['src_ip'] || '0.0.0.0';
  const dst = record['dst'] || record['dest_ip'] || record['dst_ip'] || '0.0.0.0';
  const [srcIp, srcPort] = parseIpPort(src);
  const [dstIp, dstPort] = parseIpPort(dst);
  const actionRaw = record['action'] || record['status'] || 'Blocked';
  const action = normalizeAction(actionRaw);
  const threatName = record['name'] || record['threat'] || record['signature'] || record['virus'] || record['msg'] || 'Menace Détectée';

  return {
    id: `log-${index}-${Date.now()}`,
    timestamp,
    source,
    category,
    severity,
    srcIp,
    srcPort,
    dstIp,
    dstPort,
    protocol: record['proto'] || record['protocol'] || 'TCP',
    signature: record['sig_id'] || record['signature_id'],
    cve: record['cve'],
    action,
    threatName,
    hostName: record['host'] || record['hostname'] || record['client'],
    hostMac: record['mac'],
    country: record['country'],
    raw,
  };
}

function parseSyslogLine(line: string, index: number): LogEntry | null {
  // Extract timestamp if at start: e.g. 2026-09-25T08:14:22Z or Sep 25 08:14:22
  let timestamp = new Date().toISOString();
  const timeMatch = line.match(/^(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(\.\d+)?Z?|[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})/);
  if (timeMatch) {
    timestamp = timeMatch[0];
  }

  // Device in brackets e.g. [ATP700] or [USG_FLEX]
  let source = 'Nebula Gateway';
  const deviceMatch = line.match(/\[([A-Za-z0-9_-]+)\]/);
  if (deviceMatch && !['IDP/IPS', 'Anti-Malware', 'IP_Reputation', 'Content_Filter', 'VPN_Auth', 'Traffic_Anomaly', 'CDR_Quarantine'].includes(deviceMatch[1])) {
    source = deviceMatch[1];
  }

  // Category in brackets or tags
  let category: LogCategory = 'IDP/IPS';
  const catMatch = line.match(/\[(IDP\/IPS|Anti-Malware|IP_Reputation|Content_Filter|VPN_Auth|Traffic_Anomaly|CDR_Quarantine)\]/i);
  if (catMatch) {
    category = normalizeCategory(catMatch[1]);
  } else if (/malware|virus|trojan/i.test(line)) {
    category = 'Anti-Malware';
  } else if (/reputation|botnet|c2|blacklist/i.test(line)) {
    category = 'IP_Reputation';
  } else if (/vpn|ikev2|ipsec|auth/i.test(line)) {
    category = 'VPN_Auth';
  } else if (/content|filter|phishing|domain/i.test(line)) {
    category = 'Content_Filter';
  } else if (/flood|anomaly|scan|syn/i.test(line)) {
    category = 'Traffic_Anomaly';
  } else if (/cdr|quarantine/i.test(line)) {
    category = 'CDR_Quarantine';
  }

  // Severity
  let severity: SeverityLevel = 'HIGH';
  const prioMatch = line.match(/PRIORITY=([A-Za-z]+)|SEVERITY=([A-Za-z]+)|LEVEL=([A-Za-z]+)/i);
  if (prioMatch) {
    severity = normalizeSeverity(prioMatch[1] || prioMatch[2] || prioMatch[3]);
  } else if (/critical/i.test(line)) {
    severity = 'CRITICAL';
  } else if (/high|lockbit|c2|rce|log4j/i.test(line)) {
    severity = 'HIGH';
  } else if (/medium|scan/i.test(line)) {
    severity = 'MEDIUM';
  } else {
    severity = 'LOW';
  }

  // Source and Destination IPs
  let srcIp = '0.0.0.0';
  let srcPort: number | undefined;
  let dstIp = '0.0.0.0';
  let dstPort: number | undefined;

  const srcMatch = line.match(/(?:SRC|SOURCE|SRC_IP)=([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(?::(\d+))?/i);
  if (srcMatch) {
    srcIp = srcMatch[1];
    if (srcMatch[2]) srcPort = parseInt(srcMatch[2], 10);
  } else {
    const fallbackIps = line.match(/\b([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\b/g);
    if (fallbackIps && fallbackIps[0]) {
      srcIp = fallbackIps[0];
    }
  }

  const dstMatch = line.match(/(?:DST|DEST|DESTINATION|DST_IP)=([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(?::(\d+))?/i);
  if (dstMatch) {
    dstIp = dstMatch[1];
    if (dstMatch[2]) dstPort = parseInt(dstMatch[2], 10);
  } else {
    const fallbackIps = line.match(/\b([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\b/g);
    if (fallbackIps && fallbackIps.length > 1) {
      dstIp = fallbackIps[1];
    }
  }

  // Action
  let action: LogEntry['action'] = 'Blocked';
  const actionMatch = line.match(/ACTION="?([A-Za-z_]+)"?/i);
  if (actionMatch) {
    action = normalizeAction(actionMatch[1]);
  } else if (/dropped|drop/i.test(line)) {
    action = 'Dropped';
  } else if (/quarantin/i.test(line)) {
    action = 'Quarantined';
  } else if (/alert/i.test(line)) {
    action = 'Alerted';
  }

  // Threat Name / Signature / Message
  let threatName = 'Menace Réseau Détectée';
  const nameMatch = line.match(/(?:NAME|VIRUS|MSG|TYPE|CAT)="([^"]+)"/i);
  if (nameMatch) {
    threatName = nameMatch[1];
  } else {
    const unquotedMatch = line.match(/(?:NAME|VIRUS|MSG|CAT)=([A-Za-z0-9_.-]+)/i);
    if (unquotedMatch) {
      threatName = unquotedMatch[1];
    }
  }

  // Host info
  let hostName: string | undefined;
  const hostMatch = line.match(/(?:HOST|HOSTNAME|USER)="?([^"\s]+)"?/i);
  if (hostMatch) hostName = hostMatch[1];

  let hostMac: string | undefined;
  const macMatch = line.match(/(?:MAC|TARGET_MAC)="?([0-9A-Fa-f:]{17})"?/i);
  if (macMatch) hostMac = macMatch[1];

  let country: string | undefined;
  const countryMatch = line.match(/(?:COUNTRY)="?([A-Z]{2})"?/i);
  if (countryMatch) country = countryMatch[1];

  const sigMatch = line.match(/SIG_ID=(\d+)/i);
  const cveMatch = line.match(/(CVE-\d{4}-\d{4,7})/i);

  return {
    id: `log-${index}-${Math.random().toString(36).substring(2, 7)}`,
    timestamp,
    source,
    category,
    severity,
    srcIp,
    srcPort,
    dstIp,
    dstPort,
    protocol: line.match(/PROTO=([A-Za-z]+)/i)?.[1] || 'TCP',
    signature: sigMatch?.[1],
    cve: cveMatch?.[1],
    action,
    threatName,
    hostName,
    hostMac,
    country,
    raw: line,
  };
}

function parseIpPort(val: string): [string, number | undefined] {
  const parts = val.split(':');
  const ip = parts[0] || '0.0.0.0';
  const port = parts[1] ? parseInt(parts[1], 10) : undefined;
  return [ip, port];
}

function normalizeCategory(cat: string): LogCategory {
  const c = cat.toLowerCase();
  if (c.includes('idp') || c.includes('ips') || c.includes('exploit')) return 'IDP/IPS';
  if (c.includes('malware') || c.includes('virus') || c.includes('trojan') || c.includes('ransomware')) return 'Anti-Malware';
  if (c.includes('reputation') || c.includes('botnet') || c.includes('c2')) return 'IP_Reputation';
  if (c.includes('content') || c.includes('phishing') || c.includes('web') || c.includes('domain')) return 'Content_Filter';
  if (c.includes('vpn') || c.includes('auth') || c.includes('ike')) return 'VPN_Auth';
  if (c.includes('cdr') || c.includes('quarantine')) return 'CDR_Quarantine';
  return 'Traffic_Anomaly';
}

function normalizeSeverity(s: string): SeverityLevel {
  const val = s.toUpperCase();
  if (val.includes('CRIT')) return 'CRITICAL';
  if (val.includes('HIGH')) return 'HIGH';
  if (val.includes('MED')) return 'MEDIUM';
  if (val.includes('LOW')) return 'LOW';
  return 'INFO';
}

function normalizeAction(a: string): LogEntry['action'] {
  const val = a.toLowerCase();
  if (val.includes('quarantin')) return 'Quarantined';
  if (val.includes('drop')) return 'Dropped';
  if (val.includes('block')) return 'Blocked';
  if (val.includes('alert')) return 'Alerted';
  return 'Allowed';
}
