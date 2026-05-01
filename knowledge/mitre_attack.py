"""
MITRE ATT&CK knowledge base — embedded subset covering the most common
enterprise attack techniques. Used by the Triage Agent to map observed
events onto a standardized kill chain.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


# ─────────────────────────────── Tactic catalog ──────────────────────────────

TACTICS: Dict[str, str] = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
}

TACTIC_ORDER = [
    "TA0001", "TA0002", "TA0003", "TA0004", "TA0005",
    "TA0006", "TA0007", "TA0008", "TA0009", "TA0010",
    "TA0011", "TA0040",
]


# ─────────────────────────────── Technique model ─────────────────────────────

@dataclass
class Technique:
    id: str
    name: str
    tactic_id: str
    description: str
    indicators: List[str] = field(default_factory=list)
    sub_techniques: List[str] = field(default_factory=list)

    @property
    def tactic(self) -> str:
        return TACTICS.get(self.tactic_id, "Unknown")


# ─────────────────────────────── Technique catalog ───────────────────────────

TECHNIQUES: Dict[str, Technique] = {

    # ── Initial Access ────────────────────────────────────────────────────────
    "T1566": Technique(
        id="T1566", name="Phishing", tactic_id="TA0001",
        description="Adversaries send phishing messages to gain initial access.",
        indicators=["suspicious email", "malicious attachment", "spoofed sender",
                    "link to unfamiliar domain", "credential harvesting page"],
        sub_techniques=["T1566.001", "T1566.002"],
    ),
    "T1190": Technique(
        id="T1190", name="Exploit Public-Facing Application", tactic_id="TA0001",
        description="Exploitation of a weakness in an internet-facing application.",
        indicators=["SQL injection", "RCE exploit", "web shell uploaded",
                    "unusual POST body", "exploit CVE"],
    ),
    "T1078": Technique(
        id="T1078", name="Valid Accounts", tactic_id="TA0001",
        description="Adversaries obtain and abuse credentials of existing accounts.",
        indicators=["login from unusual location", "off-hours authentication",
                    "brute force attempt", "credential stuffing", "password spray"],
    ),

    # ── Execution ─────────────────────────────────────────────────────────────
    "T1059": Technique(
        id="T1059", name="Command and Scripting Interpreter", tactic_id="TA0002",
        description="Abuse of command/scripting interpreters to execute malicious code.",
        indicators=["powershell -enc", "cmd.exe /c", "bash -i", "wscript.exe",
                    "base64 encoded payload", "invoke-expression", "IEX"],
        sub_techniques=["T1059.001", "T1059.003"],
    ),
    "T1204": Technique(
        id="T1204", name="User Execution", tactic_id="TA0002",
        description="Adversaries rely on specific actions by a user to gain execution.",
        indicators=["macro enabled document", "user clicked malicious link",
                    "double-clicked executable", "opened infected attachment"],
    ),
    "T1053": Technique(
        id="T1053", name="Scheduled Task/Job", tactic_id="TA0002",
        description="Adversaries abuse task scheduling to execute malicious code.",
        indicators=["schtasks /create", "crontab modification", "at.exe",
                    "scheduled task with unusual path"],
    ),

    # ── Persistence ───────────────────────────────────────────────────────────
    "T1547": Technique(
        id="T1547", name="Boot or Logon Autostart Execution", tactic_id="TA0003",
        description="Adversaries establish persistence through autostart mechanisms.",
        indicators=["registry run key modified", "startup folder entry",
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "new service created"],
        sub_techniques=["T1547.001"],
    ),
    "T1543": Technique(
        id="T1543", name="Create or Modify System Process", tactic_id="TA0003",
        description="Adversaries create or modify system-level processes for persistence.",
        indicators=["new service installed", "service binary path modified",
                    "sc create", "systemctl enable unknown service"],
    ),

    # ── Privilege Escalation ──────────────────────────────────────────────────
    "T1055": Technique(
        id="T1055", name="Process Injection", tactic_id="TA0004",
        description="Adversaries inject malicious code into running processes.",
        indicators=["WriteProcessMemory", "VirtualAllocEx", "CreateRemoteThread",
                    "process hollowing", "reflective DLL injection", "dll injection"],
    ),
    "T1068": Technique(
        id="T1068", name="Exploitation for Privilege Escalation", tactic_id="TA0004",
        description="Exploitation of a vulnerability to gain higher-level permissions.",
        indicators=["kernel exploit", "privilege escalation CVE", "SYSTEM shell",
                    "sudo exploit", "SUID binary abuse"],
    ),

    # ── Defense Evasion ───────────────────────────────────────────────────────
    "T1562": Technique(
        id="T1562", name="Impair Defenses", tactic_id="TA0005",
        description="Adversaries disable or modify tools used to track/detect them.",
        indicators=["antivirus disabled", "firewall rule deleted", "defender tampered",
                    "Set-MpPreference -DisableRealtimeMonitoring", "iptables flush"],
    ),
    "T1070": Technique(
        id="T1070", name="Indicator Removal", tactic_id="TA0005",
        description="Adversaries delete or alter artifacts to cover their tracks.",
        indicators=["event log cleared", "wevtutil cl", "history deleted",
                    "timestomping", ".bash_history cleared"],
    ),
    "T1027": Technique(
        id="T1027", name="Obfuscated Files or Information", tactic_id="TA0005",
        description="Adversaries obfuscate content to make detection more difficult.",
        indicators=["base64 encoded payload", "XOR obfuscation", "packed executable",
                    "steganography", "encrypted shellcode"],
    ),

    # ── Credential Access ─────────────────────────────────────────────────────
    "T1003": Technique(
        id="T1003", name="OS Credential Dumping", tactic_id="TA0006",
        description="Adversaries attempt to dump credentials to obtain hashed or cleartext passwords.",
        indicators=["mimikatz", "lsass dump", "procdump -ma lsass", "hashdump",
                    "sekurlsa::logonpasswords", "NTDS.dit access", "SAM database read"],
    ),
    "T1110": Technique(
        id="T1110", name="Brute Force", tactic_id="TA0006",
        description="Adversaries try many passwords to gain access.",
        indicators=["multiple failed logins", "login attempts from single IP",
                    "password spray", "RDP brute force", "SSH failed attempts"],
    ),
    "T1555": Technique(
        id="T1555", name="Credentials from Password Stores", tactic_id="TA0006",
        description="Adversaries search for common password storage locations.",
        indicators=["browser credential dump", "vault access", "credential manager",
                    "keychain access", ".kdbx file accessed"],
    ),

    # ── Discovery ─────────────────────────────────────────────────────────────
    "T1018": Technique(
        id="T1018", name="Remote System Discovery", tactic_id="TA0007",
        description="Adversaries identify remote systems in an environment.",
        indicators=["nmap scan", "net view", "arp -a", "network scanning",
                    "ping sweep", "port scan detected"],
    ),
    "T1083": Technique(
        id="T1083", name="File and Directory Discovery", tactic_id="TA0007",
        description="Adversaries enumerate files and directories.",
        indicators=["dir /s", "find / -name", "ls -la /etc", "tree command",
                    "recursive directory listing"],
    ),
    "T1057": Technique(
        id="T1057", name="Process Discovery", tactic_id="TA0007",
        description="Adversaries attempt to gather information about running processes.",
        indicators=["tasklist", "ps aux", "Get-Process", "wmic process list"],
    ),
    "T1046": Technique(
        id="T1046", name="Network Service Discovery", tactic_id="TA0007",
        description="Adversaries scan the network to identify open ports and services.",
        indicators=["port scan", "nmap -sV", "masscan", "network enumeration",
                    "banner grabbing"],
    ),

    # ── Lateral Movement ──────────────────────────────────────────────────────
    "T1021": Technique(
        id="T1021", name="Remote Services", tactic_id="TA0008",
        description="Adversaries use valid accounts to log into remote systems.",
        indicators=["RDP connection", "SMB lateral movement", "SSH to internal host",
                    "psexec", "wmiexec", "PsExec detected"],
        sub_techniques=["T1021.001", "T1021.002"],
    ),
    "T1550": Technique(
        id="T1550", name="Use Alternate Authentication Material", tactic_id="TA0008",
        description="Adversaries use alternate authentication material to move laterally.",
        indicators=["pass-the-hash", "pass-the-ticket", "golden ticket",
                    "kerberoasting", "overpass-the-hash"],
    ),

    # ── Collection ────────────────────────────────────────────────────────────
    "T1074": Technique(
        id="T1074", name="Data Staged", tactic_id="TA0009",
        description="Adversaries stage collected data in a central location prior to exfiltration.",
        indicators=["large archive created", ".zip .7z .rar with sensitive files",
                    "data compressed to temp folder", "staging directory created"],
    ),
    "T1114": Technique(
        id="T1114", name="Email Collection", tactic_id="TA0009",
        description="Adversaries collect email data from user accounts.",
        indicators=["email forwarding rule added", "mailbox export", "PST file created",
                    "IMAP mass download"],
    ),

    # ── Exfiltration ──────────────────────────────────────────────────────────
    "T1048": Technique(
        id="T1048", name="Exfiltration Over Alternative Protocol", tactic_id="TA0010",
        description="Adversaries steal data by exfiltrating over an alternative protocol.",
        indicators=["DNS tunneling", "ICMP tunneling", "FTP to external IP",
                    "data over HTTPS to unknown host", "large outbound transfer"],
    ),
    "T1041": Technique(
        id="T1041", name="Exfiltration Over C2 Channel", tactic_id="TA0010",
        description="Adversaries steal data by exfiltrating it over an existing C2 channel.",
        indicators=["data sent via C2 beacon", "large C2 payload", "covert channel upload"],
    ),

    # ── Command and Control ───────────────────────────────────────────────────
    "T1071": Technique(
        id="T1071", name="Application Layer Protocol", tactic_id="TA0011",
        description="Adversaries communicate using application layer protocols.",
        indicators=["beaconing over HTTPS", "periodic HTTP requests", "C2 over DNS",
                    "Cobalt Strike beacon", "unusual User-Agent"],
        sub_techniques=["T1071.001", "T1071.004"],
    ),
    "T1105": Technique(
        id="T1105", name="Ingress Tool Transfer", tactic_id="TA0011",
        description="Adversaries transfer tools from an external system.",
        indicators=["wget/curl to external IP", "bitsadmin download", "certutil -urlcache",
                    "tool downloaded from C2", "powershell DownloadFile"],
    ),

    # ── Impact ────────────────────────────────────────────────────────────────
    "T1486": Technique(
        id="T1486", name="Data Encrypted for Impact", tactic_id="TA0040",
        description="Adversaries encrypt data to interrupt availability (ransomware).",
        indicators=["mass file encryption", ".locked .encrypted file extensions",
                    "ransom note dropped", "shadow copy deletion", "vssadmin delete shadows"],
    ),
    "T1489": Technique(
        id="T1489", name="Service Stop", tactic_id="TA0040",
        description="Adversaries stop or disable services to render them unavailable.",
        indicators=["critical service stopped", "net stop", "systemctl stop",
                    "database service killed", "backup service disabled"],
    ),
    "T1496": Technique(
        id="T1496", name="Resource Hijacking", tactic_id="TA0040",
        description="Adversaries leverage victim resources for cryptomining or other tasks.",
        indicators=["CPU spike to 100%", "cryptominer process", "xmrig", "mining pool connection",
                    "GPU overload", "unusual outbound port 3333"],
    ),
}


# ─────────────────────────────── Query helpers ───────────────────────────────

def get_technique(technique_id: str) -> Optional[Technique]:
    return TECHNIQUES.get(technique_id)


def get_techniques_for_tactic(tactic_id: str) -> List[Technique]:
    return [t for t in TECHNIQUES.values() if t.tactic_id == tactic_id]


def match_indicators_to_techniques(observed: List[str]) -> List[Technique]:
    """Return techniques whose indicator list overlaps with observed strings."""
    matched: List[Technique] = []
    obs_lower = [o.lower() for o in observed]
    for technique in TECHNIQUES.values():
        for indicator in technique.indicators:
            if any(indicator.lower() in obs for obs in obs_lower):
                matched.append(technique)
                break
    return matched


def build_context_for_triage(observed_indicators: List[str]) -> str:
    """
    Build a compact MITRE ATT&CK context string for the Triage Agent prompt.
    Lists matched techniques and their tactics.
    """
    matched = match_indicators_to_techniques(observed_indicators)
    if not matched:
        return "No specific MITRE techniques matched. Perform broad analysis."
    lines = ["Matched MITRE ATT&CK techniques based on observed indicators:"]
    for t in matched:
        lines.append(f"  [{t.id}] {t.name} — {t.tactic} ({t.tactic_id})")
        lines.append(f"    Description: {t.description}")
    return "\n".join(lines)
