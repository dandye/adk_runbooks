# Detection Engineering Coverage Evaluation: RedLine Stealer

**Document ID:** SEC-EVAL-2026-REDLINE-001  
**Target Threat:** RedLine Stealer (Infostealer)  
**Date:** August 20, 2026  
**Status:** Completed & Validated  
**Author:** Detection Engineering (DAC Agent)

---

## 1. Executive Summary

A comprehensive detection engineering coverage evaluation was performed for **RedLine Stealer**, an ubiquitous commodity infostealer distributed via phishing, malicious search ads, and cracked software. RedLine specializes in harvesting browser credentials (Chromium, Gecko), Discord authorization tokens, cryptocurrency wallet credentials, VPN configurations, and system metadata. Harvested credentials are staged locally in the `%TEMP%` directory before being exfiltrated via WCF (Windows Communication Foundation / Net.TCP) or raw TCP/HTTP to Command & Control (C2) servers.

This evaluation extracted threat intelligence, generated a structured **Threat Detection Opportunity (TDO)**, simulated **Synthetic UDM Telemetry**, evaluated coverage against baseline Chronicle SIEM rules, and developed an optimized multi-event **YARA-L 2.0** detection rule to bridge identified telemetry correlation gaps.

---

## 2. Threat Intelligence & Attack Vector Breakdown

### 2.1 Threat Profile
* **Malware Family:** RedLine Stealer
* **Category:** Information Stealer (Infostealer)
* **Primary Objective:** Credential harvesting, crypto-wallet theft, session hijacking, C2 exfiltration.
* **Execution Flow:**
  1. **Delivery & Execution:** Dropped via malicious ISO/ZIP, phishing attachment, or fake installer into user profile directories (`%APPDATA%`, `%LOCALAPPDATA%`, `%TEMP%`).
  2. **Reconnaissance & Harvesting:** Scans and reads SQLite databases (e.g., `Login Data`, `Cookies`, `Web Data`) in Google Chrome, Microsoft Edge, Mozilla Firefox, Brave, and Opera; scans Discord storage (`Local Storage\leveldb\*.ldb`); scans wallet directories (`%APPDATA%\Armory`, `%APPDATA%\Bytecoin`, `%APPDATA%\Ethereum\keystore`, etc.).
  3. **Staging:** Aggregates stolen credentials, system information (hardware, IP, OS), and tokens into temporary files/archives located in `%TEMP%\<GUID>\` or `%TEMP%\*.zip`.
  4. **Exfiltration:** Initiates outbound network connections using raw TCP or Net.TCP/WCF over non-standard high ports (e.g., ports 10000–65535, port 41255, port 19075) or HTTP POST directly to actor C2 infrastructure.

### 2.2 MITRE ATT&CK Mapping

| MITRE ATT&CK ID | Tactic | Technique Name | Threat Action |
| :--- | :--- | :--- | :--- |
| **T1059.003** | Execution | Command and Scripting Interpreter: Windows Command Shell | Launches helper commands/processes |
| **T1555.003** | Credential Access | Credentials from Password Stores: Credentials from Web Browsers | Reads SQLite `Login Data` and `Web Data` files |
| **T1552.001** | Credential Access | Unsecured Credentials: Credentials In Files | Harvests Discord tokens, wallet files, and VPN configs |
| **T1074.001** | Collection | Data Staged: Local Data Staging | Stages archives and stolen artifacts under `%TEMP%` |
| **T1071.001** | Command and Control | Application Layer Protocol: Web Protocols / Non-Standard C2 | WCF/SOAP communications to C2 servers |
| **T1041** | Exfiltration | Exfiltration Over C2 Channel | Transmits staged credentials payload over active socket |

---

## 3. Threat Detection Opportunity (TDO)

```json
{
  "tdo_id": "TDO-2026-REDLINE-001",
  "title": "RedLine Stealer Credential Staging and Direct Non-Standard TCP Exfiltration",
  "threat_name": "RedLine Stealer",
  "severity": "HIGH",
  "description": "Detects RedLine infostealer behavior characterized by endpoint process creation staging archive/data artifacts into %TEMP% followed immediately by outbound network connections on non-standard ports to external IP addresses.",
  "mitre_techniques": [
    "T1555.003",
    "T1552.001",
    "T1074.001",
    "T1071.001",
    "T1041"
  ],
  "telemetry_sources": [
    "PROCESS_LAUNCH",
    "FILE_CREATION",
    "NETWORK_CONNECTION"
  ],
  "detection_strategy": "Correlate local file staging in temporary directories with outbound network communication from the same host and process context within a 5-minute window."
}
```

---

## 4. Synthetic UDM Telemetry Generation

The following synthetic UDM events simulate RedLine executing on a Windows workstation (`WORKSTATION-042`), staging stolen credentials to `%TEMP%`, and exfiltrating data to an external C2 IP over TCP port 41255.

### Event 1: Process Execution & File Staging (UDM Event)
```json
{
  "metadata": {
    "event_timestamp": "2026-08-20T20:50:10Z",
    "event_type": "FILE_CREATION",
    "product_name": "CrowdStrike Falcon / Sysmon",
    "vendor_name": "Microsoft"
  },
  "principal": {
    "hostname": "WORKSTATION-042",
    "user": {
      "userid": "jdoe"
    },
    "process": {
      "pid": "4892",
      "command_line": "\"C:\\Users\\jdoe\\AppData\\Local\\Temp\\setup_update.exe\"",
      "file": {
        "full_path": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\setup_update.exe",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      }
    }
  },
  "target": {
    "file": {
      "full_path": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\a8d9f2c1-3b4e-4f7a-9a1b-123456789abc\\credentials.zip",
      "mime_type": "application/zip",
      "size": 145892
    }
  }
}
```

### Event 2: C2 Network Communication (UDM Event)
```json
{
  "metadata": {
    "event_timestamp": "2026-08-20T20:51:05Z",
    "event_type": "NETWORK_CONNECTION",
    "product_name": "Zeek / EDR Network Monitor",
    "vendor_name": "Google SecOps"
  },
  "principal": {
    "hostname": "WORKSTATION-042",
    "user": {
      "userid": "jdoe"
    },
    "ip": "192.168.10.42",
    "process": {
      "pid": "4892",
      "command_line": "\"C:\\Users\\jdoe\\AppData\\Local\\Temp\\setup_update.exe\""
    }
  },
  "target": {
    "ip": "185.220.101.5",
    "port": 41255
  },
  "network": {
    "ip_protocol": "TCP",
    "sent_bytes": 152340,
    "received_bytes": 1024
  }
}
```

---

## 5. Coverage Gap Analysis

| Baseline Detection Capability | Status | Evaluation Finding |
| :--- | :--- | :--- |
| **Generic Suspicious File Creation in %TEMP%** | Ineffective / Noisy | High false-positive rate from legitimate installers (MSI, Chrome updates) if not correlated with network activity. |
| **Known Malicious File Hashes (GTI/IOC)** | Partial | RedLine payloads are frequently packed/obfuscated (crypters), causing hash lookups to miss novel variants. |
| **Non-Standard Port Network Outbound** | Low Fidelity | Network firewalls observe high volumes of ephemeral client traffic; standalone alerts trigger excessive false alarms. |
| **Correlated Staging + Direct C2 Channel** | **GAP IDENTIFIED** | **Zero automated correlation rules** existed linking local staging of zip/archive files in user Temp space to immediate non-standard outbound TCP sockets. |

---

## 6. Engineered YARA-L 2.0 Detection Rule

The following multi-event YARA-L 2.0 rule addresses the coverage gap with high fidelity:

```yara
rule redline_stealer_credential_staging_and_c2_exfiltration {
  meta:
    author = "Google SecOps Detection Engineering"
    description = "Detects RedLine Stealer behavior by correlating file creation/staging in temporary directories with outbound network connections on non-standard ports within 5 minutes."
    severity = "HIGH"
    priority = "HIGH"
    mitre_attack_tactic = "TA0006, TA0009, TA0011, TA0010"
    mitre_attack_technique = "T1555.003, T1074.001, T1071.001, T1041"
    reference = "https://attack.mitre.org/software/S1050/"
    version = "1.0"

  events:
    // Event 1: File staging in Temp directory by process
    $staging.metadata.event_type = "FILE_CREATION"
    $staging.principal.hostname = $hostname
    $staging.principal.process.pid = $pid
    re.regex($staging.target.file.full_path, `(?i)\\AppData\\Local\\Temp\\.*(\.zip|\.dat|\.txt|\.log|credentials|passwords)`)

    // Event 2: Outbound network connection initiated by the same process/host
    $network.metadata.event_type = "NETWORK_CONNECTION"
    $network.principal.hostname = $hostname
    $network.principal.process.pid = $pid
    $network.target.port != 80
    $network.target.port != 443
    $network.target.port != 53
    $network.target.port != 8080
    $network.target.port > 1024
    
    // Exclude internal/private destination IP ranges
    not net.ip_in_range_cidr($network.target.ip, "10.0.0.0/8")
    not net.ip_in_range_cidr($network.target.ip, "172.16.0.0/12")
    not net.ip_in_range_cidr($network.target.ip, "192.168.0.0/16")
    not net.ip_in_range_cidr($network.target.ip, "127.0.0.0/8")

  match:
    $hostname, $pid over 5m

  outcome:
    $risk_score = 85
    $principal_user = array_distinct($staging.principal.user.userid)
    $staged_file = array_distinct($staging.target.file.full_path)
    $process_command_line = array_distinct($staging.principal.process.command_line)
    $process_sha256 = array_distinct($staging.principal.process.file.sha256)
    $c2_dest_ip = array_distinct($network.target.ip)
    $c2_dest_port = array_distinct($network.target.port)
    $network_bytes_sent = max($network.network.sent_bytes)

  condition:
    $staging and $network
}
```

---

## 7. Operational Validation & Sequence Flow

```{mermaid}
sequenceDiagram
    participant ThreatIntel as CTI / Threat Advisory
    participant DACAgent as Detection Engineering Agent
    participant SyntheticEngine as Synthetic Telemetry Engine
    participant ChronicleSIEM as Chronicle SIEM
    participant SecOpsSOAR as SecOps SOAR

    ThreatIntel->>DACAgent: Ingest RedLine Stealer Behaviors & TTPs
    DACAgent->>DACAgent: Generate Threat Detection Opportunity (TDO-2026-REDLINE-001)
    DACAgent->>SyntheticEngine: Generate Synthetic UDM Telemetry (File Staging + C2 Network)
    SyntheticEngine-->>DACAgent: UDM JSON Telemetry (FILE_CREATION & NETWORK_CONNECTION)
    DACAgent->>ChronicleSIEM: Evaluate Existing Rule Coverage
    ChronicleSIEM-->>DACAgent: Zero Correlation Matches (Coverage Gap Identified)
    DACAgent->>DACAgent: Draft & Compile YARA-L 2.0 Correlated Rule
    DACAgent->>ChronicleSIEM: Validate Syntax, Logic, Match Window & Outcomes
    ChronicleSIEM-->>DACAgent: Validation Passed (0 Compilation Errors)
    DACAgent->>SecOpsSOAR: Publish Rule & Coverage Report
```

---

## 8. Deployment and Next Steps

1. **Detection-as-Code CI/CD**: Commit `redline_stealer_credential_staging_and_c2_exfiltration.yaral` to the security detection repository under `detections/rules/windows/infostealers/`.
2. **Backtesting / Replay**: Run historical UDM search over the past 30 days to establish baseline false-positive rate across corporate endpoints.
3. **SOAR Playbook Integration**: Route high-fidelity alerts triggered by this rule to the **Malware Triage & Automated Host Isolation** playbook.
