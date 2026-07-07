# Splunk Home Lab — Attack Simulation & Detection Engineering

A home lab project simulating common attacker techniques against a Windows victim VM, and building detections for them using Splunk, Sysmon, and native Windows logs.

![Lab Architecture](splunk_home_lab_architecture.png)

## 🎯 Goal

Set up a small, isolated lab environment to practice offensive techniques (mapped to MITRE ATT&CK) and validate detection coverage using a Splunk indexer + Universal Forwarder + Sysmon pipeline — the same workflow used in real SOC / detection engineering roles.

## 🖥️ Lab Environment

| Role | OS | Purpose |
|---|---|---|
| Attacker | Kali Linux | Runs offensive tooling (nmap, SMBClient, etc.) |
| Victim | Windows (VM) | Splunk Universal Forwarder + Sysmon installed, target of simulated attacks |
| Indexer | Windows (physical machine) | Splunk Enterprise, receives forwarded logs, runs detection searches |

Both machines are on the same isolated local network (bridged VM networking), with Windows Firewall configured to allow Splunk traffic on port 9997 between them.

## 🔧 Tooling

- **Splunk Enterprise** (indexer/search head)
- **Splunk Universal Forwarder** (on victim VM)
- **Sysmon** (SwiftOnSecurity config) — endpoint telemetry
- **Windows Firewall logging** — network-level telemetry
- **Windows Security Event Log** — authentication telemetry
- **Atomic techniques via manual simulation** (nmap, hydra, certutil, reg.exe)

## 📁 Repo Structure

```
splunk-home-lab/
├── README.md                              ← you are here
├── attacks/
│   ├── 01-powershell-encoded-command/
│   ├── 02-network-port-scan/
│   ├── 03-smb-bruteforce/
│   ├── 04-lolbin-certutil/
│   └── 05-registry-persistence/
└── screenshots/
    ├── 01-powershell-encoded-command/
    ├── 02-network-port-scan/
    ├── 03-smb-bruteforce/
    ├── 04-lolbin-certutil/
    └── 05-registry-persistence/
```

Each attack folder under `attacks/` contains a `README.md` with the full writeup: objective, technique, commands, detection logic, screenshots, and analysis. Screenshots for that attack live in the matching folder under `screenshots/`.

## 📊 Attack Summary

| # | Technique | MITRE ATT&CK | Detection Source | Result |
|---|---|---|---|---|
| 1 | PowerShell Encoded Command | T1059.001 | Sysmon (Event ID 1) | ✅ Detected |
| 2 | Network Port Scan | T1046 | Windows Firewall Log | ✅ Detected |
| 3 | SMB Brute Force | T1110.001 / T1021.002 | Windows Security Log (4625) | ⚠️ Attempted — tooling friction, see writeup |
| 4 | LOLBin Abuse (certutil) | T1105 / T1218 | Windows Defender (blocked) → Sysmon (detected) | 🛡️ Blocked by Defender, then ✅ Detected via Sysmon/Splunk with protection disabled |
| 5 | Registry Run Key Persistence | T1547.001 | Sysmon (Event ID 13) | ✅ Detected |

## 🧠 Key Takeaways

- **Not every log source fits every technique.** Sysmon's default config is tuned for outbound/process-level behavior — inbound network scans needed Windows Firewall logs instead.
- **Defense-in-depth is visible in the data.** Windows Defender intercepted the LOLBin technique before Sysmon ever saw it, showing that endpoint logging pipelines only see what actually executes.
- **Detection logic often needs pattern-matching, not single events.** A single network connection or login failure means nothing; the pattern (many ports/attempts from one source, in a short window) is what signals malicious activity.
- **Tooling has real-world friction.** SMB brute-forcing hit genuine compatibility issues between SMBClient and modern SMB2/3 — documented as-is, since troubleshooting is part of the real job.

## 🚀 How to Reproduce

1. Set up two VMs (or a VM + physical machine) on the same local network
2. Install Splunk Enterprise on one (indexer), Splunk Universal Forwarder + Sysmon on the other (victim)
3. Configure `outputs.conf` on the forwarder to point at the indexer's IP on port 9997
4. Enable receiving on port 9997 on the indexer
5. Follow each attack writeup under `attacks/` in order

---
*This lab was built entirely in an isolated, non-production environment for educational purposes.*
