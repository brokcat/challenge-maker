# 🛡️ APT33 – Operation Cleaver: Incident Response and Memory Forensics Report

## 🧠 Overview

This exercise simulates a **targeted cyberattack by APT33 (Elfin)** against a fictional energy company. The attacker chain includes initial access via phishing, exploitation of known vulnerabilities, malware deployment, privilege escalation, lateral movement, and data exfiltration.

A **memory image** was acquired post-incident and must now be analyzed to uncover attacker activity.

---

## 🎭 Incident Scenario

**Incident Name:** `APT33 – Operation Cleaver`  
**Target:** Energy Sector Workstation  
**Threat Actor:** APT33 (Elfin – Iranian cyberespionage group)

A targeted spear-phishing campaign was launched against a workstation in the energy sector. The attacker delivered a disguised document file which, once opened, executed a malicious macro designed to weaken the system’s defenses and stage further malicious activity.

This initial access allowed the attacker to download and execute a secondary component from a remote server. The binary was saved locally and configured to persist across reboots. Subsequent actions suggest attempts to gain elevated privileges and establish communication with an external server — likely for remote control or further post-compromise operations.

**Malware used:**  
- PowerShell-based loader  
- Payload: Remote Access Tool (e.g., NanoCore or TURNEDUP variant)  
- Post-exploitation tools: `Mimikatz`, `PsExec`  
- Persistence: Registry modification

---

## 🧰 Tools Required

- [Volatility3](https://www.volatilityfoundation.org/)
- Python 3.x
- Strings, Yara, VirusTotal (for hash lookup)
- ProcDOT (optional for visualizing execution chain)
- Wireshark (for PCAPs if available)

---

## 🧱 Attack Chain Summary (TTPs)

| MITRE ATT&CK Tactic       | Technique                                      | Description |
|---------------------------|-----------------------------------------------|-------------|
| Initial Access            | Spearphishing Attachment `T1566.001`           | Malicious Excel file |
| Execution                 | Macro Execution + PowerShell `T1059.001`       | Macro spawns PowerShell |
| Persistence               | Registry Run Key `T1547.001`                   | Persistence via HKCU |
| Privilege Escalation      | Credential Dumping `T1003.001` via Mimikatz    | Accessing LSASS |
| Lateral Movement          | PsExec `T1021.002`                              | Remote execution |
| Command and Control       | Encrypted Channel (HTTPS) `T1071.001`          | C2 traffic to real IP |
| Exfiltration              | Exfil via HTTPS `T1041`                        | Project files stolen |

---

### ❓ Q1. What was the first action taken to weaken the system’s defenses?

**Hint 1:** Think of native Windows protections disabled early in an attack.  
**Hint 2:** Look at PowerShell commands that target security settings.

✅ **Answer:**  
`Set-MpPreference -DisableRealtimeMonitoring $true`

---

### ❓ Q2. What CVE is associated with the malicious file delivered during the initial phishing stage?

**Hint 1:** The file is named as if it were an image, but its contents tell another story...  
**Hint 2:** Identify the true file format, correct the magic bytes, and compute the hash — it may lead to a well-known Microsoft Office exploit.

✅ **Answer:**  
CVE-2017-11882

---

### ❓ Q3. What is the full URL used to retrieve the PowerShell payload?

**Hint 1:** The macro contains this URL.  
**Hint 2:** Look for `DownloadString` usage in memory.

✅ **Answer:**  
`http://185.234.1.56/malware.ps1`

---

### ❓ Q4. What was the name of the final executable payload downloaded and run on the system?

**Hint 1:** It is stored in the Temp directory.  
**Hint 2:** Delivered by the PowerShell script.

✅ **Answer:**  
`payload.exe`

---

### ❓ Q5. What tool was used to perform credential dumping?

**Hint 1:** A popular post-exploitation tool for Windows.  
**Hint 2:** Check the process list and the `Documents\mimikatz` folder.

✅ **Answer:**  
`mimikatz.exe`

---

### ❓ Q6. Which command within Mimikatz was used to extract credentials?

**Hint 1:** Used to enable debug rights.  
**Hint 2:** A command to dump credentials from memory.

✅ **Answer:**  
privilege::debug  
sekurlsa::logonPasswords

---

## About the Challenge Maker

I am a Challenge Maker on CyberDefenders and likely on other platforms as well.

I am passionate about endpoint forensics, network forensics, threat hunting, CTI (Cyber Threat Intelligence), and many other fields in the cyber defensive world and space.

If you wish to contact me, you can reach me on Discord at **brokcat**. Feel free to send me feedback about my challenges—I'd love to hear your thoughts!

I am a student at **Ecole 2600**, a cybersecurity school in Paris. :fr: :pirate_flag:

---