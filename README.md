 # RemcosRAT Malware Analysis 🔍

Static analysis of a real RemcosRAT sample from MalwareBazaar.

## Environment
- OS: Kali Linux (isolated VirtualBox VM)
- Network disabled before analysis
- Sample never executed — static only

## My Workflow — Step by Step

### Step 1 — Sample Download
Downloaded from MalwareBazaar in Kali Linux:
```bash
wget "https://bazaar.abuse.ch/sample/ddfff81d.../" -O sample.zip
7z x -pinfected sample.zip
```

### Step 2 — Hash Extraction
```bash
python3 -c "
import hashlib
with open('sample.exe', 'rb') as f:
    data = f.read()
print('SHA256:', hashlib.sha256(data).hexdigest())
print('MD5:', hashlib.md5(data).hexdigest())
print('Size:', len(data), 'bytes')
"
```
Output:
- SHA256: ddfff81d72e630cb6d8e77e59f362c40b6032d16ed9cd004c7c2e049360b80c0
- MD5: b82ad2590f7b479aa1d2699401ce8b5e
- Size: 94,208 bytes
- Entropy: 6.02

### Step 3 — Strings Analysis
```bash
strings sample.exe | grep -E "(http|cmd|reg|inject)" 
strings sample.exe | grep -i "(remcos|C&C|connect|backdoor)"
strings sample.exe > all_strings.txt
wc -l all_strings.txt  # 899 strings found
```

### Step 4 — VirusTotal
 ### Step 4 — VirusTotal Hash Check

Copied SHA256 hash and pasted on virustotal.com:
ddfff81d72e630cb6d8e77e59f362c40b6032d16ed9cd004c7c2e049360b80c0

**Results:**
- 35/71 security vendors detected as malicious
- Detected as: RemcosRAT, Backdoor, RAT, Trojan
- Tags: trojan, rat, remcos, c2

**Sandbox Analysis (Behavior tab):**
- C2 Domains: afun.it.com, tg77.it.com, yellowred.in
- Registry: HKCU\Software\remcos_uydjlghidfpkwvk
- Files: \AppData\Roaming\remcos\
- Mutex: Remcos_Mutex_Inj
- Process: Backdoor.exe created

**MITRE ATT&CK from VirusTotal:**
- T1055 — Process Injection
- T1056 — Keylogger
- T1113 — Screen Capture
- T1547 — Boot Persistence

### Step 5 — MITRE ATT&CK Mapping
Mapped findings to ATT&CK techniques manually

## Findings

### Capabilities Discovered
| Capability | Evidence from strings |
|------------|----------------------|
| Keylogger | deletekeylog |
| Clipboard Theft | getclipboard, setclipboard |
| Screen Capture | screenshotdata |
| UAC Bypass | EnableLUA, reg.exe |
| C2 Communication | "Connected to C&C!" |
| Persistence | CurrentVersion\Run |

### MITRE ATT&CK
| ID | Technique |
|----|-----------|
| T1055 | Process Injection |
| T1056 | Input Capture - Keylogger |
| T1113 | Screen Capture |
| T1115 | Clipboard Data |
| T1112 | Modify Registry |
| T1548 | UAC Bypass |

### IOCs
**Hashes:**
- SHA256: ddfff81d72e630cb6d8e77e59f362c40b6032d16ed9cd004c7c2e049360b80c0
- MD5: b82ad2590f7b479aa1d2699401ce8b5e

**Registry:**
- HKCU\Software\remcos_uydjlghidfpkwvk\EXEpath

**Mutex:**
- Remcos_Mutex_Inj

**C2 Domains:**
- afun.it.com
- tg77.it.com
- yellowred.in

## Tools Used
- MalwareBazaar — sample source
- Python 3 — hash + entropy calculation
- Linux strings command — string extraction
- VirusTotal — multi-engine detection
- 7zip — password protected zip extraction

## Full Report on Medium
https://medium.com/@parthpandit402/remcosrat-malware-analysis-a-complete-static-analysis-report-56c0014a6534

⚠️ Analysis performed in isolated Kali Linux VM
⚠️ Network disabled before sample extraction
⚠️ Sample never executed — static analysis only