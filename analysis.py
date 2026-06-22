 #!/usr/bin/env python3
# RemcosRAT Static Analysis
# Run on: Kali Linux (isolated VM)
# Sample: MalwareBazaar

import hashlib
import math
import subprocess
import sys

def get_hashes(filepath):
    with open(filepath, 'rb') as f:
        data = f.read()
    sha256 = hashlib.sha256(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()
    return data, sha256, md5

def get_entropy(data):
    if not data: return 0
    freq = [data.count(bytes([b]))/len(data) for b in set(data)]
    return -sum(p * math.log2(p) for p in freq if p > 0)

def get_strings(filepath):
    # Linux strings command use kiya
    result = subprocess.run(
        ['strings', filepath],
        capture_output=True, text=True
    )
    return result.stdout.splitlines()

def find_iocs(strings):
    iocs = {
        "c2"        : ["C&C", "Remcos", "connect"],
        "keylogger" : ["keylog", "deletekeylog"],
        "clipboard" : ["clipboard", "getclipboard"],
        "screenshot": ["screenshot", "screenshotdata"],
        "uac_bypass": ["EnableLUA", "reg.exe"],
        "persistence": ["CurrentVersion\\Run", "Winlogon"],
        "sandbox_check": ["SbieDll", "PROCMON", "PROCEXPL"],
    }
    findings = {}
    for cap, patterns in iocs.items():
        matches = [p for p in patterns if any(p in s for s in strings)]
        if matches:
            findings[cap] = matches
    return findings

def main():
    filepath = sys.argv[1] if len(sys.argv) > 1 else 'sample.exe'
    
    print("="*55)
    print("   REMCOSRAT STATIC ANALYSIS REPORT")
    print("   Environment: Kali Linux — Isolated VM")
    print("="*55)
    
    # Hashes
    data, sha256, md5 = get_hashes(filepath)
    print(f"\n[+] SHA256  : {sha256}")
    print(f"[+] MD5     : {md5}")
    print(f"[+] Size    : {len(data)} bytes")
    
    # Entropy
    ent = get_entropy(data)
    flag = "<< PACKED!" if ent > 7.2 else "normal"
    print(f"[+] Entropy : {ent:.2f} ({flag})")
    
    # Strings
    strings = get_strings(filepath)
    print(f"[+] Strings : {len(strings)} found")
    
    # IOCs
    findings = find_iocs(strings)
    print(f"\n--- CAPABILITIES ---")
    for cap, matches in findings.items():
        print(f"[!] {cap}: {matches}")
    
    # VirusTotal link
    print(f"\n--- IOCs ---")
    print(f"SHA256 : {sha256}")
    print(f"MD5    : {md5}")
    print(f"VT     : https://virustotal.com/gui/file/{sha256}")
    
    print("\n--- MITRE ATT&CK ---")
    print("T1055 — Process Injection")
    print("T1056 — Input Capture (Keylogger)")
    print("T1113 — Screen Capture")
    print("T1115 — Clipboard Data")
    print("T1112 — Modify Registry")
    print("T1548 — UAC Bypass")
    
    print("\n" + "="*55)
    print("Analysis complete — sample not executed")
    print("="*55)

main()