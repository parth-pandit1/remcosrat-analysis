 import hashlib
import re
import math
import subprocess

def analyze_malware(filepath):
    with open(filepath, 'rb') as f:
        data = f.read()
    
    # Hashes
    sha256 = hashlib.sha256(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()
    
    # Entropy
    freq = [data.count(bytes([b]))/len(data) for b in set(data)]
    ent = -sum(p * math.log2(p) for p in freq if p > 0)
    
    # Strings — Linux strings command use karo
    result = subprocess.run(
        ['strings', filepath], 
        capture_output=True, text=True
    )
    strings = result.stdout.splitlines()
    
    # IOC patterns
    iocs = {
        "c2": ["C&C", "connect", "Remcos"],
        "keylogger": ["keylog", "deletekeylog"],
        "clipboard": ["clipboard", "getclipboard"],
        "screenshot": ["screenshot", "screenshotdata"],
        "uac_bypass": ["EnableLUA", "reg.exe"],
        "persistence": ["CurrentVersion\\Run", "Winlogon"],
    }
    
    print("="*50)
    print("REMCOSRAT STATIC ANALYSIS")
    print("="*50)
    print(f"SHA256  : {sha256}")
    print(f"MD5     : {md5}")
    print(f"Size    : {len(data)} bytes")
    print(f"Entropy : {ent:.2f}")
    print(f"Strings : {len(strings)} found")
    
    print("\n--- CAPABILITIES ---")
    for cap, patterns in iocs.items():
        matches = [p for p in patterns if any(p in s for s in strings)]
        if matches:
            print(f"[+] {cap}: {matches}")
    
    print(f"\nVirusTotal: https://virustotal.com/gui/file/{sha256}")

analyze_malware('sample.exe')