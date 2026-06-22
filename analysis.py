import hashlib
import re
import math

def analyze_malware(filepath):
    with open(filepath, 'rb') as f:
        data = f.read()
    
    # Hashes
    sha256 = hashlib.sha256(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()
    
    # Entropy
    freq = [data.count(bytes([b]))/len(data) for b in set(data)]
    ent = -sum(p * math.log2(p) for p in freq if p > 0)
    
    # Strings
    strings = re.findall(rb'[\x20-\x7E]{4,}', data)
    
    # Suspicious patterns
    iocs = {
        "c2": [b"C&C", b"connect", b"Remcos"],
        "keylogger": [b"keylog", b"deletekeylog"],
        "clipboard": [b"clipboard", b"getclipboard"],
        "screenshot": [b"screenshot", b"screenshotdata"],
        "uac_bypass": [b"EnableLUA", b"reg.exe"],
        "persistence": [b"CurrentVersion\\Run", b"Winlogon"],
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
        matches = [p for p in patterns if p in data]
        if matches:
            print(f"[+] {cap}: {[m.decode() for m in matches]}")
    
    print("\n--- IOCs ---")
    print(f"SHA256: {sha256}")
    print(f"MD5: {md5}")
    print(f"VT: https://virustotal.com/gui/file/{sha256}")

# Run karo
analyze_malware('sample.exe')