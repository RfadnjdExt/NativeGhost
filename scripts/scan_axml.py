import sys
import struct

def parse_axml_strings(filename):
    print(f"Scanning AXML {filename}...")
    try:
        with open(filename, "rb") as f:
            data = f.read()
    except Exception as e:
        print(f"Error: {e}")
        return

    # AXML Header: 03 00 08 00
    if data[0:4] != b"\x03\x00\x08\x00":
        print("[-] Not a standard AXML file (Magic mismatch).")
        # Try raw string scan if not AXML
    
    # String Pool Chunk usually follows.
    # We can just brute-force extract UTF-16LE strings which is what AXML uses.
    
    print("--- Extracting UTF-16 Strings (Heuristic) ---")
    # AXML strings are length-prefixed, but raw UTF-16 scan is effective.
    # Look for sequences of printable chars encoding in UTF-16.
    
    # We'll use a regex for UTF-16LE printable extraction
    import re
    # Pattern: (char + \x00) repeated.
    # Char range: \x20-\x7E (ASCII)
    
    pattern = re.compile(b"(?:[\x20-\x7E]\x00){4,}")
    
    matches = pattern.findall(data)
    
    keywords = ["com.", "api", "key", "http", "meta", "unity", "activity"]
    
    print(f"Found {len(matches)} potential string fragments.")
    
    for m in matches:
        try:
            s = m.decode("utf-16le")
            # Filter
            if any(k in s.lower() for k in keywords) or "com.mobile.legends" in s:
                print(f"  STR: {s}")
        except: pass

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scan_axml.py <file>")
    else:
        parse_axml_strings(sys.argv[1])
