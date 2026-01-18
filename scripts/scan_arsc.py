import sys
import re

def parse_arsc_strings(filename):
    print(f"Scanning ARSC {filename}...")
    try:
        with open(filename, "rb") as f:
            data = f.read()
    except Exception as e:
        print(f"Error: {e}")
        return

    # ARSC files contain a global string pool
    # Strings are usually UTF-16LE or UTF-8.
    
    print("--- Extracting Strings (Heuristic) ---")
    
    # Try UTF-16LE first
    # Pattern: Sequence of [printable, 0x00] len > 4
    pattern_utf16 = re.compile(b"(?:[\x20-\x7E]\x00){4,}")
    matches = pattern_utf16.findall(data)
    
    print(f"Found {len(matches)} UTF-16 string fragments.")
    
    keywords = ["server", "connect", "fail", "error", "api", "http", "update", "cdn", "net"]
    
    for m in matches:
        try:
            s = m.decode("utf-16le")
            if any(k in s.lower() for k in keywords):
                print(f"  STR: {s}")
        except: pass

    # Try UTF-8 (null terminated)
    # pattern_utf8 = re.compile(b"[\x20-\x7E]{4,}")
    # matches8 = pattern_utf8.findall(data)
    # Using existing scan_dir logic for that if needed.

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scan_arsc.py <file>")
    else:
        parse_arsc_strings(sys.argv[1])
