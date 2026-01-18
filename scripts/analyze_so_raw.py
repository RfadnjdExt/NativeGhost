import sys
import re
import os

def demangle(name):
    # _Z N namespace class method E -> namespace::class::method
    if name.startswith("_Z"):
        clean = name[2:]
        parts = re.findall(r"\d+(\w+)", clean)
        if parts:
            return "::".join(parts)
    return name

def analyze_raw(filename):
    print(f"Analyzing {filename} (Raw Mode)...")
    try:
        with open(filename, "rb") as f:
            data = f.read()
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    # 1. Extract All Strings (ASCII)
    print("\n--- extracting strings > 4 chars ---")
    # Regex for printable chars 
    pattern = re.compile(b"[\x20-\x7E]{4,}")
    matches = pattern.findall(data)
    
    keywords = ["api", "http", "rank", "match", "history", "record"]
    found_symbols = 0
    
    for m in matches:
        try:
            s = m.decode('utf-8')
            # Check if it looks like a symbol
            if "_Z" in s or any(k in s.lower() for k in keywords):
                if found_symbols < 50: # Limit output
                    demangled = demangle(s)
                    if demangled != s:
                        print(f"SYMBOL: {s} -> {demangled}")
                    elif any(k in s.lower() for k in keywords):
                        print(f"STRING: {s}")
                found_symbols += 1
        except: pass
    
    print(f"Total potential strings found: {len(matches)}")

    # 2. Heuristic XOR Scan
    # We will scan the *first 1MB* of data for finding hidden "http"
    print("\n--- XOR Scan (First 500KB) ---")
    limit = min(len(data), 512 * 1024) 
    sample = data[:limit]
    
    # Signatures to look for
    sigs = [b"http://", b"https://", b"api.mobilelegends", b"unity3d"]
    
    possible_keys = []
    
    for key in range(1, 256):
        # We can optimize: just XOR the first few bytes of signatures against the data?
        # No, we need to XOR the data and look for the sig.
        # To be fast, let's just XOR a small chunk? No, we don't know where strings are.
        # Python loop 500KB * 255 is slow.
        # Let's try just XORing against the keyword b"http" -> 4 bytes.
        # If we find the XORed version of "http" in the data, then we verify that key/location.
        
        # Candidate block: "http" ^ key
        # candidate = bytes([b ^ key for b in b"http"])
        # if candidate in sample:
        #    print(f"Key {key}? Found potential match.")
             
        # Actually simplest complete check:
        # Check specific meaningful strings.
        
        # Make a transformation map for the key
        # trans = bytes.maketrans(bytes(range(256)), bytes([(x ^ key) for x in range(256)]))
        # This is faster than loop.
        
        # transformed_sample = sample.translate(trans)
        
        # Using list comp is slow. translate is fast.
        
        # Construct translation table for this key
        from_b = bytes(range(256))
        to_b = bytes([(x ^ key) & 0xFF for x in range(256)])
        tt = bytes.maketrans(from_b, to_b)
        
        decrypted = sample.translate(tt)
        
        for sig in sigs:
            if sig in decrypted:
                print(f"[!] XOR Key Found: {hex(key)}")
                idx = decrypted.find(sig)
                snippet = decrypted[max(0, idx-10):min(len(decrypted), idx+50)]
                print(f"    Context: {snippet}")
                possible_keys.append(key)
                break # Move to next key if found one sig

    if not possible_keys:
        print("No simple XOR keys found.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python analyze_so_raw.py <file>")
    else:
        analyze_raw(sys.argv[1])
