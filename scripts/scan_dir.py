import sys
import re
import os

def extract_strings_from_file(filename):
    try:
        with open(filename, "rb") as f:
            data = f.read()
    except Exception as e:
        print(f"Error reading {filename}: {e}")
        return

    # Regex for printable strings > 4 chars
    pattern = re.compile(b"[\x20-\x7E]{4,}")
    matches = pattern.findall(data)
    
    keywords = [b"api.", b"http", b".com", b"rank", b"history", b"match", b"record", b"global"]
    
    found_in_file = 0
    for m in matches:
        lower_m = m.lower()
        if any(k in lower_m for k in keywords):
            try:
                s = m.decode('utf-8')
                print(f"[{os.path.basename(filename)}] {s}")
                found_in_file += 1
                if found_in_file > 20: # Limit per file
                    print(f"[{os.path.basename(filename)}] ... (truncated)")
                    break
            except: pass

def main():
    if len(sys.argv) < 2:
        print("Usage: python scan_dir.py <directory>")
        sys.exit(1)
        
    target_dir = sys.argv[1]
    print(f"Scanning directory: {target_dir}")
    
    for root, dirs, files in os.walk(target_dir):
        for file in files:
            path = os.path.join(root, file)
            extract_strings_from_file(path)

if __name__ == "__main__":
    main()
