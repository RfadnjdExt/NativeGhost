import sys
import re

def extract_strings_and_filter(filename):
    with open(filename, "rb") as f:
        data = f.read()

    # Find all printable ascii strings length >= 4
    # Regex: sequence of chars from space (32) to ~ (126)
    pattern = re.compile(b"[\x20-\x7E]{4,}")
    
    matches = pattern.findall(data)
    
    keywords = [b"api.", b"http", b".com", b"rank", b"history", b"match", b"record", b"global"]
    
    print(f"Scanning {filename}...")
    found_count = 0
    for m in matches:
        # Check if any keyword matches
        lower_m = m.lower()
        if any(k in lower_m for k in keywords):
            try:
                print(m.decode('utf-8'))
                found_count += 1
                if found_count > 200:
                    print("... (truncated)")
                    break
            except:
                pass

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python extract_metadata_strings.py <file>")
        sys.exit(1)
    
    extract_strings_and_filter(sys.argv[1])
