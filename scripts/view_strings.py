import sys
import re

def print_all_strings(filename):
    print(f"--- Strings in {filename} ---")
    with open(filename, "rb") as f:
        data = f.read()
    
    # ASCII printable > 4
    matches = re.finditer(b"[\x20-\x7E]{4,}", data)
    
    count = 0
    for m in matches:
        print(m.group().decode('utf-8'))
        count += 1
        if count > 200:
            print("... (truncated)")
            break

if __name__ == "__main__":
    print_all_strings(sys.argv[1])
