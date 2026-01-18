
import re
import sys

def extract_strings(file_path):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
            # Find strings starting with Java_ followed by word characters
            # Min length 10 to reduce noise
            pattern = b'Java_[\w_]{10,}'
            matches = re.findall(pattern, data)
            
            seen = set()
            for m in matches:
                try:
                    s = m.decode('utf-8')
                    if s not in seen and len(s) < 200:
                        print(s)
                        seen.add(s)
                except:
                    pass
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    print("Scanning memory_dump.bin...")
    try:
        with open('memory_dump.bin', 'rb') as f:
            data = f.read()
            
        print("--- Java_ Exports ---")
        matches = re.findall(b'Java_[\w_]{5,}', data)
        seen = set()
        for m in matches:
            s = m.decode('utf-8', errors='ignore')
            if s not in seen and len(s) < 100:
                print(s)
                seen.add(s)

        print("\n--- HTTP/HTTPS ---")
        matches = re.findall(b'https?://[\w./-]+', data)
        seen = set()
        for m in matches:
            s = m.decode('utf-8', errors='ignore')
            if s not in seen:
                print(s)
                seen.add(s)

        print("\n--- Sign/Token ---")
        matches = re.findall(b'[a-zA-Z0-9_]*(?:Sign|Token)[a-zA-Z0-9_]*', data)
        seen = set()
        for m in matches:
            s = m.decode('utf-8', errors='ignore')
            if s not in seen and len(s) > 4 and len(s) < 50:
                print(s)
                seen.add(s)

    except Exception as e:
        print(f"Error: {e}")
