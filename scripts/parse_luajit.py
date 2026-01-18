import sys

def scan_length_prefixed_strings(filename):
    print(f"Scanning {filename} for Length-Prefixed Strings...")
    try:
        with open(filename, "rb") as f:
            data = f.read()
    except Exception as e:
        print(f"Error: {e}")
        return

    i = 0
    size = len(data)
    found_count = 0
    
    while i < size - 10: # Safety margin
        # Assume byte at i is Length
        length = data[i]
        
        # Filter reasonable lengths for strings in game configs
        if 4 <= length <= 127:
            # Check if next 'length' bytes are printable ASCII
            candidate = data[i+1 : i+1+length]
            try:
                # Check if all chars are in printable range (0x20 - 0x7E)
                is_printable = True
                for b in candidate:
                    if not (0x20 <= b <= 0x7E):
                        is_printable = False
                        break
                
                if is_printable:
                    s = candidate.decode('utf-8')
                    # Additional filtering
                    if len(s) == length and " " not in s: # Most API strings don't have spaces
                        print(f"Offset {hex(i)}: {s}")
                        found_count += 1
                        # Skip past this string to avoid overlapping noise
                        # i += 1 + length
                        # But maybe we want overlap if false positive?
                        # Let's advance
                        # i += length 
                        # Actually safe to just i+=1 to catch everything
            except:
                pass
        
        i += 1
    
    print(f"Total candidates found: {found_count}")

if __name__ == "__main__":
    scan_length_prefixed_strings(sys.argv[1])
