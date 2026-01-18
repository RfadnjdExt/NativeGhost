import sys
import zlib
import os

def extract_zlib_streams(filename, out_dir):
    try:
        with open(filename, "rb") as f:
            data = f.read()
    except Exception as e:
        print(f"Error: {e}")
        return

    if not os.path.exists(out_dir):
        os.makedirs(out_dir)

    # Zlib magic headers: 
    # 78 01 (No/Low compression)
    # 78 9C (Default compression) - Most common
    # 78 DA (Best compression)
    
    magic = b"\x78\x9c"
    start = 0
    count = 0
    
    print(f"Scanning {filename} for Zlib streams (Magic: 78 9C)...")
    
    while True:
        offset = data.find(magic, start)
        if offset == -1:
            break
        
        # Try to decompress from this offset
        try:
            # We don't know the length, but zlib.decompress usually 
            # handles streams if we pass enough data? 
            # Actually standard zlib.decompress usually wants the exact stream or a stream object.
            # We can use a decompress object.
            
            dobj = zlib.decompressobj()
            decompressed = dobj.decompress(data[offset:offset+1024*1024]) # Try up to 1MB
            
            if len(decompressed) > 10: # Filter tiny false positives
                # Success!
                out_name = os.path.join(out_dir, f"stream_{offset:08x}.bin")
                with open(out_name, "wb") as fo:
                    fo.write(decompressed)
                
                # Check if it's text
                try:
                    text_sample = decompressed[:100].decode('utf-8')
                    if text_sample.isprintable():
                        print(f"[+] Extracted TEXT at {hex(offset)}: {text_sample.strip()}")
                except:
                    pass # Binary
                    
                count += 1
                if count % 20 == 0:
                    print(f"    Extracted {count} streams...")
                    
        except Exception:
            pass # Not a valid stream
            
        start = offset + 1 # Move forward

    print(f"Finished. Total streams extracted: {count}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python extract_zlib.py <file> <out_dir>")
    else:
        extract_zlib_streams(sys.argv[1], sys.argv[2])
