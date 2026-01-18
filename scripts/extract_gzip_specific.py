import sys
import gzip
import shutil

def extract_gzip(filename, offset, outname):
    try:
        with open(filename, "rb") as f:
            f.seek(offset)
            # Read enough data
            data = f.read()
            
        # We need to feed this to gzip.decompress?
        # gzip.decompress expects the full valid gzip stream.
        # However, trailing garbage after the stream is usually ignored by some tools, but python might complain.
        # Let's write it to a temp file and use GzipFile to read.
        
        with open("temp.gz", "wb") as tmp:
            tmp.write(data)
            
        try:
            with gzip.open("temp.gz", "rb") as gz:
                decompressed = gz.read()
                
            print(f"Success! Decompressed {len(decompressed)} bytes.")
            with open(outname, "wb") as out:
                out.write(decompressed)
                
            # Preview
            try:
                print("Preview (text):")
                print(decompressed[:200].decode('utf-8'))
            except:
                print("Preview (hex):")
                print(decompressed[:64].hex())
                
        except Exception as e:
            print(f"Gzip extraction error: {e}")
            
    except Exception as e:
        print(f"File error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python extract_gzip_specific.py <file> <offset_int> <outname>")
    else:
        extract_gzip(sys.argv[1], int(sys.argv[2]), sys.argv[3])
