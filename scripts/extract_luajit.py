import sys

def extract_chunk(filename, offset, size, outname):
    print(f"Extracting {size} bytes from {filename} at {hex(offset)}...")
    with open(filename, "rb") as f:
        f.seek(offset)
        data = f.read(size)
    
    with open(outname, "wb") as out:
        out.write(data)
    print(f"Saved to {outname}")

if __name__ == "__main__":
    extract_chunk("extracted_apk/assets/Resources4-1.dat", 0x34132a, 50000, "lua_chunk_1.luac")
    extract_chunk("extracted_apk/assets/Resources4-1.dat", 0xf85308, 50000, "lua_chunk_2.luac")
