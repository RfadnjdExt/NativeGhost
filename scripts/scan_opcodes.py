import sys
import struct

def scan_arm64_crypto(filename):
    print(f"Scanning {filename} for ARM64 Crypto Instructions...")
    try:
        with open(filename, "rb") as f:
            data = f.read()
    except Exception as e:
        print(f"Error: {e}")
        return
        
    # ARM64 Instructions are 4 bytes (Little Endian in Android)
    # We look for the Opcode generic patterns.
    # Note: We match the specific Instruction Encoding bits.
    
    # AESE Vd, Vn (AES Encryption)
    # Binary: 0100 1110 0010 1000 0100 10...
    # Hex: 4E 28 48 ... (But little endian: ... 48 28 4E is unlikely, usually instructions are le)
    # Little Endian file: 
    #   AESE V0, V0 -> 4E 28 48 00 -> File bytes: 00 48 28 4E ???
    #   Actually let's stick to the 32-bit word value.
    
    # Signatures (Masked)
    # We will iterate 4 bytes at a time and check the mask.
    
    hits = {
        "AESE (AES Encrypt)": 0,
        "AESD (AES Decrypt)": 0,
        "SHA256H": 0,
        "SHA256Su0": 0
    }
    
    # Optimization: Unpack as array of uint32
    # Ensure length is multiple of 4
    limit = len(data) - (len(data) % 4)
    instructions = struct.unpack(f"<{limit // 4}I", data[:limit])
    
    for i, inst in enumerate(instructions):
        # AESE: 0100 1110 0010 1000 0100 1... (Data processing SIMD)
        # Opcode: 0x4E284800 (Base)
        # Mask:   0xFFE0FC00 (Masking out Rd/Rn registers) ?
        # Actually: 
        #   AESE: 0100 1110 0010 1000 0100 1... 
        #   AESD: 0100 1110 0010 1000 0101 1...
        
        # Simple signatures checking "v0, v0" or similar common register usage variants might be safer for brute force
        # But let's try a loose mask.
        
        # AESE inner check: (inst & 0xFFE0F800) == 0x4E284800
        # (Instruction matching is complex, I will check for VERY common byte sequences for AES)
        
        # 4E 28 48 (AESE V?, V?)
        # Let's look at the raw bytes for: AESE V0.16B, V0.16B => 00 48 28 4E 
        
        # Common Register usage: V0-V31.
        # Check if byte pattern matches crypto extension group.
        
        # Group: 4E 28 ...
        if (inst & 0xFFE0F800) == 0x4E284800:
            hits["AESE (AES Encrypt)"] += 1
            if hits["AESE (AES Encrypt)"] == 1:
                print(f"[+] Found AESE at offset {hex(i*4)}")

        if (inst & 0xFFE0F800) == 0x4E285800:
            hits["AESD (AES Decrypt)"] += 1
            if hits["AESD (AES Decrypt)"] == 1:
                print(f"[+] Found AESD at offset {hex(i*4)}")
                
        # SHA256H: 5E 00 40 00 (Base)
        if (inst & 0xFFE0F800) == 0x5E004000:
            hits["SHA256H"] += 1
            if hits["SHA256H"] == 1:
                print(f"[+] Found SHA256H at offset {hex(i*4)}")

    for k, v in hits.items():
        print(f"{k}: {v} occurrences")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scan_opcodes.py <file>")
    else:
        scan_arm64_crypto(sys.argv[1])
