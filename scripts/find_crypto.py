import sys
import struct

def find_crypto_signatures(filename):
    print(f"Scanning {filename} for crypto constants...")
    try:
        with open(filename, "rb") as f:
            data = f.read()
    except Exception as e:
        print(f"Error: {e}")
        return

    signatures = {
        "AES S-Box (Start)": bytes.fromhex("63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76"),
        "AES Inv S-Box (Start)": bytes.fromhex("52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb"),
        "Rijndael Te0": bytes.fromhex("c6 63 63 a5 f8 7c 7c 84 ee 77 77 99 f6 7b 7b 8d"),
        "SHA-256 K[0]": bytes.fromhex("42 8a 2f 98 71 37 44 91"),
        "MD5 Transform": bytes.fromhex("78 a4 6a d7 56 b7 c7 e8 db 70 20 24 ee ce bd 7b"),
        "Zlib Header (Best Effort)": b"\x78\x9c", 
        "Gzip Header": b"\x1f\x8b\x08",
        "UnityFS Header": b"UnityFS",
        "ELF Header": b"\x7fELF"
    }

    found_any = False
    for name, sig in signatures.items():
        offset = data.find(sig)
        if offset != -1:
            print(f"[+] Found {name} at offset {hex(offset)}")
            found_any = True
            # Look for multiple occurrences
            count = data.count(sig)
            if count > 1:
                print(f"    (Total occurrences: {count})")
    
    if not found_any:
        print("[-] No common crypto constants found.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python find_crypto.py <file>")
    else:
        find_crypto_signatures(sys.argv[1])
