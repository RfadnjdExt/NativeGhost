import sys
import struct
import math

# ---- XXTEA Implementation (Simplified) ----
def xxtea_decrypt(data, key):
    # Key must be 16 bytes. Pad/Truncate.
    if len(key) < 16:
        key = key.ljust(16, b'\0')
    key = key[:16]
    
    k = struct.unpack('<4I', key)
    
    # Pad data to multiple of 4
    if len(data) % 4 != 0:
        return None # XXTEA works on words
        
    v = list(struct.unpack(f'<{len(data)//4}I', data))
    if len(v) <= 1: 
        return data
    
    n = len(v)
    z = v[n-1]
    y = v[0]
    delta = 0x9E3779B9
    q = 6 + 52 // n
    sum = (q * delta) & 0xFFFFFFFF
    
    while sum != 0:
        e = (sum >> 2) & 3
        for p in range(n-1, 0, -1):
            z = v[p-1]
            v[p] = (v[p] - (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (k[(p & 3) ^ e] ^ z)))) & 0xFFFFFFFF
            y = v[p]
        p = 0
        z = v[n-1]
        v[p] = (v[p] - (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (k[(p & 3) ^ e] ^ z)))) & 0xFFFFFFFF
        y = v[p]
        sum = (sum - delta) & 0xFFFFFFFF
    
    return struct.pack(f'<{len(v)}I', *v)

# ---- RC4 Implementation ----
def rc4_decrypt(data, key):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    res = bytearray()
    for b in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        res.append(b ^ S[(S[i] + S[j]) % 256])
    return bytes(res)

# ---- Entropy ----
def get_entropy(data):
    if not data: return 0
    size = len(data)
    counts = [0] * 256
    for b in data: counts[b] += 1
    entropy = 0
    for c in counts:
        if c > 0:
            p = c / size
            entropy -= p * math.log2(p)
    return entropy

def brute_force(filename):
    print(f"Attacking {filename}...")
    with open(filename, "rb") as f:
        data = f.read()
    
    # Keys dictionary
    keys = [
        b"com.mobile.legends",
        b"mobilelegends",
        b"MobileLegends",
        b"mlbb",
        b"MobaLegends",
        b"Unity",
        b"BytePlus",
        b"moonton",
        b"Moonton",
        b"639019186883097210", # Build Date
        b"123456",
        b"android",
        b"Android",
        b"GlobalGameManagers",
        b"Resources",
        b"Migu",
        b"LuaJIT"
    ]
    
    # Try XXTEA
    print("--- Trying XXTEA ---")
    pad_len = (4 - (len(data) % 4)) % 4
    data_padded = data + b'\0'*pad_len
    
    for k in keys:
        try:
            res = xxtea_decrypt(data_padded, k)
            if res:
                ent = get_entropy(res)
                # print(f"Key: {k}, Entropy: {ent:.4f}")
                if ent < 7.5:
                    print(f"[!] SUCCESS? XXTEA Key: {k}, Entropy: {ent:.4f}")
                    with open(f"decrypted_xxtea_{k.decode('utf-8')}.bin", "wb") as f:
                        f.write(res)
        except Exception as e:
            pass

    # Try RC4
    print("--- Trying RC4 ---")
    for k in keys:
        try:
            res = rc4_decrypt(data, k)
            ent = get_entropy(res)
            # RC4 usually doesn't reduce entropy much unless it's perfect, but let's check.
            if ent < 7.5:
                print(f"[!] SUCCESS? RC4 Key: {k}, Entropy: {ent:.4f}")
        except: pass

    print("Finished Brute Force.")

if __name__ == "__main__":
    brute_force(sys.argv[1])
