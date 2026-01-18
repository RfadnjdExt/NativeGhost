import sys
import math

def calculate_entropy(filename):
    print(f"Calculating Entropy for {filename}...")
    with open(filename, "rb") as f:
        data = f.read()
    
    if not data:
        return 0
    
    # Shannon Entropy formula
    entropy = 0
    size = len(data)
    
    counts = [0] * 256
    for b in data:
        counts[b] += 1
        
    for count in counts:
        if count == 0:
            continue
        p = count / size
        entropy -= p * math.log2(p)
        
    print(f"File Size: {size} bytes")
    print(f"Shannon Entropy: {entropy:.4f} bits/byte")
    
    if entropy > 7.95:
        print("-> Verdict: Compressed or Encrypted (AES/Strong)")
    elif entropy > 7.5:
        print("-> Verdict: Packed / High Entropy Binary")
    elif entropy > 6.0:
        print("-> Verdict: Text or Sparse Binary (Likely XOR/Obfuscated)")
    else:
        print("-> Verdict: Low Entropy (Padded/Simple)")

if __name__ == "__main__":
    calculate_entropy(sys.argv[1])
