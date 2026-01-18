import sys
import re

def scan_protobuf_signatures(filename):
    print(f"Scanning {filename} for Protobuf artifacts...")
    try:
        with open(filename, "rb") as f:
            data = f.read()
    except Exception as e:
        print(f"Error: {e}")
        return

    # 1. Hardcoded Protobuf Library Strings (Indicators)
    # These are usually present if the standard C++ libprotobuf is linked.
    proto_sig_strings = [
        b"CodedInputStream",
        b"InvalidProtocolBufferException",
        b"Protocol message tag had invalid wire type",
        b"Protocol message end-group tag",
        b"Field numbers cannot be negative",
        b"serialized_proto",
        b"DescriptorProto"
    ]
    
    found_sigs = []
    print("--- Checking for LibProtobuf Signatures ---")
    for sig in proto_sig_strings:
        if sig in data:
            print(f"[+] Found Signature: {sig.decode('utf-8')}")
            found_sigs.append(sig)
    
    if not found_sigs:
        print("[-] No standard LibProtobuf error strings found (Might be Lite version or stripped).")

    # 2. Heuristic API Field Scanner
    # Look for sequences of "variable_name" style strings.
    # Regex: [a-z]+(_[a-z0-9]+)+  (snake_case)
    #        [a-z]+([A-Z][a-z0-9]+)+ (camelCase)
    
    print("\n--- Scanning for Potential API Field Names ---")
    
    # We want strings > 4 chars, composed of a-zA-Z0-9_
    # But specifically looking for API-like patterns.
    
    snake_pattern = re.compile(b"[a-z]{2,}(_[a-z0-9]+)+")
    camel_pattern = re.compile(b"[a-z]{2,}([A-Z][a-z0-9]+)+")
    
    matches_snake = snake_pattern.findall(data)
    matches_camel = camel_pattern.findall(data)
    
    # Filter keywords to avoid noise
    keywords = [b"id", b"role", b"rank", b"name", b"server", b"zone", b"hero", b"skin", b"battle", b"match", b"team", b"win", b"loss", b"duration", b"score"]
    
    unique_fields = set()
    
    for m in matches_snake:
        # m is the full match for findall? 
        # Wait, findall with groups returns tuples. My regex has groups.
        # Let's fix regex to be non-capturing or just simple match.
        pass

    # Better loop using iterator
    for match in re.finditer(b"[a-z]{2,}(?:_[a-z0-9]+)+", data):
        s = match.group()
        if len(s) > 4 and len(s) < 40:
            if any(k in s for k in keywords):
                unique_fields.add(s)

    for match in re.finditer(b"[a-z]{2,}(?:[A-Z][a-z0-9]+)+", data):
        s = match.group()
        if len(s) > 4 and len(s) < 40:
            if any(k in s.lower() for k in keywords):
                unique_fields.add(s)

    # Print top potential fields
    print(f"Found {len(unique_fields)} potential API field names.")
    sorted_fields = sorted(list(unique_fields))
    
    # Print distinct ones
    for f in sorted_fields[:50]:
        try:
            print(f"  Field: {f.decode('utf-8')}")
        except: pass
    
    if len(sorted_fields) > 50:
        print("  ... (truncated)")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scan_protobuf.py <file>")
    else:
        scan_protobuf_signatures(sys.argv[1])
