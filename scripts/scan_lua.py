import sys
import os

def scan_for_lua(filename):
    print(f"Scanning {filename} for Lua Bytecode...")
    try:
        with open(filename, "rb") as f:
            data = f.read()
    except Exception as e:
        print(f"Error: {e}")
        return

    # Lua 5.1/5.2/5.3/5.4/Luajit Signature
    # Standard: 1B 4C 75 61 (\x1bLua)
    # LuaJIT: 1B 4C 4A (.\x1bLJ) or similar.
    
    sigs = [
        (b"\x1bLua", "Standard Lua"),
        (b"\x1bLJ", "LuaJIT")
    ]
    
    found = False
    for sig, name in sigs:
        count = data.count(sig)
        if count > 0:
            print(f"[+] Found {count} {name} chunks in {os.path.basename(filename)}")
            found = True
            
            # Print offsets of first 5
            start = 0
            for i in range(min(5, count)):
                off = data.find(sig, start)
                print(f"    Offset: {hex(off)}")
                start = off + 1

    if not found:
        print("[-] No Lua signatures found.")

def main():
    target = sys.argv[1]
    if os.path.isfile(target):
        scan_for_lua(target)
    elif os.path.isdir(target):
        for root, dirs, files in os.walk(target):
            for file in files:
                scan_for_lua(os.path.join(root, file))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scan_lua.py <file_or_dir>")
    else:
        main()
