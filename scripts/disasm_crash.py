from capstone import *
import sys

def disasm_loop():
    if len(sys.argv) < 2:
        print("Usage: python disasm_crash.py <hex_addr>")
        return

    # Rust Base = 0x400000
    BASE = 0x400000
    
    try:
        Target = int(sys.argv[1], 16)
    except ValueError:
        print("Invalid address format")
        return

    print(f"Target logic: {hex(Target)}")
    
    # Calculate offset in dump
    Offset = Target - BASE
    if Offset < 0:
        print("Address below base!")
        return
        
    print(f"Loading memory_dump.bin...")
    try:
        with open("memory_dump.bin", "rb") as f:
            data = f.read()
    except FileNotFoundError:
        print("memory_dump.bin not found")
        return
        
    if Offset >= len(data):
        print("Address beyond dump size!")
        return
        
    # Read 0x100 bytes
    size = 0x100
    code = data[Offset : Offset + size]
    
    print(f"Disassembling at {hex(Target)} (Offset {hex(Offset)})...")
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    
    for i in md.disasm(code, Target):
        print(f"   {hex(i.address)}: {i.mnemonic}\t{i.op_str}")

if __name__ == "__main__":
    disasm_loop()
