import sys
from capstone import *

def verify_code(filename, offset):
    print(f"Verifying code at offset {hex(offset)}...")
    with open(filename, "rb") as f:
        f.seek(offset)
        code = f.read(32) # Read 8 instructions
        
    print(f"Bytes: {code.hex()}")
    
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    for i in md.disasm(code, offset):
        print(f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}")

if __name__ == "__main__":
    verify_code(sys.argv[1], int(sys.argv[2], 16))
