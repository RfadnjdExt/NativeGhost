
from capstone import *
import struct

def find_pattern():
    print("Loading memory_dump.bin...")
    try:
        with open("memory_dump.bin", "rb") as f:
            data = f.read()
    except FileNotFoundError:
        print("memory_dump.bin not found")
        return

    BASE = 0x400000
    
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True # Enable details for operands
    
    # We scan for `ldr xA, [x0]` followed by `ldr xB, [xA, #48]`
    # And typically `blr xB`.
    
    print("Disassembling and scanning...")
    
    # Iterate in chunks to avoid memory issues?
    # No, decode loop on buffer is okay.
    
    last_ldr_vm = None # (addr, reg_dest)
    
    # We iterate instructions.
    # Note: Scanning 100MB is fast in C, slow in Python.
    # Check length of data
    print(f"Data size: {len(data)}")
    
    for i in md.disasm(data, BASE):
        if i.mnemonic == 'ldr':
            # Check operands
            # Op[0] = Reg Dest
            # Op[1] = Memory
            if len(i.operands) == 2 and i.operands[1].type == ARM64_OP_MEM:
                mem = i.operands[1].mem
                
                # Check 1: ldr x?, [x0]
                # mem.base == X0 (ARM64_REG_X0 = 199?)
                # We can check register name or ID.
                if i.reg_name(mem.base) == 'x0' and mem.disp == 0:
                    dest_reg = i.reg_name(i.operands[0].reg)
                    last_ldr_vm = (i.address, dest_reg)
                    
                # Check 2: ldr x?, [xA, #48]
                elif last_ldr_vm and i.reg_name(mem.base) == last_ldr_vm[1] and mem.disp == 48:
                    print(f"CANDIDATE JNI_OnLoad pattern at {hex(last_ldr_vm[0])} -> {hex(i.address)}")
                    # Reset
                    last_ldr_vm = None
                    
        # Reset if too far? 
        # Usually consecutive.
        if last_ldr_vm and (i.address - last_ldr_vm[0] > 64): # Allow 16 instructions gap
             last_ldr_vm = None
    
if __name__ == "__main__":
    find_pattern()
