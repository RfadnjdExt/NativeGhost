import sys
import struct
from capstone import *
from capstone.arm64 import *

def get_string_offset(data, target_str):
    offset = data.find(target_str.encode('utf-8'))
    if offset != -1:
        print(f"[+] Found string '{target_str}' at file offset: {hex(offset)}")
        return offset
    return None

def analyze_xrefs(filename, target_str):
    print(f"Analyzing {filename} for XREFs to '{target_str}'...")
    
    with open(filename, "rb") as f:
        data = f.read()

    # 1. Find the String
    str_offset = get_string_offset(data, target_str)
    if str_offset is None:
        print("[-] String not found.")
        return

    # In ELF, virtual address != file offset. 
    # We need to parse headers to map File Offset -> Virtual Address (VA).
    # For shared libs (.so), base is usually 0, but sections are loaded at offsets.
    # Simple Heuristic: If it's a standard Android SO, VAs in .text often match file offsets 
    # or follow a linear mapping.
    # Let's assume File Offset ~ Virtual Address for the raw analysis calculation 
    # unless we parse PHDRs nicely.
    
    # Actually, ARM64 `ADRP` works on Page Aligned addresses.
    # We need a semblance of base address. 
    # Let's find the ELF Load segments.
    
    # Quick dirty ELF parser for Load segments
    # e_phoff is at 0x20 in 64-bit ELF.
    e_phoff = struct.unpack("<Q", data[32:40])[0]
    e_phentsize = struct.unpack("<H", data[54:56])[0]
    e_phnum = struct.unpack("<H", data[56:58])[0]
    
    load_segments = []
    
    print(f"Parsing {e_phnum} Load Segments...")
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        # p_type(4), p_flags(4), p_offset(8), p_vaddr(8), ...
        p_type = struct.unpack("<I", data[off:off+4])[0]
        if p_type == 1: # PT_LOAD
            p_offset = struct.unpack("<Q", data[off+8:off+16])[0]
            p_vaddr = struct.unpack("<Q", data[off+16:off+24])[0]
            p_filesz = struct.unpack("<Q", data[off+32:off+40])[0]
            p_flags = struct.unpack("<I", data[off+4:off+8])[0] # R/W/X
            
            load_segments.append({
                "offset": p_offset,
                "vaddr": p_vaddr,
                "size": p_filesz,
                "flags": p_flags
            })
            # print(f"  Segment: Offset={hex(p_offset)} Vaddr={hex(p_vaddr)} Size={hex(p_filesz)} Flags={p_flags}")

    # Helper to convert Offset <-> VA
    def offset_to_va(off):
        for s in load_segments:
            if s["offset"] <= off < s["offset"] + s["size"]:
                return s["vaddr"] + (off - s["offset"])
        return off # Fallback

    def va_to_offset(va):
        for s in load_segments:
            if s["vaddr"] <= va < s["vaddr"] + s["size"]:
                return s["offset"] + (va - s["vaddr"])
        return None

    str_va = offset_to_va(str_offset)
    print(f"[+] String VA: {hex(str_va)}")

    # 2. Disassemble Code Sections (Executable Segments)
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True # Need details for operands

    for seg in load_segments:
        if seg["flags"] & 1: # Executable (PF_X=1)
            print(f"Scanning Executable Segment at {hex(seg['offset'])} (size {hex(seg['size'])})...")
            
            code_data = data[seg["offset"] : seg["offset"] + seg["size"]]
            base_addr = seg["vaddr"]
            
            # Since disassembling 1MB is slow in Python, we do specific scanning?
            # No, `md.disasm` is an iterator, it's okay.
            
            # We look for:
            # ADRP xN, page_of_string
            # ADD  xN, xN, page_offset
            
            # Optimization: We keep track of register values from ADRP
            # If we see `ADRP X0, 0x10000`, we recall X0 holds 0x10000 (page).
            # Then if next is `ADD X0, X0, #0x123`, we calculate target = 0x10000 + 0x123.
            # If target == str_va, we found a reference!
            
            regs = {} # Reg -> Page VA
            
            # We iterate instructions
            count = 0
            for insn in md.disasm(code_data, base_addr):
                # Check for ADRP
                if insn.id == ARM64_INS_ADRP:
                    # Generic logic: ADRP Rd, imm
                    # insn.operands[0] is reg
                    # insn.operands[1] is imm (the page address)
                    op0 = insn.operands[0]
                    op1 = insn.operands[1]
                    if op0.type == ARM64_OP_REG and op1.type == ARM64_OP_IMM:
                        regs[op0.reg] = op1.imm
                
                # Check for ADD (Immediate) which often follows ADRP
                elif (insn.id == ARM64_INS_ADD):
                    # ADD Rd, Rn, imm
                    # If Rn is in our regs map, we resolve the address
                    if len(insn.operands) >= 3:
                        op_dest = insn.operands[0]
                        op_src = insn.operands[1]
                        op_imm = insn.operands[2]
                        
                        if op_src.type == ARM64_OP_REG and op_imm.type == ARM64_OP_IMM:
                             if op_src.reg in regs:
                                 base = regs[op_src.reg]
                                 target = base + op_imm.imm
                                 
                                 # Check match (Exact or close?)
                                 if target == str_va:
                                     print(f"[!] XREF FOUND at {hex(insn.address)}")
                                     print(f"    {insn.mnemonic} {insn.op_str}")
                                     # Dump context (prev 5, next 5 instructions)
                                     # Not easy with iterator, but we can print the current one.
                                     
                                     # Let's print the register being used
                                     print(f"    -> Points to String at {hex(target)}")
                                     return # Found one, that's enough for demo
                    
                # ADR (Load address within minimal range)
                elif insn.id == ARM64_INS_ADR:
                    if len(insn.operands) >= 2:
                        op1 = insn.operands[1]
                        if op1.type == ARM64_OP_IMM:
                            target = op1.imm
                            if target == str_va:
                                print(f"[!] XREF FOUND (ADR) at {hex(insn.address)}")
                                print(f"    {insn.mnemonic} {insn.op_str}")
                                return

                # Reset regs occasionally? No, registers are volatile.
                # A simple "last seen" heuristic is usually fine for ADRP+ADD pairs.
                
                count += 1
                if count % 10000 == 0:
                    pass
                    # print(f"processed {count} instructions...")

    print("[-] No code references found using standard ADRP+ADD/ADR patterns.")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python disasm_xrefs.py <file> <string>")
    else:
        analyze_xrefs(sys.argv[1], sys.argv[2])
