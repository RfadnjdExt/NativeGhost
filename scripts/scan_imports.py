import sys
import struct

def scan_imports(filename):
    print(f"Scanning {filename} for Imports (Relocations)...")
    try:
        with open(filename, "rb") as f:
            data = f.read()
    except Exception as e:
        print(f"Error: {e}")
        return

    if data[:4] != b'\x7fELF':
        print("Not an ELF file.")
        return

    # Helper to read types
    def u64(off): return struct.unpack("<Q", data[off:off+8])[0]
    def u32(off): return struct.unpack("<I", data[off:off+4])[0]
    def u16(off): return struct.unpack("<H", data[off:off+2])[0]

    # Parse headers
    e_shoff = u64(40)
    e_shentsize = u16(58)
    e_shnum = u16(60)

    SHT_RELA = 4
    SHT_DYNSYM = 11
    SHT_STRTAB = 3

    dynsym_off = 0
    strtab_off = 0
    rela_dyn_off = 0
    rela_dyn_sz = 0
    rela_plt_off = 0
    rela_plt_sz = 0

    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_type = u32(off+4)
        sh_offset = u64(off+24)
        sh_size = u64(off+32)
        sh_name_idx = u32(off) # Index into shstrtab, we skip name check for now

        if sh_type == SHT_DYNSYM:
            dynsym_off = sh_offset
        elif sh_type == SHT_STRTAB:
             # Heuristic: The largest strtab is usually the one for dynsym
             if sh_size > 5000:
                 strtab_off = sh_offset
        elif sh_type == SHT_RELA:
            # We have multiple RELA sections (.rela.dyn, .rela.plt)
            # We just want to process all of them.
            # But usually we process them separately?
            # Let's just store the largest ones.
            if sh_size > rela_dyn_sz:
                # Assuming this is the main one or we list all?
                # Let's collect them
                pass

    # Re-scan to catch all RELA sections
    rela_sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_type = u32(off+4)
        sh_offset = u64(off+24)
        sh_size = u64(off+32)
        if sh_type == SHT_RELA:
            rela_sections.append((sh_offset, sh_size))

    if dynsym_off == 0 or strtab_off == 0:
        print("[-] Dynsym/Strtab not found.")
        return

    print(f"Parsing {len(rela_sections)} Relocation Sections...")

    # R_AARCH64_GLOB_DAT = 1025
    # R_AARCH64_JUMP_SLOT = 1026
    # Info = (sym_idx << 32) | type
    
    imports = {}

    for (r_off, r_sz) in rela_sections:
        num_entries = r_sz // 24 # Elf64_Rela is 24 bytes
        for i in range(num_entries):
            entry = r_off + i * 24
            r_offset = u64(entry) # Address to apply relocation
            r_info = u64(entry+8)
            r_addend = u64(entry+16)
            
            r_type = r_info & 0xFFFFFFFF
            r_sym = r_info >> 32
            
            # Get Symbol Name
            sym_entry = dynsym_off + r_sym * 24
            st_name = u32(sym_entry)
            
            name_off = strtab_off + st_name
            end = data.find(b'\0', name_off)
            name = data[name_off:end].decode('utf-8', errors='ignore')
            
            if name:
                # We save where this import is located (GOT address)
                # In simulation, when code reads/jumps to r_offset, it expects the address of 'name'
                imports[r_offset] = name
                # print(f"Import: {name} at GOT {hex(r_offset)}")

    print(f"[+] Found {len(imports)} Imported Symbols.")
    print("--- Top 20 Imports ---")
    sorted_imps = sorted(imports.items(), key=lambda x: x[0])
    for off, name in sorted_imps[:20]:
         print(f"{hex(off)} -> {name}")
    
    # Save full map for the emulator
    with open("imports_map.txt", "w") as f:
        for off, name in sorted_imps:
            f.write(f"{hex(off)}={name}\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scan_imports.py <file>")
    else:
        scan_imports(sys.argv[1])
