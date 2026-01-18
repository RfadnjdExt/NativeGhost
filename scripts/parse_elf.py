
import struct
import sys

def parse_elf():
    print("Starting parse_elf...")
    try:
        with open("extracted_apk/lib/arm64-v8a/libbyteplusaudio.so", "rb") as f:
            data = f.read()
            print(f"Read {len(data)} bytes")
    except Exception as e:
        print(f"File error: {e}")
        return

    if data[0:4] != b'\x7fELF':
        print("Not ELF")
        return
        
    e_phoff = struct.unpack('<Q', data[0x20:0x28])[0]
    e_phentsize = struct.unpack('<H', data[0x36:0x38])[0]
    e_phnum = struct.unpack('<H', data[0x38:0x3A])[0]
    
    print(f"PH Table @ {hex(e_phoff)}, Count {e_phnum}, Size {e_phentsize}")
    
    dynamic_vaddr = None
    dynamic_size = 0
    dynamic_offset = 0
    
    # helper for vaddr mapping
    def vaddr_to_offset(vaddr):
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            ph = data[off : off + e_phentsize]
            p_type = struct.unpack('<I', ph[0:4])[0]
            if p_type == 1: # PT_LOAD
                p_offset_seg = struct.unpack('<Q', ph[8:16])[0]
                p_vaddr_seg = struct.unpack('<Q', ph[16:24])[0]
                p_memsz_seg = struct.unpack('<Q', ph[32:40])[0]
                
                if p_vaddr_seg <= vaddr < p_vaddr_seg + p_memsz_seg:
                    return vaddr - p_vaddr_seg + p_offset_seg
        return None

    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        ph = data[off : off + e_phentsize]
        p_type = struct.unpack('<I', ph[0:4])[0]
        
        if p_type == 2: # PT_DYNAMIC
            p_offset = struct.unpack('<Q', ph[8:16])[0]
            p_vaddr = struct.unpack('<Q', ph[16:24])[0]
            p_memsz = struct.unpack('<Q', ph[32:40])[0]
            print(f"Found PT_DYNAMIC @ Offset {hex(p_offset)}, Vaddr {hex(p_vaddr)}, Size {hex(p_memsz)}")
            dynamic_vaddr = p_vaddr
            dynamic_size = p_memsz
            dynamic_offset = p_offset 
            break
            
    if dynamic_vaddr is None:
        print("No PT_DYNAMIC found")
        return
        
    # Read Dynamic Table
    dyn_data = data[dynamic_offset : dynamic_offset + dynamic_size]
    
    dt_strtab = None
    dt_symtab = None
    dt_strsz = 0
    dt_syment = 0
    
    num_dyn = len(dyn_data) // 16
    for i in range(num_dyn):
        ent = dyn_data[i*16 : (i+1)*16]
        tag = struct.unpack('<Q', ent[0:8])[0]
        val = struct.unpack('<Q', ent[8:16])[0]
        
        if tag == 5: # DT_STRTAB
            dt_strtab = val
        elif tag == 6: # DT_SYMTAB
            dt_symtab = val
        elif tag == 10: # DT_STRSZ
            dt_strsz = val
        elif tag == 11: # DT_SYMENT
            dt_syment = val
        elif tag == 0: # DT_NULL
            break
            
    print(f"STRTAB {hex(dt_strtab or 0)}, SYMTAB {hex(dt_symtab or 0)}, SZ {dt_strsz}, ENT {dt_syment}")
    
    if not dt_strtab or not dt_symtab:
        print("Missing dynamic tags")
        return
        
    strtab_off = vaddr_to_offset(dt_strtab)
    symtab_off = vaddr_to_offset(dt_symtab)
    
    print(f"Offsets: STRTAB {hex(strtab_off or 0)}, SYMTAB {hex(symtab_off or 0)}")
    
    if strtab_off is None or symtab_off is None:
        print("Could not map VAddrs")
        return

    strtab_blob = data[strtab_off : strtab_off + dt_strsz]
    
    sym_ent_size = dt_syment if dt_syment else 24
    
    print("Scanning dynamic symbols...")
    i = 0
    while True:
        off = symtab_off + i * sym_ent_size
        if off + sym_ent_size > len(data): break
        
        ent = data[off : off + sym_ent_size]
        st_name = struct.unpack('<I', ent[0:4])[0]
        st_value = struct.unpack('<Q', ent[8:16])[0]
        
        if st_name != 0 and st_name < len(strtab_blob):
            name_end = strtab_blob.find(b'\x00', st_name)
            sym_name = strtab_blob[st_name : name_end].decode('utf-8', errors='ignore')
            
            if sym_name == 'JNI_OnLoad':
                print(f"MATCH: JNI_OnLoad @ {hex(st_value)}")
                return
        
        i += 1
        if i > 20000: break
            
    print("JNI_OnLoad not found")

if __name__ == "__main__":
    parse_elf()
