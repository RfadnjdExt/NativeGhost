import sys
import struct

def scan_dynamic(filename):
    print(f"Scanning Dynamic Section of {filename}...")
    with open(filename, "rb") as f:
        data = f.read()
        
    e_shoff = struct.unpack("<Q", data[40:48])[0]
    e_shentsize = struct.unpack("<H", data[58:60])[0]
    e_shnum = struct.unpack("<H", data[60:62])[0]
    
    SHT_DYNAMIC = 6
    dyn_off = 0
    dyn_sz = 0
    
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_type = struct.unpack("<I", data[off+4:off+8])[0]
        sh_offset = struct.unpack("<Q", data[off+24:off+32])[0]
        sh_size = struct.unpack("<Q", data[off+32:off+40])[0]
        
        if sh_type == SHT_DYNAMIC:
            dyn_off = sh_offset
            dyn_sz = sh_size
            break
            
    if dyn_off == 0:
        print("[-] Dynamic section not found.")
        return

    print(f"Dynamic Section at {hex(dyn_off)}, Size {hex(dyn_sz)}")
    
    # Parse Tags
    # Elf64_Dyn: d_tag(8), d_val(8)
    # DT_INIT = 12
    # DT_FINI = 13
    # DT_INIT_ARRAY = 25
    # DT_INIT_ARRAYSZ = 27
    
    tags = {
        12: "DT_INIT",
        13: "DT_FINI",
        25: "DT_INIT_ARRAY",
        27: "DT_INIT_ARRAYSZ"
    }
    
    num_entries = dyn_sz // 16
    for i in range(num_entries):
        entry_off = dyn_off + i * 16
        d_tag = struct.unpack("<Q", data[entry_off:entry_off+8])[0]
        d_val = struct.unpack("<Q", data[entry_off+8:entry_off+16])[0]
        
        if d_tag in tags:
            print(f"[+] Found {tags[d_tag]}: {hex(d_val)}")
            
        if d_tag == 0: break # NULL tag
        
if __name__ == "__main__":
    scan_dynamic(sys.argv[1])
