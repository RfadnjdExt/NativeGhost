import sys
import struct

def scan_relocs(filename, start_addr, end_addr):
    print(f"Scanning Relocations targeting {hex(start_addr)} - {hex(end_addr)}...")
    with open(filename, "rb") as f:
        data = f.read()

    # Elf Header parsing (Reuse logic)
    e_shoff = struct.unpack("<Q", data[40:48])[0]
    e_shentsize = struct.unpack("<H", data[58:60])[0]
    e_shnum = struct.unpack("<H", data[60:62])[0]
    
    SHT_RELA = 4
    
    rela_sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_type = struct.unpack("<I", data[off+4:off+8])[0]
        sh_offset = struct.unpack("<Q", data[off+24:off+32])[0]
        sh_size = struct.unpack("<Q", data[off+32:off+40])[0]
        
        if sh_type == SHT_RELA:
            rela_sections.append((sh_offset, sh_size))
            
    # Parse Relocations
    # Entry: r_offset(8), r_info(8), r_addend(8)
    
    found_count = 0
    for r_sec_off, r_sec_sz in rela_sections:
        num = r_sec_sz // 24
        for i in range(num):
            entry = r_sec_off + i * 24
            r_offset = struct.unpack("<Q", data[entry:entry+8])[0]
            r_info = struct.unpack("<Q", data[entry+8:entry+16])[0]
            r_addend = struct.unpack("<q", data[entry+16:entry+24])[0] # Signed int64
            
            if start_addr <= r_offset < end_addr:
                print(f"Reloc at {hex(r_offset)}: Addend = {hex(r_addend)}")
                found_count += 1
                
    if found_count == 0:
        print("[-] No relocations found for this range.")
    else:
        print(f"[+] Found {found_count} relocations.")

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python scan_relocs.py <file> <start_hex> <end_hex>")
    else:
        scan_relocs(sys.argv[1], int(sys.argv[2], 16), int(sys.argv[3], 16))
