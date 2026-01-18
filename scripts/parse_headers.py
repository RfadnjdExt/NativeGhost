import sys
import struct

def parse_phdrs(filename):
    print(f"Parsing Phdrs for {filename}...")
    with open(filename, "rb") as f:
        data = f.read()

    # Elf Header
    e_phoff = struct.unpack("<Q", data[32:40])[0]
    e_phentsize = struct.unpack("<H", data[54:56])[0]
    e_phnum = struct.unpack("<H", data[56:58])[0]
    
    print(f"File Size: {hex(len(data))}")
    print(f"Phdrs at {hex(e_phoff)}, Count {e_phnum}")
    
    print("Type\tOffset\t\tVAddr\t\tFileSz\t\tMemSz")
    
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        # p_type(4), p_flags(4), p_offset(8), p_vaddr(8), p_paddr(8), p_filesz(8), p_memsz(8), p_align(8)
        p_type = struct.unpack("<I", data[off:off+4])[0]
        p_offset = struct.unpack("<Q", data[off+8:off+16])[0]
        p_vaddr = struct.unpack("<Q", data[off+16:off+24])[0]
        p_filesz = struct.unpack("<Q", data[off+32:off+40])[0]
        p_memsz = struct.unpack("<Q", data[off+40:off+48])[0]
        
        type_str = hex(p_type)
        if p_type == 1: type_str = "LOAD"
        elif p_type == 2: type_str = "DYNAMIC"
        
        print(f"{type_str}\t{hex(p_offset)}\t{hex(p_vaddr)}\t{hex(p_filesz)}\t{hex(p_memsz)}")

if __name__ == "__main__":
    parse_phdrs(sys.argv[1])
