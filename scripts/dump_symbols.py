
import sys
import struct

def dump_symbols(path):
    with open(path, 'rb') as f:
        data = f.read()

    # ELF Header (64-bit)
    if data[0:4] != b'\x7fELF':
        print("Not an ELF file")
        return

    # Find Section Headers
    shoff, = struct.unpack('<Q', data[40:48])
    shnum, = struct.unpack('<H', data[60:62])
    shstrndx, = struct.unpack('<H', data[62:64])

    # Parse Section Headers
    sections = []
    for i in range(shnum):
        off = shoff + i * 64
        sh = data[off:off+64]
        # sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize
        parts = struct.unpack('<IIQQQQIIQQ', sh)
        sections.append(parts)

    # Get .shstrtab
    shstr_sec = sections[shstrndx]
    shstr_off = shstr_sec[4]
    shstr_data = data[shstr_off : shstr_off + shstr_sec[5]]

    def get_str(idx):
        end = shstr_data.find(b'\0', idx)
        return shstr_data[idx:end].decode('utf-8')

    dynsym_sec = None
    dynstr_sec = None

    for sec in sections:
        name = get_str(sec[0])
        if name == '.dynsym':
            dynsym_sec = sec
        elif name == '.dynstr':
            dynstr_sec = sec

    if not dynsym_sec or not dynstr_sec:
        print("DynSym or DynStr not found")
        return

    # Parse DynSym
    sym_off = dynsym_sec[4]
    sym_size = dynsym_sec[5]
    sym_ent_size = dynsym_sec[9] # 24
    count = sym_size // 24
    
    str_off = dynstr_sec[4]
    str_data = data[str_off : str_off + dynstr_sec[5]]

    def get_dynstr(idx):
        end = str_data.find(b'\0', idx)
        return str_data[idx:end].decode('utf-8')

    print(f"Parsing {count} symbols...")
    for i in range(count):
        off = sym_off + i * 24
        # st_name(4), st_info(1), st_other(1), st_shndx(2), st_value(8), st_size(8)
        chunk = data[off:off+24]
        st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack('<IBBHQQ', chunk)
        
        name = get_dynstr(st_name)
        if name and st_value > 0:
            if "UpdateLoginToken" in name or "Sign" in name or "Token" in name:
                print(f"{name}: {hex(st_value)}")

if __name__ == '__main__':
    dump_symbols(r'extracted_apk\lib\arm64-v8a\libbyteplusaudio.so')
