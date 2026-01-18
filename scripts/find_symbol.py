
import sys

def find_symbol():
    print("Loading memory_dump.bin...")
    try:
        with open("memory_dump.bin", "rb") as f:
            data = f.read()
    except FileNotFoundError:
        print("memory_dump.bin not found")
        return

    # Search for string "JNI_OnLoad"
    s = b"JNI_OnLoad\x00"
    idx = data.find(s)
    if idx == -1:
        print("String 'JNI_OnLoad' not found in dump")
        return
        
    print(f"Found 'JNI_OnLoad' string at Offset {hex(idx)}")
    
    # Check if this offset is close to .dynstr
    # Now look for references to this offset in .dynsym?
    # .dynsym entry: [NameOffset(4)] [Info(1)] [Other(1)] [Shndx(2)] [Value(8)] [Size(8)]
    # We need to find `NameOffset` that matches `idx - DYNSTR_BASE`.
    # But we don't know DYNSTR_BASE cleanly from dump without parsing ELF headers.
    
    # However, ELF headers ARE in the dump (at 0).
    # We can use pyelftools or simple struct parsing to find sections.
    # But wait, memory_dump.bin IS the loaded image. Headers might be at 0.
    
    # Let's try to parse ELF header at 0.
    if data[0:4] != b'\x7fELF':
        print("Header is not ELF. Maybe dump starts at TEXT?")
        # If dump is via `dump_loader.py`, it dumps `uc.mem_read(base, size)`.
        # So it contains whatever was mapped at Base.
        # Usually checking `data[0:4]` works.
    else:
        print("ELF Header found.")
        
    # We can scan the whole file for the pattern of Symbol Entry that has Value = FunctionAddress?
    # No, we want the FunctionAddress.
    # We have the Name Offset.
    
    # Alternatively, scan for `dlsym` usage? No.
    
    # Just print the offset of the string.
    # If we have the string offset, we can manually look around the DynSym table if we knew where it is.
    
    # Let's try to use `elftools` if installed? user might have it?
    try:
        from elftools.elf.elffile import ELFFile
        from io import BytesIO
        print("Using pyelftools...")
        stream = BytesIO(data)
        elf = ELFFile(stream)
        
        symtab = elf.get_section_by_name('.dynsym')
        if not symtab:
            print("No .dynsym section")
        else:
            print("Scanning .dynsym...")
            for sym in symtab.iter_symbols():
                if sym.name == 'JNI_OnLoad':
                    print(f"JNI_OnLoad Value: {hex(sym['st_value'])}")
                    return
    except ImportError:
        print("pyelftools not installed.")
        # Fallback?
        pass

if __name__ == "__main__":
    find_symbol()
