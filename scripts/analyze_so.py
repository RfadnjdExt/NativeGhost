import sys
import struct
import re
import os

# --- ELF Constants ---
EI_MAG0, EI_MAG1, EI_MAG2, EI_MAG3 = 0, 1, 2, 3
ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3 = 0x7f, 0x45, 0x4c, 0x46 # \x7fELF
PT_LOAD = 1

def parse_elf_header(f):
    f.seek(0)
    e_ident = f.read(16)
    if not (e_ident[EI_MAG0] == ELFMAG0 and e_ident[EI_MAG1] == ELFMAG1 and 
            e_ident[EI_MAG2] == ELFMAG2 and e_ident[EI_MAG3] == ELFMAG3):
        print("Not an ELF file")
        return None

    ei_class = e_ident[4] # 1=32bit, 2=64bit
    ei_data = e_ident[5]  # 1=little, 2=big
    
    endian = "<" if ei_data == 1 else ">"
    
    # Read header based on class
    if ei_class == 2: # 64-bit
        # Elf64_Ehdr: e_ident(16), e_type(2), e_machine(2), e_version(4), e_entry(8),
        # e_phoff(8), e_shoff(8), e_flags(4), e_ehsize(2), e_phentsize(2), e_phnum(2),
        # e_shentsize(2), e_shnum(2), e_shstrndx(2)
        hdr_fmt = endian + "HHIQ3QI6H"
        hdr_size = struct.calcsize(hdr_fmt)
        data = f.read(hdr_size)
        fields = struct.unpack(hdr_fmt, data)
        return {
            "class": 64,
            "endian": endian,
            "e_phoff": fields[4],
            "e_shoff": fields[5],
            "e_phentsize": fields[8],
            "e_phnum": fields[9],
            "e_shentsize": fields[10],
            "e_shnum": fields[11],
            "e_shstrndx": fields[12],
        }
    else: # 32-bit (Simple support)
        hdr_fmt = endian + "HHIIIII6H"
        hdr_size = struct.calcsize(hdr_fmt)
        data = f.read(hdr_size)
        fields = struct.unpack(hdr_fmt, data)
        return {
            "class": 32,
            "endian": endian,
            "e_phoff": fields[4],
            "e_shoff": fields[5],
            "e_phentsize": fields[8],
            "e_phnum": fields[9],
            "e_shentsize": fields[10],
            "e_shnum": fields[11],
            "e_shstrndx": fields[12],
        }

def read_section_headers(f, elf):
    sh_fmt = ""
    if elf["class"] == 64:
        # sh_name(4), sh_type(4), sh_flags(8), sh_addr(8), sh_offset(8), sh_size(8), ...
        sh_fmt = elf["endian"] + "IIQQQQIIQQ"
    else:
        sh_fmt = elf["endian"] + "IIIIIIIIII"
        
    sh_size = struct.calcsize(sh_fmt)
    sections = []
    
    f.seek(elf["e_shoff"])
    for i in range(elf["e_shnum"]):
        data = f.read(sh_size)
        if len(data) < sh_size: break
        s = struct.unpack(sh_fmt, data)
        sections.append({
            "sh_name_idx": s[0],
            "sh_type": s[1],
            "sh_offset": s[4],
            "sh_size": s[5]
        })
    return sections

def get_string_from_table(f, offset):
    cur = f.tell()
    f.seek(offset)
    valid_bytes = b""
    while True:
        b = f.read(1)
        if b == b'\x00' or not b: break
        valid_bytes += b
    f.seek(cur)
    try:
        return valid_bytes.decode('utf-8')
    except:
        return ""

def demangle(name):
    # Very basic Itanium demangler heuristic for common patterns
    # _Z N namespace class method E -> namespace::class::method
    if name.startswith("_Z"):
        # Simplify: just strip _Z and replace known markers
        clean = name[2:]
        # Extract purely alphanumeric parts approx
        parts = re.findall(r"\d+(\w+)", clean)
        if parts:
            return "::".join(parts)
    return name

def analyze(filename):
    print(f"Analyzing {filename}...")
    with open(filename, "rb") as f:
        elf = parse_elf_header(f)
        if not elf: return

        sections = read_section_headers(f, elf)
        
        # 1. Find String Table for Section Names
        shstrtab = sections[elf["e_shstrndx"]]
        section_names = {} # offset -> name
        
        # Read the whole string table
        f.seek(shstrtab["sh_offset"])
        shstrtab_data = f.read(shstrtab["sh_size"])
        
        def get_sec_name(idx):
            end = shstrtab_data.find(b'\x00', idx)
            if end == -1: return ""
            return shstrtab_data[idx:end].decode('utf-8', 'ignore')

        print(f"Found {len(sections)} sections.")
        
        for i, s in enumerate(sections):
            name = get_sec_name(s["sh_name_idx"])
            s["name"] = name
            # print(f"Section {i}: {name} (Size: {s['sh_size']})")

        # 2. Extract Dynamic Strings (.dynstr)
        dynstr_sec = next((s for s in sections if s["name"] == ".dynstr"), None)
        if dynstr_sec:
            print("\n--- extracting .dynstr (Dynamic Symbols) ---")
            f.seek(dynstr_sec["sh_offset"])
            data = f.read(dynstr_sec["sh_size"])
            # Split by null byte
            raw_strs = data.split(b'\x00')
            
            keywords = ["api", "http", "rank", "match", "history", "record"]
            
            for b_s in raw_strs:
                if len(b_s) < 4: continue
                try:
                    s = b_s.decode('utf-8')
                    # Demangle
                    demangled = demangle(s)
                    
                    # Filter for interesting
                    if any(k in s.lower() for k in keywords):
                        print(f"SYMBOL: {s} -> {demangled}")
                except: pass
        else:
            print("No .dynstr section found.")

        # 3. Heuristic XOR Decryption on .rodata
        # Scan .rodata or .data for obfuscated strings
        rodata = next((s for s in sections if s["name"] == ".rodata"), None)
        if rodata:
            print("\n--- XOR Scan on .rodata (Experimental) ---")
            f.seek(rodata["sh_offset"])
            # read first 64KB for speed
            sample_size = min(rodata["sh_size"], 65536) 
            data = f.read(sample_size)
            
            # Try keys 1..255
            for key in range(1, 256):
                # Simple single-byte XOR
                xored = bytes([b ^ key for b in data])
                
                # Check if "http" or "api." exists in xored result
                try:
                    # Look for signatures
                    if b"http://" in xored or b"https://" in xored or b"api.mobilelegends" in xored:
                        print(f"[!] Possible XOR Key Found: {key} (Hex: {hex(key)})")
                        # Print context
                        idx = xored.find(b"http")
                        if idx == -1: idx = xored.find(b"api.")
                        snippet = xored[max(0, idx-10):min(len(xored), idx+50)]
                        print(f"    Context: {snippet}")
                except: pass
        else:
            print("No .rodata section found.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python analyze_so.py <file>")
    else:
        analyze(sys.argv[1])
