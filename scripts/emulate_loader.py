import sys
from unicorn import *
from unicorn.arm64_const import *
import struct

# Layout
BASE_ADDR = 0x400000 # Standard executable Load address (approx)
STACK_ADDR = 0x80000000
STACK_SIZE = 0x200000
HEAP_ADDR  = 0x90000000 # Memory allocator base
HEAP_PTR   = HEAP_ADDR

MAGIC_BASE = 0xF0000000 # Fake addresses for imports

imports_map = {} # addr -> name
magic_map = {}   # magic -> name

def load_imports_map(filename):
    print("Loading Imports Map...")
    with open(filename, "r") as f:
        for line in f:
            line = line.strip()
            if not line: continue
            parts = line.split('=')
            offset = int(parts[0], 16)
            name = parts[1]
            imports_map[offset] = name

# Python Implementations of OS Functions
# Lean Emulation Support
def setup_jni_env(uc, base_addr):
    # JNIEnv is a pointer to a pointer to a function table.
    # We allocate space for JNIEnv* -> JNINativeInterface* -> [Functions]
    
    # Structure:
    # [0x1000]: Pointer to 0x2000 (The JNINativeInterface*)
    # [0x2000]: [FuncPtr1, FuncPtr2, FuncPtr3...]
    
    env_ptr = base_addr
    interface_ptr = base_addr + 0x1000
    functions_base = base_addr + 0x2000
    
    # Write JNIEnv*
    uc.mem_write(env_ptr, struct.pack('<Q', interface_ptr))
    
    # Write Function Pointers (Mock generic hooks)
    # 300 JNI functions is enough space
    for i in range(300):
        # We point them to a MAGIC address that we hook
        # MAGIC_BASE is F0000000. 
        # Let's use F1000000 for JNI
        uc.mem_write(interface_ptr + (i*8), struct.pack('<Q', 0xF1000000 + (i*4)))
        
    return env_ptr

# ---- Helpers ----
def read_string(uc, ptr):
    try:
        # Read up to 256 bytes
        s = uc.mem_read(ptr, 256).split(b'\0')[0].decode('utf-8', errors='ignore')
        return s
    except:
        return f"(invalid_ptr_{hex(ptr)})"

# ---- Advanced Mocks ----
def hook_code_generic(uc, address, size, user_data):
    global HEAP_PTR
    
    if address in magic_map:
        name = magic_map[address]
        # print(f"[Import] Calling {name}")
        
        # Registers
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        x2 = uc.reg_read(UC_ARM64_REG_X2)
        
        ret_val = 0
        
        # --- Memory ---
        if "malloc" in name or "calloc" in name:
            size_arg = x0
            if "calloc" in name: size_arg = x0 * x1
            if size_arg == 0: size_arg = 64
            
            res = HEAP_PTR
            if size_arg % 8 != 0: size_arg += (8 - (size_arg % 8))
            HEAP_PTR += size_arg
            # print(f"    -> Malloc({size_arg}) = {hex(res)}")
            ret_val = res
            
        elif "free" in name:
            pass 

        # --- Strings / Logging ---
        elif "log" in name or "printf" in name:
            # syslog(prio, fmt, ...) -> X1 is fmt
            # vfprintf(fp, fmt, args) -> X1 is fmt
            # __android_log_print(prio, tag, fmt) -> X2 is fmt
            
            fmt_str = ""
            if "android_log" in name:
                tag = read_string(uc, x1)
                fmt = read_string(uc, x2)
                fmt_str = f"[{tag}] {fmt}"
            elif "syslog" in name:
                fmt_str = read_string(uc, x1) # X0=priority, X1=fmt
                # check if X1 is actually just an int code? 
                # Syslog signature: void syslog(int priority, const char *format, ...);
            elif "fprintf" in name:
                fmt_str = read_string(uc, x1) # X0=FILE*, X1=fmt
                
            print(f"[LOG] {name}: {fmt_str}")
                
        elif "vasprintf" in name:
            # int vasprintf(char **strp, const char *fmt, va_list ap);
            # We need to allocate memory for the string and put it in *strp (X0)
            # Just return a dummy string pointer
            ptr = HEAP_PTR
            HEAP_PTR += 64
            uc.mem_write(ptr, b"SimulatedString\0")
            
            # Write ptr to *strp
            uc.mem_write(x0, struct.pack('<Q', ptr))
            ret_val = 15 # length
            
        # --- Threading ---
        elif "pthread_mutex" in name:
            # pthread_mutex_lock(mutex)
            # Return 0 = Success
            ret_val = 0
            
        elif "pthread_create" in name:
            print("[!] Thread creation requested! (Ignoring)")
            ret_val = 0
            
        # --- System ---
        elif "abort" in name:
            print("[!] LIBRARY CALLED ABORT! (Suicide intercepted)")
            # We want to stop emulation to inspect, or return?
            # If we return, it might crash immediately again.
            # Let's stop.
            uc.emu_stop()
            return

        # Return simulation
        uc.reg_write(UC_ARM64_REG_X0, ret_val)
        lr = uc.reg_read(UC_ARM64_REG_LR)
        uc.reg_write(UC_ARM64_REG_PC, lr)
        
    elif address >= 0xF1000000 and address < 0xF2000000:
        idx = (address - 0xF1000000) // 4
        # JNI Call
        x0=uc.reg_read(UC_ARM64_REG_X0)
        x1=uc.reg_read(UC_ARM64_REG_X1)
        x2=uc.reg_read(UC_ARM64_REG_X2)
        print(f"[JNI] Call Function #{idx} (Args: {hex(x0)}, {hex(x1)}, {hex(x2)})")
        
        uc.reg_write(UC_ARM64_REG_X0, 0) # Return Success
        lr = uc.reg_read(UC_ARM64_REG_LR)
        uc.reg_write(UC_ARM64_REG_PC, lr)

def hook_unmapped(uc, access, address, size, value, user_data):
    # print(f"[!] Unmapped memory access at {hex(address)}")
    try:
        base = address & ~0xFFF
        # print(f"    -> Auto-mapping 4KB at {hex(base)}")
        uc.mem_map(base, 0x1000)
        return True 
    except:
        return False

def dump_strings(uc, start, size):
    print("--- Heap String Dump ---")
    try:
        data = uc.mem_read(start, size)
        # Filter printable
        current_str = ""
        for b in data:
            if 32 <= b <= 126:
                current_str += chr(b)
            else:
                if len(current_str) > 4:
                    print(f"Heap String: {current_str}")
                current_str = ""
    except: pass

def run_loader(lib_file, imports_file, entry_offset):
    load_imports_map(imports_file)
    
    with open(lib_file, "rb") as f:
        code = f.read()
    
    print(f"Code Size: {hex(len(code))}")
    
    mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    
    # 1. Map LOAD Segment
    # We load at 0x400000 (standard safe base)
    BASE = 0x400000
    # Align size to 1MB to be safe
    map_size = (len(code) + 0x100000) & ~0xFFFFF
    if map_size < 0x2000000: map_size = 0x2000000 # Min 32MB
    
    print(f"Mapping Code at {hex(BASE)} - {hex(BASE + map_size)}")
    mu.mem_map(BASE, map_size)
    mu.mem_write(BASE, code)
    
    # 2. Map Stack
    mu.mem_map(STACK_ADDR, STACK_SIZE)
    mu.reg_write(UC_ARM64_REG_SP, STACK_ADDR + STACK_SIZE)
    
    # 3. Map Trampolines (Magic)
    mu.mem_map(MAGIC_BASE, 0x100000) # 1MB
    
    # 4. Patch GOT
    print("Patching GOT...")
    magic_counter = MAGIC_BASE
    
    # Verify mapping
    # mu.mem_write(BASE + 0x988ca8, b'test') # Test write
    
    for off, name in imports_map.items():
        # GOT Entry Address = BASE + FileOffset (Assuming FileOffset == VirtualOffset)
        target_addr = BASE + off
        
        # Debug first one
        if magic_counter == MAGIC_BASE:
            print(f"Writing first patch to {hex(target_addr)} -> {hex(magic_counter)}")
            
        try:
            mu.mem_write(target_addr, struct.pack('<Q', magic_counter))
            magic_map[magic_counter] = name
            magic_counter += 4
        except UcError as e:
            print(f"Failed to write GOT at {hex(target_addr)} (Offset {hex(off)}): {e}")
            return
        
    # Setup Mocks
    global HEAP_PTR
    HEAP_PTR = BASE + map_size + 0x10000 # Heap after code
    # We need to map heap? mem_map above covers 32MB. 
    # If code is 10MB, we have 22MB heap space inside the first map.
    # Safe.
    
    jni_env = setup_jni_env(mu, BASE + map_size - 0x100000) # Put JNI Env at end of map
    
    real_entry = BASE + entry_offset

    real_entry = BASE + entry_offset

    # Hooks
    mu.hook_add(UC_HOOK_CODE, hook_code_generic)
    mu.hook_add(UC_HOOK_MEM_UNMAPPED, hook_unmapped)

    # Start
    print(f"Calling JNI_OnLoad at {hex(real_entry)}...")
    mu.reg_write(UC_ARM64_REG_X0, jni_env) # JavaVM*
    mu.reg_write(UC_ARM64_REG_X1, 0)
    mu.reg_write(UC_ARM64_REG_LR, MAGIC_BASE)
    
    try:
        mu.emu_start(real_entry, MAGIC_BASE, 0, 200000) # 200k instructions
    except UcError as e:
        print(f"Emulation Stop: {e}")
        
    # Dump Heap
    # Heap started at 0x2000000? No, HEAP_PTR started at BASE + map_size
    # But earlier I initialized HEAP_PTR = 0x2000000 (wait, line 223 says BASE + ...)
    # Let's just dump the dynamic area 0x2000000 -> 0x3000000
    dump_strings(mu, 0x2000000, 0x100000)

if __name__ == "__main__":
    # 0x46d37c is the First Init Function from DT_INIT_ARRAY
    run_loader("extracted_apk/lib/arm64-v8a/libbyteplusaudio.so", "imports_map.txt", 0x46d37c)
