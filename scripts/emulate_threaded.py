import sys
import struct
from unicorn import *
from unicorn.arm64_const import *

# ---- Constants ----
BASE_ADDR = 0x400000
STACK_BASE = 0x80000000
STACK_SIZE_MAIN = 0x200000
STACK_SIZE_THREAD = 0x100000
MAGIC_BASE = 0xF0000000
HEAP_START = 0x10000000

class Thread:
    def __init__(self, tid, stack_top, entry_point, arg=0):
        self.tid = tid
        self.context = None # Saved Unicorn Context
        self.stack_top = stack_top
        self.entry_point = entry_point
        self.arg = arg
        self.status = "READY" # READY, RUNNING, DEAD
        self.exit_code = 0

class AndroidEmulator:
    def __init__(self, lib_file, imports_file):
        self.lib_file = lib_file
        self.imports_file = imports_file
        self.mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.threads = []
        self.current_thread_idx = -1
        self.imports_map = {}
        self.magic_map = {}
        self.magic_counter = MAGIC_BASE
        self.heap_ptr = HEAP_START
        self.next_tid = 1 # Main is 0

    def load(self):
        # Load Imports
        with open(self.imports_file, "r") as f:
            for line in f:
                parts = line.strip().split('=')
                if len(parts) == 2:
                    self.imports_map[int(parts[0], 16)] = parts[1]
        
        # Load Code
        with open(self.lib_file, "rb") as f:
            code = f.read()
            
        # Map Memory
        self.mu.mem_map(0, 0x10000000) 
        self.mu.mem_write(BASE_ADDR, code)
        self.mu.mem_map(HEAP_START, 0x10000000) # Heap Area (256 MB)
        self.mu.mem_map(STACK_BASE, 0x10000000) 
        self.mu.mem_map(MAGIC_BASE, 0x100000)
        
        # Patch GOT
        print("Patching GOT...")
        for off, name in self.imports_map.items():
            target = BASE_ADDR + off
            self.mu.mem_write(target, struct.pack('<Q', self.magic_counter))
            self.magic_map[self.magic_counter] = name
            self.magic_counter += 4
            
        # Hooks
        self.mu.hook_add(UC_HOOK_CODE, self.hook_magic, begin=MAGIC_BASE, end=MAGIC_BASE+0x100000)
        self.mu.hook_add(UC_HOOK_MEM_UNMAPPED, self.hook_unmapped)
        
        # Setup Main Thread
        self.jni_env = self.setup_jni_env(0x3000000)
        stack_top = STACK_BASE + STACK_SIZE_MAIN
        entry = BASE_ADDR + 0x46d37c 
        
        main_thread = Thread(0, stack_top, entry)
        self.threads.append(main_thread)
        self.current_thread_idx = 0
        
        # Initial Registers
        self.mu.reg_write(UC_ARM64_REG_SP, stack_top)
        self.mu.reg_write(UC_ARM64_REG_X0, self.jni_env) # JavaVM*
        self.mu.reg_write(UC_ARM64_REG_X1, 0)
        self.mu.reg_write(UC_ARM64_REG_PC, entry)
        self.mu.reg_write(UC_ARM64_REG_LR, MAGIC_BASE) 
        
        # Save Initial Context
        main_thread.context = self.mu.context_save()

    def setup_jni_env(self, addr):
        env = addr
        iface = addr + 0x1000
        self.mu.mem_write(env, struct.pack('<Q', iface))
        for i in range(300):
            target = 0xF1000000 + i*4
            self.mu.mem_write(iface + i*8, struct.pack('<Q', target))
        return env

    def dump_state(self, reason):
        print(f"\n[!] EMULATOR EXIT: {reason}")
        print("    Dumping State to 'crash_dump.txt'...")
        with open("crash_dump.txt", "w") as f:
            f.write(f"Reason: {reason}\n")
            f.write(f"Active Thread: {self.current_thread_idx}\n")
            # Dump Regs of current thread
            pc = self.mu.reg_read(UC_ARM64_REG_PC)
            sp = self.mu.reg_read(UC_ARM64_REG_SP)
            lr = self.mu.reg_read(UC_ARM64_REG_LR)
            f.write(f"PC: {hex(pc)}\nSP: {hex(sp)}\nLR: {hex(lr)}\n")
            
            # Dump Threads
            f.write("\nThreads:\n")
            for t in self.threads:
                f.write(f"  T{t.tid}: {t.status} Entry={hex(t.entry_point)}\n")
                
    def dump_state(self, reason):
        print(f"\n[!] EMULATOR EXIT: {reason}")
        print("    Dumping State to 'crash_dump.txt'...")
        with open("crash_dump.txt", "w") as f:
            f.write(f"Reason: {reason}\n")
            f.write(f"Active Thread: {self.current_thread_idx}\n")
            # Dump Regs of current thread
            pc = self.mu.reg_read(UC_ARM64_REG_PC)
            sp = self.mu.reg_read(UC_ARM64_REG_SP)
            lr = self.mu.reg_read(UC_ARM64_REG_LR)
            f.write(f"PC: {hex(pc)}\nSP: {hex(sp)}\nLR: {hex(lr)}\n")
            
            # Dump Threads
            f.write("\nThreads:\n")
            for t in self.threads:
                f.write(f"  T{t.tid}: {t.status} Entry={hex(t.entry_point)}\n")
                
        print("    Dumping Heap Strings to 'heap_strings.txt'...")
        with open("heap_strings.txt", "w", encoding='utf-8') as f:
             try:
                # Scan first 64MB of Heap
                data = self.mu.mem_read(HEAP_START, 0x4000000)
                current = ""
                for b in data:
                    if 32 <= b <= 126:
                        current += chr(b)
                    else:
                        if len(current) > 5:
                            f.write(current + "\n")
                        current = ""
             except Exception as e: 
                f.write(f"Heap read failed: {e}")

    def hook_unmapped(self, uc, access, addr, size, val, data):
        try:
            base = addr & ~0xFFF
            self.mu.mem_map(base, 0x1000)
            return True
        except: return False

    def hook_magic(self, uc, addr, size, data):
        if addr in self.magic_map:
            name = self.magic_map[addr]
            # print(f"[Magic] Hook {name}")
            self.handle_import(name)
        elif addr >= 0xF1000000 and addr < 0xF2000000:
            idx = (addr - 0xF1000000) // 4
            self.handle_jni(idx)
        
        lr = uc.reg_read(UC_ARM64_REG_LR)
        uc.reg_write(UC_ARM64_REG_PC, lr)

    def handle_import(self, name):
        # High verbosity for debugging
        # print(f"[Import] {name}")
        x0 = self.mu.reg_read(UC_ARM64_REG_X0)
        x1 = self.mu.reg_read(UC_ARM64_REG_X1)
        x2 = self.mu.reg_read(UC_ARM64_REG_X2)
        x3 = self.mu.reg_read(UC_ARM64_REG_X3)
        
        ret = 0
        
        if "malloc" in name or "calloc" in name:
            # print(f"[Import] {name}")
            sz = x0
            if "calloc" in name: sz = x0 * x1
            if sz == 0: sz = 64
            ret = self.heap_ptr
            if sz % 8 != 0: sz += (8 - (sz%8))
            self.heap_ptr += sz
            
        elif "pthread_create" in name:
            print(f"[OS] pthread_create! Routine={hex(x2)} Arg={hex(x3)}")
            self.spawn_thread(x2, x3)
            ret = 0 
            
        elif "syslog" in name or "log" in name:
            pass

        elif "__sF" in name:
            # Return pointer to FILE structs
            ret = self.heap_ptr
            self.heap_ptr += 256 # Alloc some space
            
        elif "abort" in name:
            print("[OS] ABORT called!")
            self.mu.emu_stop()
            
        elif "pthread_mutex" in name:
            ret = 0
            
        self.mu.reg_write(UC_ARM64_REG_X0, ret)

    # ... (Mutex Class)
    def handle_jni(self, idx):
        # RegisterNatives is usually index 215 in the function table
        if idx == 215:
            print("[JNI] RegisterNatives called!")
            # Args: X0=Env, X1=Class, X2=MethodsPtr, X3=Count
            methods_ptr = self.mu.reg_read(UC_ARM64_REG_X2)
            count = self.mu.reg_read(UC_ARM64_REG_X3)
            
            print(f"    -> Registering {count} methods from {hex(methods_ptr)}")
            
            # Struct: {char* name, char* sig, void* fnPtr} (size=24 on 64-bit)
            for i in range(count):
                base = methods_ptr + (i * 24)
                name_ptr = struct.unpack('<Q', self.mu.mem_read(base, 8))[0]
                sig_ptr = struct.unpack('<Q', self.mu.mem_read(base+8, 8))[0]
                fn_ptr = struct.unpack('<Q', self.mu.mem_read(base+16, 8))[0]
                
                name = self.read_string(name_ptr)
                sig = self.read_string(sig_ptr)
                
                print(f"    [API] Native Method: {name}{sig} -> {hex(fn_ptr)}")
                
        self.mu.reg_write(UC_ARM64_REG_X0, 0) # Success

    def read_string(self, ptr):
        try:
            return self.mu.mem_read(ptr, 128).split(b'\0')[0].decode('utf-8', errors='ignore')
        except: return "?"

    # ... (Rest of spawn_thread remains similar)
    def spawn_thread(self, entry, arg):
        tid = self.next_tid
        self.next_tid += 1
        
        stack_top = STACK_BASE + STACK_SIZE_MAIN + (tid * STACK_SIZE_THREAD)
        
        t = Thread(tid, stack_top, entry, arg)
        self.threads.append(t)
        
        # Context Clone Strategy
        current_ctx = self.mu.context_save()
        
        self.mu.reg_write(UC_ARM64_REG_PC, entry)
        self.mu.reg_write(UC_ARM64_REG_SP, stack_top)
        self.mu.reg_write(UC_ARM64_REG_X0, arg) 
        self.mu.reg_write(UC_ARM64_REG_LR, MAGIC_BASE) 
        
        t.context = self.mu.context_save()
        print(f"[OS] Created Thread {tid} (Ctx Saved). Queue size: {len(self.threads)}")
        
        self.mu.context_restore(current_ctx)

    def run(self):
        print("Starting Scheduler Loop... (Press Ctrl+C to Stop & Dump)")
        quantum = 500000 # 500k instructions per slice (Fast)
        prev_tid = -1
        
        try:
            while True:
                # Check active threads
                alive = [t for t in self.threads if t.status != "DEAD"]
                if not alive:
                    self.dump_state("All Threads Dead")
                    break
                    
                # Round Robin
                self.current_thread_idx = (self.current_thread_idx + 1) % len(self.threads)
                t = self.threads[self.current_thread_idx]
                
                if t.status == "DEAD": continue
                
                if t.tid != prev_tid:
                    print(f"[Sched] Switch to T{t.tid} (PC={hex(t.entry_point)})") 
                    prev_tid = t.tid
                
                # Restore Context
                self.mu.context_restore(t.context)
                
                # Run Quantum
                try:
                    pc = self.mu.reg_read(UC_ARM64_REG_PC)
                    self.mu.emu_start(pc, MAGIC_BASE + 0x100000, 0, quantum)
                except UcError as e:
                    pass
                
                # Save Context
                t.context = self.mu.context_save()

        except KeyboardInterrupt:
            self.dump_state("User Interrupted")
        except Exception as e:
            self.dump_state(f"Python Exception: {e}")

if __name__ == "__main__":
    emu = AndroidEmulator("extracted_apk/lib/arm64-v8a/libbyteplusaudio.so", "imports_map.txt")
    emu.load()
    emu.run()
