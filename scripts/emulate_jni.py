import sys
from unicorn import *
from unicorn.arm64_const import *

# Memory addresses
BASE_ADDRESS = 0x1000000
STACK_ADDRESS = 0x80000000
STACK_SIZE = 0x100000 # 1MB

def hook_code(uc, address, size, user_data):
    # Print tracing info
    # print(f">>> Tracing instruction at 0x{address:x}, instruction size = {size}")
    pass

def hook_mem_invalid(uc, access, address, size, value, user_data):
    print(f"[!] Invalid Memory Access at 0x{address:x}")
    return False

def emulate_jni(filename, entry_offset):
    print(f"Loading {filename} for Emulation at offset {hex(entry_offset)}...")
    
    try:
        with open(filename, "rb") as f:
            code = f.read()

        # Initialize emulator in ARM64 mode
        mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

        # map 16MB memory for code (should be enough for 10MB lib)
        # Must be aligned to 4KB
        # 16MB = 0x1000000
        MEM_SIZE = 16 * 1024 * 1024
        mu.mem_map(BASE_ADDRESS, MEM_SIZE)

        # Write code to memory
        mu.mem_write(BASE_ADDRESS, code)

        # Map stack
        mu.mem_map(STACK_ADDRESS, STACK_SIZE)

        # Set SP (Stack Pointer) to end of stack
        mu.reg_write(UC_ARM64_REG_SP, STACK_ADDRESS + STACK_SIZE)

        # JNI_OnLoad(JavaVM *vm, void *reserved)
        # X0 = vm (Mock pointer), X1 = reserved (NULL)
        mu.reg_write(UC_ARM64_REG_X0, 0x50000000) # Mock VM address
        mu.reg_write(UC_ARM64_REG_X1, 0x0)
        
        # Add hooks
        mu.hook_add(UC_HOOK_CODE, hook_code)
        mu.hook_add(UC_HOOK_MEM_INVALID, hook_mem_invalid)

        # Calculate Start Address
        start_addr = BASE_ADDRESS + entry_offset
        # Run!
        # Run until crash or 1000 instructions
        print(f"Starting emulation at {hex(start_addr)}...")
        
        mu.emu_start(start_addr, start_addr + 0x10000, 0, 1000) 
        
        print("Emulation finished normally.")

    except UcError as e:
        print(f"[!] Emulation Crashed/Stopped: {e}")
        # Print PC
        # pc = mu.reg_read(UC_ARM64_REG_PC)
        # print(f"    PC = {hex(pc)}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python emulate_jni.py <file> <offset_int>")
    else:
        emulate_jni(sys.argv[1], int(sys.argv[2], 16))
