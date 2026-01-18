from emulate_threaded import AndroidEmulator
import struct

# Helper to dump memory
def dump_memory():
    # Pass arguments explicitly
    emu = AndroidEmulator("extracted_apk/lib/arm64-v8a/libbyteplusaudio.so", "imports_map.txt")
    emu.load() # This applies relocations and patches GOT
    
    print("Dumping Relocated Memory...")
    # Dump entire mapped code region (0x400000 to end of text/data)
    # We mapped 0x10000000 size in load() at BASE_ADDR?
    # Check emulate_threaded.py load logic.
    # It maps chunks. We should dump the contiguous block starting at BASE_ADDR.
    
    # Actually emulate_loader.py implementation of load() uses elftools.
    # It maps segments.
    # We will just dump the Unicorn memory from 0x400000 to 0x1400000 (16MB) which covers lib.
    
    BASE = 0x400000
    SIZE = 0x1000000 # 16 MB should cover the 10MB lib + heavy segments
    
    try:
        data = emu.mu.mem_read(BASE, SIZE)
        with open("memory_dump.bin", "wb") as f:
            f.write(data)
        print(f"Dumped {len(data)} bytes to memory_dump.bin")
    except Exception as e:
        print(f"Dump failed: {e}")

if __name__ == "__main__":
    dump_memory()
