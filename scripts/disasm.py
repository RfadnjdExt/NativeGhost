
import sys

def run():
    offset = 0x7f0000
    length = 0x100
    try:
        with open('memory_dump.bin', 'rb') as f:
            f.seek(offset)
            data = f.read(length)
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    try:
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
        print("Capstone enabled.")
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        # Base address = 0x400000. Offset 0x7f0000 -> 0xbf0000
        base = 0xbf0000
        for i in md.disasm(data, base):
            print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
    except ImportError:
        print("Capstone generic fallback (Hex Only):")
        # Print hex in 4-byte chunks
        for i in range(0, len(data), 4):
            chunk = data[i:i+4]
            val = int.from_bytes(chunk, 'little')
            print(f"0x{0xbf0000+i:x}: {chunk.hex()} (0x{val:08x})")

if __name__ == "__main__":
    run()
