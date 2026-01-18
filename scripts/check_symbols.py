
import lief
import sys

def check_symbols():
    lib = lief.parse("libbyteplusaudio.so")
    print("Checking exports...")
    for s in lib.exported_functions:
        if "JNI" in s.name:
            print(f"Export: {s.name} @ {hex(s.address)}")
    
    print("Checking JNI_OnLoad...")
    try:
        sym = lib.get_symbol("JNI_OnLoad")
        print(f"JNI_OnLoad FOUND @ {hex(sym.value)}")
    except:
        print("JNI_OnLoad NOT FOUND")

if __name__ == "__main__":
    check_symbols()
