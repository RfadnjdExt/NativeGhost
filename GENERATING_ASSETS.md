# Generating Assets from APK

This guide explains how to generate the required emulator assets (`memory_dump.bin` and `imports_map.txt`) starting **directly from an APK file**. No Android device or Root access is required.

## Prerequisites
- Python 3.8+
- Unzip tool (7-Zip, WinRAR, or terminal `unzip`)
- **Core Python Dependencies**:
  ```bash
  pip install capstone unicorn
  ```

## Step 1: Extract the APK
An `.apk` file is just a ZIP archive.
1.  Rename your `game.apk` to `game.zip` (optional, or just open with 7-Zip).
2.  Extract the contents.
3.  Navigate to the native library folder:
    - Path: `lib/arm64-v8a/`
4.  Locate the target library: **`libbyteplusaudio.so`** (or `libmoba.so` if targeting core logic).
    - Copy this `.so` file to your project root or know its path.

## Step 2: Generate `imports_map.txt` (Function Map)
This script scans the library to find import offsets (e.g., specific addresses for `send`/`recv`).

```bash
# Usage: python scripts/scan_imports.py <path_to_so>
python scripts/scan_imports.py lib/arm64-v8a/libbyteplusaudio.so
```
**Output**: `imports_map.txt` will be created in the current directory.

## Step 3: Generate `memory_dump.bin` (Memory Image)
This script simulates the OS loader in Python to create a memory snapshot, handling relocations automatically.

1.  **Important**: Ensure `scripts/dump_loader.py` points to your extracted `.so`.
    - Edit `scripts/dump_loader.py` line 7:
      ```python
      emu = AndroidEmulator("lib/arm64-v8a/libbyteplusaudio.so", "imports_map.txt")
      ```
2.  Run the dumper:
    ```bash
    python scripts/dump_loader.py
    ```
**Output**: `memory_dump.bin` (approx 16-32MB) in the current directory.

## Step 4: Run Emulator
Now you have the two required files (`imports_map.txt`, `memory_dump.bin`).
You can start the emulator:

```bash
cd emulator_rust
cargo run --release
```

---

## 🔄 Troubleshooting
If the emulator doesn't find the expected API strings, the logic might be in a different library.
1.  Repeat Steps 2 & 3 with **`libmoba.so`** (Core Game Logic).
2.  Repeat Steps 2 & 3 with **`libunity.so`** (Unity Engine IL2CPP).
This script scans the ELF binary for relocation entries (PLT) and maps memory addresses to function names (e.g., `sendto`, `__android_log_write`).

```bash
# Usage: python scripts/scan_imports.py <path_to_so>
python scripts/scan_imports.py path/to/libbyteplusaudio.so
```
**Output**: `imports_map.txt` in the current directory.

## Step 2: Generate `memory_dump.bin`
This script uses Unicorn Engine (Python) to "load" the library into memory, applying relocations using the `imports_map.txt` generated in Step 1. It then dumps the simulated memory to a file.

> **Note**: Update `scripts/dump_loader.py` line 7 to point to your `.so` file path if strictly needed, or ensure the default path matches.

```bash
# Usage: python scripts/dump_loader.py
python scripts/dump_loader.py
```
**Output**: `memory_dump.bin` (approx 16MB).

## Step 3: Run Emulator
Once both files are in the project root, you can run the Rust emulator:

```bash
cd emulator_rust
cargo run --release
```
