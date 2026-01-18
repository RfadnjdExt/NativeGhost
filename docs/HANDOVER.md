# Context Handover: MLBB API Extraction

## **Objective**
**Ultimate Goal**: Extract the Request (URL, Headers, Payload) for the **Top Global Leaderboard (Highest Rank) Match History**.
**Required Data Points**:
- Match Result (Win/Lose)
- Heroes used (Team & Enemy)
- Match Duration

**Current Milestones**:
1.  **Authenticate**: Debug `emulator_rust` running `libbyteplusaudio.so` to extract the `UpdateLoginToken` request (Authentication/Signature).
2.  **Replay/Query**: Use the extracted tokens to query the Leaderboard API and capture the match history details.

## **Current State**
- **Emulator**: Rust-based (Unicorn Engine), ARM64.
- **Target**: `libbyteplusaudio.so` calls `UpdateLoginToken` (via `JNI_OnLoad` manual invocation).
- **Status**:
    - `JNI_OnLoad` executes successfully (Return `10006`).
    - `UpdateLoginToken` invocation starts and runs for >350M instructions.
    - **JNI Mocks**: Implemented for `FindClass`, `GetMethodID`, `CallObjectMethod` (stubbed), `NewStringUTF`, etc.
    - **Hooks**:
        - `dlsym`: Hooks `BEF_EFFECT_JNI_OnLoad`.
        - `log`: Hooks `__android_log_write` / `print`. **(Outputting `libjingle` logs!)**
        - `network`: Hooks `sendto` / `write`.
- **Issues**:
    - **Crash/Exit**: Emulator exits (PC=0 or Crash) *after* extensive execution.
    - **API Extraction**: Not yet clearly visible in logs. Memory scanner added but results pending analysis.
    - **Logs**: `test.txt` contains `[LogPrint] libjingle` messages, indicating WebRTC/Network initialization is happening.

## **Files & Artifacts**
- `emulator_rust/src/main.rs`: Main emulator code. Contains JNI logic, hooks, and memory map.
- `memory_dump.bin`: 16MB dump of the library (+ other regions).
- `task.md`: Checklists.
- `imports_map.txt`: Offsets for PLT imports.
- `disasm.py`: Script to disassemble crash sites.

## **Next Steps for Agents**
1.  **Analyze Logs**: Read `test.txt` (handle UTF-16LE encoding) to see full `libjingle` output. Look for "URL", "token", "http", or JSON strings in the log arguments.
2.  **Verify Memory Scan**: Check if `[Analysis] Scanning Memory...` ran and found anything.
3.  **Trace Network**: If `sendto` wasn't flagged, check if `SSL_write` (OpenSSL) is used instead. (Offsets in `imports_map.txt`).
4.  **Fix Crash**: Disassemble the final PC to understand why it exits unexpectedly (if not a successful return).
5.  **Refine Hooks**: Add `SSL_write` hook to `main.rs` if `sendto` is empty.

## **Key Offsets (ARM64)**
- `JNI_OnLoad`: `0x62ed1c`
- `UpdateLoginToken`: `0x6426cc` (Symbol: `Java_com_ss_bytertc_engine_NativeRTCVideoFunctions_nativeUpdateLoginToken`)
- `MAGIC_BASE`: `0x20000000` (Used for mock JNI/return pointers)
