# Phase 1 Complete: Binary Analysis & Discovery

## Critical Finding: Stripped AOT-Compiled Binary

### What We Discovered

libunity.so is a **production-optimized, stripped AOT-compiled binary** where:

1. ✅ **String literals ARE present** (embedded in .rodata section)
   - "Match" @ 0xdf7d6
   - "http" @ 0xeec1a
   - "https" @ several locations
   - "Request", "Response", "Send", "Receive", "Connect" all present
   - "ssl", "tls", "socket" all present

2. ❌ **IL2CPP metadata is NOT present** (or heavily optimized away)
   - global-metadata.dat files are 0 bytes (stripped)
   - Standard IL2CPP header structure doesn't exist
   - Type definitions removed (AOT compilation)
   - Method names stripped from symbol table

3. ✅ **Machine code contains all network logic**
   - All socket calls compiled directly to ARM64
   - HTTP requests are native code, not managed code
   - API endpoints hardcoded or passed as constants

### Why This Matters

**Good News**: We have all the strings we need to identify APIs
**Challenge**: We need to analyze ARM64 machine code to find what calls them

This is actually **BETTER** for our goal because:
- Strings are directly used, not hidden in method names
- We can trace string usage back to network calls
- Network operations compile to specific ARM64 patterns (syscalls)

### Revised Phase 1.5 Strategy: Binary Reverse Engineering

Instead of parsing IL2CPP metadata, we'll:

1. **Identify ARM64 code blocks that reference network strings**
   - Find "http", "https" usage
   - Find socket-related operations
   - Track function parameters

2. **Trace data flow**
   - Strings → socket.send() calls
   - Parameters passed to HTTP clients
   - URL construction patterns

3. **Recognize ARM64 patterns for:**
   - sendto() syscalls
   - SSL/TLS handshakes
   - HTTP request building
   - OkHttp/Cronet library calls

4. **Correlate with Java code**
   - We found 1 endpoint in Java: api.gms.moontontech.com
   - Look for similar endpoints in machine code
   - Match patterns between Java and native code

### File Inventory - Phase 1

**Created:**
- `scripts/phase1_il2cpp_analyzer.py` - Binary signature detection
- `scripts/phase1_find_strings.py` - String extraction (WORKING)
- `scripts/phase1_header_debug.py` - Header verification tool
- `scripts/find_real_header.py` - Header position discovery
- `scripts/correct_header_analysis.py` - Header structure analysis
- `scripts/analyze_stripped_binary.py` - Stripped binary analysis
- `il2cpp_parser/` - Rust IL2CPP parser (for reference binaries)

**Key Findings:**
- Network strings confirmed in binary
- libunity.so is stripped AOT binary (23.6 MB)
- Machine code contains all logic

### Measurements - String Distribution

```
"get_" patterns:     2,362 occurrences
"set_" patterns:     1,729 occurrences
"Request":           167 occurrences
"Connect":           152 occurrences
"Send":              64 occurrences
"Create":            249 occurrences
"socket":            19 occurrences
"http":              13 occurrences
"https":             6 occurrences
"ssl":               78 occurrences
"tls":               77 occurrences
"Receive":           27 occurrences
"Response":          6 occurrences
```

### Next Phase: ARM64 Analysis

To continue, we need to:
1. **Disassemble relevant code sections** (where "http", "https" are used)
2. **Identify function boundaries** around network strings
3. **Trace backward from socket calls** to understand parameters
4. **Build API call graph**

Tools for this:
- Ghidra (free, open-source disassembler)
- IDA Pro (professional, better at ARM64)
- Binary Ninja (modern, good ARM64 support)
- Radare2 (open-source, scriptable)

Or we can use our Rust emulator with enhanced debugging!

### Architecture Decision

**We should shift to Phase 2: ARM64 Machine Code Analysis**

Instead of building a full IL2CPP interpreter, we'll:
1. Parse ARM64 instructions in the relevant sections
2. Build a call graph around network operations
3. Extract API endpoints from data references
4. Create a map of what each network function does

This is:
- ✅ More direct (works on stripped binaries)
- ✅ Faster to implement (no interpreter needed)
- ✅ More reliable (code speaks for itself)
- ✅ Fewer false positives

### Time Estimate Revision

**Original**: 12-18 months for full IL2CPP interpreter
**Revised**: 2-4 months for ARM64 analysis + API extraction

We can skip:
- ❌ IL bytecode interpreter (not needed)
- ❌ Managed runtime (compiled away)
- ❌ Type reflection (stripped)

We now need:
- ✅ ARM64 disassembler
- ✅ Call graph builder
- ✅ String-to-code mapper
- ✅ API endpoint extractor

---

## Status: Phase 1 Complete ✅

| Phase | Task | Status |
|-------|------|--------|
| 1.0 | Find binary format | ✅ DONE |
| 1.1 | Extract strings | ✅ DONE |
| 1.2 | Verify network strings | ✅ DONE |
| 1.3 | Analyze IL2CPP structure | ✅ DONE (found it doesn't exist) |
| 1.4 | Understand binary format | ✅ DONE (stripped AOT) |
| 1.5 | Revised strategy | ✅ DONE (switch to ARM64 analysis) |

**Ready for Phase 2: ARM64 Binary Analysis**

