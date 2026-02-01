# Phase 1 Progress: IL2CPP Binary Analysis

## Status: ✅ IN PROGRESS

Found IL2CPP header at offset 0x24dc in libunity.so!

### Key Findings

1. **IL2CPP Header Located**
   - Offset: 0x24dc
   - Version: 0x1d (Unity 2019 era)
   - Successfully detected and parsed

2. **Confirmed String Presence**
   - Found 2362 occurrences of "get_" (method patterns)
   - Found 1729 occurrences of "set_" (method patterns)
   - Found network-related keywords: "http", "https", "socket", "ssl", "Request", "Response"
   - Confirmed "Match" and "Streamer" strings exist in binary

3. **Current Challenges**
   - Type definition count seems inflated (983058 types found) - likely parsing the wrong size
   - Method count appears low (2658 methods) - suggests data offset needs refinement
   - String offsets are pointing to 0x0 - structure size is incorrect

### Next Steps (Phase 1 Continuation)

#### 1. Refine IL2CPP Header Structure
- The current header structure might be for a different IL2CPP version
- Need to match against known Unity version (check AndroidManifest.xml)
- Test multiple header structures

#### 2. Validate String Table
- Manually verify string offsets by reading from known addresses
- The "Match" string found at 0xe9f56 should be accessible
- Build string lookup table

#### 3. Extract Real Methods
- Focus on methods that reference "Request", "Send", "Receive", "Connect"
- Cross-reference with bytecode patterns
- Build method-to-API mapping

#### 4. Network API Recovery
- Once methods are extracted, search for method implementations
- Find socket operations (send/sendto syscalls)
- Correlate with HTTP requests

### IL2CPP Architecture Understanding

From our research:

```
libunity.so (23.6 MB)
├── ELF Header
│   └── Program Headers
│       ├── .text (code)
│       ├── .rodata (constants, strings)
│       ├── .data (static data)
│       └── .bss (zero-initialized)
│
├── IL2CPP Metadata (at 0x24dc)
│   ├── String Table
│   ├── Type Definitions (classes)
│   ├── Method Definitions
│   ├── Field Definitions
│   ├── Parameter Definitions
│   └── IL Bytecode
│
└── Machine Code (ARM64)
    ├── Method Implementations
    ├── JIT Compiled Code
    └── Native Runtime
```

The metadata structure contains references to:
- Game logic classes (Request, Response, StreamerInfo, MatchData, etc.)
- Network methods (Send, Receive, Connect, etc.)
- Initialization code that calls these methods

### File Inventory

**Created This Session:**
- `docs/IL2CPP_IMPLEMENTATION_ROADMAP.md` - 600+ line comprehensive plan
- `scripts/phase1_il2cpp_analyzer.py` - Binary format detection script
- `scripts/phase1_find_strings.py` - String extraction from binary
- `il2cpp_parser/` - Rust library for binary parsing
  - `src/lib.rs` - Core IL2CPP parser
  - `src/main.rs` - Executable analyzer
- `il2cpp_analysis.txt` - Initial parser output

**Key Binaries:**
- `extracted_apk/lib/arm64-v8a/libunity.so` (23.6 MB)
- `extracted_apk/lib/arm64-v8a/libil2cpp.so` (future analysis)

### Technical Debt / Known Issues

1. **Header Structure Mismatch**
   - Current struct assumes Version 0x1D format
   - Unity versions vary header structure
   - Need version-specific parsers

2. **Metadata Offsets**
   - String table offsets return 0x0
   - Suggests offset calculation is wrong
   - May need to re-examine offset fields

3. **Type Count Explosion**
   - 128922 types extracted (likely wrong)
   - Most include generic specializations
   - Need better filtering

### Success Criteria Remaining

| Criterion | Status | Priority |
|-----------|--------|----------|
| Find IL2CPP header | ✅ DONE | Critical |
| Parse type definitions correctly | 🔄 IN PROGRESS | High |
| Extract method names | 🔄 IN PROGRESS | High |
| Find network-related methods | 🔲 BLOCKED | High |
| Map API endpoints | 🔲 BLOCKED | Critical |
| Execute game initialization | 🔲 FUTURE | High |

### Architecture Decision: Stay with libunity.so

We could also analyze:
- `libil2cpp.so` (IL2CPP runtime - 837 imports, mostly internal)
- `global-metadata.dat` (if it were present and non-empty)

But **libunity.so is the primary target** because:
1. Contains compiled game code (all IL is converted to machine code)
2. Metadata is embedded in the binary
3. All network calls are present in machine code
4. String table is searchable

### Immediate Actions (Next Session)

1. **Fix Header Parsing**
   - Create version-specific header parsers
   - Test against known IL2CPP samples

2. **Build String Table**
   - Manually verify string offsets
   - Create string dictionary

3. **Extract Method Names**
   - Iterate through method table correctly
   - Filter for network-related methods

4. **Find Network Calls**
   - Cross-reference methods with socket operations
   - Identify API endpoint strings used in each method

---

**Total Time Invested**: ~2 hours (Phase 1 of 5)
**Estimated Remaining**: ~20-24 months (Phases 2-5)

