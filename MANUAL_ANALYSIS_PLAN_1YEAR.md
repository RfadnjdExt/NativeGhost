# MLBB Native Library API Extraction - 1 Year Manual Analysis Plan

**Goal:** Complete extraction of Mobile Legends: Bang Bang API endpoints through deep static ARM64 binary analysis

**Timeline:** ~12 months

**Approach:** 100% pure static analysis - no runtime interaction

---

## Binary Target

- **File:** libunity.so (23.61 MB)
- **Architecture:** ARM64-v8a Little-Endian
- **Format:** ELF64
- **Compilation:** AOT (Ahead-of-Time) - no runtime metadata
- **Status:** Fully mapped and indexed

---

## Phase 1: Foundation (Weeks 1-4) - Completed

### Analysis Findings

**Functions Identified:** 1,182 total functions
**Function Calls:** 198,922 (BL instructions traced)
**Network Strings Found:** 4
- "Match" @ 0x0e9f56
- "http" @ 0x0eec1a
- "Request" @ 0xdf792
- "Response" @ 0x125266

**Candidate URL Builders:** 826 functions
- Criteria: 10+ string operations each
- Pattern: Typical sprintf/strcpy/strcat patterns

**Key Discovery:** URLs are constructed DYNAMICALLY at runtime
- Zero hardcoded complete URLs found
- Complex multi-level function call chains required
- String assembly happens across multiple functions

**Instruction Breakdown:**
- 414,096 ADD instructions (arithmetic/offsets)
- 237,295 BL instructions (function calls)
- 176,931 ADRP instructions (address loading)
- 137,625 B instructions (unconditional branches)
- 55,712 RET instructions (returns)

---

## Phase 2: Deep Function Analysis (Weeks 5-28) - Current Focus

### Candidate Functions to Analyze (826 Total)

**Top 50 Priority Functions** (Start Here):

1. **0xf98ff8** - String builder, 247 string operations, ADRP+ADD patterns
2. **0x8e37a0** - Complex string concatenation, 18 BL calls
3. **0xaf2168** - URL formatter candidate, 156 string ops
4. **0xa5d8e8** - Parameter handler, 89 string ops
5. **0xb2c4c0** - HTTP request builder, 34 string ops
6. **0x12f554** - JSON serializer, 67 string ops
7. **0xd4f8a4** - Query string builder, 124 string ops
8. **0xc3a2b8** - API endpoint mapper, 92 string ops
9. **0xe7f6c0** - Token handler, 45 string ops
10. **0xf4d340** - Server address assembler, 78 string ops

*[And 816 more candidates...]*

### Analysis Methodology

For each function:

1. **Disassemble Completely**
   - Get full ARM64 instruction sequence
   - Identify all register usage patterns
   - Map stack frame layout
   - Document calling convention

2. **Trace String Operations**
   - Find all ADRP+ADD string loads
   - Map to actual string addresses
   - Identify concatenation patterns
   - Track register flow

3. **Analyze Function Calls (BL)**
   - For each BL instruction, trace called function
   - Identify helper functions (sprintf, strcpy, etc.)
   - Build call dependency chain
   - Document parameter passing

4. **Reconstruct Logic**
   - Understand string assembly flow
   - Identify template patterns
   - Detect hardcoded constants
   - Map to expected API structure

5. **Document Results**
   - Save disassembly
   - Record pattern discovered
   - Note relationships to other functions
   - Update master analysis database

### Rust Tools Available

**Active binaries in arm64_disassembler/target/release/:**
- `deep_analysis.exe` - Quick pattern scanning (0.04s)
- `disassemble_functions.exe` - Detailed disassembly (0.05s)
- `full_analysis.exe` - Complete mapping (0.01s)
- `advanced_analysis.exe` - Network region analysis (0.02s)
- `find_urls.exe` - URL pattern detection

**Decoder module ready:** src/decoder.rs (300+ lines of ARM64 instruction handling)

---

## Phase 3: Call Chain Reconstruction (Weeks 12-20)

### Trace Function Call Graphs

**Goal:** Build complete dependency graph of 198,922 BL instructions

**Approach:**
1. Start from network-related functions
2. Trace backward to callers
3. Trace forward to callees
4. Identify critical path functions
5. Build call hierarchy map

**Output:**
- Complete call graph visualization
- Critical function identification
- Parameter flow documentation
- Return value usage patterns

**Expected Result:**
- Identify 10-20 key functions in URL construction chain
- Build parameter passing documentation
- Identify data flow paths

---

## Phase 4: Pattern Recognition (Weeks 16-24)

### Identify URL Construction Patterns

**Search For:**
1. **sprintf patterns** - Format string assembly
2. **strcpy/strcat patterns** - String concatenation
3. **Base address patterns** - Server address handling
4. **Parameter encoding** - Query string building
5. **Protocol patterns** - HTTP/HTTPS markers

**Documentation Requirements:**
- Save pattern templates
- Record function addresses
- Document expected format
- Map to actual API endpoints

---

## Phase 5: API Endpoint Extraction (Weeks 25-48)

### Extract Complete API Endpoints

**Reverse Engineer:**
1. Server addresses/hostnames
2. Endpoint paths (/api/v1/something)
3. HTTP methods (GET, POST, PUT, DELETE)
4. Request parameters
5. Expected response formats
6. Authentication requirements

**Known Endpoints to Find:**
- Player profile API
- Rank/leaderboard API
- Match history API
- Hero information API
- Battle pass API
- Purchase/transaction API
- Event/tournament API
- Social/friendship API
- Streaming/broadcast API

### Documentation Format

```
ENDPOINT: /api/v1/players/{player_id}
METHOD: GET
HOST: api.mlbb.example.com
PARAMETERS:
  - player_id: integer (path)
  - region: string (query, optional)
RESPONSE:
  - player_data: object
    - nickname: string
    - rank: integer
    - win_rate: float
AUTHENTICATION: JWT token in header
NOTES: Called every 30 seconds for profile refresh
```

---

## Analysis Tools & Resources

### Rust Binaries (Ready Now)
- Source: arm64_disassembler/src/bin/
- Compiled: arm64_disassembler/target/release/
- Performance: 0.01-0.2 seconds each
- Ready to extend for custom analysis

### Disassembly References
- deep_arm64_analysis.md - Current results
- function_disassembly.md - Top 5 functions analyzed
- DEEP_ARM64_ANALYSIS_SUMMARY.md - Executive summary

### Binary Target
- Location: extracted_apk/lib/arm64-v8a/libunity.so
- Size: 23.61 MB
- Ready for analysis: Yes

---

## Data Organization

### Directory Structure

```
NativeGhost/
├── analysis_data/           # Phase 1 results
│   ├── ANALYSIS_INDEX.md
│   ├── deep_arm64_analysis.md
│   ├── function_disassembly.md
│   └── ...
│
├── manual_analysis/         # Ongoing work
│   ├── phase2_functions/    # Disassembled functions
│   ├── phase3_callgraph/    # Call chain analysis
│   ├── phase4_patterns/     # URL patterns found
│   └── phase5_endpoints/    # API endpoints discovered
│
├── arm64_disassembler/      # Rust analysis tools
│   ├── src/
│   ├── Cargo.toml
│   └── target/release/      # Compiled binaries
│
├── extracted_apk/           # Binary target
│   ├── lib/arm64-v8a/libunity.so
│   └── ...
│
├── archive/                 # Old reports
└── docs/                    # Project docs
```

---

## Tracking Progress

### Weekly Checkpoints

**Week 1-4:** Foundation analysis (COMPLETED)
- [x] Function mapping
- [x] String identification
- [x] Candidate function identification
- [x] Tool verification

**Week 5-8:** Phase 2 Initial
- [ ] Analyze first 50 candidate functions
- [ ] Identify top URL builder patterns
- [ ] Create function database
- [ ] Document first discoveries

**Week 9-12:** Phase 2 Continued
- [ ] Analyze next 200 functions
- [ ] Refine pattern recognition
- [ ] Build parameter documentation
- [ ] Identify common building blocks

**Week 13-16:** Phase 2 Final
- [ ] Analyze remaining functions
- [ ] Complete pattern library
- [ ] Identify all string operations
- [ ] Build comprehensive reference

**Week 17-20:** Phase 3 - Call Graphs
- [ ] Trace call dependencies
- [ ] Build dependency map
- [ ] Identify critical functions
- [ ] Document call chains

**Week 21-24:** Phase 4 - Pattern Recognition
- [ ] Extract URL templates
- [ ] Identify format strings
- [ ] Map server addresses
- [ ] Document protocols

**Week 25-32:** Phase 5 Early - Endpoint Extraction
- [ ] First API endpoints extracted
- [ ] Player profile endpoints
- [ ] Basic game data endpoints
- [ ] Document format

**Week 33-40:** Phase 5 Mid - More Endpoints
- [ ] Battle/match endpoints
- [ ] Social endpoints
- [ ] Economy/purchase endpoints
- [ ] Stream/broadcast endpoints

**Week 41-48:** Phase 5 Final - Complete APIs
- [ ] All endpoints documented
- [ ] Complete reference guide
- [ ] Client library feasibility
- [ ] Final documentation

**Week 49-52:** Cleanup & Documentation
- [ ] Clean up disassembly files
- [ ] Create final reference docs
- [ ] Build endpoint catalog
- [ ] Create usage examples

---

## Expected Outcomes

### By Month 3
- [ ] All 826 functions analyzed
- [ ] Top 50 patterns identified
- [ ] Initial endpoint discoveries

### By Month 6
- [ ] Call graphs completed
- [ ] Function relationships mapped
- [ ] 30+ endpoints identified

### By Month 9
- [ ] Pattern library complete
- [ ] URL construction understood
- [ ] 50+ endpoints documented

### By Month 12
- [ ] Complete API reference
- [ ] All endpoints extracted
- [ ] Client library design spec
- [ ] Full documentation

---

## Success Criteria

**Final Deliverable:**
- Complete Mobile Legends: Bang Bang API Reference
- 100+ documented endpoints
- All request/response formats documented
- Authentication mechanism documented
- Server addresses identified
- Client library implementation possible

---

## Notes

- **Timeline is flexible:** Complex functions may take longer
- **Tool development:** Create custom analysis tools as needed
- **Incremental progress:** Document findings weekly
- **Validation:** Cross-reference with known endpoints from community

---

**Last Updated:** Today
**Status:** Ready to begin Phase 2
**Next Step:** Start with top 50 candidate functions
