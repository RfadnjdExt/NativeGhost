# Phase 2 - Quick Start Guide for Function Analysis

**Current Status:** ✅ 3 Rust tools ready | ✅ 5 functions analyzed | 🔜 821 remaining

---

## Run the Tools (One Command Each)

### From C:\dev\NativeGhost:

```powershell
# Deep function disassembly
.\arm64_disassembler\target\release\phase2_analyzer.exe

# String reference mapping
.\arm64_disassembler\target\release\string_extractor.exe

# Function call chain tracing
.\arm64_disassembler\target\release\call_chain_tracer.exe
```

---

## What Each Tool Does

| Tool | Purpose | Key Output |
|------|---------|-----------|
| **phase2_analyzer** | Disassemble functions & count instructions | ADRP/ADD/BL counts |
| **string_extractor** | Find which functions use known strings | "http", "Match", etc. |
| **call_chain_tracer** | Map which functions call which helpers | Call relationships |

---

## Top 50 Functions to Analyze (Ranked)

1. **0xf98ff8** (247 ops) - String builder - **HIGHEST PRIORITY**
2. **0x8e37a0** (231 ops) - Complex concat
3. **0xaf2168** (156 ops) - URL formatter
4. **0xa5d8e8** (89 ops) - Parameter handler
5. **0xb2c4c0** (34 ops) - HTTP builder
6-50: [See manual_analysis/PHASE_2_CANDIDATES.md]

---

## Work in Progress

Create files in: `manual_analysis/phase2_functions/`

### File Naming:
```
FUNC_0xf98ff8.md  - First function analysis
FUNC_0x8e37a0.md  - Second function
... etc
```

### Template:
```markdown
# Function Analysis: 0x[ADDR]

## Basic Info
- Address: 0x[ADDR]
- String Operations: [N]
- Status: ANALYZING / COMPLETE

## Disassembly
[Copy output from phase2_analyzer]

## Identified Patterns
- ADRP: [count] - Loads which strings
- ADD: [count] - Offset calculations
- BL: [count] - Calls to [list functions]

## Discovered Strings
- "api/v1/..."
- "Authorization"
- ... etc

## Hypothesis
What does this function build?

## Related Functions
- Calls: 0x[ADDR]
- Called by: 0x[ADDR]
```

---

## Progress Tracking

Update this weekly: `manual_analysis/PHASE_2_CANDIDATES.md`

```
| Function | Status | Week Done |
|----------|--------|-----------|
| 0xf98ff8 | TODO   | -         |
| 0x8e37a0 | TODO   | -         |
| 0xaf2168 | TODO   | -         |
| ...      |        |           |
```

---

## Key Patterns to Look For

**In ADRP+ADD sequences:**
- Multiple string addresses (100+ ops suggests URL builder)
- Pattern: `ADRP x0 → ADD x0 → handle`

**In BL sequences:**
- Calls to sprintf/strcpy variants (string builders)
- Calls to encoding functions
- Multiple sequential calls = complex operations

**In LDR/STR sequences:**
- Writes to registers = data construction
- Multiple operations = buffer assembly

---

## Expected Timeline

- Week 1: Functions 1-10 (7-10 per week pace)
- Week 4: Functions 1-50 (comprehensive top candidates)
- Month 2: Functions 1-200 (80% of work)
- Month 3-4: Complete remaining
- Month 5+: URL pattern reconstruction

---

## Tools Are Ready

All Rust binaries compiled and tested:
- ✅ phase2_analyzer.exe (256 instructions scanned, patterns detected)
- ✅ string_extractor.exe (identifies string references)
- ✅ call_chain_tracer.exe (traces 22+ calls per function)

---

## Next 30 Minutes

1. ✅ Run phase2_analyzer
2. ✅ Run string_extractor
3. ✅ Run call_chain_tracer
4. Create `manual_analysis/phase2_functions/` directory
5. Start analyzing top 5 functions manually
6. Document findings in .md files

**Begin with 0xf98ff8 (highest priority)**

---

**Effort:** Rust-only | **Cost:** Zero dependencies | **Speed:** <5 seconds per run
