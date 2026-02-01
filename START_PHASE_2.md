# Phase 2 Analysis - Quick Start Guide

## Setup Complete ✅

All systems ready for 1-year deep ARM64 manual analysis.

---

## What Was Done

**Workspace Cleanup:**
- ✅ Removed all Frida-related files (4 files deleted)
- ✅ Removed extracted APK directories
- ✅ Removed old tool directories (jadx, il2cpp_parser, etc.)
- ✅ Archived old reports and logs
- ✅ Organized analysis files
- ✅ Cleaned up 200+ MB of unnecessary files

**Directories Created:**
- `analysis_data/` - Phase 1 results and references
- `manual_analysis/` - Phase 2-5 working directory
- `archive/` - Old reports and logs

**Documentation Created:**
- `MANUAL_ANALYSIS_PLAN_1YEAR.md` - Complete plan for all phases
- `manual_analysis/PHASE_2_CANDIDATES.md` - Top 50 functions to analyze

---

## Current Status

**Binary Target:** libunity.so (23.61 MB ARM64-v8a)
- Location: `extracted_apk/lib/arm64-v8a/libunity.so`
- Status: Ready for analysis

**Candidate Functions:** 826 total
- Status: Top 50 prioritized
- First function: 0xf98ff8 (247 string operations)

**Analysis Tools:** 5 Rust binaries ready
- Location: `arm64_disassembler/target/release/`
- Performance: 0.01-0.2 seconds each

**Time Commitment:** ~52 weeks
- Week 1-4: Foundation (COMPLETED)
- Week 5-24: Phase 2 Deep Analysis (STARTING NOW)
- Week 25-48: Phase 5 API Extraction
- Week 49-52: Documentation & Cleanup

---

## Begin Phase 2: Deep Function Analysis

### Step 1: Open Analysis Directory
```powershell
cd C:\dev\NativeGhost\manual_analysis
```

### Step 2: Create Phase 2 Function Subdirectories
```powershell
mkdir phase2_functions
```

### Step 3: Start with First Function (0xf98ff8)

**Run detailed disassembly:**
```powershell
cd ..\arm64_disassembler
target\release\disassemble_functions.exe | Tee-Object -FilePath ..\manual_analysis\phase2_functions\analysis_output.txt
```

**What to look for:**
1. All ADRP instructions (address loading)
2. ADD instructions following ADRP (address offset)
3. BL instructions (function calls)
4. Memory operations (LDR, STR)
5. String operations pattern

**Create function analysis file:**
```powershell
# Create template: manual_analysis/phase2_functions/FUNC_0xf98ff8.md
```

### Step 4: Document Findings

Use the template in `PHASE_2_CANDIDATES.md` to create analysis document:

```markdown
# Function Analysis: 0xf98ff8

## Basic Info
- Address: 0xf98ff8
- String Operations: 247
- BL Calls: 12
- Status: ANALYZING

## Disassembly
[Copy from output above]

## Identified Patterns
- [ ] String concatenation
- [ ] URL building
- [ ] Parameter encoding
- [ ] HTTP header building

## Discovered Strings
- List strings found via ADRP+ADD

## Related Functions
- Caller addresses
- Callee addresses

## Hypothesis
What does this function likely do?

## Next Steps
What to analyze next?
```

### Step 5: Continue with Next Functions

Repeat for all 50 priority functions in order:
1. 0xf98ff8 (247 ops)
2. 0x8e37a0 (231 ops)
3. 0xaf2168 (156 ops)
... and so on

---

## Analysis Workflow

**Daily Workflow (Recommended):**

1. **Select next function** from PHASE_2_CANDIDATES.md
2. **Run analysis tools** to generate disassembly
3. **Study disassembly** for string operations and patterns
4. **Create documentation** with findings
5. **Update progress** in PHASE_2_CANDIDATES.md

**Weekly Checkpoint:**
- [ ] Analyze 7-10 functions
- [ ] Document patterns found
- [ ] Identify any call relationships
- [ ] Update master analysis index

**Monthly Review:**
- Compile discoveries from functions
- Identify common patterns
- Plan next phase focus
- Document progress

---

## Tools Quick Reference

### Analyze Single Function
```powershell
cd arm64_disassembler

# Quick pattern scan
target\release\deep_analysis.exe

# Detailed disassembly
target\release\disassemble_functions.exe

# Network region analysis
target\release\advanced_analysis.exe
```

### Modify Tools (Optional)

Source code ready in `arm64_disassembler/src/bin/`:
- `deep_analysis.rs` - Function pattern scanner
- `disassemble_functions.rs` - Detailed disassembler
- `advanced_analysis.rs` - Network analysis

Rebuild after changes:
```powershell
cd arm64_disassembler
cargo build --release
```

---

## Expected Results

### Week 5-8 (First 50 Functions)
- [ ] Analyze first 50 candidate functions
- [ ] Identify top URL builder patterns
- [ ] Create function database
- [ ] Document first discoveries

### By Month 3
- [ ] All 826 functions analyzed
- [ ] Top 50 patterns identified
- [ ] Initial endpoint discoveries

### By Month 6
- [ ] Call graphs completed
- [ ] Function relationships mapped
- [ ] 30+ endpoints identified

### By Month 12
- [ ] Complete API reference
- [ ] 100+ endpoints documented
- [ ] Full client library spec

---

## Important Files

**Read First:**
1. `MANUAL_ANALYSIS_PLAN_1YEAR.md` - Full plan overview
2. `manual_analysis/PHASE_2_CANDIDATES.md` - Function list
3. `analysis_data/DEEP_ARM64_ANALYSIS_SUMMARY.md` - Phase 1 results

**Reference:**
- `analysis_data/deep_arm64_analysis.md` - Detailed Phase 1 results
- `analysis_data/function_disassembly.md` - Top 5 functions (examples)

**Work In Progress:**
- `manual_analysis/phase2_functions/` - Create function analysis files here

---

## Key Information from Phase 1

**Network Strings Located (Critical Reference):**
- "Match" @ 0x0e9f56
- "http" @ 0x0eec1a
- "Request" @ 0xdf792
- "Response" @ 0x125266

**Important Discovery:** These strings are NOT directly referenced by address
- Must trace dynamic string construction
- Focus on functions that build URLs at runtime

**Instruction Statistics:**
- 414,096 ADD instructions (offsets)
- 237,295 BL instructions (function calls)
- 176,931 ADRP instructions (address loads)
- 137,625 B instructions (branches)
- 55,712 RET instructions (returns)

---

## You Are Ready

The foundation is complete. The workspace is clean. The tools are compiled.

**Begin analyzing the 826 candidate functions to extract the complete API.**

Start with function **0xf98ff8** - it has the highest string operation count (247).

---

**Status:** Phase 2 Ready to Begin
**Target Functions:** 826 (Start with top 50)
**Timeline:** ~52 weeks
**Completion Deadline:** Approximately 1 year from start

Good luck! 🚀
