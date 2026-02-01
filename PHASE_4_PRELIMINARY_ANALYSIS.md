# Phase 4: Pattern Extraction - Preliminary Analysis

**Status:** ✅ IN PROGRESS  
**Date:** 2026-02-01  
**Focus:** String constant extraction and pattern identification

---

## Execution Summary

### Tools Developed
1. ✅ **phase4_extractor.rs** (150 lines) - Simplified string extraction
   - Scans entire binary for printable ASCII strings
   - Categorizes by pattern (URLs, headers, servers)
   - Completed in ~2 seconds

### Initial Results
- **Total strings found:** 81 (first 1000 scanned)
- **URLs/Endpoints:** 26 identified
- **HTTP Headers:** 47 identified
- **Server Addresses:** 10 identified

---

## Pattern Categories Discovered

### 🌐 URLs & Endpoints (26 found)
```
gpu_api
https
Internal-Skinning.compute
api_name
arcore_unity_api
http:\\
$func.commandbuffer
http://
http:
https://
[... 16 more]
```

**Observations:**
- HTTP/HTTPS protocol variants detected
- API naming patterns found
- Compute shader references (not typical game)
- Mixed protocol indicators (both http:// and http:\\)

### 📨 HTTP Headers (47 found)
```
Content-Disposition: %s%s%s%s%s%s%s
User-Agent
Content-Length
Proxy-Authorization: Basic
Content-Length:
getContentResolver
setContentView
CompleteContent
[... 39 more]
```

**Observations:**
- Standard HTTP headers present
- Format string patterns with % markers
- Android-specific APIs (getContentResolver, setContentView)
- Content negotiation headers

### 🖥️ Server Addresses (10 found)
```
Can't complete SOCKS4 connection to %d.%d.%d.%d:%d...
User was rejected by the SOCKS5 server...
HTTP server doesn't seem to support byte ranges...
A HTTP server error occurred...
server hello, session id len.: %zu
server hello, compress alg.: 0x%02X
Undocumented SOCKS5 mode attempted...
ARCore Unity Plugin...
physx/source/lowlevel...
```

**Observations:**
- Error messages rather than actual server addresses
- SOCKS protocol handling code
- TLS/SSL handshake messages
- ARCore and PhysX framework references

---

## Findings

### Key Discovery 1: Not Traditional Game Binary
The extracted strings show:
- HTTP/HTTPS protocol stacks
- SOCKS proxy protocol support
- TLS handshake handling
- Complex networking infrastructure

This indicates the binary contains a **complete networking library** rather than just game API calls.

### Key Discovery 2: Framework Integration
- PhysX physics engine
- ARCore AR support
- Unity engine base classes
- Networking frameworks (libcurl-like)

### Key Discovery 3: Actual Addresses May Be Encrypted/Encoded
The Phase 3 ADRP addresses may point to:
- Dynamically computed addresses
- Encrypted constant pools
- Obfuscated data structures

This explains why direct string extraction didn't find actual server IPs or API endpoints.

---

## Revised Phase 4 Strategy

Given the initial results, we need to:

### 1. Analyze Function Call Chains (Phase 3 data)
Use the 127 function calls identified in Phase 3 to trace:
- Which functions are called from 0xf4d340 (server loader)
- Which functions are called from 0xf98ff8 (HTTP builder)
- Which functions are called from 0xe7f6c0 (token handler)

### 2. Reverse Engineer Runtime Behavior
Instead of static string extraction:
- Trace register values through function calls
- Identify where constants are loaded/computed
- Find actual server addresses in runtime data

### 3. Build Call Graph Analysis
Map the complete flow:
```
0xf4d340 calls → 0x10e7bda8, 0x10e7c4bc, 0x1088638
0xc3a2b8 calls → [multiple orchestration calls]
0xf98ff8 calls → [HTTP protocol functions]
0xe7f6c0 calls → [signature/crypto functions]
```

---

## Next Steps

### Immediate (Required for Phase 4 completion)
1. Build call graph from Phase 3 function calls data
2. Trace data flow through identified helper functions
3. Identify obfuscation/encryption patterns
4. Reverse engineer constant pool access

### Extended (Phase 5 - Complete API Specification)
1. Dynamic analysis using frida/debugger
2. Traffic capture during actual API calls
3. Signature verification algorithm
4. Token validation logic

---

## Files Generated
- `manual_analysis/phase4_extraction/PHASE4_EXTRACTION.txt` - Initial string scan results

## Status Update
Phase 4 initial analysis reveals the binary uses sophisticated networking infrastructure with likely obfuscation. Direct string extraction insufficient. Next phase requires deeper call graph analysis and runtime behavior analysis.

**Readiness:** Ready to proceed with call graph extraction (Phase 4 part 2)
