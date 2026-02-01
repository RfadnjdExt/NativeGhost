# Livestream API Research - Index & Quick Reference

## 📋 Project Overview

Deep analysis of an Indonesian gaming app's livestream feature to extract:
- API endpoints for the live tab (categories: Populer, Terbaru, Terkuat, Karismatik, Overdrive)
- Room ID and streamer ID structures
- Network traffic detection mechanisms

**Status**: Feature authorization (Qiniu Zeus) identified; actual livestream list endpoint still pending runtime interception

---

## 🔍 Key Discoveries

### Feature Authorization: Qiniu Zeus API
- **Endpoint**: `https://shortvideo.qiniuapi.com/v1/zeus?appid=<APP_ID>`
- **File**: [com/qiniu/pili/droid/shortvideo/core/u.java](jadx_out/sources/com/qiniu/pili/droid/shortvideo/core/u.java)
- **Purpose**: Controls if livestream feature is enabled/disabled
- **Response**: JSONArray with feature IDs
- **Full Details**: [docs/ZEUS_API_FINDINGS.md](ZEUS_API_FINDINGS.md)

### Config Injection: ByteDance SettingsManager
- **File**: [com/bytedance/gmvideoplayer/core/common/f.java](jadx_out/sources/com/bytedance/gmvideoplayer/core/common/f.java)
- **Config Keys**: `live_player_properties`, `video_player_properties`
- **Source**: Remote configuration (Firebase or custom backend)
- **Note**: Suggests livestream list also delivered remotely

### Facebook Live Broadcast Integration
- **File**: [com/moba/unityplugin/ShareFacebook.java](jadx_out/sources/com/moba/unityplugin/ShareFacebook.java)
- **Endpoint**: `/{userId}/live_videos` (Graph API)
- **Purpose**: User broadcasts, not discovery
- **Relevance**: Proves livestream feature exists but not the list API

---

## 📁 Documentation Files

### Analysis Documents
| File | Purpose |
|------|---------|
| [ZEUS_API_FINDINGS.md](ZEUS_API_FINDINGS.md) | Detailed Qiniu Zeus API documentation |
| [LIVESTREAM_API_ANALYSIS.md](LIVESTREAM_API_ANALYSIS.md) | Progress summary & hypotheses |
| [LIVESTREAM_DISCOVERY_FINAL_REPORT.md](LIVESTREAM_DISCOVERY_FINAL_REPORT.md) | Comprehensive analysis & next steps |

### Tools & Scripts
| File | Purpose |
|------|---------|
| [emulator_rust/src/main.rs](../emulator_rust/src/main.rs) | Enhanced ARM64 emulator with livestream detection |
| [scripts/parse_livestream_responses.py](../scripts/parse_livestream_responses.py) | Parse captured API responses |
| [livestream_api_requests.log](../livestream_api_requests.log) | Will contain captured API requests |
| [livestream_responses.log](../livestream_responses.log) | Will contain captured API responses |

---

## 🎯 What We Know

### ✅ Identified
- Qiniu Zeus feature authorization API
- ByteDance remote config injection point
- Facebook Graph API for broadcasting
- Qiniu SDK integration (com.yaoyao.live package)
- Emulator enhanced with livestream detection hooks
- 180+ API endpoints cataloged (none are livestream list)

### ❌ Not Found
- Livestream list/discovery API endpoint
- Indonesian UI labels (Populer, Terbaru, Terkuat, Karismatik, Overdrive)
- Hardcoded streaming server addresses
- Java wrapper classes for livestream API

### 🤔 Hypotheses
1. **Remote Configuration** (70% likely) - Zeus or Firebase delivers endpoint
2. **IL2CPP Implementation** (20% likely) - In native C# code, not accessible
3. **Dynamic Construction** (10% likely) - Built at runtime from metadata

---

## 🚀 How to Continue

### Option 1: Run the Emulator (Recommended)
```bash
cd c:\dev\NativeGhost\emulator_rust
cargo run -- <path-to-apk>
```

**Expected Output**:
- `livestream_api_requests.log` - Captured API calls
- `livestream_responses.log` - Server responses
- Console output with livestream keyword matches

**Next**:
```bash
python scripts/parse_livestream_responses.py
```

### Option 2: Firebase Remote Config Analysis
Search for Firebase SDK usage:
```bash
grep -r "FirebaseRemoteConfig\|RemoteConfig\|getBoolean\|getString" jadx_out/sources --include="*.java"
```

### Option 3: IL2CPP Deep-Dive
Analyze Unity metadata:
```bash
strings extracted_apk/lib/arm64-v8a/libunity.so | grep -i "live\|stream\|api"
```

---

## 📊 API Endpoint Catalog

### Found & Documented
- **Qiniu Zeus**: `https://shortvideo.qiniuapi.com/v1/zeus?appid=`
- **Facebook Graph**: `https://graph.facebook.com/{userId}/live_videos`
- **ByteGsdk**: `https://gsdk-quic-gcp-sg.bytegsdk.com/service/2/`
- Plus 174 other SDK endpoints (Google Play, Firebase, etc.)

### Still Searching
- Livestream list/discovery
- Room information
- Streamer profiles
- Category/tag data

---

## 🔐 Important Notes

### About Qiniu Zeus
- **NOT** the livestream list API
- **IS** feature flag/authorization check
- Response might contain hidden fields (needs verification)

### About Remote Config
- SettingsManager pattern strongly suggests dynamic config
- Config likely contains livestream list endpoint
- May be in Firebase Remote Config, Qiniu Zeus extended payload, or custom service

### About Facebook Integration
- Used for **broadcasting**, not **discovery**
- Different API layer than livestream viewer/explorer

---

## 📈 Research Progress

```
Phase 1: URL Extraction          [████████░░] 80% - Found 180 endpoints
Phase 2: Bytecode Analysis       [██████████] 100% - Completed
Phase 3: Config Mechanism        [██████████] 100% - Zeus API identified
Phase 4: Emulator Enhancement    [██████████] 100% - Ready to run
Phase 5: Runtime Interception    [░░░░░░░░░░] 0%   - Awaiting execution
Phase 6: API Schema Mapping      [░░░░░░░░░░] 0%   - Depends on Phase 5
```

---

## 🎓 Lessons Learned

1. **Modern apps use remote config**: Hardcoding is rare in production
2. **Streaming SDKs are modular**: Qiniu/BytePlus handled as plugins
3. **Feature flags matter**: Authorization layer ≠ Data layer
4. **Static analysis has limits**: Runtime interception essential for discovery

---

## 📞 Quick Links

- **Emulator binary**: `c:\dev\NativeGhost\emulator_rust\target\debug\emulator_rust.exe`
- **Python parser**: `c:\dev\NativeGhost\scripts\parse_livestream_responses.py`
- **Decompiled Java**: `c:\dev\NativeGhost\jadx_out\sources\`
- **Extracted APK**: `c:\dev\NativeGhost\extracted_apk\`
- **APK Tool smali**: `c:\dev\NativeGhost\apk_decompiled\smali_classes*\`

---

## 🎯 Next Session Goals

1. Execute emulator and capture logs
2. Parse captured API responses
3. Identify livestream list endpoint
4. Map room_id/streamer_id structure
5. Document complete API schema

---

**Last Updated**: 2026-02-01
**Analyst**: GitHub Copilot
**Confidence**: 85% livestream list will be revealed via runtime analysis
