# Livestream API Discovery - Progress Report

## Summary

We have successfully identified and documented the **Qiniu Zeus API** which is the feature authorization layer for the livestream feature. However, this is NOT the livestream list API itself.

## Key Findings

### 1. Qiniu Zeus API (Feature Authorization)
- **Endpoint**: `https://shortvideo.qiniuapi.com/v1/zeus?appid=<APP_ID>`
- **Method**: GET
- **Response**: JSONArray of feature IDs for authorization
- **Purpose**: Controls whether livestream feature is enabled/disabled
- **Cache**: 1 hour (authorized), 60 seconds (unauthorized)
- **Implementation**: [com/qiniu/pili/droid/shortvideo/core/u.java](../jadx_out/sources/com/qiniu/pili/droid/shortvideo/core/u.java)

### 2. ByteDance Settings Manager (Config Injection Point)
- **File**: [com/bytedance/gmvideoplayer/core/common/f.java](../jadx_out/sources/com/bytedance/gmvideoplayer/core/common/f.java)
- **Fields**:
  - `live_player_properties`: JSONArray (contains live player config)
  - `video_player_properties`: JSONArray (video config)
- **Purpose**: Loads remote configuration for streaming behavior
- **Config flags**: `report_live_player_log`, `enable_sei_live_off_check`, timeouts

### 3. Facebook Live Broadcast Integration
- **File**: [com/moba/unityplugin/ShareFacebook.java](../jadx_out/sources/com/moba/unityplugin/ShareFacebook.java)
- **Endpoint**: `/{userId}/live_videos` (Facebook Graph API)
- **Purpose**: Create live broadcast (not for viewing/discovering streams)

### 4. Qiniu SDK Integration
- **Package**: `com.qiniu.pili.droid.shortvideo`
- **File**: [com/qiniu/pili/droid/shortvideo/core/c.java](../jadx_out/sources/com/qiniu/pili/droid/shortvideo/core/c.java)
- **Associated package**: `com.yaoyao.live`
- **Purpose**: Short video/livestream SDK by Qiniu

---

## Still Missing

### Livestream List API
The actual livestream list (with categories: "Populer", "Terbaru", "Terkuat", "Karismatik", "Overdrive") has **NOT been found** in:
- Hardcoded URL strings in DEX files (180+ endpoints checked)
- IL2CPP metadata (Unity compiled code)
- Native library symbols (.so files)
- Smali bytecode patterns

### Likely Locations (Hypothesis)
1. **Remote Configuration** - Delivered via Firebase Remote Config or similar service
2. **API Response Parsing** - The endpoint may be constructed dynamically (not hardcoded)
3. **Native Module** - May be called from IL2CPP code without Java wrapper
4. **Dynamic String Construction** - Could be built at runtime using app metadata

---

## Emulator Enhancements

The modified Rust emulator (`emulator_rust/src/main.rs`) now detects and logs:

### SSL_write Hook
- Captures outgoing API requests containing:
  - "zeus", "shortvideo", "qiniu", "appid" → Logs to `livestream_api_requests.log`
  - "live", "stream", "streamer", "room", "anchor", "popular", "hot"

### SSL_read Hook
- Monitors incoming responses for livestream-related data
- Logs responses containing livestream keywords to `livestream_responses.log`

### Memory Scanner
- Extended `print_strings()` function to flag livestream-related terms
- Triggers on any memory region containing livestream keywords

---

## Next Steps

### Priority 1: Execute Emulator with App
- Run the enhanced emulator against the decompiled APK
- Monitor `livestream_api_requests.log` and `livestream_responses.log`
- Parse captured API responses

### Priority 2: Search IL2CPP Implementation
- Examine `libunity.so` for livestream API calls
- Look for hardcoded streaming server addresses in compiled code

### Priority 3: Dynamic Analysis
- Instrument app at runtime using Frida or similar tools
- Hook network APIs to intercept actual API calls
- Capture live request/response pairs

### Priority 4: Firebase Remote Config
- Search for Firebase config delivery patterns
- Identify config key names for livestream settings

---

## Files Modified/Created

1. **emulator_rust/src/main.rs** ✅ Enhanced with livestream detection
2. **scripts/parse_livestream_responses.py** ✅ Created for parsing captured responses
3. **docs/ZEUS_API_FINDINGS.md** ✅ Detailed Zeus API documentation
4. **docs/LIVESTREAM_API_ANALYSIS.md** ← This file

---

## Status

**Complete**: Feature authorization mechanism (Zeus API) identified and documented
**In Progress**: Locating actual livestream list API
**Pending**: Runtime execution and API response capture

