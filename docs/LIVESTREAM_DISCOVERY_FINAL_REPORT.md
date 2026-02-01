# Livestream API Discovery - Final Analysis Report

## Executive Summary

After extensive analysis of the APK decompilation, we have identified the **livestream feature architecture** but have NOT yet located the actual Live tab list API endpoint. The evidence suggests it is either:

1. **Dynamically configured** via remote config service
2. **Implemented in native/IL2CPP code** (not accessible in Java decompilation)
3. **Constructed at runtime** from app metadata or server responses

---

## Discovery Timeline

### Phase 1: Initial Search
- **Goal**: Find livestream API endpoints in hardcoded URLs
- **Result**: Extracted 180+ unique endpoints from DEX files
- **Outcome**: No `/live_list`, `/stream_list`, or similar endpoints found

### Phase 2: Bytecode Analysis  
- **Goal**: Find livestream class definitions and API calls
- **Result**: Scanned smali, Java sources, and IL2CPP metadata
- **Outcome**: Found Facebook Live broadcast integration, Qiniu SDK references, but no viewer list API

### Phase 3: Config Mechanism Analysis
- **Goal**: Identify configuration injection points
- **Result**: Found Qiniu Zeus API and ByteDance SettingsManager
- **Outcome**: Identified **feature authorization layer** but not the actual data API

---

## Detailed Findings

### 1. Qiniu Zeus API (Feature Authorization)

**File**: [com/qiniu/pili/droid/shortvideo/core/u.java](../jadx_out/sources/com/qiniu/pili/droid/shortvideo/core/u.java)

**Endpoint**:
```
https://shortvideo.qiniuapi.com/v1/zeus?appid=<APP_ID>
```

**Implementation Details**:
- HTTP Method: GET
- Response Code 200: Feature Authorized
- Response Code 401: Feature Unauthorized
- Response Format: JSONArray of feature IDs

**Cache Strategy**:
- Success: 1 HOUR cache (SharedPreferences)
- Failure: 60 SECOND cache
- Cache Keys: `ts` (timestamp), `feature` (Base64 encoded)

**Authorization Check**:
```java
public boolean a(com.qiniu.pili.droid.shortvideo.core.b bVar) {
    // ... cache check logic ...
    if (!this.d.isEmpty()) {
        return this.d.contains(Integer.valueOf(bVar.a()));
    }
    return true; // If feature list is empty, allow
}
```

**Purpose**: Controls whether livestream/short video features are **enabled**, not what content to show.

---

### 2. ByteDance Settings Manager (Config Injection Point)

**File**: [com/bytedance/gmvideoplayer/core/common/f.java](../jadx_out/sources/com/bytedance/gmvideoplayer/core/common/f.java)

**Config Fields**:
```java
public static JSONArray e = null;  // live_player_properties
public static JSONArray f = null;  // video_player_properties
```

**Configuration Keys**:
- `enable_render_shared_mem`
- `report_live_player_log`
- `report_sei_detail_log`
- `enable_draw_sync`
- `update_frame_data_sync`
- `emulator_use_soft_decoder`
- `live_player_properties` ← **Contains livestream player config**
- `video_player_properties` ← **Contains video player config**
- `enable_sei_live_off_check`
- Various timeout settings (okhttp, downloader, etc.)

**Initialization Flow**:
```
1. SettingsManager.a(JSONObject config) called
2. Extracts "live_player_properties" as JSONArray
3. Stores in static field 'e'
4. Used throughout app for livestream behavior
```

**Implication**: Config is injected from **remote source** - likely Firebase Remote Config or custom backend API.

---

### 3. Facebook Live Integration (Broadcast, Not Discovery)

**File**: [com/moba/unityplugin/ShareFacebook.java](../jadx_out/sources/com/moba/unityplugin/ShareFacebook.java)

**Endpoint**: `/{userId}/live_videos` (Facebook Graph API)

**Purpose**: **Create** live broadcasts, not view/discover streams

**Flow**:
```
User shares gameplay → ShareFacebook → POST /{userId}/live_videos
                    → Returns: stream_url (RTMP), embed_html
```

**Not Relevant For**: Discovering live streams or getting live tab list

---

### 4. Native Code Hints

**REQUEST_STREAMER Constant**:
```java
// From Utile.java:75
public static final int REQUEST_STREAMER = 34;
```

**Status**: Defined but never used in Java code
**Implication**: Used from native code (IL2CPP C# → JNI) or intent result handler

**Native Libraries Scanned**:
- `libmoba.so` - Gameplay engine
- `libvp_bridge.so` - Video processing
- `libunity.so` - IL2CPP runtime
- `lib**.so` - All other native libs

**Result**: No livestream API endpoints found in symbol strings

---

## What's Missing

### The Live Tab List API
Elements we **expected to find** but **didn't**:

1. **Hardcoded endpoint URL**
   - Expected patterns: `/v1/live`, `/api/streams`, `/service/live_list`
   - Result: NOT FOUND in any DEX file or binary

2. **UI string translations**
   - Expected: "Populer", "Terbaru", "Terkuat", "Karismatik", "Overdrive"
   - Expected locations: strings.xml, assets, IL2CPP metadata
   - Result: NOT FOUND - suggests runtime-loaded translations

3. **Java API wrapper class**
   - Expected: `LiveStreamAPI`, `StreamListManager`, etc.
   - Result: NOT FOUND - suggests native implementation

4. **Network request constants**
   - Expected: `/live/popular`, `/stream/recent`, etc.
   - Result: NOT FOUND

---

## Hypotheses

### Hypothesis A: Remote Configuration
**Likelihood**: **HIGH** (70%)

The live list endpoint is delivered via:
1. Firebase Remote Config
2. Qiniu Zeus API response (extended payload)
3. Custom bytedance service

**Evidence**:
- SettingsManager pattern strongly suggests remote config
- No hardcoded URLs found despite thorough search
- Zeus API caching mechanism indicates dynamic delivery

**Test**: Hook app initialization to intercept config JSON

---

### Hypothesis B: IL2CPP Native Implementation
**Likelihood**: **MEDIUM** (20%)

The livestream list API is:
1. Called directly from C# game code
2. Endpoint hardcoded in IL2CPP binary metadata
3. No Java wrapper needed

**Evidence**:
- `REQUEST_STREAMER = 34` defined but unused in Java
- No livestream API classes in Java decompilation
- IL2CPP bytecode not fully decompiled

**Test**: Deep analysis of libunity.so metadata section

---

### Hypothesis C: Dynamic String Construction
**Likelihood**: **MEDIUM** (10%)

The API endpoint is:
1. Built at runtime from multiple sources
2. Concatenated from config values
3. Not visible in static analysis

**Evidence**:
- Some string concatenation observed in URL building
- No complete endpoint URLs in extracted strings

**Test**: Runtime interception with debugger

---

## Solution Paths

### Path 1: Emulator-Based Interception ✅ Ready
**Status**: Emulator enhanced and compiled
**Next**: Execute with app to capture network traffic

**Implementation**:
```
emulator_rust/src/main.rs
├── SSL_write hook → logs to livestream_api_requests.log
├── SSL_read hook → logs to livestream_responses.log
└── Memory scanner → flags livestream keywords
```

**Script to parse output**:
```
scripts/parse_livestream_responses.py
```

---

### Path 2: Firebase Remote Config Analysis
**Status**: Not yet analyzed
**Next**: Search for Firebase/GMS RemoteConfig calls

**Search pattern**: Look for `FirebaseRemoteConfig.getInstance()` calls

---

### Path 3: IL2CPP Metadata Deep-Dive  
**Status**: Initial scan completed (no matches)
**Next**: Full IL2CPP binary reverse engineering

**Tool needed**: `il2cppdumper` with metadata + binary analysis

---

### Path 4: Qiniu Zeus Extended Analysis
**Status**: Feature authorization identified
**Next**: Check if Zeus response contains additional payload

**Hypothesis**: Zeus API response might include:
```json
[
  { "id": 1 },
  { "id": 2 },
  "_live_list_url": "https://..."  // Hidden field
]
```

---

## Implementation Status

### Completed ✅
- [x] Full APK decompilation (JADX)
- [x] URL extraction from all DEX files
- [x] Native library scanning
- [x] IL2CPP metadata analysis
- [x] Qiniu Zeus API discovery & documentation
- [x] Facebook Live integration mapping
- [x] Emulator enhancement with livestream detection
- [x] Response parsing script creation

### In Progress 🔄
- [ ] Emulator execution and log analysis
- [ ] Firebase RemoteConfig pattern search
- [ ] IL2CPP deeper analysis

### Not Started ⏳
- [ ] Live API endpoint identification
- [ ] Room/Streamer ID structure mapping
- [ ] Runtime dynamic analysis (Frida hooks)

---

## Key Files Created

1. **docs/ZEUS_API_FINDINGS.md** - Qiniu Zeus detailed documentation
2. **docs/LIVESTREAM_API_ANALYSIS.md** - This analysis
3. **scripts/parse_livestream_responses.py** - Response parser
4. **emulator_rust/src/main.rs** - Enhanced emulator with hooks
5. **livestream_api_requests.log** - Will capture API requests
6. **livestream_responses.log** - Will capture API responses

---

## Recommendations

### Immediate Next Steps
1. **Execute emulator** with compiled binary against APK
2. **Capture network logs** during app startup and livestream feature access
3. **Parse captured responses** using provided Python script
4. **Analyze response structure** to extract livestream data schema

### If Emulator Approach Fails
1. **Use Frida** to hook `HttpsURLConnection.getInputStream()`
2. **Install APK** on real device or emulator
3. **Monitor logcat** for API traffic
4. **Intercept via mitmproxy** if possible

### Long-Term Analysis
1. Instrument IL2CPP runtime for native API calls
2. Analyze Firebase console configuration
3. Reverse-engineer streaming server architecture

---

## Conclusion

We have successfully mapped the **feature authorization infrastructure** (Qiniu Zeus + ByteDance SettingsManager) but the actual **livestream content list API** remains elusive. This is likely by design - the app uses remote configuration for flexibility.

The enhanced emulator with livestream detection hooks provides a promising path to discovery via runtime interception. Once the API endpoint is identified, documenting the room_id, streamer_id, and category structures should follow quickly.

**Confidence Level**: 85% that livestream list API will be revealed via emulator logging or Firebase config analysis.

