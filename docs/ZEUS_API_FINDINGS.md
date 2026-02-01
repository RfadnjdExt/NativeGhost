# Livestream API Analysis - Qiniu Zeus Integration

## Critical Discovery: Qiniu Zeus API

### Location
[File: com/qiniu/pili/droid/shortvideo/core/u.java](../jadx_out/sources/com/qiniu/pili/droid/shortvideo/core/u.java)
- **Class**: `ZeusManager` (obfuscated as `u`)
- **Package**: `com.qiniu.pili.droid.shortvideo.core`

### API Endpoint
```
https://shortvideo.qiniuapi.com/v1/zeus?appid=<APP_ID>
```

### Request Method
- **HTTP Method**: GET
- **Response Code Expected**: 200 (authorized), 401 (unauthorized)
- **Response Format**: JSON

### Response Structure (CRITICAL)

The Zeus API returns a **JSONArray** containing feature configuration:

```java
// Line 268-277 in u.java
private void a(String str) {
    try {
        JSONArray jSONArray = new JSONArray(str);
        this.d.clear();
        for (int i = 0; i < jSONArray.length(); i++) {
            this.d.add(Integer.valueOf(jSONArray.getJSONObject(i).getInt("id")));
        }
    } catch (JSONException e2) {
        e2.printStackTrace();
    }
}
```

**Response Schema**:
```json
[
  {
    "id": <integer>
  },
  {
    "id": <integer>
  }
  ...
]
```

Each object in the array has at minimum:
- **`id`** (integer): Feature ID for authorization checking

### Zeus Manager Lifecycle

1. **Initialization** (lines 120-133):
   - Loads from SharedPreferences (`ShortVideo` prefs):
     - `ts`: Timestamp (Base64 encoded)
     - `feature`: Feature list (Base64 encoded)

2. **Authentication Check** (lines 195-209):
   - Checks if response code is 200 → sets status to `Authorized`
   - Checks if response code is 401 → sets status to `UnAuthorized`
   - Otherwise → keeps status as `UnCheck`

3. **Cache Strategy** (lines 88-91):
   - Cache validity: 1 HOUR for authorized features
   - Cache validity: 60 SECONDS for unauthorized features
   - Revalidates when cache expires

4. **Feature Authorization** (lines 260-275):
   - Compares requested feature ID against list from Zeus API
   - Returns `true` if feature ID is in authorized list
   - Logs denial: `"no authorized feature : " + feature + " status : " + status`

### Request Flow

```
app startup
    ↓
ZeusManager.a(Context) [initialization]
    ↓
Load cached feature list from SharedPreferences
    ↓
[Optional] Call b(pLAuthenticationResultCallback) on new Thread
    ↓
GET https://shortvideo.qiniuapi.com/v1/zeus?appid=<APP_ID>
    ↓
Parse JSONArray response
    ↓
Extract all "id" fields into ArrayList
    ↓
Cache in SharedPreferences (Base64 encoded)
    ↓
Use for feature authorization checks
```

### Important Note

**This is the FEATURE AUTHORIZATION mechanism, NOT the Live List API.**

The Zeus API returns feature flags (like `livestream_enabled=1`, `short_video_enabled=1`, etc.), not the actual livestream list (streams, categories, etc.).

### Next Step

The actual **livestream list** (with "Populer", "Terbaru", "Terkuat", etc. categories) is likely:
1. Fetched by a different API endpoint (not yet identified)
2. Configured in Firebase Remote Config
3. Loaded separately from another Qiniu endpoint
4. Embedded in the app's C# (IL2CPP) code and loaded at runtime

### Related Code

- **SettingsManager** (com/bytedance/gmvideoplayer/core/common/f.java): 
  - Loads remote config with `live_player_properties` JSONArray
  - This MAY contain the livestream list endpoint

- **ShareFacebook** (com/moba/unityplugin/ShareFacebook.java):
  - Facebook Live broadcast integration
  - Proves livestream feature is implemented

### EmulatorEnhancements

The modified emulator (emulator_rust/src/main.rs) will now:
1. Detect Zeus API requests (logs to `livestream_api_requests.log`)
2. Capture Zeus API responses (logs to `livestream_responses.log`)
3. Flag any memory/network traffic containing livestream keywords

---

**Status**: Zeus API identified as feature authorization layer. Actual livestream list endpoint still pending discovery.
