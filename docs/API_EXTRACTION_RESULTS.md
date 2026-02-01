# MLBB Leaderboard API - Extraction Results

## Final Findings

### API Servers (from version.xml extracted via JADX)

**Global Region:**
- **Global Login:** `global-login.ml.youngjoygame.com:30021`
- **Global Report/Stats:** `global-report.ml.youngjoygame.com:30071`

**US Region:**
- **Login:** `login-mlus.mproject.skystone.games:30021`
- **Report:** `report-mlus.mproject.skystone.games:30071`

**Default Region:**
- **Login:** `login.ml.youngjoygame.com:30021`
- **Report:** `report.ml.youngjoygame.com:30071`
- **Log Server:** `logip="169.57.143.242" logport="9992"`

**Version Check:**
- **URL:** `https://loginclientversion.ml.youngjoygame.com:30022`

---

## Network Configuration

### From AndroidManifest.xml:
- ✅ **Cleartext Traffic Allowed:** `android:usesCleartextTraffic="true"`
- ✅ **No Certificate Pinning:** (Not implemented)
- ✅ **Hostname Verification Disabled:** (Class `q.java` returns `true` for all hosts)

### HTTP Client:
- **Framework:** OkHttp3
- **Implementation:** `com.moba.widget.WidgetWorker` uses OkHttp3 for API calls
- **Trust Manager:** Custom HostnameVerifier that accepts all hostnames (classes4.dex)

---

## Decompiled Code References

### Key Files:
1. **AppInfo.java** (com.moba.unityplugin)
   - Reads `assets/version/android/version.xml`
   - Stores: `mLoginIP`, `mLoginPort`, `mReportIP`, `mReportPort`
   - Global variants: `mLoginIPGlobal`, `mReportIPGlobal`, `mLoginPortGlobal`, `mReportPortGlobal`

2. **WidgetWorker.java** (com.moba.widget)
   - Makes OkHttp3 POST requests to `WidgetUtils.getConfigURL()`
   - Debug URL: `https://test-api.gms.moontontech.com/api/gms/external/source/2713520/2713521`
   - Prod URL: `https://api.gms.moontontech.com/api/gms/external/source/2713520/2713521`

3. **Network Stack** (tt.g.p.f.n.p / q)
   - HttpURLConnection-based class
   - Sets custom HostnameVerifier (q.java) that always returns `true`
   - No SSL pinning

---

## Protocol Information

### Endpoints Likely Include:
- `/api/v2/leaderboard` - Top global leaderboard (estimated)
- `/api/v2/match/history` - Match history (estimated)
- `/api/v2/rank/*` - Ranking queries (estimated)

**Note:** Exact endpoint paths are in encrypted/obfuscated native code (libmoba.so, libil2cpp.so)

### Authentication:
- Handled by native `UpdateLoginToken` function (libmoba.so:0x6426cc)
- Returns authentication token/session in response
- Used for subsequent API calls

### Data Encoding:
- Likely uses protobuf or custom binary format (based on `UdpPipeManager`, `SdpPacker` classes found in libmoba.so)

---

## How to Capture Actual Requests

### Option 1: mitmproxy (requires setup)
```bash
pip install mitmproxy
mitmproxy -s mitm_mlbb.py
# Configure device/emulator to use proxy
# All traffic to youngjoygame.com will be logged
```

### Option 2: tcpdump + Wireshark (alternative)
```bash
tcpdump -i any -w mlbb_capture.pcap host youngjoygame.com
# View in Wireshark, filter by HTTP/HTTPS
```

### Option 3: Frida (if device is rooted)
```javascript
// Use the frida_mlbb_api.js script provided
// Hooks OkHttp3 class before encryption
```

---

## Key Findings Summary

| Item | Value |
|------|-------|
| **Game Library** | libmoba.so (1.78MB) compiled C++ |
| **Network Type** | Cleartext allowed + TLS (no pinning) |
| **API Host** | youngjoygame.com (Moonton's parent YoungJoy) |
| **Port** | 30021 (login), 30071 (report/leaderboard) |
| **HTTP Client** | OkHttp3 (no cert pinning) |
| **Auth** | Native token from UpdateLoginToken() |
| **Hostname Verification** | Disabled (always returns true) |
| **Encryption** | TLS only, no additional app-level encryption detected |

---

## Proof of Extraction

**Files generated:**
- `apk_decompiled/` - apktool output
- `jadx_out/` - JADX CLI decompilation
- `jadx_out/sources/com/moba/` - Game logic source
- `jadx_out/resources/assets/version/android/version.xml` - API config

**Code verified in:**
- `jadx_out/sources/com/moba/unityplugin/AppInfo.java` (lines 600-780)
- `jadx_out/sources/com/moba/widget/WidgetUtils.java` (line 166)
- `jadx_out/sources/tt/g/p/f/n/q.java` (hostname verifier bypass)

