# IL2CPP Approach Summary - Prerequisites & Alternative Solutions

## Status: Blocked by Missing Dependencies

### What Happened
Attempted to use **Il2CppDumper** to extract C# source code from Unity game, but encountered missing dependencies:

1. **Il2CppDumper downloaded** ✅ (v6.7.46)
2. **.NET Runtime missing** ❌ (requires .NET 6.0)
3. **Metadata files empty** ❌ (0 bytes in extracted APK)

### Why Metadata Extraction Failed
- `global-metadata.dat` files are 0 bytes in both `extracted_apk` and `extracted_apk_old`
- Unity IL2CPP games sometimes:
  - Embed metadata inside `libil2cpp.so` binary
  - Encrypt metadata in asset bundles
  - Store metadata in custom compressed formats

### Prerequisites for IL2CPP Approach

#### Option A: Install .NET Runtime (Required for Il2CppDumper)
```powershell
# Download .NET 6 Runtime from:
https://dotnet.microsoft.com/en-us/download/dotnet/6.0

# Or use installer:
choco install dotnet-6.0-runtime
```

#### Option B: Extract Metadata from APK Properly
The APK needs to be re-extracted with proper tools that handle Unity asset encryption:

```powershell
# Use apktool instead of basic unzip:
apktool d mobile-legends.apk -o extracted_apk_proper

# Or use Asset Studio to extract Unity assets:
# https://github.com/Perfare/AssetStudio
```

## RECOMMENDED: Use Frida Instead (No Prerequisites)

### Why Frida is Better for This Task

#### Advantages:
1. ✅ **No compilation needed** - Pure JavaScript runtime hooking
2. ✅ **Captures actual requests** - Real URLs, headers, authentication tokens
3. ✅ **Works with obfuscated code** - Hooks at Java layer before encryption
4. ✅ **Immediate results** - See API calls as they happen
5. ✅ **No reverse engineering** - Don't need to understand C# source

#### What You Get:
```javascript
[OkHttp3] POST https://global-report.ml.youngjoygame.com:30071/GetTopGlobalPlayers
  [!!!] TARGET API DETECTED [!!!]
  Header: Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
  Header: X-Session-ID: 1234567890
  Header: User-Agent: MLBB/2.1.41 (Android 11)
  Body: {"hero_id":32,"region":"global","limit":100}
```

### Setup Frida (10 minutes)

#### 1. Install Frida Tools
```bash
pip install frida-tools
```

#### 2. Setup Android Device
**Option A: Physical Device (Recommended)**
```bash
# Root your device (Magisk recommended)
# Install Frida server:
adb push frida-server-16.0.19-android-arm64 /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
```

**Option B: Emulator**
```bash
# Use rooted emulator image (e.g., Nox, LDPlayer)
# Install MLBB APK
# Install Frida server same as above
```

#### 3. Run Interception
```bash
cd C:\dev\NativeGhost
frida -U -f com.mobile.legends -l frida_mlbb_api.js --no-pause
```

#### 4. Trigger API Call
1. Launch MLBB
2. Navigate: **Ranked → Top Global**
3. Select a hero (e.g., Fanny, Gusion)
4. View leaderboard/match history

#### 5. Capture Output
Frida will print:
- Full request URL with parameters
- All HTTP headers (including auth tokens)
- POST body (JSON payload)
- Stack trace showing which class initiated the call

## What We Learned from Binary Analysis

### Known API Servers (from iplist.xml)
```
login.ml.youngjoygame.com:30021          # Authentication
report.ml.youngjoygame.com:30071         # Telemetry/Stats
global-login.ml.youngjoygame.com:30021   # Global auth
global-report.ml.youngjoygame.com:30071  # Global stats (LIKELY HAS LEADERBOARD)
```

### Architecture
```
┌─────────────────────────────────────┐
│  Unity C# Game Logic (IL2CPP)      │
│  - Leaderboard UI                   │
│  - API Request Builders             │
└──────────────┬──────────────────────┘
               │ JNI Call
┌──────────────▼──────────────────────┐
│  Java/Kotlin Network Layer          │
│  - OkHttp3 / HttpURLConnection      │  ← Frida hooks HERE
│  - Adds auth headers                │
└──────────────┬──────────────────────┘
               │ Socket
┌──────────────▼──────────────────────┐
│  youngjoygame.com API               │
│  /api/v2/leaderboard (estimated)    │
└─────────────────────────────────────┘
```

### Why Emulator Approach Failed
- Targeted `UpdateLoginToken` in `libbyteplusaudio.so` (BytePlus RTC SDK)
- That function only handles **voice chat authentication**, not game APIs
- Actual leaderboard requests come from Unity C# → Java HTTP client
- No network calls detected because we were hooking wrong library

## Next Steps

### If You Want to Continue IL2CPP Approach:
1. Install .NET 6 Runtime
2. Re-extract APK with apktool or Asset Studio
3. Run Il2CppDumper
4. Search dump.cs for leaderboard classes
5. Manually reconstruct API request format

**Time estimate: 2-4 hours**

### If You Want Results Fast:
1. Setup Frida (see above)
2. Run enhanced script: `frida_mlbb_api.js`
3. Navigate to leaderboard in game
4. Copy/paste the captured request

**Time estimate: 15-30 minutes**

## Files Created
- `frida_mlbb_api.js` - Enhanced Frida hook script ✅
- `parse_metadata.py` - Custom metadata parser (blocked by empty files)
- `dump_il2cpp.py` - Il2CppDumper wrapper (needs .NET)
- `il2cppdumper/` - Il2CppDumper v6.7.46 binaries

## Recommendation
**Use Frida.** The IL2CPP approach is academically interesting but Frida will give you the exact request format in 1/10th the time.
