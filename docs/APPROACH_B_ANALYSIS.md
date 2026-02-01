# Leaderboard API Extraction - Option B (Deep Reverse Engineering)

## Summary
Since `UpdateLoginToken` doesn't make the actual leaderboard API requests, we need a different approach.

## Findings

### API Hosts (from `iplist.xml`)
```
newlogin.ml.youngjoygame.com
newlogin.ml.mlbangbang.com
login.ml.youngjoygame.com:30021
report.ml.youngjoygame.com:30071
global-login.ml.youngjoygame.com:30021
global-report.ml.youngjoygame.com:30071
https://loginclientversion.ml.youngjoygame.com:30022
```

### Architecture Analysis
1. **BytePlus RTC Library** (`libbyteplusaudio.so`):
   - Handles only voice/video streaming (WebRTC)
   - `UpdateLoginToken` = authentication only, no data fetching

2. **Game Logic**:
   - Unity-based (IL2CPP compiled C#)
   - HTTP requests made from **Java/Kotlin layer**, not native JNI
   - Native libraries found:
     - `libil2cpp.so` - Unity C# runtime
     - `libmoba.so` - Game core (3rd party SDK wrapper)
     - `libunity.so` - Unity engine

3. **Network Stack**:
   - Likely uses **OkHttp3** or **HttpURLConnection** (Java standard)
   - Requests originate from Unity C# → JNI → Java HTTP client

## Option B: Two Approaches

### Approach 1: Runtime Hooking (Fastest) ✅
**Use Frida to hook Java HTTP classes**

#### Setup:
1. Install Frida:
   ```bash
   pip install frida-tools
   ```

2. Connect rooted Android device/emulator with MLBB installed

3. Run the hook:
   ```bash
   frida -U -f com.mobile.legends -l frida_mlbb_api.js --no-pause
   ```

4. Navigate to "Top Global" leaderboard in the app

5. Frida will print:
   - Full URL with query parameters
   - HTTP headers (including auth tokens)
   - POST body (if applicable)
   - Stack trace showing which C# class made the call

#### Output Example:
```
[OkHttp3] POST https://global-report.ml.youngjoygame.com:30071/api/v2/leaderboard
  [!!!] TARGET API DETECTED [!!!]
  Header: Authorization: Bearer <token>
  Header: User-Agent: MLBB/2.1.41
  Body: {"type":"global","hero_id":123,"limit":100}
```

### Approach 2: IL2CPP Dumping (Deeper Understanding)
**Reverse engineer the C# source code**

#### Setup:
1. Download **Il2CppDumper**: https://github.com/Perfare/Il2CppDumper/releases

2. Extract to `il2cppdumper/`

3. Run:
   ```bash
   python dump_il2cpp.py
   ```

4. Open `il2cpp_dump/dump.cs` and search for:
   - `class Leaderboard`
   - `class RankSystem`
   - `class MatchHistory`
   - Methods containing `Request`, `Fetch`, `Query`

5. Find the C# code that builds the HTTP request, then:
   - Identify the URL construction logic
   - Extract required headers/parameters
   - Locate authentication token source

## Why Emulation Failed
- The emulator approach targeted **wrong entry point** (`UpdateLoginToken`)
- Actual API requests happen **asynchronously** after authentication
- Unity games use **managed code** (C#) for game logic, not native functions
- Native JNI only exposes low-level utilities, not business logic

## Recommendation
**Use Approach 1 (Frida)** - it's faster and will capture the exact request format including:
- Dynamic parameters (timestamp, nonce, etc.)
- Authentication signatures
- Proper header order

Once captured, you can replay the request with Python/curl to fetch leaderboard data programmatically.

## Next Steps
1. Set up Frida on rooted device/emulator
2. Run `frida_mlbb_api.js`
3. Trigger leaderboard view in app
4. Copy captured request → document in `mlbb_api_findings.md`
5. Build Python script to replay request with your account tokens
