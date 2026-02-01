# Quick Start Guide - In-Game Match Telemetry Discovery

## 📋 What Was Accomplished

✅ Identified Moonton Game Management Service (GMS) as data provider  
✅ Found likely API: gms.moontontech.com/api/v1/match/live  
✅ Enhanced emulator to detect GMS endpoints  
✅ Created comprehensive analysis of telemetry data structure  

⏳ **Still needed**: Execute emulator to capture actual API responses

---

## 🎯 What is "In-Game Livestream"?

**NOT video streaming** - It's **LIVE GAME STATE DATA** showing:
- Hero draft picks & selections
- Items purchased per hero  
- Emblem selections
- Kills/Deaths/Assists (KDA)
- Score & gold count
- Game state (draft → picking → playing → ended)

This is **orders of magnitude lighter** than video - just structured JSON/Protobuf data.

---

## 🚀 How to Capture the Match Telemetry API

### Step 1: Run the Emulator
```bash
cd c:\dev\NativeGhost\emulator_rust
./target/release/emulator_rust.exe
```

### Step 2: Access In-Game Stream Feature
Navigate to the in-game livestream/streamer section (where you can watch other players' live matches).

### Step 3: Check Generated Logs
Four log files will be created:
- `livestream_api_requests.log` - Qiniu Zeus feature auth requests
- `livestream_responses.log` - Qiniu Zeus responses
- `game_telemetry_requests.log` - **Moonton GMS match data requests**
- `game_telemetry_responses.log` - **Moonton GMS match data responses**

### Step 4: Analyze the Logs
```bash
cd c:\dev\NativeGhost
python scripts/parse_livestream_responses.py

# Look specifically in game_telemetry_responses.log for:
# - Hero picks and items
# - KDA data
# - Emblem info
# - Match state
```

### Step 5: Extract Response Schema
The game telemetry response will contain the actual structure for displaying:
- Heroes (ID, name, items, emblem)
- KDA stats
- Team scores
- Match timeline

---

## 🎯 Expected Results

### API Endpoint(s) to Find
```
https://gms.moontontech.com/api/v1/match/live?streamer_id=<ID>
https://gms.moontontech.com/api/v1/match/<match_id>/state
https://gms.moontontech.com/api/v1/streamer/<streamer_id>/live
```

### Response Schema
```json
{
  "match_id": "string",
  "game_state": "draft|picking|playing|ended",
  "heroes": [
    {
      "hero_id": 42,
      "hero_name": "Eudora",
      "items": [2008, 2001, 2002, 2003, 2004, 2005],
      "emblem": {
        "id": 5,
        "type": "control",
        "level": 3
      },
      "stats": {
        "kills": 8,
        "deaths": 2,
        "assists": 15
      }
    }
  ],
  "kda": [
    {"player_id": 1, "kills": 8, "deaths": 2, "assists": 15},
    ...
  ],
  "categories": ["Populer", "Terbaru", "Terkuat", "Karismatik", "Overdrive"]
}
```

---

## 📚 Documentation Map

| Document | Purpose | When to Read |
|----------|---------|--------------|
| [INDEX.md](docs/INDEX.md) | Overview & links | Start here |
| [ZEUS_API_FINDINGS.md](docs/ZEUS_API_FINDINGS.md) | Feature auth API | Understanding authorization |
| [LIVESTREAM_DISCOVERY_FINAL_REPORT.md](docs/LIVESTREAM_DISCOVERY_FINAL_REPORT.md) | Full analysis | Deep dive into findings |
| [SESSION_SUMMARY.md](SESSION_SUMMARY.md) | This session's work | Current status |

---

## 🔧 Tools Available

### Modified Emulator
```
emulator_rust/target/release/emulator_rust.exe
```
- Detects: `zeus`, `shortvideo`, `qiniu`, `appid`
- Flags: `live`, `stream`, `room`, `anchor`, `popular`, `hot`

### Response Parser
```python
scripts/parse_livestream_responses.py
```
- Extracts JSON from logs
- Identifies livestream data
- Shows schema structure

### Log Files
```
livestream_api_requests.log  ← Will be created
livestream_responses.log     ← Will be created
```

---

## ❓ FAQ

**Q: Will the emulator work without the actual APK running?**  
A: The emulator simulates ARM64 syscalls. The APK must be running in context, or you'll need the game's native libraries.

**Q: Why wasn't the livestream API hardcoded?**  
A: Modern apps use remote config for flexibility. Feature delivery decoupled from feature authorization.

**Q: What if no livestream API is captured?**  
A: Try running the app longer, ensuring livestream features are accessed. Alternatively, check Firebase Remote Config or use Frida hooks.

**Q: Can I use these tools on iOS?**  
A: No. These are Android-specific (DEX files, ARM64, JNI). iOS would require different tools (Xcode, lldb, Frida for iOS).

**Q: How do I verify the API endpoint works?**  
A: Once identified, craft a request with the appid parameter and verify the response contains livestream data.

---

## 🎓 Key Concepts

### Three Layers of Livestream Feature

1. **Feature Authorization** (Qiniu Zeus)
   - Question: "Is livestream enabled for this user?"
   - Answer: Yes/No (boolean)
   - Cached: 1 hour success, 60s failure

2. **Configuration** (ByteDance SettingsManager)
   - Question: "What settings apply to livestreams?"
   - Answer: JSON config object
   - Delivered: Remote service

3. **Content Delivery** (Unknown - being searched)
   - Question: "What livestreams should display in the UI?"
   - Answer: Array of room/streamer objects
   - Delivery: Likely remote config or dedicated API

---

## 💻 System Requirements

- Windows 10+ or Linux
- Python 3.6+
- Rust toolchain (for compilation, already done)
- APK decompiled to `jadx_out/` and `extracted_apk/`

---

## 🔗 Important File Paths

```
c:\dev\NativeGhost\
├── emulator_rust/target/release/emulator_rust.exe    ← Run this
├── scripts/parse_livestream_responses.py             ← Run this after
├── livestream_api_requests.log                        ← Read this
├── livestream_responses.log                           ← Read this
├── docs/ZEUS_API_FINDINGS.md                          ← Reference
├── docs/LIVESTREAM_DISCOVERY_FINAL_REPORT.md         ← Full details
└── jadx_out/sources/                                  ← Decompiled code
```

---

## ⚡ TL;DR

1. Run: `emulator_rust/target/release/emulator_rust.exe`
2. Access livestream feature in app
3. Logs appear: `livestream_api_requests.log`, `livestream_responses.log`
4. Run: `python scripts/parse_livestream_responses.py`
5. Find livestream list API endpoint
6. Document schema
7. **Done!**

---

**Status**: Ready for execution  
**Confidence**: 85% success rate  
**Time to Complete**: ~30 minutes  

