# MLBB Top Livestreamer API - Capture Plan

## Project Pivot: Leaderboard → Livestream

**New Goal:** Extract the API to get the list of **current top livestreamers** in Mobile Legends: Bang Bang.

## Current Findings

### 1. PCAP Analysis Results

**Current PCAP (`PCAPdroid_01_Feb_12_37_33.pcap`):**
- ✅ Contains UI click event: `Newbie_live` on port 30101 (game server)
- ❌ No actual livestream data (only button click logged)
- ❌ No livestream list request/response captured

**Network Architecture:**
- **Port 30071**: `global-report.ml.youngjoygame.com` - Telemetry (plaintext pipe-delimited)
- **Port 30101**: `161.202.215.85` - Game server (custom SDP binary protocol)
- **Port 30021**: `global-login.ml.youngjoygame.com` - Login server

### 2. Codebase Analysis

**Facebook Livestream Integration Found:**
- `com/moba/unityplugin/ShareFacebook.java`: `stopLive()` method for Facebook Live
- `com/moba/unityplugin/FacebookManager.java`: `StopLive()`, `onStopLiveCallback()`
- `com/facebook/appevents/AppEventsConstants.java`: FB livestream event tracking
  - `EVENT_NAME_LIVE_STREAMING_START`
  - `EVENT_NAME_LIVE_STREAMING_STOP`
  - `EVENT_PARAM_LIVE_STREAMING_STATUS`

**BytePlus Video Player:**
- `com/bytedance/gmvideoplayer/core/bridge/NativeLivePlayer.java` - Video player SDK (for watching streams)
- `com/bytedance/gmvideoplayer/player/liveplayer/LivePlayer` - Livestream player implementation

**Key Observation:** These are for **broadcasting** to Facebook and **playing** livestreams, not for fetching the top livestreamer list.

### 3. UI Labels Found

From PCAP port 30101:
```
~pNEpp@I107|28784;and_usa|Main_UI_Click|2018-08-15|134|24Newbie_live|1|0|0||ID|IDA
```

- **"Newbie_live"** is a UI button label
- This is a telemetry event, not actual livestream data

## Action Plan: NEW PCAP CAPTURE

### Prerequisites

1. **PCAPdroid Configuration:**
   - Filter: **MLBB Only** (com.mobile.legends)
   - **Decrypt TLS:** ON
   - **Full Payload:** ON
   - **IPv4 + IPv6:** Both enabled

2. **Device Requirements:**
   - Rooted device or ADB debugging enabled
   - PCAPdroid installed and configured

### Capture Steps (CRITICAL SEQUENCE)

**Goal:** Capture the livestream list API request/response

**YOU ARE ALREADY ON THE LIVE SCREEN - PERFECT!**

Now do these actions **EXACTLY IN ORDER:**

1. **Start PCAPdroid capture NOW** (MLBB filter, TLS Decrypt ON, Full Payload ON)

2. **While on "Populer" tab (current screen):**
   - Pull down to **REFRESH** the list
   - Wait 2-3 seconds for data to load
   - **Scroll down** slowly to load more streamers

3. **Switch to "Terbaru" tab:**
   - Click "Terbaru" (Newest)
   - Wait 2-3 seconds for list to load
   - Scroll down once

4. **Switch to "Terkuat Global" tab:**
   - Click "Terkuat Global" (Strongest Global)  
   - Wait 2-3 seconds for list to load
   - Scroll down once

5. **Click on FENRIR STARBOY** (the top streamer)
   - Wait 5 seconds in the livestream
   - Press BACK to return to list

6. **STOP PCAPdroid capture IMMEDIATELY**

7. **Save PCAP as:** `PCAPdroid_LIVESTREAM_02_Feb.pcap`

8. **Send me the PCAP file**

### What to Look For in New PCAP

Using existing tools:

```bash
# 1. Check for new telemetry messages
python parse_report_protocol.py PCAPdroid_LIVESTREAM_02_Feb.pcap 30071

# 2. Search for livestream keywords
python find_keyword_in_pcap.py PCAPdroid_LIVESTREAM_02_Feb.pcap "live"
python find_keyword_in_pcap.py PCAPdroid_LIVESTREAM_02_Feb.pcap "stream"
python find_keyword_in_pcap.py PCAPdroid_LIVESTREAM_02_Feb.pcap "anchor"
python find_keyword_in_pcap.py PCAPdroid_LIVESTREAM_02_Feb.pcap "hot"
python find_keyword_in_pcap.py PCAPdroid_LIVESTREAM_02_Feb.pcap "rank"

# 3. Dump game server traffic for analysis
python dump_port_payloads.py PCAPdroid_LIVESTREAM_02_Feb.pcap 30101 port30101_livestream.txt

# 4. Look for new HTTP endpoints
python pcap_sni.py PCAPdroid_LIVESTREAM_02_Feb.pcap
```

### Expected Data Patterns

Based on your screenshot, we're looking for API response with:

**Streamers visible in your screenshot:**
- FENRIR STARBOY - 1849K viewers - "JUNGLER GANTE"
- CreamyPriscilla ♡ - 509K viewers - "ahh.. solo mulu"
- BOS BARA - 484K viewers - "gw alin"
- Lovely x Yuki - 347K viewers - "Spread love not hai"
- More streamers: 313K, 312K, 303K, 269K viewers

**Tabs in the app:**
- Populer (Popular)
- Terbaru (Newest)
- Terkuat Global (Strongest Global)
- Karismatik (Charismatic)
- Overdrive

**Expected API Response Format (JSON/Protobuf):**
```json
{
  "code": 0,
  "data": {
    "streams": [
      {
        "uid": "...",
        "nickname": "FENRIR STARBOY",
        "title": "JUNGLER GANTE",
        "viewers": 1849000,
        "avatar": "https://...",
        "thumbnail": "https://...",
        "stream_url": "...",
        "country": "ID"
      },
      {
        "uid": "...",
        "nickname": "CreamyPriscilla ♡",
        "title": "ahh.. solo mulu",
        "viewers": 509000,
        ...
      }
    ]
  }
}
```

## Alternative Approach: APK Reverse Engineering

If PCAP fails to capture (SSL pinning, obfuscation):

### 1. String Search in Assets

```bash
# Search Unity assets for livestream API strings
grep -r "live" extracted_apk/assets/ | grep -i "api\|http\|url"
grep -r "stream" extracted_apk/assets/
grep -r "anchor" extracted_apk/assets/
```

### 2. Decompiled Java Code

Search for API endpoint construction:
```bash
grep -r "live" jadx_out/sources/com/moba/ | grep -i "url\|endpoint\|api"
grep -r "LivestreamManager" jadx_out/sources/
grep -r "StreamController" jadx_out/sources/
```

### 3. Native Library Hooks (Frida)

If livestream data is fetched via native code:

```javascript
// Hook HTTP request functions
Interceptor.attach(Module.findExportByName("libc.so", "sendto"), {
  onEnter: function(args) {
    var buf = args[1];
    var len = args[2].toInt32();
    var data = Memory.readUtf8String(buf, len);
    if (data.indexOf("live") !== -1 || data.indexOf("stream") !== -1) {
      console.log("[sendto] Livestream data: " + data);
    }
  }
});
```

## Tools Already Created

All tools are ready in `c:\dev\NativeGhost\`:

1. **pcap_sni.py** - Analyze TLS, DNS, ports
2. **dump_port_payloads.py** - Extract TCP payloads per port
3. **parse_report_protocol.py** - Parse telemetry messages
4. **find_keyword_in_pcap.py** - Search PCAP with IP:port context
5. **scan_pcap_keywords.py** - Full-packet keyword search
6. **extract_ascii_strings.py** - Extract strings from binaries

## Next Steps

1. **Immediate:** Capture new PCAP following the steps above
2. **Provide the new PCAP file name** when ready
3. **Run analysis scripts** on new PCAP to identify livestream API
4. **Extract API details** (URL, headers, payload format)
5. **Test API** with curl/Postman to verify extraction

## Success Criteria

- ✅ Identify the livestream list API endpoint
- ✅ Capture request headers (auth tokens, signatures)
- ✅ Capture response with streamer data
- ✅ Understand payload format (JSON/Protobuf)
- ✅ Replicate API call outside the game

## Notes

- The "Newbie_live" UI click is just a button label, not the actual API
- Livestream data likely on port 30101 (game server) as custom binary protocol
- May need to implement SDP binary decoder if data is not plaintext
- Facebook integration is only for user broadcasting, not for listing top streamers
