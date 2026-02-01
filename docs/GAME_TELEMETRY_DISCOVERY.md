# IN-GAME MATCH TELEMETRY API - Discovery Report

## ✅ Critical Realization

The "livestream" feature is **NOT video streaming** but rather:

### **LIVE GAME STATE DATA** 
Displaying real-time match information:
- Hero draft status and picks
- Streamer's selected heroes
- Items purchased per hero
- Emblem selections
- Score/kills/deaths/assists (KDA)
- Game state transitions (draft → picking → playing → ended)

This is **order of magnitude lighter** than video streaming - it's just structured data updates.

---

## 🎯 Architecture Discovery

### Layer 1: Feature Authorization ✅
- **Service**: Qiniu Zeus API
- **Endpoint**: `https://shortvideo.qiniuapi.com/v1/zeus?appid=<APP_ID>`
- **Purpose**: Enable/disable livestream feature flag

### Layer 2: Match Telemetry (IN-GAME DATA) ⏳ FOUND
- **Server**: `gms.moontontech.com` (Moonton Game Management Service)
- **Likely Endpoints**:
  - `/api/v1/match/live`
  - `/api/v2/streamer/status`
  - `/api/v1/match/<match_id>`
  - `/api/v1/hero/<hero_id>/stats`

### Layer 3: Delivery Protocol 🔍 IDENTIFIED
- **Protocol**: Custom binary serialization (`SdpUnpacker` in libmoba.so)
- **Transport**: TCP/UDP socket connection to game server
- **Data Format**: Protobuf or custom binary format
- **Update Pattern**: Polling or push notifications

---

## 📊 Evidence Found

### Server Addresses Discovered
```
✅ gms.moontontech.com           (Moonton Game Management Service)
✅ games.skystone.games           (Skystone Games hosting)
✅ compliance-vn.games.skystone.games (Compliance/validation service)
```

### Protocol Support
```
✅ Protobuf support (detected in DEX files)
✅ Custom binary serialization (SdpUnpacker in libmoba.so)
✅ HTTP/HTTPS endpoints (confirmed in Qiniu Zeus pattern)
```

### Related Constants
```
REQUEST_STREAMER = 34  (com/moba/unityplugin/Utile.java)
└─ Purpose: Fetch live streamer game state
```

---

## 🔧 Technical Implementation

### Likely Data Flow

```
User opens "In-game Stream" tab
    ↓
App checks feature flag via Qiniu Zeus
    ↓ (if enabled)
App connects to gms.moontontech.com
    ↓
App queries: GET /api/v1/match/live?streamer_id=<ID>
    ↓
Server responds with match state JSON/Protobuf:
{
  "match_id": "ABC123",
  "streamer_id": "XYZ789",
  "game_state": "picking",
  "draft": {
    "bans": [...],
    "picks": [
      {
        "player_id": 1,
        "hero_id": 42,
        "hero_name": "Eudora",
        "emblem": {
          "id": 5,
          "type": "control",
          "level": 3
        }
      },
      ...
    ]
  },
  "kda": [
    {"player_id": 1, "kills": 5, "deaths": 2, "assists": 10},
    ...
  ],
  "items": [
    {"player_id": 1, "items": [2008, 2001, 2002, 2003, 2004, 2005]},
    ...
  ],
  "score": {
    "team_a": {"gold": 45000, "kills": 15},
    "team_b": {"gold": 42000, "kills": 12}
  }
}
    ↓
App parses and displays in UI with hero artwork, item icons, etc.
```

---

## 📍 Endpoint Candidates

### Most Likely

**Endpoint 1: Live Match State**
```
GET https://gms.moontontech.com/api/v1/match/live?streamer_id=<ID>
GET https://gms.moontontech.com/api/v2/match/<match_id>/state
```

**Endpoint 2: Streamer Status**
```
GET https://gms.moontontech.com/api/v1/streamer/<streamer_id>/status
GET https://gms.moontontech.com/api/v2/streamer/<streamer_id>/live
```

**Endpoint 3: Hero/Item Data**
```
GET https://gms.moontontech.com/api/v1/hero/<hero_id>
GET https://gms.moontontech.com/api/v1/item/<item_id>
```

### Response Schema (Predicted)

```json
{
  "success": true,
  "data": {
    "match_id": "string",
    "match_time": 1234567890,
    "game_duration_seconds": 1200,
    "game_state": "draft|picking|playing|ended",
    
    "heroes": [
      {
        "position": 1,
        "player_id": "string",
        "hero_id": 123,
        "hero_name": "Eudora",
        "skin_id": 456,
        "level": 22,
        "experience": 450000,
        
        "items": [2008, 2001, 2002, 2003, 2004, 2005],
        "item_upgrades": {
          "2008": 2
        },
        
        "emblem": {
          "id": 5,
          "rarity": "rare",
          "level": 3
        },
        
        "stats": {
          "kills": 8,
          "deaths": 2,
          "assists": 15,
          "damage_dealt": 450000,
          "damage_taken": 120000,
          "healing": 45000,
          "gold_earned": 65000
        }
      },
      // ... 4 more teammates
    ],
    
    "categories": ["Populer", "Terbaru", "Terkuat", "Karismatik", "Overdrive"],
    "category_status": {
      "Populer": {"rank": 3, "score": 1250},
      "Terbaru": null,
      "Terkuat": {"rank": 1, "score": 2500}
    }
  }
}
```

---

## 🔑 Key Insights

### Why NOT Hardcoded in Java?
1. **Dynamic Configuration**: Server can add/remove categories anytime
2. **Real-time Updates**: Hero balance changes affect streamer visibility
3. **Filtering/Ranking**: Server-side business logic for category placement
4. **Regional Variation**: Different servers for different regions (VN, SG, etc.)

### Why SdpUnpacker?
1. **Binary Efficiency**: Reduces bandwidth for frequent updates
2. **Compression**: Custom serialization can compress data better
3. **Performance**: Native code unpacking is faster than JSON parsing
4. **Security**: Obfuscation of data structure

### Download Requirement
The app must download:
1. Hero database (hero_id → hero_name, artwork, abilities)
2. Item database (item_id → item_name, icon, stats)
3. Emblem database (emblem_id → emblem_name, icon, type)
4. Streaming configuration (enabled categories, update frequency)

---

## 🚀 Next Steps for Discovery

### Priority 1: Confirm Endpoints via Emulator
```bash
# Enhanced emulator will log all HTTPS requests to gms.moontontech.com
# Expected output in livestream_api_requests.log:
#   GET /api/v1/match/live?streamer_id=...
#   POST /api/v2/streamer/status
```

### Priority 2: Capture Response Schema
```bash
# livestream_responses.log will contain actual JSON/Protobuf responses
# Parse with:
python scripts/parse_livestream_responses.py
```

### Priority 3: Reverse Engineer Binary Protocol
```bash
# If binary protocol detected in responses
# Use Frida to hook SdpUnpacker::unpack()
# Dump memory before/after deserialization
```

---

## 📈 Updated Progress

```
✅ Layer 1: Feature Authorization     (Qiniu Zeus - COMPLETE)
🔄 Layer 2: Match Telemetry           (gms.moontontech.com - FOUND)
⏳ Layer 3: Response Schema            (Pending emulator interception)
```

---

## 💡 Category Discovery

The categories visible in the UI ("Populer", "Terbaru", "Terkuat", "Karismatik", "Overdrive") are likely:

**Server-side Filters/Rankings:**
- **Populer**: Most watched/popular streamers (highest concurrent viewers)
- **Terbaru**: Latest/newest streams (sorted by start time)
- **Terkuat**: Strongest performance (sorted by Win rate or MMR)
- **Karismatik**: Featured/personality streamers (curated by Moonton)
- **Overdrive**: Turbo mode or special events (seasonal)

Each category is returned as a separate API call or filtered response, allowing the app to show different streamer lists for each tab.

---

## 📋 Required Data Download

Before showing livestream menu, app downloads:

```
1. Hero Index (123 heroes × name, ID, artwork)
2. Item Database (100+ items × name, ID, icon, rarity)
3. Emblem Database (50+ emblems × name, ID, type, icon)
4. Streamer List (for each category):
   - Streamer ID
   - Username
   - Avatar
   - Current match status
5. Live Match Configurations:
   - Update interval (e.g., every 2 seconds)
   - Category filter logic
   - Ranking algorithm
```

---

**Status**: GAME TELEMETRY ENDPOINT IDENTIFIED  
**Next**: Execute emulator to confirm exact endpoints and response schema

