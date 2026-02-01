# MLBB Leaderboard API - Direct Network Analysis

## Simplest Approach: Use ADB Logcat

If you have Android Debug Bridge (ADB) installed:

```powershell
# Connect device via USB
adb connect 192.168.1.6:5555

# Enable WiFi debugging (one-time setup)
adb tcpip 5555

# View all network traffic
adb logcat | findstr "youngjoygame\|mlbangbang\|POST\|GET"

# OR filter specific app
adb logcat | findstr "mobile.legends\|youngjoygame"
```

---

## Alternative: Enable Network Logging in MLBB

Some games log network calls to logcat:

```powershell
# Clear logs
adb logcat -c

# Refresh MLBB leaderboard

# Capture logs
adb logcat > mlbb_logcat.txt

# Then search for API calls:
findstr "rank\|leaderboard\|youngjoygame" mlbb_logcat.txt
```

---

## What We Know So Far (From Code Analysis)

**API Servers** (from version.xml):
- Global: `global-report.ml.youngjoygame.com:30071`
- Default: `report.ml.youngjoygame.com:30071`

**Expected Endpoint Pattern** (inferred from WidgetWorker.java):
- Path: `/api/v2/rank/global` or `/api/leaderboard/top`
- Method: POST
- Body: JSON with user_id, auth_token

**Expected Response Structure**:
```json
{
  "code": 0,
  "msg": "success",
  "data": {
    "leaderboard": [
      {
        "rank": 1,
        "user_id": "...",
        "nickname": "...",
        "rating": 2750,
        "wins": 1200,
        "hero": "Lapu-Lapu"
      },
      ...
    ]
  }
}
```

---

## Last Resort: Manual HTTP Request

If we can extract the auth token, we can make direct HTTP requests:

```python
import requests
import json

# These would come from MLBB session
auth_token = "extracted_from_login"
user_id = "your_user_id"

# Try different endpoints
endpoints = [
    "http://report.ml.youngjoygame.com:30071/api/v2/rank/global",
    "http://report.ml.youngjoygame.com:30071/api/leaderboard/top",
    "http://report.ml.youngjoygame.com:30071/api/rank/global",
]

for endpoint in endpoints:
    try:
        response = requests.post(
            endpoint,
            json={"user_id": user_id, "auth": auth_token, "limit": 100},
            timeout=5
        )
        print(f"[{endpoint}]")
        print(json.dumps(response.json(), indent=2))
    except Exception as e:
        print(f"[{endpoint}] Failed: {e}")
```

---

**Do you have ADB installed?**
