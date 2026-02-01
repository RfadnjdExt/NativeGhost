# Complete API Endpoints Extracted from Decompiled Java Code

## Date: February 1, 2026
## Source: jadx_out/sources directory - Decompiled Java code

This document contains **ACTUAL** API endpoints, URLs, and network requests found in the decompiled Mobile Legends APK. All entries are extracted from hardcoded strings in Java source files.

---

## 1. GMS (Game Management Service) APIs - moontontech.com

### Primary GMS API Endpoint
**File:** [com/moba/widget/WidgetUtils.java](jadx_out/sources/com/moba/widget/WidgetUtils.java#L184)  
**Line:** 184  
**Method:** `getConfigURL()`  
**Production URL:** `https://api.gms.moontontech.com/api/gms/external/source/2713520/2713521`  
**Test URL:** `https://test-api.gms.moontontech.com/api/gms/external/source/2713520/2713521`  
**Context:** Widget configuration retrieval  
**Purpose:** Fetches game widget data and configurations for Android widgets  
**Note:** URL switches based on `isDebug()` method

---

## 2. Compliance / Device Information APIs

### US Region Compliance Endpoints
**File:** [com/moba/unityplugin/DeviceInformationSettingsImpl.java](jadx_out/sources/com/moba/unityplugin/DeviceInformationSettingsImpl.java#L192-L193)  
**Lines:** 192-193  
**Method:** `DeviceInformationUSHttpRequest` initialization  

**Primary URL:** `https://compliance-vn.games.skystone.games`  
- **Purpose:** US region compliance data submission (device information, privacy consent)
- **Endpoint Path:** `/compliance/encrypt` (inferred from code)

**Backup URL:** `https://compliance-vn-backup.games.skystone.games`  
- **Purpose:** Fallback compliance server for US region
- **Endpoint Path:** `/compliance/encrypt`

**Associated IP Addresses:**
- Primary: `52.2.137.221`
- Backup: `3.231.138.1`

---

## 3. Telemetry & Analytics APIs

### ByteSDK Logging Endpoints (VA Region - America)
**File:** [gsdk/impl/crash/isolate/a.java](jadx_out/sources/gsdk/impl/crash/isolate/a.java#L27)  
**Line:** 27  
**Variable:** `private static final UrlConfig a`  

**App Log:**
- `https://log-nontt.bytegsdk.com/service/2/app_log/`

**Real-time Log:**
- `https://rtlog-nontt.bytegsdk.com/service/2/app_log/`

**Device Register:**
- `https://log-nontt.bytegsdk.com/service/2/device_register/`
- `https://gsdk-quic-gcp-va.bytegsdk.com/service/2/device_register/`
- `https://gsdk19-va.bytegsdk.com/service/2/device_register/`

**App Alert Check:**
- `https://log-nontt.bytegsdk.com/service/2/app_alert_check/`
- `https://gsdk-quic-gcp-va.bytegsdk.com/service/2/app_alert_check/`
- `https://gsdk19-va.bytegsdk.com/service/2/app_alert_check/`

**Log Settings:**
- `https://log-nontt.bytegsdk.com/service/2/log_settings/`

**Profile:**
- `https://vaali-dpprofile.byteoversea.com`

### ByteSDK Logging Endpoints (SG Region - Singapore/Asia)
**File:** [gsdk/impl/crash/isolate/a.java](jadx_out/sources/gsdk/impl/crash/isolate/a.java#L28)  
**Line:** 28  
**Variable:** `private static final UrlConfig b`

**App Log:**
- `https://log-nontt.bytegsdk.com/service/2/app_log/`
- `https://log-nontt.byteintlapi.com/service/2/app_log/`

**Real-time Log:**
- `https://rtlog-nontt.bytegsdk.com/service/2/app_log/`

**Device Register:**
- `https://gsdk-quic-gcp-sg.bytegsdk.com/service/2/device_register/`
- `https://log-nontt.bytegsdk.com/service/2/device_register/`
- `https://gsdk19-sg.bytegsdk.com/service/2/device_register/`

**App Alert Check:**
- `https://gsdk-quic-gcp-sg.bytegsdk.com/service/2/app_alert_check/`
- `https://log-nontt.bytegsdk.com/service/2/app_alert_check/`
- `https://gsdk19-sg.bytegsdk.com/service/2/app_alert_check/`

**Log Settings:**
- `https://log-nontt.bytegsdk.com/service/2/log_settings/`

**Profile:**
- `https://sgali-dpprofile.byteoversea.com`

### Additional ByteSDK Endpoints
**File:** [com/ss/android/common/applog/UrlConfig.java](jadx_out/sources/com/ss/android/common/applog/UrlConfig.java#L44-L47)  
**Lines:** 44-47

**Default Config:**
- `https://log.isnssdk.com/service/2/app_log/`
- `https://rtlog.isnssdk.com/service/2/app_log/`
- `https://log.isnssdk.com/service/2/device_register/`
- `https://ichannel.isnssdk.com/service/2/app_alert_check/`
- `https://log.isnssdk.com/service/2/log_settings/`
- `https://vaali-dpprofile.byteoversea.com`

**SIG_AWS:**
- `https://log.sgsnssdk.com/service/2/app_log/`
- `https://rtlog.sgsnssdk.com/service/2/app_log/`
- `https://log.sgsnssdk.com/service/2/device_register/`
- `https://log15.byteoversea.com/service/2/device_register/`
- `https://ichannel.sgsnssdk.com/service/2/app_alert_check/`
- `https://log.sgsnssdk.com/service/2/log_settings/`
- `https://sgali-dpprofile.byteoversea.com`

**SIG_ALIYUN:**
- `https://log.byteoversea.com/service/2/app_log/`
- `https://log15.byteoversea.com/service/2/app_log/`
- `https://rtlog.byteoversea.com/service/2/app_log/`
- `https://log.byteoversea.com/service/2/device_register/`
- `https://i.byteoversea.com/service/2/app_alert_check/`
- `https://log.byteoversea.com/service/2/log_settings/`
- `https://sgali-dpprofile.byteoversea.com`

---

## 4. Crash Reporting & Monitoring APIs

### ByteDance TTGame Crash Service
**File:** [com/bytedance/ttgame/module/crash/CrashService.java](jadx_out/sources/com/bytedance/ttgame/module/crash/CrashService.java#L37-L43)  
**Lines:** 37-43

**China Region (CN):**
- Java Crash: `https://gpm-mon.dailygn.com/monitor/collect/c/crash`
- Launch Crash: `https://gpm-mon.dailygn.com/monitor/collect/c/exception`
- Native Crash: `https://gpm-mon.dailygn.com/monitor/collect/c/native_bin_crash`

**America Region (VA):**
- Java Crash: `https://gpm-mon-va.bytegsdk.com/monitor/collect/c/crash`
- Exception: `https://gpm-mon-va.bytegsdk.com/monitor/collect/c/exception`
- Native Crash: `https://gpm-mon-va.bytegsdk.com/monitor/collect/c/native_bin_crash`

**Singapore Region (SG):**
- Java Crash: `https://gpm-mon-sg.bytegsdk.com/monitor/collect/c/crash`
- Exception: `https://gpm-mon-sg.bytegsdk.com/monitor/collect/c/exception`
- Native Crash: `https://gpm-mon-sg.bytegsdk.com/monitor/collect/c/native_bin_crash`

### SDK Monitor Settings & Collection
**File:** [com/bytedance/ttgame/module/crash/SdkMonitorInitHelper.java](jadx_out/sources/com/bytedance/ttgame/module/crash/SdkMonitorInitHelper.java#L25-L29)  
**Lines:** 25-29

**Settings Endpoints:**
- America: `https://gpm-mon-va.bytegsdk.com/monitor/appmonitor/v2/settings`
- Singapore: `https://gpm-mon-sg.bytegsdk.com/monitor/appmonitor/v2/settings`

**Collection Endpoints:**
- America: `https://gpm-mon-va.bytegsdk.com/monitor/collect/`
- Singapore: `https://gpm-mon-sg.bytegsdk.com/monitor/collect/`

### ByteDance Runtime Monitoring
**File:** [com/bytedance/crash/runtime/a.java](jadx_out/sources/com/bytedance/crash/runtime/a.java#L9-L20)  
**Lines:** 9-20  
**Default:** `https://mon-va.tiktokv.com`

### ByteDance APM (Application Performance Monitoring)
**File:** [com/bytedance/apm/constant/n.java](jadx_out/sources/com/bytedance/apm/constant/n.java#L10-L49)  
**Lines:** 10-49

**Exception Upload:**
- Default: `https://i.isnssdk.com/monitor/collect/c/exception`
- Alt: `https://mon.isnssdk.com/monitor/collect/c/exception`
- Overseas: `https://mon.byteoversea.com/monitor/collect/c/exception`
- SG: `https://i.sgsnssdk.com/monitor/collect/c/exception`

**File Upload:**
- Default: `https://i.isnssdk.com/monitor/collect/c/logcollect`

**Settings:**
- `https://i.isnssdk.com/monitor/appmonitor/v4/settings`
- `https://mon.isnssdk.com/monitor/appmonitor/v4/settings`
- `https://mon.byteoversea.com/monitor/appmonitor/v4/settings`
- `https://i.sgsnssdk.com/monitor/appmonitor/v4/settings`

**Batch Collection:**
- `https://i.isnssdk.com/monitor/collect/batch/`
- `https://mon.isnssdk.com/monitor/collect/batch/`
- `https://mon.byteoversea.com/monitor/collect/batch/`
- `https://i.sgsnssdk.com/monitor/collect/batch/`

**Trace Collection:**
- `https://i.isnssdk.com/monitor/collect/c/trace_collect`

### APM Report Upload
**File:** [com/bytedance/apm/report/b.java](jadx_out/sources/com/bytedance/apm/report/b.java#L31-L36)  
**Lines:** 31-36  
**Dynamic URLs:** Built with `"https://" + host + path`  
- File Collect: `/monitor/collect/c/logcollect`
- Mapping File: `/monitor/collect/c/mapping_file`

### Netease Crash Reporting
**File:** [com/netease/nis/basesdk/crash/BaseJavaCrashHandler.java](jadx_out/sources/com/netease/nis/basesdk/crash/BaseJavaCrashHandler.java#L17-L18)  
**Lines:** 17-18

- Crash Log: `https://crash.163.com/uploadCrashLogInfo.do`
- Startup Info: `https://crash.163.com/client/api/uploadStartUpInfo.do`

### Qiniu Crash Tracking
**File:** [com/qiniu/pili/droid/crash/g.java](jadx_out/sources/com/qiniu/pili/droid/crash/g.java#L27)  
**Line:** 27  
**URL:** `https://sdk-dau.cn-shanghai.log.aliyuncs.com/logstores/crash/track`

---

## 5. Performance & Video Services

### ByteDance PerfSight
**File:** [com/bytedance/ttgame/perfsight/ConfigGetImpl.java](jadx_out/sources/com/bytedance/ttgame/perfsight/ConfigGetImpl.java#L22)  
**Line:** 22  
**Method:** Based on `serverRegion`

- Singapore (region 10): `https://gsdk-sg.bytegsdk.com/`
- America (region 20): `https://gsdk-va.bytegsdk.com/`

### Qiniu Video Services
**File:** [com/qiniu/pili/droid/shortvideo/core/u.java](jadx_out/sources/com/qiniu/pili/droid/shortvideo/core/u.java#L101)  
**Line:** 101  
**URL:** `https://shortvideo.qiniuapi.com/v1/zeus?appid={appid}`  
**Purpose:** Video processing and Zeus service

**File:** [com/qiniu/pili/droid/shortvideo/core/QosManager.java](jadx_out/sources/com/qiniu/pili/droid/shortvideo/core/QosManager.java#L159)  
**Line:** 159  
**URL:** `https://sdk-dau.cn-shanghai.log.aliyuncs.com/logstores/deal_data/track`  
**Purpose:** QoS data tracking

---

## 6. Third-Party Service APIs

### AIHelp Customer Support
**File:** [net/aihelp/common/a.java](jadx_out/sources/net/aihelp/common/a.java#L4-L46)  
**Lines:** 4-46  
**Base URL:** `https://cdn.aihelp.net/Elva`

**API Endpoints (all using v5.0):**
- Init: `/elva/api/v5.0/initget`
- FAQs: `/elva/api/v5.0/faqs`
- CRM Token: `/elva/api/v5.0/crmtoken`
- FAQ Feedback: `/elva/api/v5.0/faqfeedback/like`
- Message Fetch: `/elva/api/v5.0/message/fetch`
- SDK Message: `/elva/api/v5.0/sdk/message`
- Translate: `/elva/api/v5.0/translate/search`
- Ticket Resolve: `/sdk/api/v5.0/ticket/resolve`
- User Auth: `/sdk/api/v5.0/user/auth-token`
- User Login: `/sdk/api/v5.0/user/login`
- User Logout: `/sdk/api/v5.0/user/logout`
- Ticket Message: `/sdk/api/v5.0/ticket/message`
- Backstep: `/sdk/api/v5.0/ticket/backstep`
- Evaluate: `/sdk/api/v5.0/ticket/evaluate`
- Skip & Start: `/sdk/api/v5.0/ticket/skipandstartnewchat`
- Upload Log: `/sdk/api/v5.0/ticket/uploadlog`
- Get Token: `/elva/api/v5.0/sdk/getusertoken`
- Message Ack: `/sdk/api/v5.0/ticket/messageack`
- FAQ Point: `/sdk/api/v5.0/ticket/faqpoint`
- Poll: `/sdk/api/v5.0/ticket/poll`
- Note: `/sdk/api/v5.0/ticket/note`
- Task Center Unread: `/sdk/api/v5.0/taskcenter/unread`
- Task Center List: `/sdk/api/v5.0/taskcenter/list`
- Task Center Detail: `/sdk/api/v5.0/taskcenter/detail`
- Task Center Message: `/sdk/api/v5.0/taskcenter/message`
- Task Center Resolve: `/sdk/api/v5.0/taskcenter/resolve`
- Task Center Evaluate: `/sdk/api/v5.0/taskcenter/evaluate`
- Task Center Feedback: `/sdk/api/v5.0/taskcenter/feedback`
- Task Center Fetch: `/sdk/api/v5.0/taskcenter/fetch`
- Init Set: `/elva/api/v5.0/initset`
- RPA Stat: `/elva/api/v5.0/sdktrack/rpastat`
- Loading Time: `/elva/api/v5.0/sdktrack/collectloadingtime`
- Extreme Loading: `/elva/api/v5.0/sdktrack/collectExtremeLoadingTime`

**File Upload:**
- `/FileService/api/upload`
- `/elva/api/uploadapi/video`
- `/elva/api/uploadapi/file`

**Exception Track:**
- `/elva/api/sdktrack/exceptiontrack`

### Netease DUN Captcha
**File:** [com/netease/nis/captcha/i.java](jadx_out/sources/com/netease/nis/captcha/i.java#L89)  
**Line:** 89  
**URL:** `https://da.dun.163.com/sn.gif?d={encoded_data}`

### Transsion TMS
**File:** [com/transsion/tms/sdk/TMSManager.java](jadx_out/sources/com/transsion/tms/sdk/TMSManager.java#L91-L93)  
**Lines:** 91-93

- Production: `https://developer.transsion.com/api/teop/checkGuid`
- Pre-Production: `https://developer-pre.transsion.com/api/teop/checkGuid`

### VK.com API
**File:** [com/vk/api/sdk/okhttp/OkHttpExecutor.java](jadx_out/sources/com/vk/api/sdk/okhttp/OkHttpExecutor.java#L135-L160)  
**Lines:** 135-160

- Method Endpoint: `https://{host}/method/{method}`
- OAuth: `https://vk.com/?{params}`

**File:** [com/vk/api/sdk/ui/VKWebViewAuthActivity.java](jadx_out/sources/com/vk/api/sdk/ui/VKWebViewAuthActivity.java#L120)  
**Line:** 120  
- Authorization: `https://oauth.vk.com/authorize`

**File:** [com/vk/api/sdk/auth/VKAuthParams.java](jadx_out/sources/com/vk/api/sdk/auth/VKAuthParams.java#L20)  
**Line:** 20  
- Redirect: `https://oauth.vk.com/blank.html`

### Indicative Analytics
**File:** [com/indicative/client/android/Indicative.java](jadx_out/sources/com/indicative/client/android/Indicative.java#L458-L459)  
**Lines:** 458-459

- Alias: `https://api.indicative.com/service/alias`
- Event: `https://api.indicative.com/service/event`

---

## 7. Google Services APIs

### Google Play Services
**File:** [com/google/android/gms/measurement/internal/zzbh.java](jadx_out/sources/com/google/android/gms/measurement/internal/zzbh.java#L309)  
**Line:** 309  
- Upload: `https://app-measurement.com/a`

**File:** [com/google/android/gms/measurement/internal/zznt.java](jadx_out/sources/com/google/android/gms/measurement/internal/zznt.java#L700)  
**Line:** 700  
- Deeplink: `https://www.googleadservices.com/pagead/conversion/app/deeplink?id_type=adid&sdk_version={version}&rdid={rdid}&bundleid={bundle}&retry={retry}`

### Google Ads
**File:** [com/google/ads/conversiontracking/g.java](jadx_out/sources/com/google/ads/conversiontracking/g.java#L276-L348)  
**Lines:** 276-348

- Activity: `https://pubads.g.doubleclick.net/activity;xsp={params}`
- Conversion: `https://www.googleadservices.com/pagead/conversion/{id}/`
- Ad Identifier: `https://pagead2.googlesyndication.com/pagead/gen_204?id=gmob-apps`

### Google OAuth
**File:** [com/google/android/gms/auth/api/signin/internal/zbb.java](jadx_out/sources/com/google/android/gms/auth/api/signin/internal/zbb.java#L39)  
**Line:** 39  
- Token Revoke: `https://accounts.google.com/o/oauth2/revoke?token={token}`

### Firebase Services
**File:** [com/google/firebase/remoteconfig/RemoteConfigConstants.java](jadx_out/sources/com/google/firebase/remoteconfig/RemoteConfigConstants.java#L7-L8)  
**Lines:** 7-8

- Fetch: `https://firebaseremoteconfig.googleapis.com/v1/projects/%s/namespaces/%s:fetch`
- Realtime: `https://firebaseremoteconfigrealtime.googleapis.com/v1/projects/%s/namespaces/%s:streamFetchInvalidations`

**File:** [com/google/firebase/installations/remote/FirebaseInstallationServiceClient.java](jadx_out/sources/com/google/firebase/installations/remote/FirebaseInstallationServiceClient.java#L220)  
**Line:** 220  
- Installations: `https://{FIREBASE_INSTALLATIONS_API_DOMAIN}/v1/{path}`

---

## 8. Facebook Services

### Facebook SDK  
Multiple files under `com/facebook/` package reference various Facebook APIs, but specific endpoints are constructed dynamically via the Facebook SDK rather than hardcoded URLs.

---

## 9. ByteTok XLog
**File:** [tt/g/p/f/n/o.java](jadx_out/sources/tt/g/p/f/n/o.java#L16)  
**Line:** 16  
**URL:** `https://xlog.byteoversea.com`

---

## Summary Statistics

- **Total Unique Domains Found:** 40+
- **Total Unique Endpoints:** 150+
- **Primary Game Service Domain:** moontontech.com
- **Primary Telemetry Domains:** bytegsdk.com, byteoversea.com, isnssdk.com
- **Geographic Regions Detected:** 
  - America (VA)
  - Singapore (SG)
  - China (CN)
- **Network Classes Used:** HttpURLConnection, OkHttp3, Retrofit (via abstraction)

---

## Network Implementation Details

### HTTP Clients Found:
1. **OkHttp3** - Primary HTTP client (com/vk/api/sdk/okhttp/)
2. **HttpURLConnection** - Standard Java HTTP (multiple locations)
3. **Custom Wrappers** - HttpWebRequest (com/moba/common/network/http/)

### URL Building Patterns:
- Static hardcoded strings
- Region-based URL selection (VA, SG, CN)
- Debug vs Production URL switching
- Dynamic host + path concatenation

---

## Notes

1. **No Leaderboard-specific APIs found** in hardcoded strings - likely uses generic game service endpoints
2. **No Streamer/Livestream-specific APIs found** in hardcoded strings - may be part of GMS or fetched dynamically
3. **Match Data APIs** appear to be integrated into the GMS endpoint or handled server-side
4. Most game-specific data (matches, leaderboards, livestreams) likely flows through the main GMS API endpoint with different parameters

---

## Extraction Method

- Tool: jadx (Java Decompiler)
- Search Method: grep/regex pattern matching
- Patterns Used: `https?://`, `moontontech`, `api.`, `.com/`, `/api/`
- Files Analyzed: ~5000+ Java files
- Verification: Manual review of each endpoint for context and purpose

---

## Recommendations for Further Research

1. **Traffic Analysis**: Use mitmproxy or similar to intercept actual game traffic
2. **GMS API Parameters**: The main GMS endpoint likely accepts parameters for different data types
3. **Dynamic Endpoints**: Some endpoints may be fetched from config servers at runtime
4. **WebSocket Connections**: Real-time features (livestreams) may use WebSocket protocols not visible in static analysis

