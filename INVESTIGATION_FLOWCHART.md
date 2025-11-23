# Investigation Flowchart

Visual guide to the complete investigation process.

## 🎯 Complete Investigation Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    START INVESTIGATION                      │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ↓
┌─────────────────────────────────────────────────────────────┐
│  PHASE 1: SETUP & PREPARATION                               │
├─────────────────────────────────────────────────────────────┤
│  1. Run ./setup.sh (installs all tools)                     │
│  2. Connect POCO C85 via USB                                │
│  3. Enable USB debugging on phone                           │
│  4. Verify: adb devices                                     │
│  5. Install Frida server on phone                           │
│  6. Verify: frida-ps -U                                     │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ↓
┌─────────────────────────────────────────────────────────────┐
│  PHASE 2: ROOT PHONE (OPTIONAL BUT RECOMMENDED)             │
├─────────────────────────────────────────────────────────────┤
│  Run: bash scripts/root_phone.sh                            │
│                                                              │
│  What happens:                                              │
│  • Unlocks bootloader (requires Xiaomi account)             │
│  • Downloads Magisk                                          │
│  • Patches boot image                                        │
│  • Flashes rooted boot                                       │
│  • Verifies root access                                      │
│                                                              │
│  ⚠️  WARNING: Wipes all data! Backup first!                 │
│  Time: 30-60 minutes                                        │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ↓
┌─────────────────────────────────────────────────────────────┐
│  PHASE 3: BASELINE ESTABLISHMENT                            │
├─────────────────────────────────────────────────────────────┤
│  Run: python3 scripts/monitor_baseline.py --duration 1800  │
│                                                              │
│  What happens:                                              │
│  • Hooks into all running apps                              │
│  • Monitors for 30 minutes                                  │
│  • Phone should be idle (screen off)                        │
│  • Detects any unexpected audio access                      │
│                                                              │
│  Output: data/logs/baseline_TIMESTAMP.json                  │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ↓
┌─────────────────────────────────────────────────────────────┐
│  PHASE 4: USER APPS TEST (CONVERSATION TEST)                │
├─────────────────────────────────────────────────────────────┤
│  Run: python3 scripts/monitor_conversation.py \             │
│       --keywords "underwater basket weaving" \              │
│       --duration 600                                        │
│                                                              │
│  What happens:                                              │
│  • Starts Frida hooks (audio + network)                     │
│  • Starts tcpdump (network capture)                         │
│  • You talk for 10 minutes about the topic                  │
│  • Phone nearby, screen off                                 │
│  • DO NOT type keywords anywhere!                           │
│                                                              │
│  Real-time alerts:                                          │
│  🚨 RECORDING STARTED by com.instagram.android              │
│  🌐 NETWORK UPLOAD to 185.199.108.133                       │
│                                                              │
│  Output:                                                     │
│  • data/logs/conversation_TIMESTAMP.json                    │
│  • data/captures/conversation_TIMESTAMP.pcap                │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ↓
┌─────────────────────────────────────────────────────────────┐
│  PHASE 5: SYSTEM APPS TEST (REQUIRES ROOT)                  │
├─────────────────────────────────────────────────────────────┤
│  Run: python3 scripts/analyze_system_apps.py --duration 600│
│                                                              │
│  What happens:                                              │
│  • Checks root access                                        │
│  • Lists all Xiaomi/MIUI system packages                    │
│  • Monitors suspicious packages:                            │
│    - com.xiaomi.xmsf (Service Framework)                    │
│    - com.miui.analytics (Telemetry)                         │
│    - com.xiaomi.finddevice (Find My Device)                 │
│    - com.miui.cloudservice (Cloud sync)                     │
│    - And 11+ more suspicious packages                       │
│  • Attaches Frida hooks to each                             │
│  • Monitors for 10 minutes each                             │
│                                                              │
│  Output: data/reports/system_apps_analysis_TIMESTAMP.json   │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ↓
┌─────────────────────────────────────────────────────────────┐
│  PHASE 6: IMMEDIATE ANALYSIS                                │
├─────────────────────────────────────────────────────────────┤
│  Step 1: Analyze Network Capture                            │
│  Run: python3 scripts/analyze_pcap.py \                     │
│       data/captures/conversation_TIMESTAMP.pcap             │
│                                                              │
│  Finds:                                                      │
│  • Large uploads (>1MB = suspicious)                        │
│  • Connections to Chinese servers                           │
│  • Unusual ports                                            │
│  • Upload timing and volume                                 │
│  ────────────────────────────────────────────────────────   │
│  Step 2: Correlate Events                                   │
│  Run: python3 scripts/correlate_events.py \                 │
│       data/logs/conversation_TIMESTAMP.json                 │
│                                                              │
│  Finds:                                                      │
│  • Audio access → Network upload patterns                   │
│  • Time correlation (<60s = very suspicious)                │
│  • Calculates suspicion score                               │
│  • Identifies culprit apps                                  │
│                                                              │
│  Output: data/reports/correlation_TIMESTAMP.json            │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ↓
          ┌──────────────┴──────────────┐
          │                              │
          ↓                              ↓
┌──────────────────────┐      ┌──────────────────────┐
│  NO SUSPICIOUS       │      │  SUSPICIOUS ACTIVITY │
│  ACTIVITY FOUND      │      │  DETECTED!           │
└──────────┬───────────┘      └──────────┬───────────┘
           │                              │
           ↓                              ↓
┌──────────────────────┐      ┌──────────────────────────────────┐
│  ✅ VERDICT:         │      │  ⚠️  VERDICT:                    │
│  Phone is NOT        │      │  Phone MAY BE spying             │
│  spying on you       │      │                                  │
│                      │      │  Proceed to Phase 7              │
│  You can:            │      └──────────┬───────────────────────┘
│  • Update blog post  │                 │
│  • Share findings    │                 ↓
└──────────────────────┘      ┌──────────────────────────────────┐
                              │  PHASE 7: CONFIRMATION           │
                              ├──────────────────────────────────┤
                              │  Monitor for 24-48 hours:         │
                              │                                   │
                              │  Check for targeted content:      │
                              │  • YouTube recommendations        │
                              │  • Instagram/Facebook ads         │
                              │  • TikTok feed                    │
                              │  • Google search suggestions      │
                              │                                   │
                              │  Document:                        │
                              │  • Screenshots of targeted content│
                              │  • Timestamps                     │
                              │  • Correlation with test topic    │
                              └──────────┬───────────────────────┘
                                         │
                        ┌────────────────┴────────────────┐
                        │                                  │
                        ↓                                  ↓
         ┌──────────────────────────┐      ┌──────────────────────────┐
         │  🚨 CONFIRMED            │      │  ❌ FALSE POSITIVE /     │
         │  SURVEILLANCE            │      │  INCONCLUSIVE            │
         └──────────┬───────────────┘      └──────────┬───────────────┘
                    │                                  │
                    ↓                                  ↓
         ┌──────────────────────────┐      ┌──────────────────────────┐
         │  EVIDENCE:               │      │  Continue monitoring or  │
         │  ✓ Audio access without  │      │  accept results          │
         │    user interaction      │      │                          │
         │  ✓ No recording indicator│      │  Update BLOG_POST.md     │
         │  ✓ Network upload <60s   │      │  with findings           │
         │  ✓ Large data transfer   │      └──────────────────────────┘
         │  ✓ Ads about test topic  │
         │                          │
         │  ACTIONS:                │
         │  1. Document everything  │
         │  2. Disable/uninstall app│
         │  3. Revoke permissions   │
         │  4. Block network access │
         │  5. Update BLOG_POST.md  │
         │  6. Report findings:     │
         │     • Manufacturer       │
         │     • Privacy advocates  │
         │     • Media              │
         │     • Authorities        │
         │  7. Consider custom ROM  │
         │  8. Share methodology    │
         └──────────────────────────┘
```

## 📋 Quick Decision Tree

```
Did app access microphone?
│
├─ NO → ✅ Not surveillance (at least not via mic)
│
└─ YES → Was there a recording indicator?
         │
         ├─ YES → Was it expected (call, voice note, etc.)?
         │        │
         │        ├─ YES → ✅ Normal behavior
         │        │
         │        └─ NO → ⚠️ Investigate further
         │
         └─ NO → Was there network activity within 60s?
                  │
                  ├─ NO → ⚠️ Suspicious but inconclusive
                  │
                  └─ YES → How much data?
                           │
                           ├─ <100KB → ⚠️ Medium suspicion
                           │
                           └─ >100KB → Did ads appear about topic?
                                       │
                                       ├─ NO → ⚠️ High suspicion, monitor longer
                                       │
                                       └─ YES → 🚨 CONFIRMED SURVEILLANCE
```

## 🎯 Evidence Scoring System

```
┌─────────────────────────────────────────────────────────────┐
│  SURVEILLANCE EVIDENCE CALCULATOR                           │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Audio access during conversation:           +5 points      │
│  No user interaction:                        +10 points     │
│  No recording indicator shown:               +15 points     │
│  Network activity within 10 seconds:         +20 points     │
│  Network activity within 60 seconds:         +10 points     │
│  Upload size >100KB:                         +10 points     │
│  Upload size >1MB:                           +15 points     │
│  Upload to Chinese server:                   +10 points     │
│  Upload to analytics domain:                 +5 points      │
│  Topic appears in ads within 24h:            +30 points     │
│  Topic appears in ads within 48h:            +20 points     │
│  Multiple correlated events:                 +5 each        │
│                                                              │
├─────────────────────────────────────────────────────────────┤
│  SCORE INTERPRETATION:                                      │
│                                                              │
│  0-10 points    = ✅ Normal behavior                        │
│  11-30 points   = ⚠️ Suspicious, investigate further        │
│  31-50 points   = 🚨 High suspicion, likely surveillance    │
│  51+ points     = 🚨🚨 Confirmed surveillance, take action  │
└─────────────────────────────────────────────────────────────┘
```

## 🕐 Time Investment

```
┌──────────────────────────┬─────────────┬──────────────┐
│ Phase                    │ Time        │ Active Work  │
├──────────────────────────┼─────────────┼──────────────┤
│ 1. Setup                 │ 30 min      │ 30 min       │
│ 2. Root (optional)       │ 60 min      │ 20 min       │
│ 3. Baseline              │ 30 min      │ 5 min        │
│ 4. User Apps Test        │ 20 min      │ 15 min       │
│ 5. System Apps (root)    │ 30 min      │ 10 min       │
│ 6. Immediate Analysis    │ 10 min      │ 10 min       │
│ 7. Confirmation (24-48h) │ 24-48 hours │ 10 min       │
├──────────────────────────┼─────────────┼──────────────┤
│ TOTAL (without root)     │ ~2 hours    │ ~1.5 hours   │
│ TOTAL (with root)        │ ~3 hours    │ ~2 hours     │
│ TOTAL (with confirmation)│ 24-48 hours │ ~2 hours     │
└──────────────────────────┴─────────────┴──────────────┘
```

## 📊 Files Generated

```
spyphone_or_trusyphone/
│
├─ data/
│  ├─ logs/
│  │  ├─ baseline_20251123_142315.json ............... Baseline test results
│  │  ├─ conversation_20251123_153045.json .......... Conversation test results
│  │  └─ longterm_20251123_180000_final.json ........ Long-term monitoring
│  │
│  ├─ captures/
│  │  ├─ conversation_20251123_153045.pcap .......... Network packet capture
│  │  └─ (analyzed with Wireshark or analyze_pcap.py)
│  │
│  └─ reports/
│     ├─ pcap_analysis_20251123_154500.json ......... Network analysis results
│     ├─ correlation_20251123_154800.json ........... Event correlation
│     ├─ app_analysis_com.xiaomi.xmsf_*.json ........ App-specific report
│     └─ system_apps_analysis_*.json ................ System apps report
│
└─ BLOG_POST.md (update with findings) ............... Public article
```

---

**Next Step**: Start with setup and follow the flowchart! 🚀

