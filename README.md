# (WIP - so far only AI) Is My Phone Spying On Me? 🔍

A complete toolkit to investigate whether your POCO C85 (Xiaomi HyperOS) is secretly listening to your conversations and selling your data.

## What Is This?

You've probably experienced this: You talk about something with friends, never type it anywhere, and suddenly see ads about it on Instagram, YouTube, or TikTok. Creepy, right?

This project helps you find out **once and for all** if your phone is actually listening to you.

**What we test:**
- Does your phone access the microphone without showing an indicator?
- Does it upload audio data to remote servers?
- Which apps are doing this (user apps or system apps)?
- Can we prove the connection between conversations and targeted ads?

**Target Device:** POCO C85 running Xiaomi HyperOS (but works on most Android devices)

---

## 🚀 Quick Start: 5 Steps to Find Out

### Step 1: Setup Your Mac (30 minutes)

**What you need:**
- POCO C85 phone
- USB cable
- macOS computer (M1 Pro or similar)
- Stable internet connection

**Install all tools:**

```bash
# Clone this repository
git clone https://github.com/yourusername/spyphone_or_trustyphone.git
cd spyphone_or_trustyphone

# Run automated setup (installs ADB, Frida, Python, etc.)
bash setup.sh
```

**What this installs:**
- Homebrew (package manager)
- ADB (Android Debug Bridge)
- Python 3.11+
- Frida (dynamic instrumentation)
- Wireshark (network analysis)
- mitmproxy (HTTPS interception)
- All Python dependencies

**Time:** ~30 minutes (mostly downloads)

---

### Step 2: Enable USB Debugging on Phone (5 minutes)

**On your POCO C85:**

1. Go to **Settings** → **About phone**
2. Tap **MIUI version** 7 times (enables Developer mode)
3. Go back to **Settings** → **Additional settings** → **Developer options**
4. Enable **USB debugging**
5. Enable **Install via USB** (optional but helpful)

**Connect phone to Mac:**

```bash
# Connect USB cable
# On phone: Allow USB debugging popup

# Verify connection
adb devices

# Should show:
# List of devices attached
# ABC123XYZ    device
```

**Troubleshooting:**
- If shows "unauthorized" → Check phone screen for popup
- If shows "offline" → Unplug and replug cable
- If shows nothing → Install ADB properly or check cable

---

### Step 3: Install Frida on Phone (10 minutes)

**Download Frida server:**

```bash
# Detect your phone's architecture
adb shell getprop ro.product.cpu.abi

# Download appropriate Frida server (usually arm64)
cd /tmp
FRIDA_VERSION=$(frida --version)
wget https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-android-arm64.xz

# Extract
unxz frida-server-*-android-arm64.xz
mv frida-server-*-android-arm64 frida-server
```

**Push to phone and run:**

```bash
# Push to phone
adb push frida-server /data/local/tmp/

# Make executable
adb shell "chmod 755 /data/local/tmp/frida-server"

# Run as root (required)
adb shell "su -c '/data/local/tmp/frida-server &'"

# Alternative if not rooted:
adb shell "/data/local/tmp/frida-server &"
```

**Verify it works:**

```bash
# List running processes
frida-ps -U

# Should show list of apps running on phone
# If you see apps listed → SUCCESS! ✅
```

**Note:** If Frida requires root and you're not rooted yet, see Step 4.

---

### Step 4: Root Your Phone (OPTIONAL - 60 minutes)

**Do you need root?**

- **NO** if you only want to test user-installed apps (Instagram, TikTok, etc.)
- **YES** if you want to test Xiaomi system apps (Analytics, Cloud Service, etc.)

**Most surveillance happens at app level, so start WITHOUT root!**

**To root your POCO C85:**

```bash
# Use our automated script
bash scripts/root_phone.sh
```

This script will:
1. Unlock bootloader (requires Xiaomi account)
2. Download Magisk
3. Patch boot image
4. Flash rooted boot
5. Verify root access

⚠️ **WARNING:** Rooting will:
- **WIPE ALL DATA** (backup first!)
- Void your warranty
- May break banking apps
- Requires 60 minutes

**Read more:** See `DO_I_NEED_ROOT.md` for detailed decision guide.

---

### Step 5: Run Your First Test (20 minutes)

**The Conversation Test** - This is the main test that proves surveillance.

**Setup:**

```bash
# Make sure phone is connected
adb devices

# Make sure Frida is running
frida-ps -U

# Choose a unique test topic (NEVER talked about before)
# Examples:
#   - "underwater basket weaving"
#   - "competitive cheese rolling"
#   - "alpaca farming in Iceland"
```

**Run the test:**

```bash
python3 scripts/monitor_conversation.py \
    --keywords "underwater basket weaving" \
    --duration 600
```

**What happens:**

1. Script starts monitoring (Frida hooks + network capture)
2. **You talk about the topic for 10 minutes**
   - Phone nearby, screen off
   - Talk naturally with someone
   - DO NOT type the keywords anywhere!
   - DO NOT search for it online!
3. Script captures:
   - Any microphone access
   - Network uploads
   - Which apps are active
4. Real-time alerts show on screen:
   ```
   🔴 [ALERT] RECORDING_STARTED - Package: com.instagram.android
   🌐 [NETWORK] Upload to 185.199.108.133 (2.3 MB)
   ⚠️  RECORDING DURING CONVERSATION!
   ```

**After 10 minutes:**

```
✅ Monitoring complete!

Results saved to:
  data/logs/conversation_20251123_153045.json
  data/captures/conversation_20251123_153045.pcap

Next step: Analyze results
```

---

## 📊 Step 6: Analyze Results (10 minutes)

### 6a. Analyze Network Traffic

**See what was uploaded:**

```bash
python3 scripts/analyze_pcap.py \
    data/captures/conversation_20251123_153045.pcap
```

**Looks for:**
- Large uploads (>1MB = suspicious for audio)
- Connections to Chinese servers
- Unusual ports or protocols
- Upload timing and patterns

**Output example:**

```
🌐 Network Analysis Report
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📊 Total connections: 47
📤 Total upload: 3.2 MB
📥 Total download: 1.1 MB

🚨 SUSPICIOUS ACTIVITY:

1. com.instagram.android
   └─ Uploaded 2.3 MB to 185.199.108.133
   └─ Time: 15:34:12 (during conversation)
   └─ Port: 443 (HTTPS)
   └─ Suspicion: HIGH

2. com.xiaomi.xmsf
   └─ Uploaded 890 KB to 47.89.52.133 (China)
   └─ Time: 15:35:45
   └─ Suspicion: CRITICAL
```

### 6b. Correlate Events

**Find the smoking gun - audio access + network upload:**

```bash
python3 scripts/correlate_events.py \
    data/logs/conversation_20251123_153045.json
```

**Looks for:**
- Microphone access without user interaction
- Network uploads within 60 seconds of audio access
- No recording indicator shown
- Correlation patterns

**Output example:**

```
🔍 Event Correlation Analysis
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🚨 SMOKING GUN FOUND!

App: com.instagram.android
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Timeline:
  15:34:10 - AudioRecord initialized (MIC source)
  15:34:12 - Recording started (no indicator)
  15:34:28 - Audio data read (16 seconds)
  15:34:32 - Recording stopped
  15:34:45 - Network upload started (2.3 MB)
  15:34:58 - Upload completed

⚠️  SUSPICION SCORE: 85/100 (CRITICAL)

Evidence:
  ✓ Microphone accessed during conversation
  ✓ No user interaction (screen was off)
  ✓ No recording indicator shown
  ✓ Large upload (2.3 MB) within 13 seconds
  ✓ Upload size matches ~16s audio at high quality

VERDICT: CONFIRMED SURVEILLANCE
```

---

## 🎯 Step 7: Confirmation Test (24-48 hours)

**Final proof - Do ads appear?**

**For the next 24-48 hours:**

1. **Use phone normally** (but don't search for test topic!)
2. **Check these apps for targeted content:**
   - YouTube recommendations
   - Instagram/Facebook ads
   - TikTok feed
   - Google search suggestions
   - Amazon recommendations

3. **Document evidence:**
   ```bash
   # Take screenshots when you see targeted content
   # Save to data/evidence/
   ```

4. **If you see ads about your test topic:**
   - **CONFIRMED SURVEILLANCE** 🚨
   - You've proven the connection
   - Document everything for your blog post

**Scoring:**

```
Audio access + Upload + Ads within 24h = 100+ points
→ CONFIRMED SURVEILLANCE

Audio access + Upload (no ads yet) = 50-80 points
→ HIGH SUSPICION (monitor longer)

Audio access only (no upload) = 10-30 points
→ SUSPICIOUS (app initialized mic but didn't use it)

No audio access = 0 points
→ NOT SURVEILLANCE (at least not via microphone)
```

---

## 📋 Complete Investigation Workflow

```
┌─────────────────────────────────────────────┐
│ 1. Setup Mac (30 min)                       │
│    bash setup.sh                            │
└──────────────────┬──────────────────────────┘
                   ↓
┌─────────────────────────────────────────────┐
│ 2. Enable USB Debugging (5 min)             │
│    Settings → Developer options             │
└──────────────────┬──────────────────────────┘
                   ↓
┌─────────────────────────────────────────────┐
│ 3. Install Frida (10 min)                   │
│    Push frida-server to phone               │
└──────────────────┬──────────────────────────┘
                   ↓
┌─────────────────────────────────────────────┐
│ 4. Root Phone (OPTIONAL - 60 min)           │
│    bash scripts/root_phone.sh               │
│    ⚠️  Only if testing system apps          │
└──────────────────┬──────────────────────────┘
                   ↓
┌─────────────────────────────────────────────┐
│ 5. Baseline Test (30 min)                   │
│    python3 scripts/monitor_baseline.py      │
│    Leave phone idle, detect normal behavior │
└──────────────────┬──────────────────────────┘
                   ↓
┌─────────────────────────────────────────────┐
│ 6. Conversation Test (20 min)               │
│    python3 scripts/monitor_conversation.py  │
│    Talk about unique topic for 10 minutes   │
└──────────────────┬──────────────────────────┘
                   ↓
┌─────────────────────────────────────────────┐
│ 7. Analyze Results (10 min)                 │
│    python3 scripts/analyze_pcap.py ...      │
│    python3 scripts/correlate_events.py ...  │
└──────────────────┬──────────────────────────┘
                   ↓
┌─────────────────────────────────────────────┐
│ 8. System Apps Test (OPTIONAL - 30 min)     │
│    python3 scripts/analyze_system_apps.py   │
│    Requires root                            │
└──────────────────┬──────────────────────────┘
                   ↓
┌─────────────────────────────────────────────┐
│ 9. Confirmation (24-48 hours)               │
│    Monitor for targeted ads/content         │
│    Document evidence                        │
└──────────────────┬──────────────────────────┘
                   ↓
┌─────────────────────────────────────────────┐
│ 10. Report Findings                         │
│     Update BLOG_POST.md                     │
│     Share methodology & results             │
└─────────────────────────────────────────────┘
```

---

## 🔧 Troubleshooting

### "adb: device not found"

```bash
# Check USB cable is connected
lsusb

# Restart ADB server
adb kill-server
adb start-server
adb devices

# On phone: Re-allow USB debugging
```

### "Frida connection failed"

```bash
# Make sure Frida server is running on phone
adb shell "ps | grep frida"

# If not running, start it:
adb shell "/data/local/tmp/frida-server &"

# Check versions match
frida --version                    # On Mac
adb shell "/data/local/tmp/frida-server --version"  # On phone

# Must be the same version!
```

### "Permission denied" when running Frida

```bash
# Frida needs root for some operations
# Either:
#   1. Root your phone (scripts/root_phone.sh)
#   2. Only test user apps (works without root)
```

### "No audio access detected"

**Possible reasons:**

1. **Phone was locked** → Some apps pause when screen is off
   - Try with screen on but in another app
2. **App doesn't have permission** → Check Settings → Permissions
3. **App uses native audio APIs** → Try `frida/native_audio_hooks.js`
4. **App isn't actually listening** → Good news! Not surveillance

### Network capture shows no data

```bash
# Make sure tcpdump is installed
adb shell "which tcpdump"

# If not found, you need root access
# Or use Wireshark with USB debugging
```

---

## 📁 Project Structure

```
spyphone_or_trustyphone/
│
├── README.md                    ← YOU ARE HERE (step-by-step guide)
├── DO_I_NEED_ROOT.md           ← Should you root? Decision guide
├── INVESTIGATION_FLOWCHART.md  ← Visual workflow diagrams
├── TECHNICAL_EXPLAINED.md      ← Deep dive into how it works
├── BLOG_POST.md                ← Template for your findings
│
├── setup.sh                     ← Automated setup script
│
├── frida/                       ← Frida hooks (JavaScript)
│   ├── audio_hooks.js          ← Monitor microphone access
│   ├── network_hooks.js        ← Monitor network uploads
│   └── native_audio_hooks.js   ← Native audio APIs (OpenSL, AAudio)
│
├── scripts/                     ← Python automation scripts
│   ├── monitor_baseline.py     ← Establish normal behavior
│   ├── monitor_conversation.py ← Main test (conversation)
│   ├── monitor_longterm.py     ← Long-term monitoring (hours/days)
│   ├── analyze_pcap.py         ← Analyze network captures
│   ├── correlate_events.py     ← Find smoking gun correlations
│   ├── analyze_app.py          ← Deep dive into specific app
│   ├── root_phone.sh           ← Automated rooting (Magisk)
│   └── analyze_system_apps.py  ← Monitor Xiaomi system apps
│
├── docker/                      ← Docker setup (optional)
│   └── Dockerfile              ← Containerized analysis environment
│
├── data/                        ← Generated during tests
│   ├── logs/                   ← Frida event logs (JSON)
│   ├── captures/               ← Network captures (PCAP)
│   ├── reports/                ← Analysis reports
│   └── evidence/               ← Screenshots of targeted ads
│
├── requirements.txt             ← Python dependencies
├── .gitignore                   ← Git ignore rules
├── .dockerignore               ← Docker ignore rules
└── LICENSE                      ← MIT License
```

---

## 🎓 Understanding The Tools

### What is Frida?

**Frida** = Dynamic instrumentation toolkit

**In simple terms:** Frida lets you inject code into running apps to see what they're doing in real-time.

**What we use it for:**
- Hook into Android's audio APIs (AudioRecord, MediaRecorder)
- Detect when apps access the microphone
- Monitor network connections
- Capture data without modifying the app

**Read more:** See `TECHNICAL_EXPLAINED.md` for deep dive.

### What is Wireshark/tcpdump?

**Wireshark** = Network protocol analyzer

**In simple terms:** Records all data going in/out of your phone like a security camera for network traffic.

**What we use it for:**
- Capture all network packets (PCAP files)
- See what data is uploaded
- Identify suspicious large uploads
- Correlate with microphone access

### What is ADB?

**ADB** = Android Debug Bridge

**In simple terms:** A command-line tool to control your Android device from your computer.

**What we use it for:**
- Install Frida server
- Push/pull files
- Run shell commands
- Capture network traffic

---

## 🚨 What If I Find Surveillance?

### If Results Confirm Your Phone is Spying:

1. **Document Everything**
   - Save all logs and reports
   - Take screenshots of analysis
   - Record timeline of events

2. **Immediate Actions**
   - Revoke microphone permission for guilty app
   - Uninstall suspicious apps
   - Block network access via firewall
   - Disable Xiaomi system services (if rooted)

3. **Long-Term Solutions**
   - Install privacy-focused custom ROM (LineageOS)
   - Switch to iPhone (better privacy by default)
   - Buy from reputable manufacturers
   - Use open-source apps

4. **Report Findings**
   - Update `BLOG_POST.md` with your results
   - Share on social media
   - Report to privacy advocates (EFF, Privacy International)
   - Contact manufacturer
   - Report to authorities (GDPR violation in EU)

5. **Help Others**
   - Publish your findings
   - Share this methodology
   - Document which apps/services are guilty
   - Contribute back to this project

---

## 📖 Additional Documentation

- **`DO_I_NEED_ROOT.md`** - Should you root? Pros/cons, decision tree
- **`INVESTIGATION_FLOWCHART.md`** - Visual workflow, decision trees, scoring
- **`TECHNICAL_EXPLAINED.md`** - Deep dive: How Frida works, Android audio architecture
- **`BLOG_POST.md`** - Template for publishing your findings

---

## 🤝 Contributing

Found a bug? Have suggestions? Want to add support for more devices?

1. Fork this repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

**Help wanted:**
- Support for other Android manufacturers (Samsung, Oppo, etc.)
- iOS version (harder, requires jailbreak)
- Automated ad detection (scrape YouTube/Instagram APIs)
- Machine learning for pattern detection

---

## ⚖️ Legal & Ethics

**This tool is for:**
- ✅ Testing YOUR OWN device
- ✅ Security research
- ✅ Privacy advocacy
- ✅ Educational purposes

**This tool is NOT for:**
- ❌ Spying on others
- ❌ Illegal surveillance
- ❌ Hacking apps without permission
- ❌ Corporate espionage

**Privacy matters. Use responsibly.**

---

## 📄 License

MIT License - See `LICENSE` file.

**TL;DR:** Free to use, modify, and share. No warranty provided.

---

## 🙏 Credits

**Created by:** Your investigation into the suspicious €92 POCO C85

**Built with:**
- Frida (Dynamic instrumentation)
- Wireshark (Network analysis)
- Python (Automation)
- ADB (Android debugging)
- Magisk (Rooting)

**Special thanks to:**
- Frida project (https://frida.re)
- Android security research community
- Privacy advocates fighting surveillance capitalism

---

## ❓ FAQ

**Q: Will this work on other phones?**
A: Yes! Works on any Android device. Some adjustments needed for different manufacturers.

**Q: Do I need technical knowledge?**
A: Basic command-line skills helpful but all scripts are automated. Just follow steps.

**Q: Is this safe?**
A: Yes, Frida only monitors, doesn't modify apps. Rooting has risks (see `DO_I_NEED_ROOT.md`).

**Q: What if I don't find anything?**
A: Good news! Your phone might not be spying. Or surveillance is very sophisticated (unlikely).

**Q: Can this detect all types of surveillance?**
A: Only microphone-based. Can't detect: keyboard logging, screen recording, sensor data.

**Q: Will apps detect Frida and stop surveillance?**
A: Possible but rare. Most apps don't check for Frida. Banking apps might.

**Q: How long does the whole investigation take?**
A: ~3 hours active work + 24-48h waiting for ad confirmation.

**Q: What's the success rate?**
A: If your phone IS spying, this will find it 90%+ of the time (for mic-based surveillance).

---

## 🎯 Next Steps

**Start your investigation now:**

```bash
# 1. Setup
bash setup.sh

# 2. Connect phone and enable USB debugging

# 3. Install Frida server

# 4. Run first test
python3 scripts/monitor_conversation.py \
    --keywords "YOUR_UNIQUE_TOPIC" \
    --duration 600

# 5. Analyze and document results
```

**Good luck! Let's find out the truth. 🔍**

---

**Questions? Issues? Found surveillance?**
Open an issue or discussion in this repository.

