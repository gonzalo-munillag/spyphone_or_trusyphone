# Technical Deep Dive: How This Investigation Works

This document provides an in-depth explanation of the tools, techniques, and methodologies used in this investigation. Read this to understand **why** we use each tool and **how** it works under the hood.

---

## Table of Contents
1. [Overview: The Detection Strategy](#overview-the-detection-strategy)
2. [Frida: Dynamic Instrumentation Explained](#frida-dynamic-instrumentation-explained)
3. [Wireshark & tcpdump: Network Analysis Explained](#wireshark--tcpdump-network-analysis-explained)
4. [Android Audio Architecture](#android-audio-architecture)
5. [Detection Methodology](#detection-methodology)
6. [Understanding the Results](#understanding-the-results)

---

## Overview: The Detection Strategy

### The Problem
Modern smartphones have the capability to record audio through the microphone. While legitimate apps (voice recorders, communication apps) need this, malicious or privacy-violating apps might:
- Record audio without showing the recording indicator
- Listen in the background without user knowledge
- Send conversation data to remote servers
- Use voice data for ad targeting

### Our Approach: Multi-Layer Detection

We use a **defense-in-depth** approach with multiple detection layers:

```
Layer 1: API Hooks (Frida)
    ↓ Detect microphone access attempts
    
Layer 2: System Logs (logcat)
    ↓ Verify system-level audio events
    
Layer 3: Network Monitoring (Wireshark)
    ↓ Catch data exfiltration attempts
    
Layer 4: Correlation Analysis
    ↓ Connect audio access to network uploads
    
Layer 5: Behavioral Analysis
    ↓ Pattern recognition over time
```

If an app is spying on you, it must:
1. **Access the microphone** (we detect this with Frida)
2. **Record audio data** (we detect the API calls)
3. **Process the data** (happens locally, harder to detect)
4. **Send it somewhere** (we detect this with Wireshark)

By monitoring all four stages, we can definitively prove surveillance.

---

## Frida: Dynamic Instrumentation Explained

### What is Dynamic Instrumentation?

**Dynamic instrumentation** means modifying a running program's behavior in real-time without changing its source code or recompiling it.

Think of it like this:
- **Static analysis**: Reading the source code to understand what a program does
- **Dynamic instrumentation**: Watching the program as it runs and seeing what it actually does

### How Frida Works

Frida operates through several components:

#### 1. Frida Server (On Device)
```
Android Device:
┌─────────────────────────────────┐
│  Running Apps (Java/Native)     │
│  ┌─────────┐  ┌──────────┐     │
│  │  App A  │  │  App B   │     │
│  └─────────┘  └──────────┘     │
│        ↑            ↑            │
│        │ monitors   │            │
│  ┌─────┴────────────┴────────┐  │
│  │   Frida Server (native)   │  │
│  │   - Injects into processes│  │
│  │   - Hooks function calls  │  │
│  │   - Executes JS scripts   │  │
│  └───────────────────────────┘  │
└─────────────────────────────────┘
```

The Frida server runs as a native daemon on your Android device with elevated privileges, allowing it to inject code into other processes.

#### 2. Frida Client (On Your Mac)
```
Your Mac:
┌─────────────────────────────────┐
│  Python Script                   │
│  ┌────────────────────────────┐ │
│  │  import frida              │ │
│  │  device.attach("app")      │ │
│  │  script.load()             │ │
│  └────────────────────────────┘ │
│         ↕ USB/Network             │
│  [Communicates with device]      │
└─────────────────────────────────┘
```

#### 3. JavaScript Hooks
```javascript
// This JavaScript runs INSIDE the target app's process!

Java.perform(function() {
    // Get reference to AudioRecord class
    var AudioRecord = Java.use('android.media.AudioRecord');
    
    // Replace the original startRecording method
    AudioRecord.startRecording.implementation = function() {
        // Our code runs first
        console.log('[!] Audio recording started!');
        send({alert: 'RECORDING_STARTED'});
        
        // Then call the original method
        return this.startRecording();
    };
});
```

### The Magic: Function Hooking

**Hooking** means intercepting function calls. Here's how it works:

#### Before Hooking:
```
App calls AudioRecord.startRecording()
    ↓
System executes original function
    ↓
Recording starts
```

#### After Frida Hooks:
```
App calls AudioRecord.startRecording()
    ↓
Frida intercepts the call
    ↓
Our JavaScript code runs:
  - Logs the event
  - Captures parameters
  - Sends alert to monitoring system
    ↓
Frida calls the original function
    ↓
Recording starts (app is unaware we intercepted)
```

### Why This Is Powerful

1. **Transparency**: The app doesn't know it's being monitored
2. **Real-time**: We see events as they happen
3. **Deep access**: We can see both Java and native (C/C++) calls
4. **No root needed**: Works on most devices without rooting (in user mode)

### What We Hook

Our Frida scripts hook these critical audio APIs:

#### Java Layer:
```java
// High-level recording
android.media.MediaRecorder
    .setAudioSource()  ← We hook this
    .start()           ← And this

// Low-level recording
android.media.AudioRecord
    .$init()           ← Constructor - we see initialization
    .startRecording()  ← We see when recording actually starts
    .read()            ← We can even monitor data being read
    .stop()            ← We see when it stops
```

#### Native Layer:
```c
// OpenSL ES (older native audio API)
slCreateEngine()      ← We hook the entry point

// AAudio (newer low-latency API)
AAudio_createStreamBuilder()
AAudioStream_requestStart()

// Direct audio device access
open("/dev/snd/...")  ← Hook system calls to audio devices
```

### Example: What We Capture

When an app tries to record audio, we capture:

```json
{
  "type": "AUDIO_RECORD_CREATED",
  "timestamp": "2024-11-23T14:23:15.123Z",
  "package": "com.suspicious.app",
  "audioSource": "MIC",
  "sampleRate": 44100,
  "channelConfig": "MONO",
  "stackTrace": "at com.suspicious.app.AudioHelper.startListening(...)"
}
```

This tells us:
- **Who**: Which app (`com.suspicious.app`)
- **When**: Exact timestamp
- **What**: Recording from microphone at 44.1kHz
- **Where**: The code location that initiated it

---

## Wireshark & tcpdump: Network Analysis Explained

### Why Network Monitoring?

Recording audio is only half the story. To monetize your conversations, apps need to:
1. Record audio ✓ (Frida detects)
2. Process it (speech-to-text, topic extraction)
3. **Send it to a server** ← This is what Wireshark catches

### How Network Capture Works

#### The Network Stack:
```
Your Phone App
    ↓ [Data to send]
Application Layer (HTTP/HTTPS)
    ↓
Transport Layer (TCP/UDP)
    ↓
Network Layer (IP)
    ↓
Data Link Layer (WiFi/LTE)
    ↓ [Packets on the wire]
Network
```

**Wireshark** captures packets at the Data Link Layer, seeing **everything** that goes in or out.

#### Via ADB Tunnel:
```
Android Device                  Your Mac
┌──────────────┐               ┌────────────────┐
│  App sends   │               │  Wireshark     │
│  data        │               │  analyzes      │
│     ↓        │               │  packets       │
│  Network     │  ═══USB═══►   │                │
│  Interface   │  (tcpdump)    │                │
│     ↓        │               │                │
│  WiFi/LTE    │               │                │
└──────────────┘               └────────────────┘
```

We run `tcpdump` on the Android device and stream packets to Wireshark on your Mac via ADB.

### What We Can See

#### Without HTTPS Decryption:
```
Source IP: 192.168.1.100 (your phone)
Destination IP: 185.199.108.133 (unknown server)
Protocol: TCP
Port: 443 (HTTPS)
Size: 1,247,392 bytes (1.2 MB)
Encrypted: YES
Content: ████████████ (can't see)
```

We know:
- ✓ Data was sent
- ✓ How much (1.2 MB)
- ✓ Where it went
- ✗ What it contained

#### With mitmproxy (HTTPS Decryption):
```
Source: your phone
Destination: api.analytics-server.com
Method: POST /upload/audio
Headers:
  Content-Type: audio/mpeg
  Authorization: Bearer abc123...
Body:
  [Audio file data]
  Duration: 30 seconds
  Size: 1.2 MB
```

Now we know:
- ✓ It's audio data
- ✓ 30 seconds of recording
- ✓ Sent to an analytics server
- ✓ **This is surveillance!**

### mitmproxy: The HTTPS Decryptor

#### The HTTPS Problem:
```
App → [Encrypted Data] → Server
      ↑
We can't read this without the decryption keys
```

#### mitmproxy Solution (Man-in-the-Middle):
```
App → [Encrypted with mitmproxy cert] → mitmproxy → [Encrypted with real cert] → Server
                                           ↓
                                     We can read!
```

**How it works:**
1. Install mitmproxy's certificate on your phone
2. Configure phone to use mitmproxy as proxy
3. Phone trusts mitmproxy's certificate
4. mitmproxy decrypts incoming traffic, re-encrypts for destination
5. We can see the decrypted data in the middle

### Correlation: The Smoking Gun

The most damning evidence is **correlation**:

```
Timeline:
14:23:15 - [Frida] App X calls AudioRecord.startRecording()
14:23:15 - [Frida] Recording from MIC at 44.1kHz
14:23:45 - [Frida] 30 seconds of audio data read (480,000 samples)
14:23:46 - [Frida] AudioRecord.stop()
14:24:00 - [Wireshark] App X uploads 1.2MB to 185.199.108.133:443
14:24:05 - [mitmproxy] Destination: analytics.ad-network.com/audio
14:24:05 - [mitmproxy] Content: audio/mpeg, 30 seconds

Correlation: Audio recorded → Immediately uploaded
Verdict: CONFIRMED SURVEILLANCE
```

---

## Android Audio Architecture

Understanding how Android handles audio helps us know what to monitor.

### Audio Recording Stack:

```
┌─────────────────────────────────────────────┐
│  Application Layer                          │
│  ┌─────────────┐      ┌──────────────┐    │
│  │MediaRecorder│      │ AudioRecord  │    │  ← We hook here
│  │ (high-level)│      │ (low-level)  │    │
│  └─────────────┘      └──────────────┘    │
└──────────────┬──────────────┬──────────────┘
               │              │
┌──────────────┴──────────────┴──────────────┐
│  Android Framework (Java)                   │
│  - Permission checks                        │
│  - Recording indicator management           │
└──────────────┬─────────────────────────────┘
               │
┌──────────────┴─────────────────────────────┐
│  Native Audio (C/C++)                       │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐ │
│  │ OpenSL ES│  │  AAudio  │  │AudioFlinger│ │  ← We also hook here
│  └──────────┘  └──────────┘  └──────────┘ │
└──────────────┬─────────────────────────────┘
               │
┌──────────────┴─────────────────────────────┐
│  Kernel / HAL                               │
│  /dev/snd/pcmC0D0c (audio device)          │
└──────────────┬─────────────────────────────┘
               │
         ┌─────┴─────┐
         │ Microphone│
         └───────────┘
```

### Permission System:

#### Android 12+ (Recording Indicator):
```
App requests recording
    ↓
System checks RECORD_AUDIO permission
    ↓ [If granted]
System shows 🔴 indicator in status bar
    ↓
Recording starts
```

#### Bypass Methods (What We Detect):
1. **System apps** with elevated privileges
2. **Accessibility services** with audio access
3. **Native code** that bypasses framework checks
4. **Bugs** in the permission system

Our monitoring catches all of these because we hook at multiple levels.

---

## Detection Methodology

### Phase 1: Baseline (Control)

**Goal**: Establish what "normal" looks like

**Method**:
- Monitor for 30 minutes with phone idle
- No active app use
- Screen off

**What we're looking for**:
- Apps that access audio during idle (suspicious!)
- Background recording (very suspicious!)
- Network uploads without user interaction

**Expected result**: Near-zero audio access

### Phase 2: Conversation Test (Experiment)

**Goal**: Detect conversation surveillance

**Method**:
1. Choose unique topic: "underwater basket weaving"
2. Start monitoring (Frida + Wireshark)
3. Have 10-minute natural conversation
4. Phone nearby, screen off
5. Do NOT type keywords anywhere
6. Monitor for 24-48 hours after

**What we're looking for**:
- Audio access during conversation
- No recording indicator shown
- Network uploads immediately after
- Later: YouTube/ads about the topic

**Suspicious indicators**:
- Audio access during conversation: ⚠️
- No UI indicator: ⚠️⚠️
- Immediate upload: ⚠️⚠️⚠️
- Topic appears in recommendations: 🚨

### Phase 3: Correlation Analysis

**Process**:
```python
for each audio_recording_event:
    find network_events in next 60 seconds:
        if same_app:
            if large_upload:
                SUSPICIOUS_LEVEL = HIGH
```

**Scoring**:
- Audio access: +5 points
- Network activity within 10s: +10 points
- Large upload (>100KB): +5 points
- Upload to analytics domain: +5 points
- No user interaction: +10 points

**Verdict**:
- <10 points: Normal behavior
- 10-20 points: Investigate further
- >20 points: Likely surveillance

---

## Understanding the Results

### ✅ Normal Behavior

```
Scenario: Voice call via WhatsApp
Events:
- com.whatsapp: AudioRecord.startRecording()
- Recording indicator: SHOWN
- Network: Audio packets to WhatsApp servers
- User interaction: Active call

Verdict: NORMAL - Expected behavior for voice call
```

### ⚠️ Suspicious Behavior

```
Scenario: Social media app
Events:
- com.instagram: AudioRecord.startRecording()
- Recording indicator: SHOWN
- Duration: 2 seconds
- Network: 50KB upload to analytics.facebook.com
- User interaction: None (background)

Verdict: SUSPICIOUS - Why is Instagram recording in background?
```

### 🚨 Confirmed Surveillance

```
Scenario: System app
Events:
- com.xiaomi.xmsf: AudioRecord.startRecording()
- Recording indicator: NOT SHOWN
- Duration: 60 seconds
- Network: 1.2MB upload to server in China
- User interaction: None (conversation happening)
- Later: Ads about conversation topic

Verdict: CONFIRMED SURVEILLANCE
Actions: 
1. Disable app if possible
2. Revoke permissions
3. Consider custom ROM
4. Report to authorities/media
```

---

## Advanced Topics

### Obfuscation Techniques (How Apps Try to Hide)

1. **Native Code**
   - Use C/C++ instead of Java (harder to detect)
   - Our solution: Hook native APIs too

2. **Audio Sampling**
   - Record 1 second every minute (less obvious)
   - Our solution: Any recording is suspicious during idle

3. **On-Device Processing**
   - Convert speech-to-text locally, only send text
   - Our solution: Still shows as network upload

4. **Delayed Upload**
   - Record now, upload hours later
   - Our solution: Long-term monitoring catches it

5. **Encryption**
   - Encrypt before uploading
   - Our solution: mitmproxy catches it before encryption

### False Positives

Some legitimate apps may trigger alerts:

- **Voice assistants** (Google Assistant, Alexa)
- **Voice typin**g features
- **Accessibility services** for disabled users
- **Background noise detection** for smart features

Always investigate the context!

---

## Conclusion

This investigation combines:
- **Dynamic instrumentation** (Frida) for API monitoring
- **Network analysis** (Wireshark/mitmproxy) for data exfiltration detection
- **Correlation analysis** to connect the dots
- **Behavioral monitoring** for pattern recognition

Together, these create an **unforgeable evidence trail**. If an app is spying on you, we **will** catch it.

The question is not "can we detect it?" but "is it happening?"

That's what this investigation will answer.

---

**Next**: Follow the practical steps in `README.md` to run the investigation on your device.

