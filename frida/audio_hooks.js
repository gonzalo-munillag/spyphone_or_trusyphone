/**
 * ============================================================================
 * FRIDA SCRIPT: Audio Recording API Hooks
 * ============================================================================
 * 
 * PURPOSE:
 *   Detects when apps access the microphone by hooking Android's audio APIs.
 *   This catches both legitimate and covert audio recording attempts.
 * 
 * HOW IT WORKS:
 *   Frida injects this JavaScript code into running Android processes.
 *   We replace (hook) original audio functions with our own versions that:
 *   1. Log the event (who, when, what parameters)
 *   2. Call the original function (so app continues normally)
 *   3. Send data back to monitoring script on your Mac
 * 
 * WHAT WE MONITOR:
 *   - AudioRecord: Low-level direct audio recording (most common)
 *   - MediaRecorder: High-level recording (includes video)
 *   - AudioManager: System audio state management
 *   - Permission checks: When apps check RECORD_AUDIO permission
 * 
 * WHY MULTIPLE APIS:
 *   Apps can use different APIs to access audio:
 *   - Normal apps use AudioRecord or MediaRecorder
 *   - Some apps use MediaRecorder for both audio & video
 *   - System apps might use lower-level APIs
 *   We hook all of them to catch everything
 * 
 * OUTPUT:
 *   JSON events sent to monitoring script via send() function
 *   Each event includes: timestamp, app package, API used, parameters
 * 
 * ROOT REQUIRED:
 *   NO - Works without root for user apps
 *   YES - For system apps (like Xiaomi services)
 * ============================================================================
 */

console.log('[*] Audio Hooks Script Loading...');

// Global session tracking
// We assign each AudioRecord instance a unique ID to track its lifecycle
var activeSessions = {};  // Maps session ID to session info
var sessionCounter = 0;    // Auto-incrementing session ID

/**
 * ============================================================================
 * HOOK: AudioRecord (Low-Level Audio Recording)
 * ============================================================================
 * 
 * WHAT IS AUDIORECORD:
 *   AudioRecord is Android's low-level API for recording raw audio data.
 *   It gives apps direct access to PCM audio streams from the microphone.
 * 
 * WHY IT'S IMPORTANT:
 *   This is the MOST COMMON way apps record audio. If an app is listening
 *   to you, it's probably using AudioRecord.
 * 
 * WHAT WE HOOK:
 *   1. Constructor ($init): Captures when recording is initialized
 *   2. startRecording(): Captures when recording actually begins
 *   3. stop(): Captures when recording stops
 *   4. read(): (sampled) Monitors data being read from microphone
 * 
 * PARAMETERS EXPLAINED:
 *   - audioSource: Where audio comes from (MIC, VOICE_CALL, etc.)
 *   - sampleRate: Quality (44100 = CD quality, 16000 = voice)
 *   - channelConfig: MONO or STEREO
 *   - audioFormat: Bit depth (PCM_8BIT, PCM_16BIT, etc.)
 *   - bufferSize: How much data to buffer (in bytes)
 * 
 * SUSPICIOUS INDICATORS:
 *   - audioSource = MIC during idle time
 *   - High sample rates (44100+) = recording quality audio
 *   - Stack trace not from expected app code
 * ============================================================================
 */
function hookAudioRecord() {
    console.log('[*] Hooking AudioRecord...');
    
    Java.perform(function() {
        try {
            // Get references to Android classes we need
            var AudioRecord = Java.use('android.media.AudioRecord');
            var Process = Java.use('android.os.Process');
            
            // ----------------------------------------------------------------
            // HOOK 1: AudioRecord Constructor
            // ----------------------------------------------------------------
            // This is called when app creates a new AudioRecord instance
            // It doesn't start recording yet, just initializes the object
            AudioRecord.$init.overload(
                'int', 'int', 'int', 'int', 'int'
            ).implementation = function(audioSource, sampleRate, channelConfig, audioFormat, bufferSize) {
                // Our custom implementation that runs INSTEAD of the original
                // We log everything, then call the original to let recording proceed
                
                // ============================================================
                // STEP 1: Generate unique session ID for tracking
                // ============================================================
                // Each AudioRecord instance gets a unique ID so we can track
                // its entire lifecycle (create → start → read → stop)
                var sessionId = sessionCounter++;  // Auto-increment counter
                
                // ============================================================
                // STEP 2: Capture metadata about this recording session
                // ============================================================
                var timestamp = new Date().toISOString();  // ISO 8601 timestamp
                var pid = Process.myPid();  // Process ID (which app process)
                var uid = Process.myUid();  // User ID (which Android user)
                
                // Get the call stack to see which part of the app called this
                // This helps identify if it's legitimate code or hidden surveillance
                var stackTrace = getStackTrace();
                
                // ============================================================
                // STEP 3: Decode audio source parameter
                // ============================================================
                // Android uses integer constants for audio sources
                // We map them to human-readable strings for the logs
                var sourceTypes = {
                    0: 'DEFAULT',              // Default audio source
                    1: 'MIC',                  // 🚨 Main microphone (SUSPICIOUS if during idle)
                    2: 'VOICE_UPLINK',         // Transmitted audio during call
                    3: 'VOICE_DOWNLINK',       // Received audio during call
                    4: 'VOICE_CALL',           // Call audio (both directions)
                    5: 'CAMCORDER',            // Camera/video recording
                    6: 'VOICE_RECOGNITION',    // Voice assistant (OK Button, Google)
                    7: 'VOICE_COMMUNICATION',  // VoIP apps (WhatsApp, Telegram)
                    9: 'REMOTE_SUBMIX',        // System audio routing
                    10: 'UNPROCESSED'          // Raw mic without processing
                };
                
                // ============================================================
                // STEP 4: Build event object with all captured information
                // ============================================================
                var info = {
                    type: 'AUDIO_RECORD_CREATED',  // Event type identifier
                    sessionId: sessionId,           // Our tracking ID
                    timestamp: timestamp,           // When this happened
                    pid: pid,                       // Process ID
                    uid: uid,                       // User ID
                    
                    // Audio parameters (these tell us quality and purpose):
                    audioSource: sourceTypes[audioSource] || audioSource,  // Where audio comes from
                    sampleRate: sampleRate,         // Hz (44100=CD, 16000=voice, 8000=phone)
                    channelConfig: channelConfig,   // Mono vs Stereo
                    audioFormat: audioFormat,       // Bit depth (8/16/24 bit)
                    bufferSize: bufferSize,         // Buffer size in bytes
                    
                    // Forensic information:
                    stackTrace: stackTrace,         // Call stack for debugging
                    package: getPackageName()       // Which app (e.g., com.instagram.android)
                };
                
                // ============================================================
                // STEP 5: Send event to monitoring script (on your Mac)
                // ============================================================
                send(info);  // Frida's send() transmits to Python script
                console.log('[!] AudioRecord created by ' + info.package);
                
                // ============================================================
                // STEP 6: Store session info for correlation with later events
                // ============================================================
                // When startRecording() or stop() is called, we'll need this info
                activeSessions[sessionId] = info;
                
                // ============================================================
                // STEP 7: Call the ORIGINAL constructor to let app proceed
                // ============================================================
                // This is critical! We must call the original method or the app breaks
                // The app has NO IDEA we intercepted this call
                var result = this.$init(audioSource, sampleRate, channelConfig, audioFormat, bufferSize);
                
                // ============================================================
                // STEP 8: Tag this AudioRecord object with our session ID
                // ============================================================
                // We attach our session ID to the Java object so when other
                // methods (start, stop, read) are called, we can correlate them
                this.fridaSessionId = sessionId;
                
                // Return the result from original constructor
                return result;
            };
            
            // ----------------------------------------------------------------
            // HOOK 2: AudioRecord.startRecording()
            // ----------------------------------------------------------------
            // This is called when recording ACTUALLY STARTS
            // Constructor just sets up, this method activates the microphone
            // 🚨 THIS IS THE KEY MOMENT - MIC IS NOW ACTIVE!
            AudioRecord.startRecording.implementation = function() {
                // ============================================================
                // Retrieve session ID we attached in constructor
                // ============================================================
                // If fridaSessionId exists, we hooked the constructor
                // If not, this AudioRecord was created before our script loaded
                var sessionId = this.fridaSessionId || 'unknown';
                var timestamp = new Date().toISOString();
                
                // ============================================================
                // Build alert event
                // ============================================================
                var info = {
                    type: 'RECORDING_STARTED',     // 🚨 CRITICAL EVENT
                    sessionId: sessionId,          // Links to AUDIO_RECORD_CREATED
                    timestamp: timestamp,
                    package: getPackageName(),
                    
                    // AudioRecord has internal state we can check:
                    state: this.getState(),               // UNINITIALIZED/INITIALIZED
                    recordingState: this.getRecordingState()  // RECORDSTATE_STOPPED/RECORDING
                };
                
                // ============================================================
                // Send CRITICAL ALERT to monitoring script
                // ============================================================
                send(info);
                console.log('[!!!] RECORDING STARTED by ' + info.package);
                // Triple exclamation marks (!!!) indicate high-priority alert
                
                // ============================================================
                // Call original method to actually start recording
                // ============================================================
                return this.startRecording();
            };
            
            // ----------------------------------------------------------------
            // HOOK 3: AudioRecord.stop()
            // ----------------------------------------------------------------
            // Called when app stops recording
            // This closes the recording session - mic is now inactive
            AudioRecord.stop.implementation = function() {
                // Retrieve our session ID
                var sessionId = this.fridaSessionId || 'unknown';
                var timestamp = new Date().toISOString();
                
                // Build stop event
                var info = {
                    type: 'RECORDING_STOPPED',     // Recording ended
                    sessionId: sessionId,          // Links to start event
                    timestamp: timestamp,
                    package: getPackageName()
                };
                
                // Log the stop event
                send(info);
                console.log('[*] Recording stopped by ' + info.package);
                
                // Call original stop() method
                return this.stop();
            };
            
            // ----------------------------------------------------------------
            // HOOK 4: AudioRecord.read() - Monitor audio data being captured
            // ----------------------------------------------------------------
            // This is called repeatedly while recording to get audio samples
            // It reads raw PCM data from the microphone into a buffer
            // Can be called hundreds of times per second!
            AudioRecord.read.overload('[B', 'int', 'int').implementation = function(audioData, offsetInBytes, sizeInBytes) {
                // audioData: Java byte array that will receive the audio
                // offsetInBytes: Where to start writing in the array
                // sizeInBytes: How many bytes to read
                
                var sessionId = this.fridaSessionId || 'unknown';
                
                // ============================================================
                // Call original read() to actually get audio data
                // ============================================================
                var bytesRead = this.read(audioData, offsetInBytes, sizeInBytes);
                // bytesRead: How many bytes were actually read (can be less than requested)
                
                // ============================================================
                // Sampling: Only log 1% of reads to avoid flooding logs
                // ============================================================
                // read() is called VERY frequently (e.g., 100 times/second)
                // Logging every call would generate gigabytes of logs
                // Instead, we randomly sample 1% to show recording is active
                if (Math.random() < 0.01) {  // 1% probability
                    var info = {
                        type: 'AUDIO_DATA_READ',       // Data was actually captured
                        sessionId: sessionId,
                        timestamp: new Date().toISOString(),
                        bytesRead: bytesRead,          // How much audio data
                        package: getPackageName()
                    };
                    send(info);
                    
                    // Note: We're NOT logging the actual audio content (audioData)
                    // because that would be huge and privacy-invasive
                    // We only care THAT data is being read, not WHAT it contains
                }
                
                return bytesRead;
            };
            
            console.log('[+] AudioRecord hooked successfully');
            
        } catch (e) {
            console.log('[-] Error hooking AudioRecord: ' + e);
        }
    });
}

/**
 * Hook MediaRecorder - High-level recording API
 * Used for both audio and video recording
 */
function hookMediaRecorder() {
    console.log('[*] Hooking MediaRecorder...');
    
    Java.perform(function() {
        try {
            var MediaRecorder = Java.use('android.media.MediaRecorder');
            var Process = Java.use('android.os.Process');
            
            // Hook setAudioSource
            MediaRecorder.setAudioSource.implementation = function(audioSource) {
                var timestamp = new Date().toISOString();
                
                var sourceTypes = {
                    0: 'DEFAULT',
                    1: 'MIC',
                    2: 'VOICE_UPLINK',
                    3: 'VOICE_DOWNLINK',
                    4: 'VOICE_CALL',
                    5: 'CAMCORDER',
                    6: 'VOICE_RECOGNITION',
                    7: 'VOICE_COMMUNICATION'
                };
                
                var info = {
                    type: 'MEDIARECORDER_AUDIO_SOURCE',
                    timestamp: timestamp,
                    audioSource: sourceTypes[audioSource] || audioSource,
                    package: getPackageName(),
                    stackTrace: getStackTrace()
                };
                
                send(info);
                console.log('[!] MediaRecorder audio source set: ' + info.audioSource);
                
                return this.setAudioSource(audioSource);
            };
            
            // Hook start
            MediaRecorder.start.implementation = function() {
                var timestamp = new Date().toISOString();
                
                var info = {
                    type: 'MEDIARECORDER_STARTED',
                    timestamp: timestamp,
                    package: getPackageName()
                };
                
                send(info);
                console.log('[!!!] MEDIARECORDER STARTED by ' + info.package);
                
                return this.start();
            };
            
            // Hook stop
            MediaRecorder.stop.implementation = function() {
                var timestamp = new Date().toISOString();
                
                var info = {
                    type: 'MEDIARECORDER_STOPPED',
                    timestamp: timestamp,
                    package: getPackageName()
                };
                
                send(info);
                console.log('[*] MediaRecorder stopped by ' + info.package);
                
                return this.stop();
            };
            
            console.log('[+] MediaRecorder hooked successfully');
            
        } catch (e) {
            console.log('[-] Error hooking MediaRecorder: ' + e);
        }
    });
}

/**
 * Hook AudioManager - Check recording indicator status
 */
function hookAudioManager() {
    console.log('[*] Hooking AudioManager...');
    
    Java.perform(function() {
        try {
            var AudioManager = Java.use('android.media.AudioManager');
            
            // Hook setMode (can indicate voice call mode)
            AudioManager.setMode.implementation = function(mode) {
                var modeTypes = {
                    0: 'NORMAL',
                    1: 'RINGTONE',
                    2: 'IN_CALL',
                    3: 'IN_COMMUNICATION'
                };
                
                var info = {
                    type: 'AUDIO_MODE_CHANGED',
                    timestamp: new Date().toISOString(),
                    mode: modeTypes[mode] || mode,
                    package: getPackageName()
                };
                
                send(info);
                
                return this.setMode(mode);
            };
            
            console.log('[+] AudioManager hooked successfully');
            
        } catch (e) {
            console.log('[-] Error hooking AudioManager: ' + e);
        }
    });
}

/**
 * ============================================================================
 * HELPER FUNCTION: Get Package Name
 * ============================================================================
 * 
 * PURPOSE:
 *   Identifies which app is currently running by getting its package name
 *   (e.g., "com.instagram.android", "com.xiaomi.xmsf")
 * 
 * HOW IT WORKS:
 *   - Gets the current Application instance via ActivityThread
 *   - Retrieves the ApplicationContext
 *   - Extracts package name from context
 * 
 * USED BY:
 *   All hook functions to identify the culprit app
 * 
 * RETURNS:
 *   Package name string (e.g., "com.example.app") or "unknown" if fails
 */
function getPackageName() {
    try {
        // ActivityThread is Android's internal class managing app lifecycle
        var ActivityThread = Java.use('android.app.ActivityThread');
        
        // Get the current running application instance
        var currentApplication = ActivityThread.currentApplication();
        
        if (currentApplication) {
            // Get application context (contains app metadata)
            var context = currentApplication.getApplicationContext();
            
            // Extract package name (unique app identifier)
            return context.getPackageName();
        }
    } catch (e) {
        // If anything fails (not in app context, permissions, etc.)
        return 'unknown';
    }
    return 'unknown';
}

/**
 * ============================================================================
 * HELPER FUNCTION: Get Stack Trace
 * ============================================================================
 * 
 * PURPOSE:
 *   Captures the call stack showing which code called the audio API
 *   This helps identify if the call is from legitimate app code or
 *   hidden surveillance code
 * 
 * HOW IT WORKS:
 *   - Creates a new Exception object (doesn't throw it)
 *   - Uses Android's Log.getStackTraceString() to format the stack
 *   - Returns multi-line string showing the call chain
 * 
 * EXAMPLE OUTPUT:
 *   java.lang.Exception
 *     at com.example.app.AudioHelper.startRecording(AudioHelper.java:45)
 *     at com.example.app.MainActivity.onCreate(MainActivity.java:123)
 *     ...
 * 
 * WHY IT'S USEFUL:
 *   - Shows WHERE in the app the audio access originated
 *   - Can reveal obfuscated or hidden code
 *   - Helps distinguish legitimate vs suspicious calls
 * 
 * RETURNS:
 *   Multi-line stack trace string or "Stack trace unavailable"
 */
function getStackTrace() {
    try {
        // Create a new Exception (just for its stack trace, not thrown)
        var Exception = Java.use('java.lang.Exception');
        var exceptionInstance = Exception.$new();
        
        // Use Android's Log class to format the stack trace nicely
        var Log = Java.use('android.util.Log');
        var stackTrace = Log.getStackTraceString(exceptionInstance);
        
        return stackTrace;
    } catch (e) {
        // If stack trace extraction fails
        return 'Stack trace unavailable';
    }
}

/**
 * Hook permission checks
 */
function hookPermissions() {
    console.log('[*] Hooking permission checks...');
    
    Java.perform(function() {
        try {
            var ContextWrapper = Java.use('android.content.ContextWrapper');
            
            ContextWrapper.checkPermission.overload('java.lang.String', 'int', 'int').implementation = function(permission, pid, uid) {
                var result = this.checkPermission(permission, pid, uid);
                
                if (permission.includes('RECORD_AUDIO')) {
                    var info = {
                        type: 'PERMISSION_CHECK',
                        timestamp: new Date().toISOString(),
                        permission: permission,
                        result: result === 0 ? 'GRANTED' : 'DENIED',
                        pid: pid,
                        uid: uid,
                        package: getPackageName()
                    };
                    
                    send(info);
                }
                
                return result;
            };
            
            console.log('[+] Permission checks hooked successfully');
            
        } catch (e) {
            console.log('[-] Error hooking permissions: ' + e);
        }
    });
}

// Initialize all hooks
setTimeout(function() {
    console.log('[*] Initializing audio surveillance detection...');
    hookAudioRecord();
    hookMediaRecorder();
    hookAudioManager();
    hookPermissions();
    console.log('[+] All hooks initialized. Monitoring for audio access...');
}, 0);

