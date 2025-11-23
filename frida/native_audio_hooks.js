/**
 * ============================================================================
 * FRIDA SCRIPT: Native (C/C++) Audio API Hooks
 * ============================================================================
 * 
 * PURPOSE:
 *   Catches apps that use native code (C/C++) to access audio instead of
 *   Java APIs. This is a common obfuscation technique to avoid detection.
 * 
 * WHY NATIVE CODE IS SUSPICIOUS:
 *   - Harder to detect with standard Android monitoring
 *   - Can sometimes bypass permission checks
 *   - Often used by apps trying to hide their behavior
 *   - Performance-critical apps (games, audio processors) also use it
 * 
 * WHAT WE MONITOR:
 *   1. OpenSL ES: Older native audio API (still widely used)
 *      - slCreateEngine(): Entry point to OpenSL ES
 *      - Used by many apps for low-latency audio
 * 
 *   2. AAudio: Newer low-latency API (Android 8.0+)
 *      - AAudio_createStreamBuilder(): Creates audio stream
 *      - AAudioStream_requestStart(): Starts recording/playback
 * 
 *   3. Native JNI Calls: Direct audio device access
 *      - Functions in libaudioclient.so, libaudioflinger.so
 *      - Direct access to /dev/snd/* device files
 * 
 *   4. System Calls: Lowest level
 *      - open() calls to /dev/snd/pcmC0D0c (audio capture device)
 *      - This is what ALL audio APIs eventually call
 * 
 * HOW IT WORKS:
 *   Unlike Java hooks, we use Interceptor.attach() to hook native functions
 *   by their memory address. We find functions by name in shared libraries.
 * 
 * WHEN THIS CATCHES SOMETHING:
 *   If audio_hooks.js finds nothing but this script does, the app is:
 *   - Using native code to access audio
 *   - Possibly trying to avoid detection
 *   - Potentially malicious (or just performance-optimized)
 * 
 * ROOT REQUIRED: NO (usually)
 *   Some system libraries may require root to hook
 * ============================================================================
 */

console.log('[*] Native Audio Hooks Script Loading...');

/**
 * Hook OpenSL ES audio APIs
 */
function hookOpenSLES() {
    console.log('[*] Hooking OpenSL ES...');
    
    try {
        // OpenSL ES uses function pointers in structs, making it tricky to hook
        // We'll hook the entry point: slCreateEngine
        
        var slCreateEngine = Module.findExportByName('libOpenSLES.so', 'slCreateEngine');
        
        if (slCreateEngine) {
            Interceptor.attach(slCreateEngine, {
                onEnter: function(args) {
                    console.log('[!] OpenSL ES Engine Created');
                    
                    send({
                        type: 'OPENSLES_ENGINE_CREATED',
                        timestamp: new Date().toISOString(),
                        address: slCreateEngine
                    });
                },
                onLeave: function(retval) {
                    console.log('[*] slCreateEngine returned: ' + retval);
                }
            });
            
            console.log('[+] OpenSL ES hooked successfully');
        } else {
            console.log('[-] OpenSL ES not found (may not be used)');
        }
        
    } catch (e) {
        console.log('[-] Error hooking OpenSL ES: ' + e);
    }
}

/**
 * Hook AAudio (Android's new low-latency audio API)
 */
function hookAAudio() {
    console.log('[*] Hooking AAudio...');
    
    try {
        // Hook AAudio stream creation
        var AAudio_createStreamBuilder = Module.findExportByName('libaaudio.so', 'AAudio_createStreamBuilder');
        
        if (AAudio_createStreamBuilder) {
            Interceptor.attach(AAudio_createStreamBuilder, {
                onEnter: function(args) {
                    console.log('[!] AAudio Stream Builder Created');
                    
                    send({
                        type: 'AAUDIO_STREAM_BUILDER_CREATED',
                        timestamp: new Date().toISOString()
                    });
                },
                onLeave: function(retval) {
                    console.log('[*] AAudio_createStreamBuilder returned: ' + retval);
                }
            });
            
            console.log('[+] AAudio hooked successfully');
        } else {
            console.log('[-] AAudio not found (may not be used)');
        }
        
        // Hook stream opening
        var AAudioStream_requestStart = Module.findExportByName('libaaudio.so', 'AAudioStream_requestStart');
        
        if (AAudioStream_requestStart) {
            Interceptor.attach(AAudioStream_requestStart, {
                onEnter: function(args) {
                    console.log('[!!!] AAudio Stream STARTED');
                    
                    send({
                        type: 'AAUDIO_STREAM_STARTED',
                        timestamp: new Date().toISOString(),
                        stream: args[0]
                    });
                }
            });
        }
        
    } catch (e) {
        console.log('[-] Error hooking AAudio: ' + e);
    }
}

/**
 * Hook native AudioRecord calls via JNI
 */
function hookNativeAudioRecord() {
    console.log('[*] Hooking native AudioRecord JNI...');
    
    try {
        // Look for common native audio recording functions
        var libNames = ['libaudioclient.so', 'libaudioflinger.so', 'libaudio.so'];
        
        libNames.forEach(function(libName) {
            try {
                var lib = Process.getModuleByName(libName);
                
                if (lib) {
                    console.log('[+] Found ' + libName);
                    
                    // Hook common recording functions
                    var exports = lib.enumerateExports();
                    exports.forEach(function(exp) {
                        if (exp.name.toLowerCase().includes('record') || 
                            exp.name.toLowerCase().includes('capture') ||
                            exp.name.toLowerCase().includes('audio')) {
                            
                            try {
                                Interceptor.attach(exp.address, {
                                    onEnter: function(args) {
                                        console.log('[*] Native call: ' + exp.name);
                                        
                                        send({
                                            type: 'NATIVE_AUDIO_CALL',
                                            timestamp: new Date().toISOString(),
                                            function: exp.name,
                                            library: libName
                                        });
                                    }
                                });
                            } catch (e) {
                                // Some functions may not be hookable, that's okay
                            }
                        }
                    });
                }
            } catch (e) {
                console.log('[-] ' + libName + ' not found: ' + e);
            }
        });
        
    } catch (e) {
        console.log('[-] Error hooking native audio: ' + e);
    }
}

/**
 * Monitor audio-related system calls
 */
function hookAudioSystemCalls() {
    console.log('[*] Monitoring audio system calls...');
    
    try {
        // Hook open() for audio device files
        var openPtr = Module.findExportByName(null, 'open');
        
        if (openPtr) {
            Interceptor.attach(openPtr, {
                onEnter: function(args) {
                    var path = Memory.readUtf8String(args[0]);
                    
                    // Check if opening audio device
                    if (path && (path.includes('/dev/snd') || 
                                 path.includes('audio') || 
                                 path.includes('pcm'))) {
                        
                        console.log('[!] Opening audio device: ' + path);
                        
                        send({
                            type: 'AUDIO_DEVICE_OPENED',
                            timestamp: new Date().toISOString(),
                            path: path
                        });
                    }
                }
            });
        }
        
    } catch (e) {
        console.log('[-] Error hooking system calls: ' + e);
    }
}

// Initialize all native hooks
setTimeout(function() {
    console.log('[*] Initializing native audio monitoring...');
    hookOpenSLES();
    hookAAudio();
    hookNativeAudioRecord();
    hookAudioSystemCalls();
    console.log('[+] Native audio monitoring active');
}, 0);

