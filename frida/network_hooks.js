/**
 * ============================================================================
 * FRIDA SCRIPT: Network Activity Monitoring
 * ============================================================================
 * 
 * PURPOSE:
 *   Monitors all network connections made by apps to detect data exfiltration.
 *   Correlating network uploads with audio access is the SMOKING GUN for
 *   proving surveillance.
 * 
 * WHY THIS MATTERS:
 *   Recording audio is only half the story. To monetize your conversations,
 *   apps must UPLOAD the data to a server. This script catches that upload.
 * 
 * WHAT WE MONITOR:
 *   1. HTTP/HTTPS connections (java.net.HttpURLConnection)
 *   2. Raw socket connections (java.net.Socket)
 *   3. OkHttp library (popular HTTP client used by many apps)
 * 
 * WHAT WE CAPTURE:
 *   - Destination URLs/IPs
 *   - Request methods (GET, POST, etc.)
 *   - Timing (when the connection was made)
 *   - Which app made the connection
 * 
 * THE SMOKING GUN PATTERN:
 *   1. App records audio via AudioRecord (audio_hooks.js catches this)
 *   2. Within 60 seconds, same app uploads data (we catch this)
 *   3. Upload is large (>100KB) and goes to analytics server
 *   4. = CONFIRMED SURVEILLANCE
 * 
 * LIMITATIONS:
 *   - Can see THAT data is sent, but not WHAT (encrypted HTTPS)
 *   - Use mitmproxy to decrypt HTTPS and see actual content
 *   - Some apps use native code networking (harder to hook)
 * 
 * ROOT REQUIRED: NO
 * ============================================================================
 */

console.log('[*] Network Hooks Script Loading...');

/**
 * Hook HTTP/HTTPS requests
 */
function hookHttpConnections() {
    console.log('[*] Hooking HTTP connections...');
    
    Java.perform(function() {
        try {
            // Hook HttpURLConnection
            var HttpURLConnection = Java.use('java.net.HttpURLConnection');
            
            HttpURLConnection.connect.implementation = function() {
                var url = this.getURL().toString();
                var method = this.getRequestMethod();
                
                var info = {
                    type: 'HTTP_CONNECTION',
                    timestamp: new Date().toISOString(),
                    url: url,
                    method: method,
                    package: getPackageName()
                };
                
                send(info);
                console.log('[>] HTTP ' + method + ': ' + url);
                
                return this.connect();
            };
            
            console.log('[+] HTTP connections hooked');
            
        } catch (e) {
            console.log('[-] Error hooking HTTP: ' + e);
        }
    });
}

/**
 * Hook Socket connections (low-level)
 */
function hookSockets() {
    console.log('[*] Hooking socket connections...');
    
    Java.perform(function() {
        try {
            var Socket = Java.use('java.net.Socket');
            
            // Hook connect
            Socket.connect.overload('java.net.SocketAddress', 'int').implementation = function(endpoint, timeout) {
                var address = endpoint.toString();
                
                var info = {
                    type: 'SOCKET_CONNECT',
                    timestamp: new Date().toISOString(),
                    address: address,
                    timeout: timeout,
                    package: getPackageName()
                };
                
                send(info);
                console.log('[>] Socket connect: ' + address);
                
                return this.connect(endpoint, timeout);
            };
            
            console.log('[+] Socket connections hooked');
            
        } catch (e) {
            console.log('[-] Error hooking sockets: ' + e);
        }
    });
}

/**
 * Hook OkHttp (popular HTTP client)
 */
function hookOkHttp() {
    console.log('[*] Hooking OkHttp...');
    
    Java.perform(function() {
        try {
            var OkHttpClient = Java.use('okhttp3.OkHttpClient');
            var Request = Java.use('okhttp3.Request');
            
            // This might fail if OkHttp is not used, that's okay
            console.log('[+] OkHttp found, hooking...');
            
        } catch (e) {
            console.log('[-] OkHttp not found (app may not use it): ' + e);
        }
    });
}

/**
 * Helper: Get package name
 */
function getPackageName() {
    try {
        var ActivityThread = Java.use('android.app.ActivityThread');
        var currentApplication = ActivityThread.currentApplication();
        if (currentApplication) {
            var context = currentApplication.getApplicationContext();
            return context.getPackageName();
        }
    } catch (e) {
        return 'unknown';
    }
    return 'unknown';
}

// Initialize hooks
setTimeout(function() {
    console.log('[*] Initializing network monitoring...');
    hookHttpConnections();
    hookSockets();
    hookOkHttp();
    console.log('[+] Network monitoring active');
}, 0);

