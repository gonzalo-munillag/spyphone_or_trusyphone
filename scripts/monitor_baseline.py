#!/usr/bin/env python3
"""
Baseline Monitoring Script

Establishes normal device behavior during idle time.
Runs all apps with audio hooks for 30 minutes to see
what "normal" microphone access looks like.

Usage:
    python3 monitor_baseline.py [--duration SECONDS]
"""

import frida
import sys
import json
import time
import argparse
from datetime import datetime
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

class BaselineMonitor:
    """
    Baseline Monitoring Class
    
    Monitors the device during idle time to establish "normal" behavior.
    This creates a baseline to compare against during active surveillance tests.
    """
    
    def __init__(self, duration=1800):  # 30 minutes default
        """
        Initialize the baseline monitor
        
        Args:
            duration: How many seconds to monitor (default: 1800 = 30 minutes)
        """
        # Configuration
        self.duration = duration  # How long to monitor
        
        # Frida connection objects
        self.device = None        # Will hold USB device connection
        self.sessions = []        # List of active Frida sessions (one per process)
        
        # Data collection
        self.events = []          # All captured events from Frida hooks
        self.start_time = datetime.now()  # When monitoring started
        
    def on_message(self, message, data):
        """
        Callback function for Frida messages
        
        This is called by Frida every time our JavaScript hooks send data.
        The hooks use send() in JS, which triggers this function in Python.
        
        Args:
            message: Dictionary containing type and payload
            data: Binary data (not used in our case)
        """
        # ====================================================================
        # Handle normal messages from our hooks
        # ====================================================================
        if message['type'] == 'send':
            # Extract the payload (the data our hooks sent)
            payload = message['payload']
            
            # Add timestamp of when WE received it (vs when it was generated)
            payload['_received_at'] = datetime.now().isoformat()
            
            # Store this event for later analysis
            self.events.append(payload)
            
            # ================================================================
            # Print real-time alerts based on event severity
            # ================================================================
            event_type = payload.get('type', 'UNKNOWN')
            package = payload.get('package', 'unknown')
            
            # 🚨 CRITICAL: Recording actually started
            if 'RECORDING_STARTED' in event_type or 'MEDIARECORDER_STARTED' in event_type:
                print(f"\n🔴 [ALERT] {event_type} - Package: {package}")
                print(f"    Time: {payload.get('timestamp')}")
                print(f"    ⚠️  RECORDING DURING IDLE TIME!")
                
            # ⚠️ WARNING: Audio API was initialized (not recording yet)
            elif 'AUDIO_RECORD_CREATED' in event_type:
                print(f"\n⚠️  [WARNING] Audio recording initialized by: {package}")
                
            # 📊 INFO: Audio data being read (only logged 1% of the time by hook)
            elif 'AUDIO_DATA_READ' in event_type:
                # Don't print - too spammy even with sampling
                # The data is still collected in self.events
                pass
                
            # 📊 INFO: Other events (permission checks, etc.)
            else:
                print(f"📊 [{event_type}] {package}")
        
        # ====================================================================
        # Handle errors from Frida
        # ====================================================================        
        elif message['type'] == 'error':
            # Frida hook had an error (could be app crashed, hook failed, etc.)
            print(f"\n❌ Error: {message['stack']}", file=sys.stderr)
    
    def load_script(self, script_path):
        """
        Load a Frida JavaScript file
        
        Args:
            script_path: Path to .js file
            
        Returns:
            String containing JavaScript code
        """
        with open(script_path, 'r') as f:
            return f.read()
    
    def attach_to_system_server(self):
        """
        Attach to system_server process (requires root)
        
        system_server is Android's core system process that manages many
        system services. Monitoring it can catch system-level surveillance.
        
        NOTE: This usually requires root access and may not work on all devices
        """
        print("[*] Attaching to system_server...")
        try:
            # Try to spawn and attach to system_server
            # This will likely fail without root - that's OK, we skip it
            pid = self.device.spawn(['system_server'])
            session = self.device.attach('system_server')
            
            # Load our audio hooks script
            script_dir = Path(__file__).parent.parent / 'frida'
            audio_script = self.load_script(script_dir / 'audio_hooks.js')
            script = session.create_script(audio_script)
            script.on('message', self.on_message)  # Register our callback
            script.load()  # Inject the script
            
            # Keep track of this session
            self.sessions.append(session)
            print("[+] Attached to system_server")
        except Exception as e:
            # This usually fails without root - don't worry about it
            print(f"[-] Could not attach to system_server: {e}")
            print("    (This is normal without root access)")
    
    def monitor_all_apps(self):
        """
        Attach to all currently running processes
        
        This is the main monitoring setup. We iterate through all running
        processes and inject our Frida hooks into each one.
        
        Returns:
            True if at least one process was successfully monitored
        """
        print("[*] Scanning for running processes...")
        
        # ====================================================================
        # Get list of all running processes on device
        # ====================================================================
        processes = self.device.enumerate_processes()
        # Returns list of Process objects with: pid, name, parameters
        
        # ====================================================================
        # Load our Frida hooks (JavaScript)
        # ====================================================================
        monitored = 0  # Counter for successfully attached processes
        script_dir = Path(__file__).parent.parent / 'frida'
        audio_script = self.load_script(script_dir / 'audio_hooks.js')
        
        # ====================================================================
        # Loop through all processes and try to attach
        # ====================================================================
        for proc in processes:
            # ----------------------------------------------------------------
            # Skip system processes we can't or shouldn't hook
            # ----------------------------------------------------------------
            if proc.name in ['zygote', 'zygote64', 'kernel', 'init']:
                # zygote: App spawning process (too privileged)
                # kernel: Linux kernel (can't hook)
                # init: System initialization (can't hook)
                continue
            
            try:
                # ------------------------------------------------------------
                # Attach to this process and inject our hooks
                # ------------------------------------------------------------
                session = self.device.attach(proc.pid)
                # attach() connects to the running process via Frida server
                
                script = session.create_script(audio_script)
                # Compiles and prepares our JavaScript hooks
                
                script.on('message', self.on_message)
                # Register our Python callback for messages from JS
                
                script.load()
                # Inject and execute the JavaScript in the target process
                # Our hooks are now active in this app!
                
                # ------------------------------------------------------------
                # Keep track of this session
                # ------------------------------------------------------------
                self.sessions.append(session)
                monitored += 1
                
                print(f"[+] Monitoring: {proc.name} (PID: {proc.pid})")
                
            except Exception as e:
                # Some processes can't be attached to:
                # - System protected processes
                # - Processes with anti-debugging
                # - Processes that crash on attachment
                # This is normal - just skip them silently
                pass
        
        print(f"\n[+] Monitoring {monitored} processes")
        return monitored > 0
    
    def spawn_monitor(self, package_name):
        """Spawn and monitor a specific app"""
        print(f"[*] Spawning and monitoring: {package_name}")
        try:
            pid = self.device.spawn([package_name])
            session = self.device.attach(pid)
            
            script_dir = Path(__file__).parent.parent / 'frida'
            audio_script = self.load_script(script_dir / 'audio_hooks.js')
            script = session.create_script(audio_script)
            script.on('message', self.on_message)
            script.load()
            
            self.device.resume(pid)
            self.sessions.append(session)
            
            print(f"[+] Monitoring: {package_name}")
        except Exception as e:
            print(f"[-] Could not monitor {package_name}: {e}")
    
    def run(self):
        """Run the baseline monitoring"""
        print("="*60)
        print("BASELINE MONITORING")
        print("="*60)
        print(f"Duration: {self.duration} seconds ({self.duration/60:.1f} minutes)")
        print(f"Start time: {self.start_time}")
        print()
        print("Please leave your device idle (screen off, no active use)")
        print("This will establish normal background behavior")
        print()
        
        # Connect to device
        try:
            self.device = frida.get_usb_device(timeout=10)
            print(f"[+] Connected to device: {self.device.name}")
        except Exception as e:
            print(f"❌ Could not connect to device: {e}")
            print("Make sure:")
            print("  1. Device is connected via USB")
            print("  2. USB debugging is enabled")
            print("  3. frida-server is running on device")
            return False
        
        # Monitor running apps
        self.monitor_all_apps()
        
        print()
        print("="*60)
        print("MONITORING IN PROGRESS")
        print("="*60)
        print("Press Ctrl+C to stop early")
        print()
        
        # Monitor for specified duration
        try:
            end_time = time.time() + self.duration
            while time.time() < end_time:
                remaining = int(end_time - time.time())
                sys.stdout.write(f"\r⏱️  Time remaining: {remaining//60:02d}:{remaining%60:02d}")
                sys.stdout.flush()
                time.sleep(1)
            
            print("\n\n[+] Monitoring complete")
            
        except KeyboardInterrupt:
            print("\n\n[!] Monitoring stopped by user")
        
        # Save results
        self.save_results()
        
        # Cleanup
        for session in self.sessions:
            try:
                session.detach()
            except:
                pass
        
        return True
    
    def save_results(self):
        """Save collected events to file"""
        output_dir = Path(__file__).parent.parent / 'data' / 'logs'
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = output_dir / f'baseline_{timestamp}.json'
        
        results = {
            'test_type': 'baseline',
            'start_time': self.start_time.isoformat(),
            'end_time': datetime.now().isoformat(),
            'duration_seconds': self.duration,
            'events': self.events,
            'summary': {
                'total_events': len(self.events),
                'audio_record_created': len([e for e in self.events if e.get('type') == 'AUDIO_RECORD_CREATED']),
                'recording_started': len([e for e in self.events if 'RECORDING_STARTED' in e.get('type', '')]),
                'unique_packages': list(set([e.get('package') for e in self.events if e.get('package')])),
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n[+] Results saved to: {output_file}")
        print(f"\nSummary:")
        print(f"  Total events: {results['summary']['total_events']}")
        print(f"  Audio record sessions: {results['summary']['audio_record_created']}")
        print(f"  Recording starts: {results['summary']['recording_started']}")
        print(f"  Unique packages: {len(results['summary']['unique_packages'])}")
        
        if results['summary']['recording_started'] > 0:
            print(f"\n⚠️  WARNING: {results['summary']['recording_started']} recording events during idle!")
            print("  Packages involved:")
            for pkg in results['summary']['unique_packages']:
                print(f"    - {pkg}")

def main():
    parser = argparse.ArgumentParser(description='Baseline monitoring for audio surveillance detection')
    parser.add_argument('--duration', type=int, default=1800,
                        help='Monitoring duration in seconds (default: 1800 = 30 minutes)')
    
    args = parser.parse_args()
    
    monitor = BaselineMonitor(duration=args.duration)
    success = monitor.run()
    
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()

