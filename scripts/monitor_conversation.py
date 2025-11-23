#!/usr/bin/env python3
"""
================================================================================
CONVERSATION TEST MONITORING SCRIPT
================================================================================

PURPOSE:
    This is the MAIN test for detecting audio surveillance. It monitors your
    device while you have a conversation about a specific topic, checking if
    any apps secretly record and upload the audio.

THE TEST:
    1. You choose a unique topic (e.g., "underwater basket weaving")
    2. Script starts monitoring (Frida + network capture)
    3. You talk about the topic for 10 minutes (phone nearby, screen off)
    4. Script captures all audio access and network activity
    5. Analysis shows if any apps recorded audio and uploaded data
    6. Later, you check if ads/videos appear about that topic

WHY THIS WORKS:
    - Unique topic ensures it's not algorithmic prediction
    - NOT typing means it can only come from audio
    - Correlation of audio access + network upload = proof
    - Appearance of topic in ads = confirmation

WHAT IT MONITORS:
    - All audio API calls (via Frida hooks)
    - All network connections (via Frida hooks)
    - All network packets (via tcpdump/ADB)
    - Timing and correlation between events

OUTPUT FILES:
    - data/logs/conversation_TIMESTAMP.json (Frida events)
    - data/captures/conversation_TIMESTAMP.pcap (network packets)
    - Console output with real-time alerts

USAGE:
    python3 monitor_conversation.py \
        --duration 600 \
        --keywords "underwater basket weaving"

OPTIONS:
    --duration  : How many seconds to monitor (default: 600 = 10 minutes)
    --keywords  : The conversation topic to test

REQUIREMENTS:
    - Frida server running on device
    - ADB connection established
    - tcpdump on device (usually pre-installed)

EXPECTED RESULTS:
    - Normal: No audio access during conversation
    - Suspicious: Audio access but delayed network upload
    - CONFIRMED: Audio access + immediate upload (smoking gun!)

ROOT REQUIRED: NO (for user apps), YES (for system apps)

TIME TO RUN: 10-20 minutes (plus analysis time)
================================================================================
"""

import frida
import sys
import json
import time
import argparse
import subprocess
from datetime import datetime
from pathlib import Path

# Add parent directory to path for potential future imports
sys.path.insert(0, str(Path(__file__).parent.parent))

class ConversationMonitor:
    def __init__(self, duration, keywords):
        self.duration = duration
        self.keywords = keywords
        self.device = None
        self.sessions = []
        self.events = []
        self.start_time = datetime.now()
        self.pcap_process = None
        self.pcap_file = None
        
    def on_message(self, message, data):
        """Callback for Frida messages"""
        if message['type'] == 'send':
            payload = message['payload']
            payload['_received_at'] = datetime.now().isoformat()
            self.events.append(payload)
            
            event_type = payload.get('type', 'UNKNOWN')
            package = payload.get('package', 'unknown')
            
            if 'RECORDING_STARTED' in event_type or 'MEDIARECORDER_STARTED' in event_type:
                print(f"\n🚨 [CRITICAL] {event_type}")
                print(f"    Package: {package}")
                print(f"    Time: {payload.get('timestamp')}")
                print(f"    ⚠️  RECORDING ACTIVE DURING CONVERSATION!")
            elif 'AUDIO_RECORD_CREATED' in event_type:
                print(f"\n⚠️  [ALERT] Audio API initialized")
                print(f"    Package: {package}")
                print(f"    Source: {payload.get('audioSource')}")
            elif 'HTTP_CONNECTION' in event_type:
                print(f"\n🌐 [NETWORK] {package} → {payload.get('url')}")
            else:
                print(f"📊 [{event_type}] {package}")
                
        elif message['type'] == 'error':
            print(f"\n❌ Error: {message['stack']}", file=sys.stderr)
    
    def load_script(self, script_path):
        """Load a Frida script file"""
        with open(script_path, 'r') as f:
            return f.read()
    
    def start_network_capture(self):
        """Start capturing network traffic"""
        capture_dir = Path(__file__).parent.parent / 'data' / 'captures'
        capture_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.pcap_file = capture_dir / f'conversation_{timestamp}.pcap'
        
        print(f"[*] Starting network capture: {self.pcap_file}")
        
        # Start tcpdump via adb
        cmd = [
            'adb', 'shell',
            f'tcpdump -i any -w /sdcard/capture.pcap 2>/dev/null'
        ]
        
        try:
            self.pcap_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            print("[+] Network capture started")
            time.sleep(2)  # Give it time to start
        except Exception as e:
            print(f"[-] Could not start network capture: {e}")
            print("    Network analysis will not be available")
    
    def stop_network_capture(self):
        """Stop network capture and pull file"""
        if self.pcap_process:
            print("[*] Stopping network capture...")
            subprocess.run(['adb', 'shell', 'killall tcpdump'], 
                          capture_output=True)
            self.pcap_process.terminate()
            self.pcap_process.wait(timeout=5)
            
            # Pull the capture file
            print("[*] Retrieving capture file...")
            subprocess.run([
                'adb', 'pull',
                '/sdcard/capture.pcap',
                str(self.pcap_file)
            ], capture_output=True)
            
            # Clean up
            subprocess.run(['adb', 'shell', 'rm /sdcard/capture.pcap'],
                          capture_output=True)
            
            print(f"[+] Network capture saved: {self.pcap_file}")
    
    def monitor_all_apps(self):
        """Monitor all running apps with audio and network hooks"""
        print("[*] Scanning for running processes...")
        processes = self.device.enumerate_processes()
        
        monitored = 0
        script_dir = Path(__file__).parent.parent / 'frida'
        
        # Combine audio and network hooks
        audio_script = self.load_script(script_dir / 'audio_hooks.js')
        network_script = self.load_script(script_dir / 'network_hooks.js')
        combined_script = audio_script + "\n\n" + network_script
        
        for proc in processes:
            if proc.name in ['zygote', 'zygote64', 'kernel', 'init']:
                continue
            
            try:
                session = self.device.attach(proc.pid)
                script = session.create_script(combined_script)
                script.on('message', self.on_message)
                script.load()
                
                self.sessions.append(session)
                monitored += 1
                
                print(f"[+] Monitoring: {proc.name} (PID: {proc.pid})")
                
            except Exception as e:
                pass
        
        print(f"\n[+] Monitoring {monitored} processes")
    
    def run(self):
        """Run the conversation test"""
        print("="*60)
        print("CONVERSATION TEST MONITORING")
        print("="*60)
        print(f"Duration: {self.duration} seconds ({self.duration/60:.1f} minutes)")
        print(f"Keywords: {self.keywords}")
        print(f"Start time: {self.start_time}")
        print()
        print("🎯 TEST PROTOCOL:")
        print("  1. Place phone nearby with screen off")
        print("  2. Have a natural conversation including the keywords")
        print("  3. Do NOT type the keywords anywhere")
        print("  4. Speak naturally for the duration")
        print("  5. Monitor will capture all audio access attempts")
        print()
        
        # Connect to device
        try:
            self.device = frida.get_usb_device(timeout=10)
            print(f"[+] Connected to device: {self.device.name}")
        except Exception as e:
            print(f"❌ Could not connect to device: {e}")
            return False
        
        # Start network capture
        self.start_network_capture()
        
        # Monitor apps
        self.monitor_all_apps()
        
        print()
        print("="*60)
        print("🎤 READY TO RECORD CONVERSATION")
        print("="*60)
        print("Start talking now!")
        print("Press Ctrl+C to stop early")
        print()
        
        # Monitor for duration
        try:
            end_time = time.time() + self.duration
            while time.time() < end_time:
                remaining = int(end_time - time.time())
                sys.stdout.write(f"\r⏱️  Time remaining: {remaining//60:02d}:{remaining%60:02d}  |  Events captured: {len(self.events)}")
                sys.stdout.flush()
                time.sleep(1)
            
            print("\n\n[+] Monitoring complete")
            
        except KeyboardInterrupt:
            print("\n\n[!] Monitoring stopped by user")
        
        # Stop network capture
        self.stop_network_capture()
        
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
        output_file = output_dir / f'conversation_{timestamp}.json'
        
        # Analyze events
        audio_events = [e for e in self.events if 'AUDIO' in e.get('type', '')]
        recording_events = [e for e in self.events if 'RECORDING_STARTED' in e.get('type', '')]
        network_events = [e for e in self.events if 'HTTP' in e.get('type', '') or 'SOCKET' in e.get('type', '')]
        
        # Find suspicious packages (those that recorded audio)
        suspicious_packages = list(set([
            e.get('package') for e in recording_events 
            if e.get('package') and e.get('package') != 'unknown'
        ]))
        
        results = {
            'test_type': 'conversation',
            'keywords': self.keywords,
            'start_time': self.start_time.isoformat(),
            'end_time': datetime.now().isoformat(),
            'duration_seconds': self.duration,
            'pcap_file': str(self.pcap_file) if self.pcap_file else None,
            'events': self.events,
            'summary': {
                'total_events': len(self.events),
                'audio_events': len(audio_events),
                'recording_events': len(recording_events),
                'network_events': len(network_events),
                'suspicious_packages': suspicious_packages,
                'unique_packages': list(set([e.get('package') for e in self.events if e.get('package')])),
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n[+] Results saved to: {output_file}")
        print(f"\n" + "="*60)
        print("CONVERSATION TEST SUMMARY")
        print("="*60)
        print(f"Total events captured: {results['summary']['total_events']}")
        print(f"Audio-related events: {results['summary']['audio_events']}")
        print(f"Recording starts: {results['summary']['recording_events']}")
        print(f"Network events: {results['summary']['network_events']}")
        
        if suspicious_packages:
            print(f"\n🚨 SUSPICIOUS ACTIVITY DETECTED!")
            print(f"   {len(suspicious_packages)} package(s) accessed microphone:")
            for pkg in suspicious_packages:
                pkg_events = [e for e in recording_events if e.get('package') == pkg]
                print(f"\n   📱 {pkg}")
                print(f"      Recording events: {len(pkg_events)}")
                
                # Check for network activity
                pkg_network = [e for e in network_events if e.get('package') == pkg]
                if pkg_network:
                    print(f"      Network activity: {len(pkg_network)} events")
                    print(f"      ⚠️  POTENTIAL DATA EXFILTRATION!")
        else:
            print(f"\n✅ No suspicious microphone access detected")
            
        print(f"\n💡 Next steps:")
        print(f"   1. Analyze network capture: python3 scripts/analyze_pcap.py {self.pcap_file}")
        print(f"   2. Correlate events: python3 scripts/correlate_events.py {output_file}")
        print(f"   3. Monitor for targeted ads over next 24-48 hours")

def main():
    parser = argparse.ArgumentParser(description='Conversation test for audio surveillance')
    parser.add_argument('--duration', type=int, default=600,
                        help='Monitoring duration in seconds (default: 600 = 10 minutes)')
    parser.add_argument('--keywords', type=str, required=True,
                        help='Conversation keywords/topic to test for')
    
    args = parser.parse_args()
    
    monitor = ConversationMonitor(duration=args.duration, keywords=args.keywords)
    success = monitor.run()
    
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()

