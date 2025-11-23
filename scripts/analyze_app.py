#!/usr/bin/env python3
"""
App-Specific Deep Dive Analysis

Performs detailed analysis of a specific app's behavior,
including permissions, file access, and network activity.

Usage:
    python3 analyze_app.py --package com.example.app
"""

import frida
import sys
import json
import subprocess
import argparse
from datetime import datetime
from pathlib import Path

class AppAnalyzer:
    def __init__(self, package_name):
        self.package = package_name
        self.device = None
        self.session = None
        self.events = []
        self.app_info = {}
        
    def get_app_info(self):
        """Get app information using ADB"""
        print(f"[*] Gathering information about {self.package}...")
        
        # Get package info
        result = subprocess.run(
            ['adb', 'shell', 'dumpsys', 'package', self.package],
            capture_output=True, text=True
        )
        
        if result.returncode != 0:
            print(f"❌ Package not found: {self.package}")
            return False
        
        # Parse permissions
        permissions = []
        for line in result.stdout.split('\n'):
            if 'permission' in line.lower() and 'granted=true' in line:
                perm = line.strip().split(':')[0] if ':' in line else line.strip()
                permissions.append(perm)
        
        self.app_info = {
            'package': self.package,
            'permissions': permissions,
            'has_microphone_permission': any('RECORD_AUDIO' in p for p in permissions),
            'has_internet_permission': any('INTERNET' in p for p in permissions)
        }
        
        print(f"[+] App Info:")
        print(f"    Microphone permission: {self.app_info['has_microphone_permission']}")
        print(f"    Internet permission: {self.app_info['has_internet_permission']}")
        print(f"    Total permissions: {len(permissions)}")
        
        return True
    
    def on_message(self, message, data):
        """Handle Frida messages"""
        if message['type'] == 'send':
            payload = message['payload']
            payload['_received_at'] = datetime.now().isoformat()
            self.events.append(payload)
            
            event_type = payload.get('type', 'UNKNOWN')
            print(f"  [{event_type}] {payload.get('timestamp', '')}")
        
        elif message['type'] == 'error':
            print(f"❌ {message['stack']}")
    
    def load_script(self, script_path):
        """Load Frida script"""
        with open(script_path, 'r') as f:
            return f.read()
    
    def monitor_app(self, duration=300):
        """Monitor the app for specified duration"""
        print(f"[*] Monitoring {self.package} for {duration} seconds...")
        
        try:
            self.device = frida.get_usb_device(timeout=10)
        except Exception as e:
            print(f"❌ Could not connect to device: {e}")
            return False
        
        # Spawn the app
        try:
            print(f"[*] Launching {self.package}...")
            pid = self.device.spawn([self.package])
            self.session = self.device.attach(pid)
        except Exception as e:
            print(f"[-] Could not spawn app, trying to attach to running process...")
            try:
                self.session = self.device.attach(self.package)
            except Exception as e2:
                print(f"❌ Could not attach: {e2}")
                return False
        
        # Load comprehensive monitoring script
        script_dir = Path(__file__).parent.parent / 'frida'
        
        combined_script = ""
        for script_file in ['audio_hooks.js', 'network_hooks.js', 'native_audio_hooks.js']:
            script_path = script_dir / script_file
            if script_path.exists():
                combined_script += self.load_script(script_path) + "\n\n"
        
        script = self.session.create_script(combined_script)
        script.on('message', self.on_message)
        script.load()
        
        # Resume if spawned
        try:
            self.device.resume(self.package)
        except:
            pass
        
        print(f"\n[+] Monitoring active. Use the app normally.")
        print("    Press Ctrl+C to stop\n")
        
        # Monitor
        import time
        try:
            time.sleep(duration)
        except KeyboardInterrupt:
            print("\n[!] Stopped by user")
        
        return True
    
    def analyze_events(self):
        """Analyze collected events"""
        print(f"\n[*] Analyzing {len(self.events)} events...")
        
        analysis = {
            'total_events': len(self.events),
            'audio_events': [],
            'network_events': [],
            'suspicious_behaviors': []
        }
        
        for event in self.events:
            event_type = event.get('type', '')
            
            if 'AUDIO' in event_type or 'RECORDING' in event_type:
                analysis['audio_events'].append(event)
            
            if 'HTTP' in event_type or 'SOCKET' in event_type:
                analysis['network_events'].append(event)
        
        # Check for suspicious patterns
        if analysis['audio_events'] and analysis['network_events']:
            analysis['suspicious_behaviors'].append({
                'type': 'AUDIO_WITH_NETWORK',
                'description': 'App accessed audio and network during session',
                'severity': 'HIGH' if len(analysis['audio_events']) > 5 else 'MEDIUM'
            })
        
        return analysis
    
    def save_results(self, analysis):
        """Save analysis results"""
        output_dir = Path(__file__).parent.parent / 'data' / 'reports'
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = output_dir / f'app_analysis_{self.package}_{timestamp}.json'
        
        report = {
            'package': self.package,
            'timestamp': timestamp,
            'app_info': self.app_info,
            'analysis': analysis,
            'events': self.events
        }
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[+] Report saved to: {report_file}")
        return report
    
    def display_report(self, analysis):
        """Display analysis report"""
        print("\n" + "="*60)
        print(f"APP ANALYSIS: {self.package}")
        print("="*60)
        
        print(f"\nTotal events: {analysis['total_events']}")
        print(f"Audio events: {len(analysis['audio_events'])}")
        print(f"Network events: {len(analysis['network_events'])}")
        
        if analysis['suspicious_behaviors']:
            print(f"\n⚠️  SUSPICIOUS BEHAVIORS DETECTED:")
            for behavior in analysis['suspicious_behaviors']:
                print(f"   [{behavior['severity']}] {behavior['description']}")
        else:
            print(f"\n✅ No obvious suspicious behavior detected")
        
        if analysis['audio_events']:
            print(f"\n🎤 Audio Access Summary:")
            audio_types = {}
            for event in analysis['audio_events']:
                event_type = event.get('type', 'UNKNOWN')
                audio_types[event_type] = audio_types.get(event_type, 0) + 1
            
            for event_type, count in audio_types.items():
                print(f"   {event_type}: {count}")
    
    def run(self, duration=300):
        """Run the app analysis"""
        print("="*60)
        print("APP-SPECIFIC DEEP DIVE ANALYSIS")
        print("="*60)
        
        if not self.get_app_info():
            return False
        
        if not self.monitor_app(duration):
            return False
        
        analysis = self.analyze_events()
        self.display_report(analysis)
        self.save_results(analysis)
        
        return True

def main():
    parser = argparse.ArgumentParser(description='Deep dive analysis of specific app')
    parser.add_argument('--package', required=True,
                       help='Package name (e.g., com.example.app)')
    parser.add_argument('--duration', type=int, default=300,
                       help='Monitoring duration in seconds (default: 300)')
    
    args = parser.parse_args()
    
    analyzer = AppAnalyzer(args.package)
    success = analyzer.run(duration=args.duration)
    
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()

