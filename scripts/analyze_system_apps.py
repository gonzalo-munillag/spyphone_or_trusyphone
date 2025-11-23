#!/usr/bin/env python3
"""
================================================================================
SYSTEM APPS SURVEILLANCE ANALYZER (REQUIRES ROOT)
================================================================================

PURPOSE:
    Specifically analyzes Xiaomi/MIUI system apps that may conduct surveillance.
    These apps have elevated privileges and can bypass normal permission checks.

WHY SYSTEM APPS ARE DANGEROUS:
    - Can't be uninstalled (pre-installed by manufacturer)
    - Have system-level permissions
    - Bypass standard Android privacy controls
    - Often send data to Chinese servers
    - User has no control over them

WHAT THIS ANALYZES:
    - com.xiaomi.xmsf (Xiaomi Service Framework)
    - com.miui.analytics (Telemetry and analytics)
    - com.xiaomi.finddevice (Find My Device)
    - com.miui.cloudservice (Cloud sync)
    - com.xiaomi.mipicks (App recommendations)
    - All other com.xiaomi.* and com.miui.* packages

REQUIRES:
    - ROOT ACCESS (phone must be rooted)
    - Frida server running as root
    - Active investigation after user apps analysis

USAGE:
    python3 analyze_system_apps.py --duration 600

WORKFLOW:
    1. Root phone (scripts/root_phone.sh)
    2. Analyze user apps (monitor_conversation.py)
    3. Run this script to analyze system apps
    4. Compare results to find surveillance source

ROOT CHECK:
    Script automatically verifies root access before starting

TIME: 10-30 minutes
================================================================================
"""

import frida
import sys
import json
import subprocess
from datetime import datetime
from pathlib import Path

class SystemAppAnalyzer:
    """
    Analyzes Xiaomi/MIUI system apps for surveillance
    
    Focuses on manufacturer apps that have elevated privileges
    and are common sources of data collection.
    """
    
    # ========================================================================
    # List of suspicious Xiaomi/MIUI system packages
    # ========================================================================
    # These are known to collect data or have questionable privacy practices
    SUSPICIOUS_PACKAGES = [
        # Core Xiaomi services
        'com.xiaomi.xmsf',              # Xiaomi Service Framework (push notifications, analytics)
        'com.miui.analytics',           # Analytics and telemetry
        'com.xiaomi.finddevice',        # Find My Device (location tracking)
        
        # Cloud and sync services
        'com.miui.cloudservice',        # Cloud synchronization
        'com.miui.cloudbackup',         # Cloud backup
        'com.xiaomi.account',           # Xiaomi account management
        
        # Content and recommendations
        'com.xiaomi.mipicks',           # App recommendations
        'com.android.browser',          # MIUI browser (may be customized)
        'com.miui.contentextension',    # Content suggestions
        
        # System utilities with network access
        'com.miui.securitycenter',      # Security app (has many permissions)
        'com.miui.securityadd',         # Security add-on
        'com.xiaomi.scanner',           # QR scanner (camera + network access)
        
        # Potentially concerning
        'com.miui.systemAdSolution',    # System ads (yes, really)
        'com.xiaomi.joyose',            # Unknown Xiaomi service
        'com.miui.daemon',              # Background daemon
    ]
    
    def __init__(self, duration=600):
        """
        Initialize system app analyzer
        
        Args:
            duration: How long to monitor each app (default: 600 = 10 minutes)
        """
        self.duration = duration
        self.device = None
        self.events = {}  # Keyed by package name
        self.app_info = {}  # Information about each app
        
    def check_root(self):
        """
        Verify root access is available
        
        Returns:
            bool: True if root access confirmed
        """
        print("[*] Checking root access...")
        
        try:
            # Try to run 'id' command as root
            result = subprocess.run(
                ['adb', 'shell', 'su', '-c', 'id'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if 'uid=0(root)' in result.stdout:
                print("✅ Root access confirmed")
                return True
            else:
                print("❌ Root access not available")
                return False
                
        except Exception as e:
            print(f"❌ Could not verify root: {e}")
            return False
    
    def list_system_apps(self):
        """
        List all Xiaomi/MIUI system packages installed
        
        Returns:
            list: Package names found on device
        """
        print("\n[*] Scanning for Xiaomi/MIUI system packages...")
        
        # Get all xiaomi and miui packages
        result = subprocess.run(
            ['adb', 'shell', 'pm', 'list', 'packages'],
            capture_output=True,
            text=True
        )
        
        all_packages = result.stdout.strip().split('\n')
        
        # Filter for xiaomi and miui packages
        system_packages = []
        for line in all_packages:
            pkg = line.replace('package:', '').strip()
            if 'xiaomi' in pkg.lower() or 'miui' in pkg.lower():
                system_packages.append(pkg)
        
        print(f"[+] Found {len(system_packages)} Xiaomi/MIUI packages")
        
        # Show which of our suspicious list are present
        found_suspicious = [pkg for pkg in self.SUSPICIOUS_PACKAGES if pkg in system_packages]
        if found_suspicious:
            print(f"\n⚠️  Found {len(found_suspicious)} known suspicious packages:")
            for pkg in found_suspicious:
                print(f"    - {pkg}")
        
        return system_packages
    
    def get_app_permissions(self, package):
        """
        Get granted permissions for a package
        
        Args:
            package: Package name to check
            
        Returns:
            dict: App information including permissions
        """
        result = subprocess.run(
            ['adb', 'shell', 'dumpsys', 'package', package],
            capture_output=True,
            text=True
        )
        
        permissions = []
        for line in result.stdout.split('\n'):
            if 'granted=true' in line:
                # Extract permission name
                if 'android.permission' in line:
                    perm = line.split('android.permission.')[1].split(':')[0].strip()
                    permissions.append(f'android.permission.{perm}')
        
        return {
            'package': package,
            'permissions': permissions,
            'has_record_audio': 'android.permission.RECORD_AUDIO' in permissions,
            'has_internet': 'android.permission.INTERNET' in permissions,
            'has_location': any('LOCATION' in p for p in permissions)
        }
    
    def analyze_package(self, package):
        """
        Deep analysis of a single system package
        
        Args:
            package: Package name to analyze
            
        Returns:
            dict: Analysis results
        """
        print(f"\n{'='*70}")
        print(f"ANALYZING: {package}")
        print(f"{'='*70}")
        
        # Get app info and permissions
        info = self.get_app_permissions(package)
        self.app_info[package] = info
        
        print(f"[+] Permissions:")
        print(f"    Microphone: {info['has_record_audio']}")
        print(f"    Internet: {info['has_internet']}")
        print(f"    Location: {info['has_location']}")
        print(f"    Total: {len(info['permissions'])}")
        
        # Try to attach with Frida
        print(f"\n[*] Attaching Frida hooks...")
        
        try:
            self.device = frida.get_usb_device(timeout=10)
            
            # Try to attach (requires root for system apps)
            try:
                session = self.device.attach(package)
            except:
                # If not running, try to spawn it
                print(f"[*] App not running, spawning...")
                try:
                    pid = self.device.spawn([package])
                    session = self.device.attach(pid)
                    self.device.resume(pid)
                except Exception as e:
                    print(f"[-] Could not spawn/attach: {e}")
                    return None
            
            # Load hooks
            script_dir = Path(__file__).parent.parent / 'frida'
            combined_script = ""
            for script_file in ['audio_hooks.js', 'network_hooks.js']:
                script_path = script_dir / script_file
                if script_path.exists():
                    with open(script_path, 'r') as f:
                        combined_script += f.read() + "\n\n"
            
            script = session.create_script(combined_script)
            
            events_for_package = []
            def on_message(message, data):
                if message['type'] == 'send':
                    payload = message['payload']
                    events_for_package.append(payload)
                    event_type = payload.get('type', 'UNKNOWN')
                    print(f"    [{event_type}] {payload.get('timestamp', '')}")
            
            script.on('message', on_message)
            script.load()
            
            print(f"[+] Monitoring for {self.duration} seconds...")
            print("    (Use the device normally if app has UI)")
            
            import time
            time.sleep(self.duration)
            
            self.events[package] = events_for_package
            
            session.detach()
            
            return {
                'package': package,
                'events': len(events_for_package),
                'audio_events': len([e for e in events_for_package if 'AUDIO' in e.get('type', '')]),
                'network_events': len([e for e in events_for_package if 'HTTP' in e.get('type', '') or 'SOCKET' in e.get('type', '')])
            }
            
        except Exception as e:
            print(f"[-] Analysis failed: {e}")
            return None
    
    def generate_report(self):
        """
        Generate comprehensive report of all system apps
        
        Returns:
            dict: Complete analysis report
        """
        output_dir = Path(__file__).parent.parent / 'data' / 'reports'
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = output_dir / f'system_apps_analysis_{timestamp}.json'
        
        report = {
            'timestamp': timestamp,
            'device': subprocess.run(['adb', 'shell', 'getprop', 'ro.product.model'], 
                                   capture_output=True, text=True).stdout.strip(),
            'app_info': self.app_info,
            'events': self.events,
            'summary': {
                'apps_analyzed': len(self.events),
                'apps_with_audio_access': len([pkg for pkg, events in self.events.items() 
                                             if any('AUDIO' in e.get('type', '') for e in events)]),
                'apps_with_network': len([pkg for pkg, events in self.events.items() 
                                        if any('HTTP' in e.get('type', '') or 'SOCKET' in e.get('type', '') for e in events)])
            }
        }
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[+] Report saved to: {report_file}")
        
        return report
    
    def display_summary(self):
        """Display summary of findings"""
        print("\n" + "="*70)
        print("SYSTEM APPS ANALYSIS SUMMARY")
        print("="*70)
        
        # Apps with audio access
        audio_apps = []
        for pkg, events in self.events.items():
            audio_events = [e for e in events if 'AUDIO' in e.get('type', '')]
            if audio_events:
                audio_apps.append((pkg, len(audio_events)))
        
        if audio_apps:
            print(f"\n🚨 System apps with audio access: {len(audio_apps)}")
            for pkg, count in sorted(audio_apps, key=lambda x: x[1], reverse=True):
                print(f"    {pkg}: {count} events")
                # Check if also has network
                network_events = [e for e in self.events[pkg] if 'HTTP' in e.get('type', '') or 'SOCKET' in e.get('type', '')]
                if network_events:
                    print(f"        ⚠️  Also has {len(network_events)} network events!")
        else:
            print("\n✅ No suspicious audio access detected in system apps")
    
    def run(self):
        """Main execution"""
        print("="*70)
        print("SYSTEM APPS SURVEILLANCE ANALYZER")
        print("="*70)
        print("\n⚠️  Requires ROOT access\n")
        
        # Check root
        if not self.check_root():
            print("\n❌ ROOT REQUIRED!")
            print("\nRun: bash scripts/root_phone.sh")
            return False
        
        # List system apps
        system_packages = self.list_system_apps()
        
        # Analyze suspicious ones
        print(f"\n[*] Will analyze {len(self.SUSPICIOUS_PACKAGES)} suspicious packages...")
        print("    (This may take 10-30 minutes)")
        
        for pkg in self.SUSPICIOUS_PACKAGES:
            if pkg in system_packages:
                self.analyze_package(pkg)
            else:
                print(f"\n[-] {pkg} not found on device")
        
        # Generate report
        self.display_summary()
        self.generate_report()
        
        return True

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Analyze Xiaomi system apps for surveillance')
    parser.add_argument('--duration', type=int, default=600,
                       help='Monitoring duration per app in seconds (default: 600)')
    
    args = parser.parse_args()
    
    analyzer = SystemAppAnalyzer(duration=args.duration)
    success = analyzer.run()
    
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()

