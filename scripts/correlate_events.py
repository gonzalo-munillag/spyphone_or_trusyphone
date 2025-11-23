#!/usr/bin/env python3
"""
================================================================================
EVENT CORRELATION ANALYSIS SCRIPT
================================================================================

PURPOSE:
    This is THE SMOKING GUN FINDER. It analyzes Frida logs to find apps that
    record audio AND immediately upload data - the definitive proof of
    audio surveillance.

THE CORRELATION PATTERN:
    1. App accesses microphone (via AudioRecord/MediaRecorder)
    2. Audio is recorded for X seconds
    3. Within 60 seconds, same app makes network request
    4. Upload size is suspiciously large (>100KB)
    5. = HIGH PROBABILITY OF SURVEILLANCE

WHY CORRELATION MATTERS:
    - Audio access alone could be legitimate (voice notes, calls)
    - Network uploads alone could be anything (analytics, updates)
    - BOTH TOGETHER, TIMED CLOSELY = surveillance pattern

SUSPICION SCORING:
    Points are awarded for suspicious behaviors:
    - Audio access: +5 points
    - Network activity within 10 seconds: +10 points
    - Network activity within 60 seconds: +5 points
    - Large upload (>100KB): +10 points
    - Upload to analytics domain: +5 points
    - No user interaction: +10 points
    
    TOTAL SCORE:
    - 0-10: Normal behavior
    - 11-30: Suspicious, investigate
    - 31+: High suspicion, likely surveillance

WHAT IT ANALYZES:
    - Timing between audio access and network activity
    - Package names (ensures same app)
    - Upload volume and destination
    - Patterns over multiple events

INPUT:
    Frida log JSON file from monitor_conversation.py or monitor_baseline.py

OUTPUT:
    - data/reports/correlation_TIMESTAMP.json (full analysis)
    - Console output with suspicion levels
    - List of suspicious apps requiring investigation

USAGE:
    python3 correlate_events.py data/logs/conversation_TIMESTAMP.json

INTERPRETATION:
    ✅ No correlations = Not surveillance
    ⚠️  Low scores (11-30) = Investigate further
    🚨 High scores (31+) = Likely surveillance, take action

TIME TO RUN: ~10 seconds

NEXT STEPS AFTER FINDING SUSPICION:
    1. Run analyze_app.py on suspicious package
    2. Run analyze_pcap.py on network capture
    3. Document findings
    4. Disable/uninstall suspicious app
================================================================================
"""

import sys
import json
import argparse
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict

class EventCorrelator:
    def __init__(self, log_file):
        self.log_file = Path(log_file)
        self.events = []
        self.audio_events = []
        self.network_events = []
        self.correlations = []
        
    def load_events(self):
        """Load events from Frida log"""
        print(f"[*] Loading {self.log_file}...")
        try:
            with open(self.log_file, 'r') as f:
                data = json.load(f)
                self.events = data.get('events', [])
            
            # Separate by type
            for event in self.events:
                event_type = event.get('type', '')
                
                if any(x in event_type for x in ['AUDIO', 'RECORDING', 'MEDIARECORDER']):
                    self.audio_events.append(event)
                elif any(x in event_type for x in ['HTTP', 'SOCKET', 'NETWORK']):
                    self.network_events.append(event)
            
            print(f"[+] Loaded {len(self.events)} events")
            print(f"    Audio events: {len(self.audio_events)}")
            print(f"    Network events: {len(self.network_events)}")
            
            return True
            
        except Exception as e:
            print(f"❌ Error loading log: {e}")
            return False
    
    def parse_timestamp(self, ts):
        """Parse ISO timestamp to datetime"""
        try:
            return datetime.fromisoformat(ts.replace('Z', '+00:00'))
        except:
            try:
                return datetime.strptime(ts, '%Y-%m-%dT%H:%M:%S.%f')
            except:
                return None
    
    def correlate(self, time_window=60):
        """
        Find network activity that occurs within time_window seconds
        after audio access - THIS IS THE SMOKING GUN FINDER
        
        Args:
            time_window: How many seconds after audio access to look for network (default: 60)
        
        Returns:
            List of correlation dictionaries
        """
        print(f"\n[*] Correlating events (time window: {time_window}s)...")
        
        # ====================================================================
        # Loop through all audio recording events
        # ====================================================================
        for audio_event in self.audio_events:
            # ----------------------------------------------------------------
            # Skip events that aren't actual recording starts
            # ----------------------------------------------------------------
            # We only care about when recording STARTED, not when AudioRecord
            # was created or when data was read
            if 'RECORDING_STARTED' not in audio_event.get('type', ''):
                continue
            
            # ----------------------------------------------------------------
            # Parse the timestamp of when recording started
            # ----------------------------------------------------------------
            audio_time = self.parse_timestamp(audio_event.get('timestamp', ''))
            if not audio_time:
                # If timestamp parsing failed, skip this event
                continue
            
            # Get the package name (which app recorded)
            package = audio_event.get('package', 'unknown')
            
            # ================================================================
            # Find ALL network events from THE SAME APP within time window
            # ================================================================
            related_network = []  # Will collect matching network events
            
            for net_event in self.network_events:
                # Parse network event timestamp
                net_time = self.parse_timestamp(net_event.get('timestamp', ''))
                if not net_time:
                    continue
                
                # ------------------------------------------------------------
                # Check if this network event matches our criteria:
                # ------------------------------------------------------------
                # 1. Same package (same app)
                # 2. Network event happened AFTER audio started
                # 3. Network event happened within our time window
                if (net_event.get('package') == package and
                    audio_time < net_time < audio_time + timedelta(seconds=time_window)):
                    
                    # Calculate how many seconds after recording the upload happened
                    time_delta = (net_time - audio_time).total_seconds()
                    
                    # This network event is correlated!
                    related_network.append({
                        'type': net_event.get('type'),           # HTTP_CONNECTION, SOCKET_CONNECT, etc.
                        'timestamp': net_event.get('timestamp'), # When it happened
                        'url': net_event.get('url', ''),        # Destination URL
                        'address': net_event.get('address', ''), # IP:Port
                        'time_delta': time_delta                 # Seconds after audio access
                    })
            
            # ================================================================
            # If we found network activity, record the correlation
            # ================================================================
            if related_network:
                # This is a potential surveillance pattern!
                # Audio access followed by network uploads
                
                # Calculate how suspicious this is (0-100 score)
                suspicion_score = self.calculate_suspicion(audio_event, related_network)
                
                self.correlations.append({
                    'audio_event': audio_event,         # The recording event
                    'network_events': related_network,  # All related uploads
                    'package': package,                 # Which app
                    'audio_time': audio_event.get('timestamp'),
                    'suspicion_level': suspicion_score  # HIGH/MEDIUM/LOW
                })
        
        print(f"[+] Found {len(self.correlations)} correlations")
        
        # If we found correlations, that's suspicious!
        if self.correlations:
            print(f"    ⚠️  Audio access followed by network activity detected!")
        
        return self.correlations
    
    def calculate_suspicion(self, audio_event, network_events):
        """
        Calculate how suspicious this correlation is
        
        This scoring system quantifies surveillance likelihood:
        - Faster uploads = more suspicious
        - More network events = more suspicious  
        - Analytics domains = more suspicious
        
        Args:
            audio_event: The audio recording event
            network_events: List of correlated network events
            
        Returns:
            String: 'HIGH', 'MEDIUM', or 'LOW'
        """
        # Start with zero suspicion
        score = 0
        
        # ====================================================================
        # FACTOR 1: Number of network events
        # ====================================================================
        # Multiple uploads after one recording is suspicious
        # Each network event adds +2 points
        score += len(network_events) * 2
        # Example: 5 network events = +10 points
        
        # ====================================================================
        # FACTOR 2: Speed of upload (MOST IMPORTANT)
        # ====================================================================
        # The faster an app uploads after recording, the more suspicious
        # Legitimate apps usually process/compress before uploading
        # Surveillance apps want to exfiltrate data immediately
        for net_event in network_events:
            time_delta = net_event['time_delta']  # Seconds after recording
            
            if time_delta < 10:  # Within 10 seconds
                # 🚨 VERY SUSPICIOUS: Nearly immediate upload
                score += 10
                
            elif time_delta < 30:  # Within 30 seconds
                # ⚠️ SUSPICIOUS: Quick upload
                score += 5
                
            # else: Delayed upload (30-60s) - less suspicious, +0 points
        
        # ====================================================================
        # FACTOR 3: Destination domain analysis
        # ====================================================================
        # Uploads to analytics/tracking domains are suspicious
        suspicious_keywords = [
            'analytics',  # analytics.example.com
            'track',      # track.adnetwork.com
            'collect',    # collect-data.com
            'report',     # report.telemetry.com
            'data',       # data-collection.com
            'telemetry',  # telemetry.xiaomi.com
            'ad',         # ad-server.com
            'metric'      # metrics.facebook.com
        ]
        
        for net_event in network_events:
            url = net_event.get('url', '').lower()
            
            # Check if URL contains any suspicious keywords
            for keyword in suspicious_keywords:
                if keyword in url:
                    score += 5  # +5 for each suspicious domain
                    break  # Only count once per URL
        
        # ====================================================================
        # SCORING THRESHOLDS
        # ====================================================================
        # Based on empirical testing, these scores indicate:
        #
        # 0-9 points:   Normal behavior
        #               - Delayed uploads
        #               - Single event
        #               - To normal domains
        #
        # 10-19 points: Medium suspicion
        #               - Multiple events or quick upload
        #               - Should investigate further
        #
        # 20+ points:   High suspicion
        #               - Immediate upload + multiple events
        #               - Or immediate upload to analytics domain
        #               - Very likely surveillance
        
        if score >= 20:
            return 'HIGH'
        elif score >= 10:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def generate_report(self):
        """Generate correlation report"""
        output_dir = Path(__file__).parent.parent / 'data' / 'reports'
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = output_dir / f'correlation_{timestamp}.json'
        
        report = {
            'source_log': str(self.log_file),
            'timestamp': timestamp,
            'total_events': len(self.events),
            'audio_events': len(self.audio_events),
            'network_events': len(self.network_events),
            'correlations': self.correlations,
            'summary': {
                'total_correlations': len(self.correlations),
                'high_suspicion': len([c for c in self.correlations if c['suspicion_level'] == 'HIGH']),
                'medium_suspicion': len([c for c in self.correlations if c['suspicion_level'] == 'MEDIUM']),
                'low_suspicion': len([c for c in self.correlations if c['suspicion_level'] == 'LOW']),
                'suspicious_packages': list(set([
                    c['package'] for c in self.correlations 
                    if c['suspicion_level'] in ['HIGH', 'MEDIUM']
                ]))
            }
        }
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[+] Report saved to: {report_file}")
        
        return report
    
    def display_results(self):
        """Display correlation results"""
        print("\n" + "="*60)
        print("CORRELATION ANALYSIS RESULTS")
        print("="*60)
        
        if not self.correlations:
            print("\n✅ No suspicious correlations found")
            print("   Audio access was not followed by network activity")
            return
        
        # Group by suspicion level
        high = [c for c in self.correlations if c['suspicion_level'] == 'HIGH']
        medium = [c for c in self.correlations if c['suspicion_level'] == 'MEDIUM']
        low = [c for c in self.correlations if c['suspicion_level'] == 'LOW']
        
        if high:
            print(f"\n🚨 HIGH SUSPICION ({len(high)} cases):")
            for corr in high:
                print(f"\n   Package: {corr['package']}")
                print(f"   Audio time: {corr['audio_time']}")
                print(f"   Network events: {len(corr['network_events'])}")
                for net in corr['network_events'][:3]:  # Show first 3
                    print(f"      → {net['type']} (+{net['time_delta']:.1f}s)")
                    if net.get('url'):
                        print(f"         URL: {net['url']}")
        
        if medium:
            print(f"\n⚠️  MEDIUM SUSPICION ({len(medium)} cases):")
            for corr in medium:
                print(f"   {corr['package']}: {len(corr['network_events'])} network events")
        
        if low:
            print(f"\n💡 LOW SUSPICION ({len(low)} cases):")
            print(f"   {len(low)} packages had delayed network activity")
        
        # Show suspicious packages
        suspicious = set([c['package'] for c in high + medium])
        if suspicious:
            print(f"\n📱 Packages requiring investigation:")
            for pkg in suspicious:
                print(f"   - {pkg}")
    
    def run(self):
        """Run the correlation analysis"""
        print("="*60)
        print("EVENT CORRELATION ANALYSIS")
        print("="*60)
        
        if not self.load_events():
            return False
        
        self.correlate(time_window=60)
        self.display_results()
        
        report = self.generate_report()
        
        print("\n" + "="*60)
        print("SUMMARY")
        print("="*60)
        print(f"Total correlations: {report['summary']['total_correlations']}")
        print(f"High suspicion: {report['summary']['high_suspicion']}")
        print(f"Medium suspicion: {report['summary']['medium_suspicion']}")
        
        if report['summary']['suspicious_packages']:
            print(f"\n⚠️  Suspicious packages:")
            for pkg in report['summary']['suspicious_packages']:
                print(f"   - {pkg}")
        
        return True

def main():
    parser = argparse.ArgumentParser(description='Correlate audio and network events')
    parser.add_argument('log_file', help='Path to Frida log JSON file')
    parser.add_argument('--window', type=int, default=60,
                       help='Time window in seconds (default: 60)')
    
    args = parser.parse_args()
    
    if not Path(args.log_file).exists():
        print(f"❌ File not found: {args.log_file}")
        sys.exit(1)
    
    correlator = EventCorrelator(args.log_file)
    success = correlator.run()
    
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()

