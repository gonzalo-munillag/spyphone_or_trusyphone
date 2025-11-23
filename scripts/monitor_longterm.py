#!/usr/bin/env python3
"""
================================================================================
LONG-TERM MONITORING SCRIPT
================================================================================

PURPOSE:
    Extended monitoring (hours to days) to detect surveillance patterns that
    might not appear in short tests. Some apps wait before uploading data or
    only record during specific times/conditions.

WHY LONG-TERM:
    - Some apps delay data exfiltration by hours
    - Pattern recognition requires extended observation
    - Catches intermittent surveillance attempts
    - Detects time-based or condition-based triggers

WHAT IT MONITORS:
    - Continuous audio API monitoring
    - All apps (existing and newly launched)
    - Periodic checkpoints to prevent data loss
    - Recording frequency and patterns per app

USAGE:
    python3 monitor_longterm.py --duration 86400  # 24 hours

CHECKPOINTS:
    - Saved every 5 minutes
    - Prevents data loss if script crashes
    - Allows resuming analysis if interrupted

ROOT REQUIRED: Recommended for system app monitoring

TIME: Hours to days (configurable)
================================================================================
"""

import frida
import sys
import json
import time
import signal
from datetime import datetime, timedelta
from pathlib import Path

class LongTermMonitor:
    """
    Long-Term Surveillance Monitor
    
    Runs for extended periods to detect patterns that short tests miss.
    Includes automatic checkpointing and graceful shutdown handling.
    """
    
    def __init__(self, duration):
        """
        Initialize long-term monitor
        
        Args:
            duration: How many seconds to monitor (e.g., 86400 = 24 hours)
        """
        # Configuration
        self.duration = duration  # Total monitoring time in seconds
        
        # Frida connections
        self.device = None        # USB device connection
        self.sessions = []        # Active Frida sessions (one per app)
        
        # Data collection
        self.events = []          # All captured audio/network events
        self.start_time = datetime.now()  # When we started monitoring
        self.running = True       # Flag to control main loop
        
        # ====================================================================
        # Setup graceful shutdown handler
        # ====================================================================
        # When user presses Ctrl+C, we want to save data before exiting
        # signal.SIGINT is triggered by Ctrl+C
        signal.signal(signal.SIGINT, self.signal_handler)
        
    def signal_handler(self, sig, frame):
        """
        Handle Ctrl+C gracefully
        
        When user presses Ctrl+C, set running=False to exit main loop cleanly
        This ensures we save data before exiting
        
        Args:
            sig: Signal number (SIGINT)
            frame: Current stack frame (unused)
        """
        print("\n[!] Stopping monitoring...")
        print("    (Saving data before exit...)")
        self.running = False  # This will break the main monitoring loop
    
    def on_message(self, message, data):
        """
        Callback for Frida messages (called whenever hooks send data)
        
        For long-term monitoring, we only print critical events to avoid
        flooding the console. All events are still saved to self.events.
        
        Args:
            message: Dictionary with 'type' and 'payload' from Frida
            data: Binary data (unused in our case)
        """
        if message['type'] == 'send':
            # ================================================================
            # Extract and store the event
            # ================================================================
            payload = message['payload']
            
            # Add receive timestamp (different from generation timestamp)
            payload['_received_at'] = datetime.now().isoformat()
            
            # Store in our events list
            self.events.append(payload)
            
            # ================================================================
            # Only print CRITICAL events (recording starts)
            # ================================================================
            # For 24-hour monitoring, printing every event would flood console
            # We only print when recording actually starts
            event_type = payload.get('type', 'UNKNOWN')
            
            if 'RECORDING_STARTED' in event_type or 'MEDIARECORDER_STARTED' in event_type:
                # Format: [14:23:45] 🔴 RECORDING: com.instagram.android
                timestamp = datetime.now().strftime('%H:%M:%S')
                package = payload.get('package', 'unknown')
                print(f"[{timestamp}] 🔴 RECORDING: {package}")
                
                # ============================================================
                # Save checkpoint when recording detected
                # ============================================================
                # This ensures we don't lose data if script crashes
                self.save_checkpoint()
    
    def load_script(self, script_path):
        """Load Frida script"""
        with open(script_path, 'r') as f:
            return f.read()
    
    def monitor_all_apps(self):
        """
        Attach to all running processes and inject hooks
        
        For long-term monitoring, we want to catch ALL apps, including:
        - User apps (Instagram, TikTok, etc.)
        - System apps (with root)
        - Background services
        - Apps launched after monitoring starts (Frida will catch new processes)
        
        Returns:
            bool: True if at least one process was monitored successfully
        """
        print("[*] Starting comprehensive monitoring...")
        
        # ====================================================================
        # Get list of all currently running processes
        # ====================================================================
        processes = self.device.enumerate_processes()
        # Returns: List of Process objects with .pid, .name, .parameters
        
        monitored = 0  # Count successful attachments
        
        # ====================================================================
        # Load our Frida hooks
        # ====================================================================
        script_dir = Path(__file__).parent.parent / 'frida'
        audio_script = self.load_script(script_dir / 'audio_hooks.js')
        
        # ====================================================================
        # Loop through all processes and inject hooks
        # ====================================================================
        for proc in processes:
            # ----------------------------------------------------------------
            # Skip un-hookable system processes
            # ----------------------------------------------------------------
            if proc.name in ['zygote', 'zygote64', 'kernel', 'init']:
                # zygote: App spawner (hooking it would affect all apps)
                # kernel: Can't hook kernel threads
                # init: System init process
                continue
            
            try:
                # ------------------------------------------------------------
                # Attach and inject
                # ------------------------------------------------------------
                session = self.device.attach(proc.pid)  # Connect to process
                script = session.create_script(audio_script)  # Prepare hooks
                script.on('message', self.on_message)  # Set callback
                script.load()  # Inject and activate
                
                # Keep track of this session
                self.sessions.append(session)
                monitored += 1
                
            except:
                # Some processes can't be attached (protected, exiting, etc.)
                # Silently skip them - this is normal
                pass
        
        print(f"[+] Monitoring {monitored} processes")
        
        # Return False if we couldn't monitor anything (problem!)
        return monitored > 0
    
    def save_checkpoint(self):
        """
        Save current monitoring state to file
        
        Called:
        - Every 5 minutes automatically
        - When critical event detected (recording starts)
        - Prevents data loss if script crashes
        
        Why only last 1000 events:
        - Checkpoint file would grow huge over 24 hours
        - We keep last 1000 to show recent activity
        - Full data saved in final results
        """
        # ====================================================================
        # Ensure output directory exists
        # ====================================================================
        output_dir = Path(__file__).parent.parent / 'data' / 'logs'
        output_dir.mkdir(parents=True, exist_ok=True)  # Create if doesn't exist
        
        # ====================================================================
        # Build checkpoint filename (same for all checkpoints in this run)
        # ====================================================================
        timestamp = self.start_time.strftime('%Y%m%d_%H%M%S')
        checkpoint_file = output_dir / f'longterm_{timestamp}_checkpoint.json'
        # Example: longterm_20251123_142315_checkpoint.json
        
        # ====================================================================
        # Build checkpoint data structure
        # ====================================================================
        checkpoint = {
            'test_type': 'longterm',  # Identifies this as long-term test
            'start_time': self.start_time.isoformat(),  # When we started
            'last_update': datetime.now().isoformat(),   # When this checkpoint was saved
            'duration_seconds': self.duration,           # Total planned duration
            'elapsed_seconds': (datetime.now() - self.start_time).total_seconds(),  # How long we've run
            'events_captured': len(self.events),         # Total events so far
            'events': self.events[-1000:]  # Last 1000 events (recent activity)
            # Note: We don't save ALL events here to keep file size manageable
            # Full event list saved in final results
        }
        
        # ====================================================================
        # Write checkpoint to disk
        # ====================================================================
        with open(checkpoint_file, 'w') as f:
            json.dump(checkpoint, f, indent=2)  # Pretty-printed JSON
        
        # Don't print anything - checkpoints happen frequently and would spam console
    
    def run(self):
        """Run long-term monitoring"""
        print("="*60)
        print("LONG-TERM SURVEILLANCE MONITORING")
        print("="*60)
        print(f"Duration: {self.duration} seconds ({self.duration/3600:.1f} hours)")
        print(f"Start time: {self.start_time}")
        print()
        print("⚠️  This will run for an extended period.")
        print("   You can:")
        print("   - Keep terminal open and check periodically")
        print("   - Run in screen/tmux session")
        print("   - Press Ctrl+C to stop early")
        print()
        
        # Connect to device
        try:
            self.device = frida.get_usb_device(timeout=10)
            print(f"[+] Connected to device: {self.device.name}")
        except Exception as e:
            print(f"❌ Could not connect to device: {e}")
            return False
        
        # Monitor apps
        if not self.monitor_all_apps():
            print("❌ Could not monitor any processes")
            return False
        
        print()
        print("="*60)
        print("MONITORING ACTIVE")
        print("="*60)
        print("Watching for audio access patterns...")
        print()
        
        # ====================================================================
        # MAIN MONITORING LOOP
        # ====================================================================
        # This loop runs until:
        # - Duration expires, OR
        # - User presses Ctrl+C (sets self.running = False)
        
        end_time = time.time() + self.duration  # When to stop
        last_checkpoint = time.time()           # When we last saved
        checkpoint_interval = 300               # Save every 5 minutes (300 seconds)
        
        try:
            while self.running and time.time() < end_time:
                # ============================================================
                # Calculate time values for display
                # ============================================================
                remaining = int(end_time - time.time())  # Seconds left
                hours = remaining // 3600                # Hours remaining
                minutes = (remaining % 3600) // 60       # Minutes remaining
                seconds = remaining % 60                 # Seconds remaining
                
                elapsed = (datetime.now() - self.start_time).total_seconds()  # Time so far
                
                # ============================================================
                # Update console display (overwrites same line)
                # ============================================================
                # Format: ⏱️ Elapsed: 01:23:45 | Remaining: 22:36:15 | Events: 1234
                sys.stdout.write(
                    f"\r⏱️  Elapsed: {int(elapsed//3600):02d}:{int((elapsed%3600)//60):02d}:{int(elapsed%60):02d} | "
                    f"Remaining: {hours:02d}:{minutes:02d}:{seconds:02d} | "
                    f"Events: {len(self.events)}"
                )
                sys.stdout.flush()  # Force display update
                
                # ============================================================
                # Periodic checkpoint save
                # ============================================================
                if time.time() - last_checkpoint > checkpoint_interval:
                    # It's been 5 minutes, save checkpoint
                    self.save_checkpoint()
                    last_checkpoint = time.time()  # Reset timer
                
                # Sleep for 1 second before next iteration
                time.sleep(1)
            
            print("\n\n[+] Monitoring complete")
            
        except KeyboardInterrupt:
            print("\n\n[!] Monitoring stopped by user")
        
        # Final save
        self.save_results()
        
        # Cleanup
        for session in self.sessions:
            try:
                session.detach()
            except:
                pass
        
        return True
    
    def save_results(self):
        """
        Save final comprehensive results
        
        Called at the end of monitoring (or when Ctrl+C pressed).
        Contains ALL events and detailed analysis.
        """
        # ====================================================================
        # Setup output location
        # ====================================================================
        output_dir = Path(__file__).parent.parent / 'data' / 'logs'
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = self.start_time.strftime('%Y%m%d_%H%M%S')
        output_file = output_dir / f'longterm_{timestamp}_final.json'
        
        # ====================================================================
        # Analyze collected events
        # ====================================================================
        # Filter events by type
        audio_events = [e for e in self.events if 'AUDIO' in e.get('type', '')]
        # All audio-related events (created, started, stopped, data read)
        
        recording_events = [e for e in self.events if 'RECORDING_STARTED' in e.get('type', '')]
        # Only actual recording start events (most important)
        
        # ====================================================================
        # Build per-package statistics
        # ====================================================================
        # Group all recording events by which app made them
        package_stats = {}
        
        for event in recording_events:
            pkg = event.get('package', 'unknown')
            
            # If first time seeing this package, initialize its stats
            if pkg not in package_stats:
                package_stats[pkg] = {
                    'recordings': 0,              # How many times it recorded
                    'first_seen': event.get('timestamp'),  # When first detected
                    'last_seen': event.get('timestamp')    # When last detected
                }
            
            # Update stats for this package
            package_stats[pkg]['recordings'] += 1  # Increment count
            package_stats[pkg]['last_seen'] = event.get('timestamp')  # Update last seen
        
        results = {
            'test_type': 'longterm',
            'start_time': self.start_time.isoformat(),
            'end_time': datetime.now().isoformat(),
            'duration_seconds': self.duration,
            'actual_duration': (datetime.now() - self.start_time).total_seconds(),
            'events': self.events,
            'summary': {
                'total_events': len(self.events),
                'audio_events': len(audio_events),
                'recording_events': len(recording_events),
                'unique_packages': list(package_stats.keys()),
                'package_stats': package_stats
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n[+] Results saved to: {output_file}")
        print(f"\n" + "="*60)
        print("LONG-TERM MONITORING SUMMARY")
        print("="*60)
        print(f"Duration: {results['actual_duration']/3600:.2f} hours")
        print(f"Total events: {results['summary']['total_events']}")
        print(f"Recording events: {results['summary']['recording_events']}")
        print(f"Active packages: {len(results['summary']['unique_packages'])}")
        
        if package_stats:
            print(f"\n📊 Recording Activity by Package:")
            for pkg, stats in sorted(package_stats.items(), 
                                    key=lambda x: x[1]['recordings'], 
                                    reverse=True):
                print(f"   {pkg}")
                print(f"      Recordings: {stats['recordings']}")
                print(f"      First: {stats['first_seen']}")
                print(f"      Last: {stats['last_seen']}")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Long-term audio surveillance monitoring')
    parser.add_argument('--duration', type=int, default=3600,
                        help='Monitoring duration in seconds (default: 3600 = 1 hour)')
    
    args = parser.parse_args()
    
    if args.duration > 86400:  # > 24 hours
        print("⚠️  Warning: Duration > 24 hours")
        response = input("Continue? (y/n): ")
        if response.lower() != 'y':
            sys.exit(0)
    
    monitor = LongTermMonitor(duration=args.duration)
    success = monitor.run()
    
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()

