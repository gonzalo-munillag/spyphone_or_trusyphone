#!/usr/bin/env python3
"""
Network Capture Analysis Script

Analyzes packet capture files to find suspicious data uploads,
unusual connections, and potential data exfiltration.

Requires: scapy
Install: pip3 install scapy

Usage:
    python3 analyze_pcap.py <pcap_file>
"""

import sys
import json
import argparse
from pathlib import Path
from collections import defaultdict
from datetime import datetime

try:
    from scapy.all import rdpcap, IP, TCP, UDP
except ImportError:
    print("Error: scapy not installed")
    print("Install with: pip3 install scapy")
    sys.exit(1)

class PcapAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = Path(pcap_file)
        self.packets = None
        self.analysis = {
            'total_packets': 0,
            'tcp_connections': defaultdict(int),
            'udp_connections': defaultdict(int),
            'upload_volume': defaultdict(int),
            'download_volume': defaultdict(int),
            'suspicious_hosts': [],
            'chinese_servers': [],
            'unusual_ports': [],
            'large_uploads': [],
        }
        
    def load_pcap(self):
        """Load the pcap file"""
        print(f"[*] Loading {self.pcap_file}...")
        try:
            self.packets = rdpcap(str(self.pcap_file))
            self.analysis['total_packets'] = len(self.packets)
            print(f"[+] Loaded {len(self.packets)} packets")
            return True
        except Exception as e:
            print(f"❌ Error loading pcap: {e}")
            return False
    
    def analyze_connections(self):
        """Analyze network connections"""
        print("[*] Analyzing connections...")
        
        for pkt in self.packets:
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                
                # Track TCP connections
                if TCP in pkt:
                    dst_port = pkt[TCP].dport
                    connection = f"{dst_ip}:{dst_port}"
                    self.analysis['tcp_connections'][connection] += 1
                    
                    # Track upload/download volume
                    pkt_size = len(pkt)
                    if pkt[TCP].flags & 0x02:  # SYN flag - outgoing
                        self.analysis['upload_volume'][dst_ip] += pkt_size
                    else:
                        self.analysis['download_volume'][dst_ip] += pkt_size
                    
                    # Flag unusual ports
                    if dst_port not in [80, 443, 8080, 8443] and dst_port < 10000:
                        self.analysis['unusual_ports'].append({
                            'ip': dst_ip,
                            'port': dst_port,
                            'protocol': 'TCP'
                        })
                
                # Track UDP connections
                elif UDP in pkt:
                    dst_port = pkt[UDP].dport
                    connection = f"{dst_ip}:{dst_port}"
                    self.analysis['udp_connections'][connection] += 1
                
                # Check for Chinese IP ranges (simplified)
                if self.is_chinese_ip(dst_ip):
                    self.analysis['chinese_servers'].append({
                        'ip': dst_ip,
                        'packets': 1
                    })
        
        # Find large uploads
        for ip, volume in self.analysis['upload_volume'].items():
            if volume > 1024 * 1024:  # > 1MB
                self.analysis['large_uploads'].append({
                    'ip': ip,
                    'bytes': volume,
                    'mb': round(volume / 1024 / 1024, 2)
                })
        
        print(f"[+] Found {len(self.analysis['tcp_connections'])} unique TCP connections")
        print(f"[+] Found {len(self.analysis['udp_connections'])} unique UDP connections")
    
    def is_chinese_ip(self, ip):
        """
        Check if IP is likely Chinese (simplified check)
        In reality, you'd use a GeoIP database
        """
        # Common Chinese IP ranges (very simplified)
        chinese_prefixes = [
            '1.', '14.', '27.', '36.', '39.', '42.', '58.', '59.', '60.',
            '61.', '101.', '106.', '110.', '111.', '112.', '113.', '114.',
            '115.', '116.', '117.', '118.', '119.', '120.', '121.', '122.',
            '123.', '124.', '125.', '183.', '202.', '203.', '210.', '211.',
            '218.', '219.', '220.', '221.', '222.', '223.'
        ]
        
        for prefix in chinese_prefixes:
            if ip.startswith(prefix):
                return True
        return False
    
    def find_suspicious_patterns(self):
        """Find suspicious network patterns"""
        print("[*] Looking for suspicious patterns...")
        
        # Large uploads immediately after conversation
        if self.analysis['large_uploads']:
            print(f"\n⚠️  Found {len(self.analysis['large_uploads'])} large uploads:")
            for upload in sorted(self.analysis['large_uploads'], 
                               key=lambda x: x['bytes'], reverse=True)[:10]:
                print(f"    {upload['ip']}: {upload['mb']} MB")
        
        # Connections to Chinese servers
        if self.analysis['chinese_servers']:
            chinese_ips = set([s['ip'] for s in self.analysis['chinese_servers']])
            print(f"\n⚠️  Found connections to {len(chinese_ips)} Chinese IP addresses:")
            for ip in list(chinese_ips)[:10]:
                print(f"    {ip}")
        
        # Unusual ports
        if self.analysis['unusual_ports']:
            print(f"\n⚠️  Found {len(self.analysis['unusual_ports'])} unusual ports:")
            unique_ports = {}
            for item in self.analysis['unusual_ports']:
                key = f"{item['ip']}:{item['port']}"
                unique_ports[key] = item
            for key, item in list(unique_ports.items())[:10]:
                print(f"    {item['ip']}:{item['port']} ({item['protocol']})")
    
    def generate_report(self):
        """Generate analysis report"""
        output_dir = Path(__file__).parent.parent / 'data' / 'reports'
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = output_dir / f'pcap_analysis_{timestamp}.json'
        
        # Convert defaultdicts to regular dicts for JSON serialization
        report = {
            'pcap_file': str(self.pcap_file),
            'timestamp': timestamp,
            'total_packets': self.analysis['total_packets'],
            'tcp_connections': dict(self.analysis['tcp_connections']),
            'udp_connections': dict(self.analysis['udp_connections']),
            'upload_volume': {k: v for k, v in self.analysis['upload_volume'].items()},
            'download_volume': {k: v for k, v in self.analysis['download_volume'].items()},
            'chinese_servers': list(set([s['ip'] for s in self.analysis['chinese_servers']])),
            'large_uploads': self.analysis['large_uploads'],
            'unusual_ports': self.analysis['unusual_ports'][:50],  # Limit to 50
        }
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[+] Report saved to: {report_file}")
        
        return report
    
    def run(self):
        """Run the analysis"""
        print("="*60)
        print("NETWORK CAPTURE ANALYSIS")
        print("="*60)
        
        if not self.load_pcap():
            return False
        
        self.analyze_connections()
        self.find_suspicious_patterns()
        
        print("\n" + "="*60)
        print("SUMMARY")
        print("="*60)
        print(f"Total packets: {self.analysis['total_packets']}")
        print(f"TCP connections: {len(self.analysis['tcp_connections'])}")
        print(f"UDP connections: {len(self.analysis['udp_connections'])}")
        print(f"Large uploads (>1MB): {len(self.analysis['large_uploads'])}")
        
        chinese_ips = set([s['ip'] for s in self.analysis['chinese_servers']])
        if chinese_ips:
            print(f"⚠️  Chinese servers: {len(chinese_ips)}")
        
        self.generate_report()
        
        return True

def main():
    parser = argparse.ArgumentParser(description='Analyze network packet capture')
    parser.add_argument('pcap_file', help='Path to pcap file')
    
    args = parser.parse_args()
    
    if not Path(args.pcap_file).exists():
        print(f"❌ File not found: {args.pcap_file}")
        sys.exit(1)
    
    analyzer = PcapAnalyzer(args.pcap_file)
    success = analyzer.run()
    
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()

