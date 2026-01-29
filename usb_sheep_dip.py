#!/usr/bin/env python3
"""
USB Sheep Dip Scanner
A Raspberry Pi-based USB malware scanning system
"""

import os
import sys
import time
import subprocess
import json
import hashlib
from pathlib import Path
from datetime import datetime
import pyudev

class USBSheepDip:
    def __init__(self):
        self.scan_dir = Path("/mnt/usb_scan")
        self.log_dir = Path("/var/log/usb_sheep_dip")
        self.quarantine_dir = Path("/var/quarantine")
        
        # Create necessary directories
        for directory in [self.scan_dir, self.log_dir, self.quarantine_dir]:
            directory.mkdir(parents=True, exist_ok=True)
    
    def log(self, message, level="INFO"):
        """Log messages to file and console"""
        timestamp = datetime.now().isoformat()
        log_message = f"[{timestamp}] [{level}] {message}"
        print(log_message)
        
        log_file = self.log_dir / f"scan_{datetime.now().strftime('%Y%m%d')}.log"
        with open(log_file, 'a') as f:
            f.write(log_message + "\n")
    
    def calculate_hash(self, filepath):
        """Calculate SHA256 hash of a file"""
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            self.log(f"Error calculating hash for {filepath}: {e}", "ERROR")
            return None
    
    def scan_with_clamav(self, mount_point):
        """Scan mounted USB with ClamAV"""
        self.log(f"Starting ClamAV scan of {mount_point}")
        
        try:
            result = subprocess.run(
                ['clamscan', '-r', '-i', '--bell', str(mount_point)],
                capture_output=True,
                text=True,
                timeout=3600  # 1 hour timeout
            )
            
            scan_results = {
                'timestamp': datetime.now().isoformat(),
                'scan_type': 'clamav',
                'mount_point': str(mount_point),
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'threats_found': result.returncode != 0
            }
            
            # Save detailed results
            result_file = self.log_dir / f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(result_file, 'w') as f:
                json.dump(scan_results, f, indent=2)
            
            if result.returncode == 0:
                self.log("ClamAV scan completed: NO THREATS FOUND", "SUCCESS")
            else:
                self.log("ClamAV scan completed: THREATS DETECTED!", "WARNING")
                self.log(f"Scan output:\n{result.stdout}", "WARNING")
            
            return scan_results
            
        except subprocess.TimeoutExpired:
            self.log("ClamAV scan timed out!", "ERROR")
            return None
        except Exception as e:
            self.log(f"Error during ClamAV scan: {e}", "ERROR")
            return None
    
    def scan_with_yara(self, mount_point):
        """Scan with YARA rules if available"""
        yara_rules = Path("/usr/local/share/yara-rules")
        
        if not yara_rules.exists():
            self.log("YARA rules not found, skipping YARA scan")
            return None
        
        self.log(f"Starting YARA scan of {mount_point}")
        
        try:
            result = subprocess.run(
                ['yara', '-r', str(yara_rules / "*.yar"), str(mount_point)],
                capture_output=True,
                text=True,
                timeout=600
            )
            
            if result.stdout:
                self.log(f"YARA matches found:\n{result.stdout}", "WARNING")
                return {'matches': result.stdout}
            else:
                self.log("YARA scan completed: no matches", "SUCCESS")
                return {'matches': None}
                
        except Exception as e:
            self.log(f"YARA scan error: {e}", "ERROR")
            return None
    
    def analyze_filesystem(self, mount_point):
        """Analyze filesystem structure and suspicious patterns"""
        self.log(f"Analyzing filesystem structure of {mount_point}")
        
        suspicious_patterns = [
            '.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', 
            '.jar', '.lnk', '.dll', '.sys', '.ps1'
        ]
        
        suspicious_files = []
        file_count = 0
        hidden_files = 0
        
        try:
            for root, dirs, files in os.walk(mount_point):
                for file in files:
                    file_count += 1
                    filepath = Path(root) / file
                    
                    # Check for hidden files
                    if file.startswith('.'):
                        hidden_files += 1
                    
                    # Check for suspicious extensions
                    if any(file.lower().endswith(ext) for ext in suspicious_patterns):
                        suspicious_files.append({
                            'path': str(filepath),
                            'size': filepath.stat().st_size if filepath.exists() else 0,
                            'hash': self.calculate_hash(filepath)
                        })
            
            analysis = {
                'total_files': file_count,
                'hidden_files': hidden_files,
                'suspicious_files': suspicious_files,
                'suspicious_count': len(suspicious_files)
            }
            
            self.log(f"Filesystem analysis: {file_count} files, {len(suspicious_files)} suspicious")
            
            if suspicious_files:
                self.log(f"Found {len(suspicious_files)} potentially suspicious files", "WARNING")
                for sf in suspicious_files[:10]:  # Log first 10
                    self.log(f"  - {sf['path']}", "WARNING")
            
            return analysis
            
        except Exception as e:
            self.log(f"Error during filesystem analysis: {e}", "ERROR")
            return None
    
    def mount_usb(self, device):
        """Mount USB device safely"""
        self.log(f"Attempting to mount {device}")
        
        # Unmount if already mounted
        subprocess.run(['umount', str(self.scan_dir)], stderr=subprocess.DEVNULL)
        
        try:
            # Mount read-only with noexec for safety
            result = subprocess.run(
                ['mount', '-o', 'ro,noexec,nosuid,nodev', device, str(self.scan_dir)],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                self.log(f"Successfully mounted {device} at {self.scan_dir}", "SUCCESS")
                return True
            else:
                self.log(f"Failed to mount {device}: {result.stderr}", "ERROR")
                return False
                
        except Exception as e:
            self.log(f"Mount error: {e}", "ERROR")
            return False
    
    def unmount_usb(self):
        """Safely unmount USB"""
        self.log("Unmounting USB device")
        try:
            subprocess.run(['umount', str(self.scan_dir)], check=True)
            self.log("USB unmounted successfully", "SUCCESS")
        except Exception as e:
            self.log(f"Error unmounting: {e}", "ERROR")
    
    def full_scan(self, device):
        """Perform complete scan of USB device"""
        self.log("="*60)
        self.log(f"STARTING FULL SCAN OF {device}")
        self.log("="*60)
        
        if not self.mount_usb(device):
            return False
        
        try:
            # Run all scans
            clamav_results = self.scan_with_clamav(self.scan_dir)
            yara_results = self.scan_with_yara(self.scan_dir)
            fs_analysis = self.analyze_filesystem(self.scan_dir)
            
            # Determine overall status
            threats_found = (
                (clamav_results and clamav_results.get('threats_found', False)) or
                (fs_analysis and fs_analysis.get('suspicious_count', 0) > 0)
            )
            
            self.log("="*60)
            if threats_found:
                self.log("SCAN COMPLETE: THREATS OR SUSPICIOUS FILES DETECTED", "WARNING")
                self.log("DO NOT USE THIS USB DRIVE ON PRODUCTION SYSTEMS", "WARNING")
            else:
                self.log("SCAN COMPLETE: NO THREATS DETECTED", "SUCCESS")
                self.log("USB appears clean (but remain cautious)", "SUCCESS")
            self.log("="*60)
            
            return True
            
        finally:
            self.unmount_usb()
    
    def monitor_usb_insertion(self):
        """Monitor for USB device insertion"""
        self.log("USB Sheep Dip Scanner started")
        self.log("Monitoring for USB device insertion...")
        
        context = pyudev.Context()
        monitor = pyudev.Monitor.from_netlink(context)
        monitor.filter_by(subsystem='block', device_type='partition')
        
        for device in iter(monitor.poll, None):
            if device.action == 'add':
                # Wait a moment for device to settle
                time.sleep(2)
                
                device_node = device.device_node
                self.log(f"New USB device detected: {device_node}")
                
                # Perform scan
                self.full_scan(device_node)
                
                self.log("Waiting for next USB device...")

def main():
    print("""
    ╔════════════════════════════════════════╗
    ║     USB Sheep Dip Scanner v1.0        ║
    ║   Raspberry Pi Malware Scanner        ║
    ╚════════════════════════════════════════╝
    """)
    
    # Check for root privileges
    if os.geteuid() != 0:
        print("ERROR: This script must be run as root (use sudo)")
        sys.exit(1)
    
    scanner = USBSheepDip()
    
    if len(sys.argv) > 1:
        # Manual scan mode
        device = sys.argv[1]
        scanner.full_scan(device)
    else:
        # Monitoring mode
        try:
            scanner.monitor_usb_insertion()
        except KeyboardInterrupt:
            print("\n\nShutting down scanner...")
            sys.exit(0)

if __name__ == "__main__":
    main()
