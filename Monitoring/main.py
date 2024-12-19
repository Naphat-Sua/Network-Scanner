# macOS only

import argparse
import re
import subprocess
import logging
import hashlib
import json
import os
from datetime import datetime
from time import sleep
from threading import Thread
import queue
from scapy.all import Ether, srp, ARP
import sqlite3
from getpass import getpass
import jwt
from cryptography.fernet import Fernet
import platform
import psutil
import objc
from Foundation import *
from SystemConfiguration import *

class MacNetworkAuth:
    def __init__(self):
        self.db_path = os.path.expanduser('~/Library/Application Support/MacNetMon/network_monitor.db')
        self.keychain_service = 'MacNetMon'
        self.setup_storage()
        
    def setup_storage(self):
        # Create application directory in macOS
        app_dir = os.path.expanduser('~/Library/Application Support/MacNetMon')
        if not os.path.exists(app_dir):
            os.makedirs(app_dir)
            
        # Setup SQLite database
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users
                    (username TEXT PRIMARY KEY, password TEXT, role TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS audit_log
                    (timestamp TEXT, username TEXT, action TEXT, details TEXT)''')
        conn.commit()
        conn.close()

    def store_keychain(self, username, token):
        """Store authentication token in macOS Keychain"""
        try:
            subprocess.run([
                'security', 'add-generic-password',
                '-a', username,
                '-s', self.keychain_service,
                '-w', token
            ], check=True)
        except subprocess.CalledProcessError:
            return False
        return True

class MacNetworkMonitor:
    def __init__(self, token):
        self.token = token
        self.logger = self.setup_logging()
        self.interface = self.get_default_interface()
        
    def setup_logging(self):
        log_dir = os.path.expanduser('~/Library/Logs/MacNetMon')
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
            
        logger = logging.getLogger('MacNetMon')
        logger.setLevel(logging.INFO)
        handler = logging.FileHandler(os.path.join(log_dir, 'network_monitor.log'))
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

    def get_default_interface(self):
        """Get the default network interface on macOS"""
        try:
            route_cmd = subprocess.run(['route', 'get', 'default'], 
                                     capture_output=True, text=True)
            interface_line = [line for line in route_cmd.stdout.split('\n') 
                            if 'interface' in line]
            if interface_line:
                return interface_line[0].split(':')[1].strip()
        except Exception as e:
            self.logger.error(f"Error getting default interface: {e}")
        return 'en0' 

    def get_network_info(self):
        """Get network information using SystemConfiguration framework"""
        try:
            net_prefs = SCDynamicStoreCreate(None, "MacNetMon", None, None)
            net_info = SCDynamicStoreCopyValue(net_prefs, "State:/Network/Global/IPv4")
            return net_info
        except Exception as e:
            self.logger.error(f"Error getting network info: {e}")
            return None

    def scan_network(self, ip_range):
        """Scan network using macOS-specific optimizations"""
        if not self.verify_permissions():
            self.logger.error("Insufficient permissions for network scanning")
            return "Error: Insufficient permissions"

        try:
            arp_scan = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            devices = self.parse_arp_output(arp_scan.stdout)
            
            if not devices:
                devices = self.scapy_scan(ip_range)
                
            return devices
            
        except Exception as e:
            self.logger.error(f"Scan error: {e}")
            return f"Error during scan: {e}"

    def parse_arp_output(self, arp_output):
        """Parse macOS arp command output"""
        devices = []
        pattern = r'\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]+)'
        
        for line in arp_output.split('\n'):
            match = re.search(pattern, line)
            if match:
                devices.append({
                    'ip': match.group(1),
                    'mac': match.group(2),
                    'timestamp': datetime.now().isoformat()
                })
        return devices

    def verify_permissions(self):
        """Verify if the tool has necessary permissions on macOS"""
        try:
            # Check for admin rights
            admin_check = subprocess.run(['groups'], capture_output=True, text=True)
            if 'admin' not in admin_check.stdout:
                return False
                
            # Check network access permissions
            return os.access('/dev/bpf0', os.R_OK | os.W_OK)
        except:
            return False

    def monitor_system(self):
        """Monitor system-specific network metrics"""
        net_io = psutil.net_io_counters(pernic=True)
        wifi = None
        try:
            wifi = subprocess.run(['airport', '-I'], capture_output=True, text=True)
        except:
            pass
            
        return {
            'network_io': net_io,
            'wifi_info': wifi.stdout if wifi else None,
            'timestamp': datetime.now().isoformat()
        }

def main():
    if platform.system() != 'Darwin':
        print("This tool is designed for macOS only")
        return

    parser = argparse.ArgumentParser(description='macOS Network Monitoring Tool')
    parser.add_argument('-u', '--username', required=True, help='Username for authentication')
    parser.add_argument('-ip', '--ip_range', required=True, help='IP range to monitor (e.g., 192.168.1.0/24)')
    parser.add_argument('-i', '--interval', type=int, default=300, help='Monitoring interval in seconds')
    args = parser.parse_args()

    # Check for root privileges if needed
    if os.geteuid() != 0:
        print("This tool requires root privileges. Please run with sudo.")
        return

    auth = MacNetworkAuth()
    monitor = MacNetworkMonitor(None)  # Token will be added after authentication

    try:
        while True:
            results = monitor.scan_network(args.ip_range)
            sys_metrics = monitor.monitor_system()
            
            print(f"\nNetwork Scan Results ({datetime.now().isoformat()})")
            for device in results:
                print(f"IP: {device['ip']}, MAC: {device['mac']}")
            
            print("\nSystem Metrics:")
            for nic, io in sys_metrics['network_io'].items():
                print(f"{nic}: Sent={io.bytes_sent}, Received={io.bytes_recv}")
            
            sleep(args.interval)
            
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
