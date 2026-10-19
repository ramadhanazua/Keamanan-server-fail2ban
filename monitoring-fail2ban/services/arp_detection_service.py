# services/arp_detection_service.py
import subprocess
import re
import time
from collections import defaultdict
from datetime import datetime
import os
import json

class ARPDetectionService:
    def __init__(self):
        self.arp_table = {}  # IP -> MAC Address
        self.arp_history = defaultdict(list)  # IP -> list of (timestamp, mac)
        self.suspicious_events = []
        self.known_good_macs = {}  # IP -> MAC yang diketahui benar
        self.last_check = datetime.now()
        self.detection_enabled = True
        
        # Daftar IP kritis yang dimonitor
        self.critical_ips = [
            '192.168.186.1',     # Gateway
            '192.168.186.134',   # Server sendiri
            '192.168.186.10',    # Admin client
            '192.168.186.133',   # Attacker (waspadai!)
        ]
        
        # Load known good MACs jika ada
        self._load_known_macs()
    
    def _load_known_macs(self):
        """Load known good MAC addresses dari file"""
        try:
            config_file = '/etc/arp_known_macs.json'
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    self.known_good_macs = json.load(f)
        except:
            pass
    
    def _save_known_macs(self):
        """Save known good MAC addresses ke file"""
        try:
            config_file = '/etc/arp_known_macs.json'
            with open(config_file, 'w') as f:
                json.dump(self.known_good_macs, f, indent=2)
        except:
            pass
    
    def get_arp_table(self):
        """
        Mendapatkan tabel ARP dari sistem
        Returns: dict {ip: mac}
        """
        try:
            # Coba dengan ip neigh (lebih modern)
            result = subprocess.run(
                ['ip', 'neigh', 'show'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            arp_table = {}
            lines = result.stdout.split('\n')
            
            for line in lines:
                parts = line.split()
                if len(parts) >= 5:
                    ip = parts[0]
                    mac = parts[4].upper()
                    state = parts[3] if len(parts) > 3 else ''
                    if mac and state not in ['FAILED', 'INCOMPLETE']:
                        arp_table[ip] = mac
            
            # Jika ip neigh gagal, coba arp -n
            if not arp_table:
                result = subprocess.run(
                    ['arp', '-n'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                lines = result.stdout.split('\n')
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 3 and parts[0] != 'Address':
                        ip = parts[0]
                        mac = parts[2].upper()
                        if mac != '(incomplete)':
                            arp_table[ip] = mac
            
            return arp_table
            
        except Exception as e:
            print(f"[ERROR] Getting ARP table: {e}")
            return {}
    
    def check_arp_spoofing(self):
        """
        Memeriksa indikasi ARP Spoofing
        Returns: dict dengan hasil deteksi
        """
        try:
            current_table = self.get_arp_table()
            detected_events = []
            warnings = []
            status = 'OK'
            
            # 1. Cek perubahan MAC pada IP critical
            for ip in self.critical_ips:
                if ip in current_table:
                    mac = current_table[ip]
                    
                    # Cek dengan known good MAC
                    if ip in self.known_good_macs:
                        if self.known_good_macs[ip] != mac:
                            event = {
                                'type': 'MAC_CHANGE',
                                'ip': ip,
                                'old_mac': self.known_good_macs[ip],
                                'new_mac': mac,
                                'timestamp': datetime.now().isoformat(),
                                'severity': 'CRITICAL'
                            }
                            detected_events.append(event)
                            warnings.append(f"🚨 MAC change detected for {ip}: {self.known_good_macs[ip]} -> {mac}")
                            status = 'CRITICAL'
                    
                    # Cek dengan history
                    elif ip in self.arp_table:
                        old_mac = self.arp_table[ip]
                        if old_mac != mac:
                            event = {
                                'type': 'MAC_CHANGE',
                                'ip': ip,
                                'old_mac': old_mac,
                                'new_mac': mac,
                                'timestamp': datetime.now().isoformat(),
                                'severity': 'HIGH'
                            }
                            detected_events.append(event)
                            warnings.append(f"⚠️ MAC change detected for {ip}: {old_mac} -> {mac}")
                            if status != 'CRITICAL':
                                status = 'HIGH'
                    
                    # Simpan history
                    self.arp_history[ip].append({
                        'timestamp': datetime.now().isoformat(),
                        'mac': mac
                    })
                    if len(self.arp_history[ip]) > 100:
                        self.arp_history[ip].pop(0)
            
            # 2. Cek duplicate MAC (dua IP dengan MAC sama)
            mac_to_ips = {}
            for ip, mac in current_table.items():
                if mac not in mac_to_ips:
                    mac_to_ips[mac] = []
                mac_to_ips[mac].append(ip)
            
            for mac, ips in mac_to_ips.items():
                if len(ips) > 1:
                    # Filter hanya IP yang ada di critical_ips atau subnet lokal
                    critical_ips_found = [ip for ip in ips if ip in self.critical_ips]
                    if critical_ips_found:
                        event = {
                            'type': 'DUPLICATE_MAC',
                            'mac': mac,
                            'ips': ips,
                            'timestamp': datetime.now().isoformat(),
                            'severity': 'CRITICAL'
                        }
                        detected_events.append(event)
                        warnings.append(f"🚨 DUPLICATE MAC {mac} found for IPs: {', '.join(ips)}")
                        status = 'CRITICAL'
                    else:
                        # Duplicate MAC tapi bukan IP critical - tetap dicatat
                        event = {
                            'type': 'DUPLICATE_MAC',
                            'mac': mac,
                            'ips': ips,
                            'timestamp': datetime.now().isoformat(),
                            'severity': 'MEDIUM'
                        }
                        detected_events.append(event)
            
            # 3. Update ARP table
            self.arp_table = current_table
            
            # Simpan events
            if detected_events:
                self.suspicious_events.extend(detected_events)
                if len(self.suspicious_events) > 100:
                    self.suspicious_events = self.suspicious_events[-100:]
            
            # 4. Dapatkan status ARP untuk semua IP critical
            arp_status = {}
            for ip in self.critical_ips:
                mac = current_table.get(ip, 'UNKNOWN')
                arp_status[ip] = {
                    'mac': mac,
                    'status': 'OK' if ip not in self.known_good_macs or self.known_good_macs.get(ip) == mac else 'CHANGED',
                    'known_mac': self.known_good_macs.get(ip, 'UNKNOWN')
                }
            
            return {
                'detected': len(detected_events) > 0,
                'status': status,
                'events': detected_events[-10:],
                'warnings': warnings,
                'arp_table': arp_status,
                'critical_ips': self.critical_ips,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            print(f"[ERROR] ARP detection: {e}")
            return {
                'detected': False,
                'status': 'ERROR',
                'events': [],
                'warnings': [f'Error: {str(e)}'],
                'error': str(e)
            }
    
    def set_known_mac(self, ip, mac):
        """
        Set known good MAC untuk IP tertentu
        """
        self.known_good_macs[ip] = mac.upper()
        self._save_known_macs()
        return True
    
    def get_arp_history(self, ip=None):
        """
        Mendapatkan history ARP untuk satu IP atau semua
        """
        if ip:
            return self.arp_history.get(ip, [])
        return dict(self.arp_history)
    
    def get_suspicious_events(self, limit=50):
        """
        Mendapatkan daftar event mencurigakan
        """
        return self.suspicious_events[-limit:]
    
    def scan_network(self):
        """
        Scan network untuk update ARP cache
        """
        try:
            # Ping network
            network = '192.168.186.0/24'
            subprocess.run(
                ['nmap', '-sn', network],
                capture_output=True,
                timeout=30
            )
            return self.check_arp_spoofing()
        except Exception as e:
            print(f"[ERROR] Network scan: {e}")
            return {'error': str(e)}
