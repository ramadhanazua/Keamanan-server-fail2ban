# services/nmap_detection_service.py
import subprocess
import re
import os
from collections import defaultdict
from datetime import datetime, timedelta


class NmapDetectionService:
    def __init__(self):
        self.log_paths = [
            '/var/log/kern.log',
            '/var/log/syslog',
            '/var/log/ufw.log',
            '/var/log/auth.log',
        ]

        self.ignored_ips = [
            '127.0.0.1',
            '192.168.186.1',
            '192.168.186.2',
            '192.168.186.10',
            '192.168.186.134',
            '192.168.186.254',
            '192.168.186.255',
        ]

        self.ignored_ports = [
            '68', '67', '53', '137', '138', '139', '5353', '1900',
        ]

        self.PORT_SCAN_THRESHOLD = 5
        self.CONNECTION_THRESHOLD = 10
        self.IPTABLES_TIMEOUT = 30

    def is_ignored_ip(self, ip):
        """Cek apakah IP harus diabaikan"""
        if not ip:
            return True
        if ip in self.ignored_ips:
            return True
        if ip.startswith('127.') or ip.startswith('::1'):
            return True
        return False

    def is_ignored_port(self, port):
        """Cek apakah port harus diabaikan"""
        if not port:
            return True
        return str(port) in self.ignored_ports

    def get_blocked_ips(self):
        """Dapatkan daftar IP yang sudah diblokir di iptables"""
        try:
            result = subprocess.run(
                ['sudo', '-n', '/sbin/iptables-save'],
                capture_output=True,
                text=True,
                timeout=self.IPTABLES_TIMEOUT
            )

            blocked_ips = set()

            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    match = re.search(r'-A INPUT -s (\d+\.\d+\.\d+\.\d+)(?:/32)? -j DROP', line)
                    if match:
                        blocked_ips.add(match.group(1))

            return blocked_ips

        except Exception as e:
            print(f"[WARN] Cannot get blocked IPs: {e}")
            return set()

    def _read_log(self, log_file, lines=500):
        """Baca log tanpa sudo (karena user sudah di group adm)"""
        try:
            if not os.path.exists(log_file):
                return ""

            result = subprocess.run(
                ['tail', '-n', str(lines), log_file],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                return result.stdout

            result = subprocess.run(
                ['sudo', '-n', 'tail', '-n', str(lines), log_file],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.stdout

        except Exception as e:
            print(f"[WARN] Cannot read {log_file}: {e}")
            return ""

    def check_iptables_log(self):
        """Deteksi port scanning dari log iptables/kernel"""
        try:
            detected = defaultdict(lambda: {
                'ports': set(),
                'count': 0,
                'first_seen': None,
                'last_seen': None,
                'sources': set()
            })

            patterns = [
                (r'PORT-SCAN:.*?SRC=(\d+\.\d+\.\d+\.\d+).*?DPT=(\d+)', 'iptables'),
                (r'SCAN:.*?SRC=(\d+\.\d+\.\d+\.\d+).*?DPT=(\d+)', 'iptables'),
            ]

            for log_file in self.log_paths:
                content = self._read_log(log_file)
                if not content:
                    continue

                for line in content.split('\n'):
                    if 'PORT-SCAN' not in line and 'SCAN:' not in line:
                        continue

                    for pattern, source in patterns:
                        match = re.search(pattern, line)
                        if match:
                            src_ip = match.group(1)
                            dst_port = match.group(2)

                            if self.is_ignored_ip(src_ip):
                                continue

                            if self.is_ignored_port(dst_port):
                                continue

                            if dst_port == '22' and 'ACK' in line and 'SYN' not in line:
                                continue

                            detected[src_ip]['ports'].add(dst_port)
                            detected[src_ip]['count'] += 1
                            detected[src_ip]['sources'].add(source)

                            ts_match = re.search(r'(\w{3}\s+\d+\s+\d+:\d+:\d+)', line)
                            if ts_match:
                                ts = ts_match.group(1)
                                if not detected[src_ip]['first_seen']:
                                    detected[src_ip]['first_seen'] = ts
                                detected[src_ip]['last_seen'] = ts

            result = {}
            for ip, data in detected.items():
                port_count = len(data['ports'])
                is_scanning = port_count >= self.PORT_SCAN_THRESHOLD

                if port_count >= 100:
                    severity = 'CRITICAL'
                elif port_count >= 20:
                    severity = 'HIGH'
                elif port_count >= 10:
                    severity = 'MEDIUM'
                else:
                    severity = 'LOW'

                result[ip] = {
                    'ip': ip,
                    'unique_ports': port_count,
                    'total_attempts': data['count'],
                    'ports': sorted(list(data['ports']), key=lambda x: int(x))[:30],
                    'first_seen': data['first_seen'] or 'N/A',
                    'last_seen': data['last_seen'] or 'N/A',
                    'status': 'SCANNING' if is_scanning else 'SUSPICIOUS',
                    'severity': severity,
                    'sources': list(data['sources'])
                }

            return result

        except Exception as e:
            print(f"[ERROR] check_iptables_log: {e}")
            return {}

    def check_ssh_log(self):
        """Deteksi SSH connection attempts dari log auth"""
        try:
            content = self._read_log('/var/log/auth.log', lines=1000)
            if not content:
                return {}

            detected = defaultdict(lambda: {
                'count': 0,
                'ports': set(['22']),
                'first_seen': None,
                'last_seen': None
            })

            patterns = [
                r'from (\d+\.\d+\.\d+\.\d+) port (\d+)',
                r'Connection from (\d+\.\d+\.\d+\.\d+) port (\d+)',
            ]

            for line in content.split('\n'):
                if 'Accepted password' in line or 'Accepted publickey' in line:
                    continue

                for pattern in patterns:
                    match = re.search(pattern, line)
                    if match:
                        src_ip = match.group(1)

                        if self.is_ignored_ip(src_ip):
                            continue

                        detected[src_ip]['count'] += 1

                        ts_match = re.search(r'(\w{3}\s+\d+\s+\d+:\d+:\d+)', line)
                        if ts_match:
                            ts = ts_match.group(1)
                            if not detected[src_ip]['first_seen']:
                                detected[src_ip]['first_seen'] = ts
                            detected[src_ip]['last_seen'] = ts
                        break

            formatted = {}
            for ip, data in detected.items():
                if data['count'] >= self.CONNECTION_THRESHOLD:
                    formatted[ip] = {
                        'ip': ip,
                        'unique_ports': len(data['ports']),
                        'total_attempts': data['count'],
                        'ports': list(data['ports']),
                        'first_seen': data['first_seen'] or 'N/A',
                        'last_seen': data['last_seen'] or 'N/A',
                        'status': 'SCANNING',
                        'severity': 'MEDIUM',
                        'sources': ['ssh']
                    }

            return formatted

        except Exception as e:
            print(f"[ERROR] check_ssh_log: {e}")
            return {}

    def check_active_connections(self):
        """Deteksi port scanning dari koneksi aktif (via ss)"""
        try:
            result = subprocess.run(
                ['ss', '-tn', 'state', 'syn-recv'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                result = subprocess.run(
                    ['sudo', '-n', 'ss', '-tn', 'state', 'syn-recv'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

            detected = defaultdict(lambda: {
                'ports': set(),
                'count': 0
            })

            lines = result.stdout.split('\n')[1:]

            for line in lines:
                parts = line.split()
                if len(parts) >= 4:
                    peer = parts[4] if len(parts) > 4 else ''
                    local = parts[3] if len(parts) > 3 else ''

                    peer_match = re.match(r'(\d+\.\d+\.\d+\.\d+):(\d+)', peer)
                    if peer_match:
                        src_ip = peer_match.group(1)

                        if self.is_ignored_ip(src_ip):
                            continue

                        local_match = re.search(r':(\d+)$', local)
                        if local_match:
                            port = local_match.group(1)
                            if self.is_ignored_port(port):
                                continue
                            detected[src_ip]['ports'].add(port)
                            detected[src_ip]['count'] += 1

            formatted = {}
            for ip, data in detected.items():
                if len(data['ports']) >= self.PORT_SCAN_THRESHOLD:
                    formatted[ip] = {
                        'ip': ip,
                        'unique_ports': len(data['ports']),
                        'total_attempts': data['count'],
                        'ports': sorted(list(data['ports']), key=lambda x: int(x))[:30],
                        'first_seen': 'N/A',
                        'last_seen': 'N/A',
                        'status': 'SCANNING',
                        'severity': 'HIGH',
                        'sources': ['active']
                    }

            return formatted

        except Exception as e:
            print(f"[ERROR] check_active_connections: {e}")
            return {}

    def check_all(self):
        """Gabungkan semua deteksi"""
        try:
            # Dapatkan IP yang sudah diblokir
            blocked_ips = self.get_blocked_ips()

            iptables_result = self.check_iptables_log()
            ssh_result = self.check_ssh_log()
            active_result = self.check_active_connections()

            # ==========================================================
            # FILTER IP YANG SUDAH DIBLOKIR
            # ==========================================================
            for ip in list(iptables_result.keys()):
                if ip in blocked_ips:
                    del iptables_result[ip]

            for ip in list(ssh_result.keys()):
                if ip in blocked_ips:
                    del ssh_result[ip]

            for ip in list(active_result.keys()):
                if ip in blocked_ips:
                    del active_result[ip]

            print(f"[DEBUG] Blocked IPs: {len(blocked_ips)}")
            print(f"[DEBUG] iptables: {len(iptables_result)} IPs")
            print(f"[DEBUG] ssh: {len(ssh_result)} IPs")
            print(f"[DEBUG] active: {len(active_result)} IPs")

            merged = {}

            for source, data in [
                ('iptables', iptables_result),
                ('ssh', ssh_result),
                ('active', active_result)
            ]:
                for ip, info in data.items():
                    if ip in merged:
                        merged[ip]['total_attempts'] += info.get('total_attempts', 0)
                        merged[ip]['unique_ports'] = max(
                            merged[ip]['unique_ports'],
                            info.get('unique_ports', 0)
                        )
                        if 'ports' in info:
                            existing_ports = set(merged[ip].get('ports', []))
                            existing_ports.update(info['ports'])
                            merged[ip]['ports'] = sorted(list(existing_ports), key=lambda x: int(x))[:30]
                        merged[ip]['sources'].extend(info.get('sources', []))
                    else:
                        merged[ip] = {
                            'ip': ip,
                            'total_attempts': info.get('total_attempts', 0),
                            'unique_ports': info.get('unique_ports', 0),
                            'ports': info.get('ports', []),
                            'status': info.get('status', 'SUSPICIOUS'),
                            'severity': info.get('severity', 'MEDIUM'),
                            'sources': info.get('sources', []),
                            'first_seen': info.get('first_seen', 'N/A'),
                            'last_seen': info.get('last_seen', 'N/A')
                        }

            for ip in merged:
                port_count = merged[ip]['unique_ports']
                if port_count >= 100:
                    merged[ip]['severity'] = 'CRITICAL'
                    merged[ip]['status'] = 'PORT SCAN DETECTED'
                elif port_count >= 20:
                    merged[ip]['severity'] = 'HIGH'
                    merged[ip]['status'] = 'SCANNING'
                elif port_count >= 10:
                    merged[ip]['severity'] = 'MEDIUM'
                    merged[ip]['status'] = 'SCANNING'
                elif port_count >= 5:
                    merged[ip]['severity'] = 'LOW'
                    merged[ip]['status'] = 'SUSPICIOUS'

            for ip in merged:
                merged[ip]['sources'] = list(set(merged[ip]['sources']))

            return {
                'detected': len(merged) > 0,
                'total_suspects': len(merged),
                'suspects': merged,
                'blocked_count': len(blocked_ips),
                'blocked_ips': list(blocked_ips),
                'timestamp': datetime.now().isoformat()
            }

        except Exception as e:
            print(f"[ERROR] check_all: {e}")
            import traceback
            traceback.print_exc()
            return {
                'detected': False,
                'total_suspects': 0,
                'suspects': {},
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }

    def block_ip(self, ip):
        """Blokir IP yang melakukan scanning (timeout 30 detik)"""
        try:
            if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                return {'success': False, 'error': 'Invalid IP format'}

            # Cek apakah sudah diblokir
            blocked = self.get_blocked_ips()
            if ip in blocked:
                return {'success': False, 'error': f'IP {ip} already blocked'}

            # Blokir IP
            result = subprocess.run(
                ['sudo', '-n', '/sbin/iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP'],
                capture_output=True,
                text=True,
                timeout=self.IPTABLES_TIMEOUT
            )

            if result.returncode != 0:
                error_msg = result.stderr.strip() if result.stderr else 'Unknown error'
                return {'success': False, 'error': error_msg}

            print(f"[BLOCKED] IP {ip} blocked due to port scanning")
            return {'success': True, 'message': f'IP {ip} blocked'}

        except subprocess.TimeoutExpired:
            return {'success': False, 'error': f'Command timeout ({self.IPTABLES_TIMEOUT}s)'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def unblock_ip(self, ip):
        """Unblock IP"""
        try:
            if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                return {'success': False, 'error': 'Invalid IP format'}

            result = subprocess.run(
                ['sudo', '-n', '/sbin/iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'],
                capture_output=True,
                text=True,
                timeout=self.IPTABLES_TIMEOUT
            )

            if result.returncode != 0:
                return {'success': False, 'error': result.stderr or 'Failed to unblock'}

            return {'success': True, 'message': f'IP {ip} unblocked'}

        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Command timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
