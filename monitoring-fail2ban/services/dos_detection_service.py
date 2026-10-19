# services/dos_detection_service.py
import subprocess
import re
import os
from collections import defaultdict, deque
from datetime import datetime, timedelta


class DoSDetectionService:
    def __init__(self):
        self.ssh_attempts = defaultdict(lambda: deque(maxlen=200))
        self.flood_detected = {}
        self.last_check = datetime.now()
        self.auth_log_path = '/var/log/auth.log'
        self.syslog_path = '/var/log/syslog'
        self.kern_log_path = '/var/log/kern.log'
        self.IPTABLES_TIMEOUT = 30

        # ==========================================================
        # IP YANG DIABAIKAN
        # ==========================================================
        self.ignored_ips = [
            '127.0.0.1',
            '192.168.186.1',     # Gateway
            '192.168.186.2',     # VM Host
            '192.168.186.10',    # Admin client
            '192.168.186.134',   # Server sendiri
            '192.168.186.254',   # DHCP / VMware NAT
            '192.168.186.255',   # Broadcast
        ]

        # ==========================================================
        # PORT YANG DIABAIKAN
        # ==========================================================
        self.ignored_ports = [
            '68', '67', '53', '137', '138', '139', '5353', '1900',
        ]

        # Threshold
        self.SYN_FLOOD_THRESHOLD = 50   # 50 SYN packet = flood
        self.SSH_FLOOD_THRESHOLD = 20   # 20 SSH failure = flood

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

    def _read_log(self, log_file, lines=1000):
        """Baca log tanpa sudo (user sudah di group adm)"""
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

            # Fallback ke sudo
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

    # ==========================================================
    # DETEKSI SYN FLOOD (dari kern.log / syslog)
    # ==========================================================
    def check_syn_flood(self):
        """
        Deteksi SYN flood dari log iptables/kernel
        Mencari paket SYN ke port 22 (atau port lain)
        """
        try:
            detected = defaultdict(lambda: {
                'count': 0,
                'ports': set(),
                'first_seen': None,
                'last_seen': None,
                'sources': set()
            })

            current_time = datetime.now()

            # Baca dari kern.log dan syslog
            for log_file in [self.kern_log_path, self.syslog_path]:
                content = self._read_log(log_file, lines=1000)
                if not content:
                    continue

                for line in content.split('\n'):
                    # Cari SSH-FLOOD-DROP atau PORT-SCAN dengan SYN
                    if 'SSH-FLOOD-DROP' not in line and 'PORT-SCAN' not in line:
                        continue

                    # Harus ada SYN (bukan ACK)
                    if 'SYN' not in line:
                        continue

                    # Extract IP dan port
                    ip_match = re.search(r'SRC=(\d+\.\d+\.\d+\.\d+)', line)
                    port_match = re.search(r'DPT=(\d+)', line)

                    if not ip_match or not port_match:
                        continue

                    src_ip = ip_match.group(1)
                    dst_port = port_match.group(1)

                    # Skip IP yang diabaikan
                    if self.is_ignored_ip(src_ip):
                        continue

                    # Skip port yang diabaikan
                    if self.is_ignored_port(dst_port):
                        continue

                    detected[src_ip]['count'] += 1
                    detected[src_ip]['ports'].add(dst_port)
                    detected[src_ip]['sources'].add('iptables')

                    # Timestamp
                    ts_match = re.search(r'(\w{3}\s+\d+\s+\d+:\d+:\d+)', line)
                    if ts_match:
                        ts = ts_match.group(1)
                        if not detected[src_ip]['first_seen']:
                            detected[src_ip]['first_seen'] = ts
                        detected[src_ip]['last_seen'] = ts

            # Format hasil
            result = {}
            for ip, data in detected.items():
                if data['count'] >= self.SYN_FLOOD_THRESHOLD:
                    result[ip] = {
                        'ip': ip,
                        'attempts_1m': data['count'],
                        'attempts_5m': data['count'],
                        'total_attempts': data['count'],
                        'ports': sorted(list(data['ports']), key=lambda x: int(x))[:10],
                        'first_seen': data['first_seen'] or 'N/A',
                        'last_seen': data['last_seen'] or 'N/A',
                        'status': 'FLOOD_DETECTED',
                        'severity': 'CRITICAL' if data['count'] >= 200 else 'HIGH',
                        'type': 'SYN_FLOOD',
                        'sources': list(data['sources'])
                    }

            return result

        except Exception as e:
            print(f"[ERROR] check_syn_flood: {e}")
            return {}

    # ==========================================================
    # DETEKSI SSH FLOOD (dari auth.log)
    # ==========================================================
    def check_ssh_auth_flood(self):
        """
        Deteksi SSH flood dari log auth (kegagalan login)
        """
        try:
            content = self._read_log(self.auth_log_path, lines=2000)
            if not content:
                return {}

            detected = defaultdict(lambda: {
                'count': 0,
                'first_seen': None,
                'last_seen': None
            })

            current_time = datetime.now()

            # Pattern untuk kegagalan login
            patterns = [
                r'Failed password for .* from (\d+\.\d+\.\d+\.\d+)',
                r'Invalid user .* from (\d+\.\d+\.\d+\.\d+)',
                r'authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+)',
            ]

            for line in content.split('\n'):
                # Skip login sukses
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

            result = {}
            for ip, data in detected.items():
                if data['count'] >= self.SSH_FLOOD_THRESHOLD:
                    result[ip] = {
                        'ip': ip,
                        'attempts_1m': data['count'],
                        'attempts_5m': data['count'],
                        'total_attempts': data['count'],
                        'first_seen': data['first_seen'] or 'N/A',
                        'last_seen': data['last_seen'] or 'N/A',
                        'status': 'FLOOD_DETECTED',
                        'severity': 'HIGH' if data['count'] >= 100 else 'MEDIUM',
                        'type': 'SSH_FLOOD',
                        'sources': ['auth']
                    }

            return result

        except Exception as e:
            print(f"[ERROR] check_ssh_auth_flood: {e}")
            return {}

    # ==========================================================
    # GABUNGKAN SEMUA DETEKSI
    # ==========================================================
    def check_ssh_flood(self):
        """
        Gabungkan deteksi SYN flood dan SSH flood
        """
        try:
            syn_flood = self.check_syn_flood()
            ssh_flood = self.check_ssh_auth_flood()

            print(f"[DEBUG] SYN flood: {len(syn_flood)} IPs")
            print(f"[DEBUG] SSH flood: {len(ssh_flood)} IPs")

            # Gabungkan
            merged = {}
            for source, data in [('syn', syn_flood), ('ssh', ssh_flood)]:
                for ip, info in data.items():
                    if ip in merged:
                        # Update
                        merged[ip]['total_attempts'] += info.get('total_attempts', 0)
                        merged[ip]['attempts_1m'] += info.get('attempts_1m', 0)
                        merged[ip]['attempts_5m'] += info.get('attempts_5m', 0)
                        merged[ip]['sources'].extend(info.get('sources', []))
                        # Ambil severity tertinggi
                        if info.get('severity') == 'CRITICAL':
                            merged[ip]['severity'] = 'CRITICAL'
                    else:
                        merged[ip] = dict(info)
                        merged[ip]['sources'] = info.get('sources', [])

            # Deduplicate sources
            for ip in merged:
                merged[ip]['sources'] = list(set(merged[ip]['sources']))

            return merged

        except Exception as e:
            print(f"[ERROR] check_ssh_flood: {e}")
            return {}

    # ==========================================================
    # STATUS SSH
    # ==========================================================
    def get_ssh_status(self):
        """Mendapatkan status service SSH"""
        try:
            result = subprocess.run(
                ['systemctl', 'status', 'ssh', '--no-pager'],
                capture_output=True,
                text=True,
                timeout=5
            )

            lines = result.stdout.split('\n')
            status = {
                'active': False,
                'cpu_usage': '0%',
                'memory_usage': '0%',
                'connections': 0,
                'pid': None,
                'uptime': 'N/A',
                'load_average': 'N/A'
            }

            for line in lines:
                if 'Active:' in line:
                    if 'active (running)' in line:
                        status['active'] = True
                        uptime_match = re.search(r'active \(running\) since (.*?)(;|$)', line)
                        if uptime_match:
                            status['uptime'] = uptime_match.group(1).strip()
                    elif 'inactive' in line:
                        status['active'] = False
                if 'Main PID:' in line:
                    pid_match = re.search(r'Main PID:\s+(\d+)', line)
                    if pid_match:
                        status['pid'] = pid_match.group(1)

            if status['active']:
                conn_result = subprocess.run(
                    ['ss', '-tn', 'state', 'established', '(', 'sport', '=', '22', ')'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                status['connections'] = max(0, len(conn_result.stdout.split('\n')) - 2)

                if status['pid']:
                    ps_result = subprocess.run(
                        ['ps', '-p', status['pid'], '-o', '%cpu,%mem'],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    lines = ps_result.stdout.split('\n')
                    if len(lines) > 1 and lines[1].strip():
                        parts = lines[1].split()
                        if len(parts) >= 2:
                            status['cpu_usage'] = parts[0] + '%'
                            status['memory_usage'] = parts[1] + '%'

            load_result = subprocess.run(
                ['uptime'],
                capture_output=True,
                text=True,
                timeout=5
            )
            load_match = re.search(r'load average:\s+([\d.]+),\s+([\d.]+),\s+([\d.]+)', load_result.stdout)
            if load_match:
                status['load_average'] = f"{load_match.group(1)} / {load_match.group(2)} / {load_match.group(3)}"

            return status

        except Exception as e:
            print(f"[ERROR] get_ssh_status: {e}")
            return {
                'active': False,
                'cpu_usage': '0%',
                'memory_usage': '0%',
                'connections': 0,
                'pid': None,
                'uptime': 'N/A',
                'load_average': 'N/A',
                'error': str(e)
            }

    # ==========================================================
    # IPTABLES STATS
    # ==========================================================
    def get_iptables_stats(self):
        """Mendapatkan statistik dari iptables SSH_LIMIT"""
        try:
            stats = {
                'chain_exists': False,
                'packets': 0,
                'bytes': 0,
                'dropped_ips': [],
                'hashlimit_stats': '',
                'rules': []
            }

            # Cek chain SSH_LIMIT
            result = subprocess.run(
                ['sudo', '-n', '/sbin/iptables', '-L', 'SSH_LIMIT', '-n', '-v'],
                capture_output=True,
                text=True,
                timeout=self.IPTABLES_TIMEOUT
            )

            if 'Chain SSH_LIMIT' in result.stdout:
                stats['chain_exists'] = True
                stats['rules'] = result.stdout

                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Chain SSH_LIMIT' in line:
                        continue
                    parts = line.split()
                    if len(parts) >= 2 and parts[0].isdigit():
                        try:
                            stats['packets'] += int(parts[0])
                            stats['bytes'] += int(parts[1])
                        except:
                            pass

            # Baca hashlimit stats
            hashlimit_path = '/proc/net/ipt_hashlimit/ssh-limit'
            if os.path.exists(hashlimit_path):
                try:
                    result = subprocess.run(
                        ['cat', hashlimit_path],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    stats['hashlimit_stats'] = result.stdout
                except:
                    pass

            # Baca log SSH-FLOOD-DROP
            for log_file in [self.kern_log_path, self.syslog_path]:
                if os.path.exists(log_file):
                    try:
                        result = subprocess.run(
                            ['grep', 'SSH-FLOOD-DROP', log_file],
                            capture_output=True,
                            text=True,
                            timeout=5
                        )

                        ip_pattern = r'SRC=(\d+\.\d+\.\d+\.\d+)'
                        ips = re.findall(ip_pattern, result.stdout)
                        ip_counts = {}
                        for ip in ips:
                            if self.is_ignored_ip(ip):
                                continue
                            ip_counts[ip] = ip_counts.get(ip, 0) + 1

                        for ip, count in ip_counts.items():
                            stats['dropped_ips'].append({'ip': ip, 'count': count})

                        stats['dropped_ips'].sort(key=lambda x: x['count'], reverse=True)
                    except:
                        pass

            return stats

        except Exception as e:
            print(f"[ERROR] get_iptables_stats: {e}")
            return {'error': str(e)}

    # ==========================================================
    # FAIL2BAN STATUS
    # ==========================================================
    def get_fail2ban_status(self):
        """Mendapatkan status Fail2Ban"""
        try:
            status = {
                'active': False,
                'banned_ips': [],
                'current_bans': 0,
                'total_bans': 0,
                'jails': [],
                'jail_details': {},
                'error': None
            }

            result = subprocess.run(
                ['sudo', '-n', '/usr/bin/fail2ban-client', 'status'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                status['error'] = result.stderr or 'Fail2Ban command failed'
                return status

            for line in result.stdout.split('\n'):
                if 'Jail list:' in line:
                    jails_str = line.split('Jail list:')[1].strip()
                    if jails_str:
                        status['jails'] = [j.strip() for j in jails_str.split(',')]

            status['active'] = True

            total_banned = 0
            all_banned_ips = []

            for jail in status['jails']:
                try:
                    jail_result = subprocess.run(
                        ['sudo', '-n', '/usr/bin/fail2ban-client', 'status', jail],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )

                    jail_info = {
                        'name': jail,
                        'currently_banned': 0,
                        'total_banned': 0,
                        'banned_ips': []
                    }

                    for line in jail_result.stdout.split('\n'):
                        if 'Currently banned:' in line:
                            match = re.search(r'(\d+)', line)
                            if match:
                                jail_info['currently_banned'] = int(match.group(1))
                                total_banned += int(match.group(1))
                        if 'Total banned:' in line:
                            match = re.search(r'(\d+)', line)
                            if match:
                                jail_info['total_banned'] = int(match.group(1))
                        if 'Banned IP list:' in line:
                            ips_str = line.split('Banned IP list:')[1].strip()
                            if ips_str and ips_str != 'None':
                                ips = re.findall(r'\d+\.\d+\.\d+\.\d+', ips_str)
                                jail_info['banned_ips'] = ips
                                all_banned_ips.extend(ips)

                    status['jail_details'][jail] = jail_info
                except Exception as e:
                    print(f"[ERROR] jail {jail}: {e}")
                    continue

            status['total_bans'] = total_banned
            status['current_bans'] = total_banned
            status['banned_ips'] = list(set(all_banned_ips))

            return status

        except Exception as e:
            print(f"[ERROR] get_fail2ban_status: {e}")
            return {'active': False, 'error': str(e), 'jails': [], 'banned_ips': []}
