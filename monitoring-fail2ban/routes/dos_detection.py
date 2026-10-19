# routes/dos_detection.py
from flask import Blueprint, render_template, jsonify, request
from services.dos_detection_service import DoSDetectionService
from datetime import datetime
import subprocess
import json
import re

dos_bp = Blueprint('dos', __name__, url_prefix='/dos')
dos_service = DoSDetectionService()

@dos_bp.route('/')
def dos_dashboard():
    """Halaman utama deteksi DoS"""
    return render_template('dos_detection.html')

@dos_bp.route('/api/status')
def api_status():
    """API untuk mendapatkan status deteksi DoS"""
    # Deteksi flooding
    flood_detected = dos_service.check_ssh_flood()
    
    # Status SSH
    ssh_status = dos_service.get_ssh_status()
    
    # Iptables stats
    iptables_stats = dos_service.get_iptables_stats()
    
    # Fail2Ban status (SEMUA JAIL, tidak hanya sshd)
    fail2ban_status = dos_service.get_fail2ban_status()
    
    return jsonify({
        'ssh': ssh_status,
        'flood_ips': flood_detected,
        'iptables': iptables_stats,
        'fail2ban': fail2ban_status,
        'timestamp': datetime.now().isoformat()
    })

@dos_bp.route('/api/block', methods=['POST'])
def api_block_ip():
    """Memblokir IP menggunakan iptables"""
    try:
        data = request.get_json()
        ip = data.get('ip')
        
        if not ip:
            return jsonify({'success': False, 'error': 'IP required'}), 400
        
        # Validasi IP sederhana
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
            return jsonify({'success': False, 'error': 'Invalid IP format'}), 400
        
        # Blokir IP di iptables
        cmd = [
            'sudo', 'iptables', '-I', 'INPUT',
            '-s', ip,
            '-j', 'DROP'
        ]
        subprocess.run(cmd, check=True, timeout=5)
        
        # Tambahkan ke Fail2Ban (coba ke semua jail yang aktif)
        try:
            # Dapatkan daftar jail aktif
            result = subprocess.run(
                ['sudo', 'fail2ban-client', 'status'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            jail_list = []
            for line in result.stdout.split('\n'):
                if 'Jail list:' in line:
                    jails_str = line.split('Jail list:')[1].strip()
                    if jails_str:
                        jail_list = [j.strip() for j in jails_str.split(',')]
            
            # Ban IP di semua jail
            for jail in jail_list:
                try:
                    subprocess.run(
                        ['sudo', 'fail2ban-client', 'set', jail, 'banip', ip],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                except:
                    continue
        except:
            pass
        
        return jsonify({'success': True, 'message': f'IP {ip} blocked'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@dos_bp.route('/api/block-all', methods=['POST'])
def api_block_all():
    """Memblokir semua IP yang terdeteksi flooding"""
    try:
        detected = dos_service.check_ssh_flood()
        flood_ips = []
        
        # Ambil IP dengan status FLOOD_DETECTED
        if isinstance(detected, dict):
            for ip, info in detected.items():
                if isinstance(info, dict) and info.get('status') == 'FLOOD_DETECTED':
                    flood_ips.append(ip)
        
        blocked = 0
        for ip in flood_ips:
            try:
                subprocess.run([
                    'sudo', 'iptables', '-I', 'INPUT',
                    '-s', ip,
                    '-j', 'DROP'
                ], check=True, timeout=5)
                blocked += 1
            except:
                continue
        
        return jsonify({'success': True, 'blocked': blocked})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@dos_bp.route('/api/unblock', methods=['POST'])
def api_unblock_ip():
    """Melepas blokir IP dari iptables"""
    try:
        data = request.get_json()
        ip = data.get('ip')
        
        if not ip:
            return jsonify({'success': False, 'error': 'IP required'}), 400
        
        # Hapus aturan blokir (cari dan hapus)
        cmd = ['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP']
        subprocess.run(cmd, check=True, timeout=5)
        
        return jsonify({'success': True, 'message': f'IP {ip} unblocked'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
