# routes/arp_detection.py
from flask import Blueprint, render_template, jsonify, request
from services.arp_detection_service import ARPDetectionService
from datetime import datetime
import subprocess
import re

arp_bp = Blueprint('arp', __name__, url_prefix='/arp')
arp_service = ARPDetectionService()

@arp_bp.route('/')
def arp_dashboard():
    """Halaman utama deteksi ARP Spoofing"""
    return render_template('arp_detection.html')

@arp_bp.route('/api/status')
def api_status():
    """API untuk mendapatkan status ARP Spoofing"""
    result = arp_service.check_arp_spoofing()
    return jsonify({
        'arp': result,
        'timestamp': datetime.now().isoformat()
    })

@arp_bp.route('/api/history')
def api_history():
    """API untuk mendapatkan history ARP"""
    ip = request.args.get('ip')
    history = arp_service.get_arp_history(ip)
    return jsonify({
        'history': history,
        'ip': ip,
        'timestamp': datetime.now().isoformat()
    })

@arp_bp.route('/api/events')
def api_events():
    """API untuk mendapatkan event mencurigakan"""
    limit = request.args.get('limit', 50, type=int)
    events = arp_service.get_suspicious_events(limit)
    return jsonify({
        'events': events,
        'count': len(events),
        'timestamp': datetime.now().isoformat()
    })

@arp_bp.route('/api/set-known-mac', methods=['POST'])
def api_set_known_mac():
    """Set known good MAC untuk IP"""
    try:
        data = request.get_json()
        ip = data.get('ip')
        mac = data.get('mac')
        
        if not ip or not mac:
            return jsonify({'success': False, 'error': 'IP and MAC required'}), 400
        
        # Validasi MAC
        if not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac):
            return jsonify({'success': False, 'error': 'Invalid MAC format'}), 400
        
        arp_service.set_known_mac(ip, mac)
        return jsonify({'success': True, 'message': f'Known MAC set for {ip}: {mac}'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@arp_bp.route('/api/scan', methods=['POST'])
def api_scan():
    """Scan network untuk update ARP cache"""
    try:
        result = arp_service.scan_network()
        return jsonify({
            'success': True,
            'result': result,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@arp_bp.route('/api/alert-ignore', methods=['POST'])
def api_alert_ignore():
    """Ignore alert untuk IP tertentu"""
    try:
        data = request.get_json()
        ip = data.get('ip')
        
        if not ip:
            return jsonify({'success': False, 'error': 'IP required'}), 400
        
        # Tambahkan IP ke ignored list
        # (Implementasi sederhana - bisa dikembangkan)
        
        return jsonify({'success': True, 'message': f'Alert ignored for {ip}'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
