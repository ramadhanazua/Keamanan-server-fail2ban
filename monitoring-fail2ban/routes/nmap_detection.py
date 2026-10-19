# routes/nmap_detection.py
from flask import Blueprint, render_template, jsonify, request
from services.nmap_detection_service import NmapDetectionService
from datetime import datetime
import re

nmap_bp = Blueprint('nmap', __name__, url_prefix='/nmap')
nmap_service = NmapDetectionService()

@nmap_bp.route('/')
def nmap_dashboard():
    """Halaman utama deteksi Nmap Scanning"""
    return render_template('nmap_detection.html')

@nmap_bp.route('/api/status')
def api_status():
    """API untuk mendapatkan status deteksi Nmap"""
    result = nmap_service.check_all()
    return jsonify({
        'nmap': result,
        'timestamp': datetime.now().isoformat()
    })

@nmap_bp.route('/api/block', methods=['POST'])
def api_block_ip():
    """Blokir IP yang melakukan scanning"""
    try:
        data = request.get_json()
        ip = data.get('ip')
        
        if not ip:
            return jsonify({'success': False, 'error': 'IP required'}), 400
        
        result = nmap_service.block_ip(ip)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
