"""
Container Management API - Minimal Clean Version
"""

import os
import subprocess
from datetime import datetime
from flask import Blueprint, jsonify
import requests

containers_bp = Blueprint('containers', __name__, url_prefix='/api/containers')

@containers_bp.route('/health')
def get_all_container_health():
    """Get health status of all configured containers"""
    try:
        health_status = {}

        # Check ClamAV container
        try:
            clamav_url = os.environ.get('CLAMAV_URL', 'http://clamav-scanner:5000')
            response = requests.get(f'{clamav_url}/health', timeout=10)
            if response.status_code == 200:
                data = response.json()
                health_status['clamav-scanner'] = {
                    'available': data.get('status') == 'healthy',
                    'status': data.get('status', 'unknown'),
                    'version': data.get('version', 'Container Service'),
                    'service': 'clamav-scanner',
                    'type': 'av-scanner'
                }
            else:
                health_status['clamav-scanner'] = {
                    'available': False,
                    'status': f'http_error_{response.status_code}',
                    'service': 'clamav-scanner',
                    'type': 'av-scanner'
                }
        except Exception as e:
            health_status['clamav-scanner'] = {
                'available': False,
                'status': 'unreachable',
                'error': str(e),
                'service': 'clamav-scanner',
                'type': 'av-scanner'
            }

        # Check YARA container
        try:
            yara_url = os.environ.get('YARA_URL', 'http://yara-scanner:5001')
            response = requests.get(f'{yara_url}/health', timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                health_status['yara-scanner'] = {
                    'available': data.get('status') == 'ready',
                    'status': data.get('status', 'unknown'),
                    'rules_loaded': data.get('rules_loaded', 0),
                    'uptime_seconds': data.get('uptime_seconds', 0),
                    'version': 'Container Service',
                    'service': 'yara-scanner',
                    'type': 'yara-service'
                }
            else:
                health_status['yara-scanner'] = {
                    'available': False,
                    'status': f'http_error_{response.status_code}',
                    'service': 'yara-scanner',
                    'type': 'yara-service'
                }
        except Exception as e:
            health_status['yara-scanner'] = {
                'available': False,
                'status': 'error',
                'error': str(e),
                'service': 'yara-scanner',
                'type': 'yara-service'
            }

        return jsonify({
            'success': True,
            'containers': health_status,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@containers_bp.route('/<container_id>/restart', methods=['POST'])
def restart_container(container_id):
    """Restart a specific container (may not work from within container)"""
    try:
        # Validate container ID  
        valid_containers = ['yara-scanner', 'clamav-scanner']
        if container_id not in valid_containers:
            return jsonify({
                'success': False,
                'error': f'Cannot restart {container_id}. Valid options: {valid_containers}'
            }), 400
        
        # Attempt restart using docker-compose
        try:
            cmd = ['docker-compose', 'restart', container_id]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                return jsonify({
                    'success': True,
                    'message': f'Container {container_id} restart initiated',
                    'container_id': container_id,
                    'timestamp': datetime.now().isoformat()
                })
            else:
                return jsonify({
                    'success': False,
                    'error': f'Restart failed: {result.stderr}',
                    'container_id': container_id
                }), 500
                
        except subprocess.TimeoutExpired:
            return jsonify({
                'success': False,
                'error': 'Restart command timeout',
                'container_id': container_id
            }), 500
        except FileNotFoundError:
            return jsonify({
                'success': False,
                'error': 'docker-compose not found - restart from host instead',
                'container_id': container_id
            }), 500
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500