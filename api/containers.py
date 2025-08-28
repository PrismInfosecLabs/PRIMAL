"""
Container Management API Routes
Handles containerized antivirus engine health checks and management
"""

import requests
from datetime import datetime
from urllib.parse import urljoin
from flask import Blueprint, request, jsonify
from services import MalwareAnalyzer

# Create blueprint for container routes
containers_bp = Blueprint('containers', __name__, url_prefix='/api/containers')

# Initialize services
analyzer = MalwareAnalyzer()


@containers_bp.route('/health')
def check_container_health():
    """Check health of all container services"""
    try:
        health_status = {}
        
        # Check if analyzer has container engines
        if not hasattr(analyzer, 'av_scanner') or not hasattr(analyzer.av_scanner, 'container_engines'):
            return jsonify({
                'success': True,
                'containers': {},
                'message': 'No container engines configured',
                'timestamp': datetime.now().isoformat()
            })
        
        for engine_id, engine in analyzer.av_scanner.container_engines.items():
            try:
                health_url = urljoin(engine['url'], '/health')
                response = requests.get(health_url, timeout=5)
                
                if response.status_code == 200:
                    health_data = response.json()
                    health_status[engine_id] = {
                        'status': health_data.get('status', 'unknown'),
                        'version': health_data.get('version', 'unknown'),
                        'available': health_data.get('status') == 'healthy',
                        'last_check': datetime.now().isoformat()
                    }
                else:
                    health_status[engine_id] = {
                        'status': 'error',
                        'error': f'HTTP {response.status_code}',
                        'available': False,
                        'last_check': datetime.now().isoformat()
                    }
            except Exception as e:
                health_status[engine_id] = {
                    'status': 'error',
                    'error': str(e),
                    'available': False,
                    'last_check': datetime.now().isoformat()
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


@containers_bp.route('/add', methods=['POST'])
def add_container_engine():
    """Add a new containerized AV engine"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'No request data provided'
            }), 400
        
        required_fields = ['engine_id', 'name', 'url']
        if not all(field in data for field in required_fields):
            return jsonify({
                'success': False,
                'error': 'Missing required fields: engine_id, name, url'
            }), 400
        
        engine_config = {
            'name': data['name'],
            'url': data['url'],
            'enabled': data.get('enabled', True),
            'type': 'container',
            'timeout': data.get('timeout', 60)
        }
        
        # Add engine using the service
        if hasattr(analyzer, 'av_manager'):
            analyzer.av_manager.add_container_engine(data['engine_id'], engine_config)
        else:
            # Fallback for older structure
            analyzer.av_scanner.container_engines = analyzer.av_scanner.container_engines or {}
            analyzer.av_scanner.container_engines[data['engine_id']] = engine_config
        
        return jsonify({
            'success': True,
            'message': f'Container engine {data["engine_id"]} added successfully'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@containers_bp.route('/remove/<engine_id>', methods=['DELETE'])
def remove_container_engine(engine_id):
    """Remove a containerized AV engine"""
    try:
        # Remove engine using the service
        if hasattr(analyzer, 'av_manager'):
            result = analyzer.av_manager.remove_container_engine(engine_id)
        else:
            # Fallback for older structure
            if hasattr(analyzer.av_scanner, 'container_engines') and engine_id in analyzer.av_scanner.container_engines:
                del analyzer.av_scanner.container_engines[engine_id]
                result = {'success': True}
            else:
                result = {'success': False, 'error': 'Engine not found'}
        
        if result['success']:
            return jsonify({
                'success': True,
                'message': f'Container engine {engine_id} removed successfully'
            })
        else:
            return jsonify({
                'success': False,
                'error': result.get('error', 'Failed to remove engine')
            }), 404
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@containers_bp.route('/list')
def list_container_engines():
    """List all configured container engines"""
    try:
        engines = {}
        
        if hasattr(analyzer, 'av_scanner') and hasattr(analyzer.av_scanner, 'container_engines'):
            engines = analyzer.av_scanner.container_engines
        
        engine_list = []
        for engine_id, config in engines.items():
            engine_list.append({
                'engine_id': engine_id,
                'name': config.get('name', engine_id),
                'url': config.get('url', ''),
                'enabled': config.get('enabled', True),
                'type': config.get('type', 'container'),
                'timeout': config.get('timeout', 60)
            })
        
        return jsonify({
            'success': True,
            'engines': engine_list,
            'total': len(engine_list)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@containers_bp.route('/<engine_id>/status')
def get_engine_status(engine_id):
    """Get detailed status for a specific container engine"""
    try:
        if not hasattr(analyzer, 'av_scanner') or not hasattr(analyzer.av_scanner, 'container_engines'):
            return jsonify({'error': 'No container engines configured'}), 404
        
        engines = analyzer.av_scanner.container_engines
        if engine_id not in engines:
            return jsonify({'error': f'Engine {engine_id} not found'}), 404
        
        engine = engines[engine_id]
        
        try:
            # Check health
            health_url = urljoin(engine['url'], '/health')
            response = requests.get(health_url, timeout=5)
            
            if response.status_code == 200:
                health_data = response.json()
                
                # Try to get additional stats
                try:
                    stats_url = urljoin(engine['url'], '/stats')
                    stats_response = requests.get(stats_url, timeout=3)
                    stats_data = stats_response.json() if stats_response.status_code == 200 else {}
                except:
                    stats_data = {}
                
                return jsonify({
                    'success': True,
                    'engine_id': engine_id,
                    'config': engine,
                    'health': health_data,
                    'stats': stats_data,
                    'available': health_data.get('status') == 'healthy',
                    'last_check': datetime.now().isoformat()
                })
            else:
                return jsonify({
                    'success': False,
                    'engine_id': engine_id,
                    'config': engine,
                    'error': f'HTTP {response.status_code}',
                    'available': False,
                    'last_check': datetime.now().isoformat()
                })
                
        except Exception as e:
            return jsonify({
                'success': False,
                'engine_id': engine_id,
                'config': engine,
                'error': str(e),
                'available': False,
                'last_check': datetime.now().isoformat()
            })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@containers_bp.route('/<engine_id>/restart', methods=['POST'])
def restart_container_engine(engine_id):
    """Restart a container engine (if supported)"""
    try:
        if not hasattr(analyzer, 'av_scanner') or not hasattr(analyzer.av_scanner, 'container_engines'):
            return jsonify({'error': 'No container engines configured'}), 404
        
        engines = analyzer.av_scanner.container_engines
        if engine_id not in engines:
            return jsonify({'error': f'Engine {engine_id} not found'}), 404
        
        engine = engines[engine_id]
        
        try:
            # Try to call restart endpoint
            restart_url = urljoin(engine['url'], '/restart')
            response = requests.post(restart_url, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                return jsonify({
                    'success': True,
                    'message': f'Engine {engine_id} restart initiated',
                    'result': result
                })
            else:
                return jsonify({
                    'success': False,
                    'error': f'Restart failed: HTTP {response.status_code}'
                }), 500
                
        except Exception as e:
            return jsonify({
                'success': False,
                'error': f'Restart failed: {str(e)}'
            }), 500
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500