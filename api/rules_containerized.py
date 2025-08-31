"""
YARA Rules API Routes (Containerized Version)
Handles YARA rule management via the containerized YARA service
"""

import os
import glob
from datetime import datetime
from flask import Blueprint, request, jsonify
from config import Config
from av_services.container_yara_manager import ContainerYaraManager

# Create blueprint for rules routes
rules_bp = Blueprint('rules', __name__, url_prefix='/api/rules')

# Initialize containerized YARA manager
container_yara_manager = None

def get_yara_manager():
    """Get or initialize the containerized YARA manager"""
    global container_yara_manager
    if container_yara_manager is None:
        try:
            container_yara_manager = ContainerYaraManager()
        except Exception as e:
            print(f"Failed to initialize containerized YARA manager: {e}")
    return container_yara_manager


@rules_bp.route('/')
def list_rules():
    """API endpoint for paginated rule listing via containerized service"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)
        search = request.args.get('search', '', type=str).lower()
        directory = request.args.get('directory', '', type=str)
        
        yara_manager = get_yara_manager()
        if not yara_manager or not yara_manager.is_available():
            return jsonify({
                'error': 'YARA service not available',
                'rules': [],
                'pagination': {
                    'page': page, 'per_page': per_page, 'total': 0, 'pages': 0,
                    'has_prev': False, 'has_next': False
                }
            })
        
        try:
            # Get rules from containerized service with pagination
            params = {
                'page': page,
                'per_page': per_page,
                'search': search,
                'directory': directory if directory != 'all' else ''
            }
            
            # Make request to containerized service
            import requests
            yara_url = yara_manager.yara_url
            response = requests.get(f"{yara_url}/rules/list", params=params, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    return jsonify({
                        'rules': result.get('rules', []),
                        'pagination': result.get('pagination', {})
                    })
            
            # Fallback: use basic list method
            all_rules = yara_manager.list_rule_files()
            
            # Filter by search term
            if search:
                all_rules = [rule for rule in all_rules if 
                            search in rule.get('filename', '').lower() or 
                            search in rule.get('directory', '').lower() or
                            search in rule.get('relative_path', '').lower()]
            
            # Filter by directory
            if directory and directory != 'all':
                all_rules = [rule for rule in all_rules if rule.get('directory') == directory]
            
            # Calculate pagination
            total = len(all_rules)
            start = (page - 1) * per_page
            end = start + per_page
            
            # Get rules for current page
            rules_page = []
            for rule in all_rules[start:end]:
                rules_page.append({
                    'filename': rule.get('filename', 'Unknown'),
                    'relative_path': rule.get('relative_path', ''),
                    'directory': rule.get('directory', 'root'),
                    'size': rule.get('size', 0),
                    'estimated_rules': rule.get('estimated_rules', 0)
                })
            
            pages = (total + per_page - 1) // per_page if total > 0 else 0
            
            return jsonify({
                'rules': rules_page,
                'pagination': {
                    'page': page,
                    'per_page': per_page,
                    'total': total,
                    'pages': pages,
                    'has_prev': page > 1,
                    'has_next': end < total
                }
            })
            
        except Exception as e:
            print(f"Error fetching rules from containerized service: {e}")
            return jsonify({
                'error': f'Error communicating with YARA service: {str(e)}',
                'rules': [],
                'pagination': {
                    'page': 1, 'per_page': 20, 'total': 0, 'pages': 0,
                    'has_prev': False, 'has_next': False
                }
            }), 503
        
    except Exception as e:
        print(f"API rules error: {e}")
        return jsonify({
            'error': str(e),
            'rules': [],
            'pagination': {
                'page': 1, 'per_page': 20, 'total': 0, 'pages': 0,
                'has_prev': False, 'has_next': False
            }
        }), 500


@rules_bp.route('/content/<path:rule_path>')
def get_rule_content(rule_path):
    """Get rule content for viewing/editing via containerized service"""
    try:
        yara_manager = get_yara_manager()
        if not yara_manager or not yara_manager.is_available():
            return jsonify({'error': 'YARA service not available'}), 503
        
        try:
            content = yara_manager.get_rule_content(rule_path)
            
            # Get additional file info from filesystem if possible
            full_path = os.path.join(Config.RULES_FOLDER, rule_path)
            file_size = 0
            if os.path.exists(full_path):
                file_size = os.path.getsize(full_path)
            
            return jsonify({
                'content': content,
                'size': file_size,
                'path': rule_path
            })
            
        except FileNotFoundError:
            return jsonify({'error': 'Rule file not found'}), 404
        except ValueError:
            return jsonify({'error': 'Invalid rule path'}), 400
        except Exception as e:
            return jsonify({'error': f'Error retrieving rule: {str(e)}'}), 500
        
    except Exception as e:
        print(f"Rule content error: {e}")
        return jsonify({'error': str(e)}), 500


@rules_bp.route('/directories')
def get_directories():
    """Get available rule directories via containerized service"""
    try:
        yara_manager = get_yara_manager()
        if not yara_manager or not yara_manager.is_available():
            return jsonify(['root'])
        
        try:
            directories = yara_manager.get_directories()
            return jsonify(directories)
        except Exception as e:
            print(f"Error getting directories from YARA service: {e}")
            # Fallback to filesystem scan
            return _get_directories_from_filesystem()
        
    except Exception as e:
        print(f"Error getting directories: {e}")
        return jsonify(['root'])


def _get_directories_from_filesystem():
    """Fallback method to get directories directly from filesystem"""
    try:
        rule_files = glob.glob(os.path.join(Config.RULES_FOLDER, "**", "*.yar"), recursive=True) + \
                    glob.glob(os.path.join(Config.RULES_FOLDER, "**", "*.yara"), recursive=True)
        
        directories = set()
        for rule_file in rule_files:
            try:
                rel_path = os.path.relpath(rule_file, Config.RULES_FOLDER)
                directory = os.path.dirname(rel_path) if os.path.dirname(rel_path) else 'root'
                directories.add(directory)
            except Exception:
                continue
        
        return jsonify(sorted(list(directories)) if directories else ['root'])
    except Exception as e:
        print(f"Filesystem fallback error: {e}")
        return jsonify(['root'])


@rules_bp.route('/debug')
def debug_rules():
    """Debug endpoint to see containerized YARA service status"""
    try:
        yara_manager = get_yara_manager()
        
        debug_info = {
            'service_available': False,
            'service_status': 'not_initialized',
            'rules_folder': Config.RULES_FOLDER
        }
        
        if yara_manager:
            debug_info['service_available'] = yara_manager.is_available()
            debug_info['service_status'] = yara_manager.get_service_status()
            debug_info['yara_url'] = yara_manager.yara_url
            
            if yara_manager.is_available():
                stats = yara_manager.get_rule_stats()
                debug_info['stats'] = stats
        
        # Also check filesystem
        rule_files = glob.glob(os.path.join(Config.RULES_FOLDER, "**", "*.yar"), recursive=True) + \
                    glob.glob(os.path.join(Config.RULES_FOLDER, "**", "*.yara"), recursive=True)
        
        fs_directories = set()
        for rule_file in rule_files:
            rel_path = os.path.relpath(rule_file, Config.RULES_FOLDER)
            directory = os.path.dirname(rel_path) if os.path.dirname(rel_path) else 'root'
            fs_directories.add(directory)
        
        debug_info.update({
            'filesystem_directories': sorted(list(fs_directories)),
            'total_files_found': len(rule_files)
        })
        
        return jsonify(debug_info)
        
    except Exception as e:
        return jsonify({'error': str(e)})


@rules_bp.route('/test')
def test_rules_api():
    """Simple test endpoint for containerized rules API"""
    try:
        yara_manager = get_yara_manager()
        
        test_info = {
            'status': 'ok',
            'rules_folder': Config.RULES_FOLDER,
            'timestamp': datetime.now().isoformat(),
            'service_type': 'containerized'
        }
        
        if yara_manager:
            test_info['yara_service_available'] = yara_manager.is_available()
            test_info['yara_url'] = yara_manager.yara_url
        
        return jsonify(test_info)
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e),
            'service_type': 'containerized'
        }), 500


@rules_bp.route('/stats')
def get_rules_statistics():
    """Get YARA rules statistics from containerized service"""
    try:
        yara_manager = get_yara_manager()
        if not yara_manager or not yara_manager.is_available():
            return jsonify({
                'success': False,
                'error': 'YARA service not available'
            }), 503
        
        stats = yara_manager.get_rule_stats()
        
        return jsonify({
            'success': True,
            'statistics': stats,
            'service_type': 'containerized'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@rules_bp.route('/reload', methods=['POST'])
def reload_rules():
    """Reload YARA rules in the containerized service"""
    try:
        yara_manager = get_yara_manager()
        if not yara_manager or not yara_manager.is_available():
            return jsonify({
                'success': False,
                'error': 'YARA service not available'
            }), 503
        
        success = yara_manager.reload_rules()
        
        if success:
            stats = yara_manager.get_rule_stats()
            return jsonify({
                'success': True,
                'message': 'YARA rules reloaded successfully in containerized service',
                'statistics': stats
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to reload rules in YARA service'
            }), 500
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@rules_bp.route('/validate', methods=['POST'])
def validate_rule():
    """Validate a YARA rule (local validation since it doesn't require full compilation)"""
    try:
        data = request.get_json()
        if not data or 'content' not in data:
            return jsonify({'valid': False, 'error': 'No rule content provided'}), 400
        
        content = data['content']
        
        validation_result = {
            'valid': False,
            'errors': [],
            'warnings': []
        }
        
        try:
            # Basic validation using YARA (this doesn't require the full rule database)
            import yara
            yara.compile(source=content)
            validation_result['valid'] = True
        except Exception as e:
            validation_result['errors'].append(f"YARA compilation error: {str(e)}")
        
        return jsonify({
            'success': True,
            'validation': validation_result,
            'service_type': 'containerized'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@rules_bp.route('/search')
def search_rules():
    """Search YARA rules (basic implementation)"""
    try:
        query = request.args.get('q', '')
        search_type = request.args.get('type', 'all')
        limit = min(request.args.get('limit', 50, type=int), 100)
        
        if not query:
            return jsonify({'error': 'Search query required'}), 400
        
        yara_manager = get_yara_manager()
        if not yara_manager or not yara_manager.is_available():
            return jsonify({
                'success': False,
                'error': 'YARA service not available'
            }), 503
        
        # Use the YARA manager's search functionality
        search_results = yara_manager.search_rules(query, search_type, limit)
        
        return jsonify({
            'success': True,
            'query': query,
            'search_type': search_type,
            'results': search_results,
            'total_found': len(search_results),
            'service_type': 'containerized'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@rules_bp.route('/service-status')
def get_service_status():
    """Get detailed status of the containerized YARA service"""
    try:
        yara_manager = get_yara_manager()
        
        if not yara_manager:
            return jsonify({
                'service_type': 'containerized',
                'status': 'not_initialized',
                'available': False
            })
        
        service_status = yara_manager.get_service_status()
        service_status['service_type'] = 'containerized'
        service_status['manager_available'] = yara_manager.is_available()
        
        return jsonify(service_status)
        
    except Exception as e:
        return jsonify({
            'service_type': 'containerized',
            'status': 'error',
            'error': str(e),
            'available': False
        }), 500