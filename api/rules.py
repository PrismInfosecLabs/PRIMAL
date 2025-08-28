"""
YARA Rules API Routes
Handles YARA rule management, listing, and content retrieval
"""

import os
import glob
from datetime import datetime
from flask import Blueprint, request, jsonify
from config import Config
from services import MalwareAnalyzer

# Create blueprint for rules routes
rules_bp = Blueprint('rules', __name__, url_prefix='/api/rules')

# Initialize services
analyzer = MalwareAnalyzer()


@rules_bp.route('/')
def list_rules():
    """Fixed API endpoint for paginated rule listing"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)
        search = request.args.get('search', '', type=str).lower()
        directory = request.args.get('directory', '', type=str)
        
        # Safety check for analyzer and yara_manager
        if not hasattr(analyzer, 'yara_manager') or not analyzer.yara_manager:
            return jsonify({
                'error': 'YARA manager not initialized',
                'rules': [],
                'pagination': {
                    'page': page, 'per_page': per_page, 'total': 0, 'pages': 0,
                    'has_prev': False, 'has_next': False
                }
            })
        
        # Get all rules safely
        try:
            all_rules = analyzer.yara_manager.list_rule_files()
        except Exception as e:
            return jsonify({
                'error': f'Error listing rules: {str(e)}',
                'rules': [],
                'pagination': {
                    'page': page, 'per_page': per_page, 'total': 0, 'pages': 0,
                    'has_prev': False, 'has_next': False
                }
            })
        
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
    """Get rule content for viewing/editing"""
    try:
        full_path = os.path.join(Config.RULES_FOLDER, rule_path)
        
        # Security check
        if not os.path.commonpath([Config.RULES_FOLDER, full_path]) == Config.RULES_FOLDER:
            return jsonify({'error': 'Invalid path'}), 400
        
        if not os.path.exists(full_path):
            return jsonify({'error': 'File not found'}), 404
        
        try:
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            return jsonify({'error': f'Cannot read file: {str(e)}'}), 500
        
        return jsonify({
            'content': content,
            'size': os.path.getsize(full_path),
            'path': rule_path
        })
        
    except Exception as e:
        print(f"Rule content error: {e}")
        return jsonify({'error': str(e)}), 500


@rules_bp.route('/directories')
def get_directories():
    """Get available rule directories"""
    try:
        # Safety fallback
        if not hasattr(analyzer, 'yara_manager') or not analyzer.yara_manager:
            return jsonify(['root'])
        
        # Get directories from filesystem directly (more reliable)
        try:
            rule_files = glob.glob(os.path.join(Config.RULES_FOLDER, "**", "*.yar"), recursive=True) + \
                        glob.glob(os.path.join(Config.RULES_FOLDER, "**", "*.yara"), recursive=True)
        except Exception as e:
            print(f"Error globbing rule files: {e}")
            return jsonify(['root'])
        
        directories = set()
        for rule_file in rule_files:
            try:
                rel_path = os.path.relpath(rule_file, Config.RULES_FOLDER)
                directory = os.path.dirname(rel_path) if os.path.dirname(rel_path) else 'root'
                directories.add(directory)
            except Exception as e:
                print(f"Error processing rule file {rule_file}: {e}")
                continue
        
        sorted_dirs = sorted(list(directories)) if directories else ['root']
        return jsonify(sorted_dirs)
        
    except Exception as e:
        print(f"Error getting directories: {e}")
        return jsonify(['root'])


@rules_bp.route('/debug')
def debug_rules():
    """Debug endpoint to see what's happening with rules"""
    try:
        # Get rule stats
        stats = analyzer.yara_manager.get_rule_stats()
        
        # Get directories from filesystem
        rule_files = glob.glob(os.path.join(Config.RULES_FOLDER, "**", "*.yar"), recursive=True) + \
                    glob.glob(os.path.join(Config.RULES_FOLDER, "**", "*.yara"), recursive=True)
        
        fs_directories = set()
        for rule_file in rule_files:
            rel_path = os.path.relpath(rule_file, Config.RULES_FOLDER)
            directory = os.path.dirname(rel_path) if os.path.dirname(rel_path) else 'root'
            fs_directories.add(directory)
        
        return jsonify({
            'stats': stats,
            'filesystem_directories': sorted(list(fs_directories)),
            'total_files_found': len(rule_files),
            'rules_folder': Config.RULES_FOLDER
        })
        
    except Exception as e:
        return jsonify({'error': str(e)})


@rules_bp.route('/test')
def test_rules_api():
    """Simple test endpoint for rules API"""
    try:
        return jsonify({
            'status': 'ok',
            'rules_folder': Config.RULES_FOLDER,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500


@rules_bp.route('/stats')
def get_rules_statistics():
    """Get YARA rules statistics"""
    try:
        stats = analyzer.yara_manager.get_rule_stats()
        
        return jsonify({
            'success': True,
            'statistics': stats
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@rules_bp.route('/validate', methods=['POST'])
def validate_rule():
    """Validate a YARA rule before upload"""
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
            import yara
            # Try to compile the rule
            yara.compile(source=content)
            validation_result['valid'] = True
        except Exception as e:
            validation_result['errors'].append(f"YARA compilation error: {str(e)}")
        
        return jsonify({
            'success': True,
            'validation': validation_result
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@rules_bp.route('/search')
def search_rules():
    """Search YARA rules by content or metadata"""
    try:
        query = request.args.get('q', '')
        search_type = request.args.get('type', 'all')  # 'content', 'filename', 'all'
        limit = min(request.args.get('limit', 50, type=int), 100)
        
        if not query:
            return jsonify({'error': 'Search query required'}), 400
        
        # Use the YARA manager's search functionality
        search_results = analyzer.yara_manager.search_rules(query, search_type, limit)
        
        return jsonify({
            'success': True,
            'query': query,
            'search_type': search_type,
            'results': search_results,
            'total_found': len(search_results)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500