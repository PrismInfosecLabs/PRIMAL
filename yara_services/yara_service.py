#!/usr/bin/env python3
"""
YARA Microservice
Provides YARA rule compilation and scanning as a containerized service
"""

import os
import json
import time
import traceback
from datetime import datetime
from flask import Flask, request, jsonify, send_file
from werkzeug.exceptions import RequestEntityTooLarge
import tempfile
import logging
from logging.handlers import RotatingFileHandler

# Import the existing YaraManager from the new location
from yara_services.yara_manager import YaraManager

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

# Initialize YARA manager
RULES_FOLDER = '/app/rules'
yara_manager = None
initialization_start_time = None
initialization_status = "initializing"
initialization_error = None

def setup_yara_logging():
    os.makedirs('/app/logs', exist_ok=True)
    
    handler = RotatingFileHandler(
        '/app/logs/yara_service.log',
        maxBytes=5242880,
        backupCount=3
    )
    handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    
    logging.basicConfig(level=logging.INFO, handlers=[handler])

def initialize_yara_manager():
    """Initialize YARA manager with error handling"""
    global yara_manager, initialization_status, initialization_error
    
    print(f"[YARA SERVICE] Starting YARA manager initialization...")
    print(f"[YARA SERVICE] Rules folder: {RULES_FOLDER}")
    print(f"[YARA SERVICE] Rules folder exists: {os.path.exists(RULES_FOLDER)}")
    
    try:
        # Ensure rules directory exists
        os.makedirs(RULES_FOLDER, exist_ok=True)
        
        # Initialize YARA manager
        yara_manager = YaraManager(RULES_FOLDER)
        
        # Get initial stats
        stats = yara_manager.get_rule_stats()
        print(f"[YARA SERVICE] ? Initialized successfully!")
        print(f"[YARA SERVICE] Loaded {stats.get('total_files', 0)} rule files")
        print(f"[YARA SERVICE] Skipped {stats.get('skipped_files', 0)} files")
        print(f"[YARA SERVICE] Directories: {list(stats.get('by_directory', {}).keys())}")
        
        initialization_status = "ready"
        return True
        
    except Exception as e:
        error_msg = f"Failed to initialize YARA manager: {str(e)}"
        print(f"[YARA SERVICE] ? {error_msg}")
        print(f"[YARA SERVICE] Traceback: {traceback.format_exc()}")
        
        initialization_status = "error" 
        initialization_error = error_msg
        return False

@app.route('/health')
def health_check():
    """Health check endpoint for container orchestration"""
    uptime = time.time() - initialization_start_time if initialization_start_time else 0
    
    health_data = {
        'status': initialization_status,
        'service': 'yara-scanner',
        'timestamp': datetime.now().isoformat(),
        'uptime_seconds': round(uptime, 2)
    }
    
    if initialization_status == "ready" and yara_manager:
        stats = yara_manager.get_rule_stats()
        health_data.update({
            'rules_loaded': stats.get('total_files', 0),
            'rules_skipped': stats.get('skipped_files', 0),
            'directories': len(stats.get('by_directory', {}))
        })
        return jsonify(health_data), 200
        
    elif initialization_status == "error":
        health_data['error'] = initialization_error
        return jsonify(health_data), 503
        
    else:  # initializing
        return jsonify(health_data), 503

@app.route('/scan', methods=['POST'])
def scan_file():
    """
    Scan a file with YARA rules
    Expects either file upload or file path
    """
    if initialization_status != "ready":
        return jsonify({
            'success': False,
            'error': f'Service not ready (status: {initialization_status})',
            'status': initialization_status
        }), 503
    
    try:
        file_path = None
        temp_file = None
        
        # Check if file was uploaded
        if 'file' in request.files:
            uploaded_file = request.files['file']
            if uploaded_file.filename == '':
                return jsonify({'success': False, 'error': 'No file selected'}), 400
            
            # Save uploaded file to temporary location
            temp_file = tempfile.NamedTemporaryFile(delete=False)
            uploaded_file.save(temp_file.name)
            file_path = temp_file.name
            
        # Check if file path was provided
        elif 'file_path' in request.form:
            file_path = request.form['file_path']
            if not os.path.exists(file_path):
                return jsonify({'success': False, 'error': 'File not found'}), 404
                
        # Check if file path was provided in JSON
        elif request.is_json:
            data = request.get_json()
            if 'file_path' in data:
                file_path = data['file_path']
                if not os.path.exists(file_path):
                    return jsonify({'success': False, 'error': 'File not found'}), 404
        
        if not file_path:
            return jsonify({'success': False, 'error': 'No file provided'}), 400
        
        print(f"[YARA SERVICE] Scanning file: {file_path}")
        
        # Perform YARA scan
        scan_start = time.time()
        matches = yara_manager.scan_file(file_path)
        scan_time = time.time() - scan_start
        
        print(f"[YARA SERVICE] Scan completed in {scan_time:.2f}s, found {len(matches)} matches")
        
        # Clean up temporary file if created
        if temp_file:
            try:
                os.unlink(temp_file.name)
            except:
                pass
        
        return jsonify({
            'success': True,
            'matches': matches,
            'scan_time': round(scan_time, 3),
            'total_matches': len(matches),
            'timestamp': datetime.now().isoformat()
        })
        
    except RequestEntityTooLarge:
        return jsonify({'success': False, 'error': 'File too large'}), 413
        
    except Exception as e:
        print(f"[YARA SERVICE] Scan error: {str(e)}")
        print(f"[YARA SERVICE] Traceback: {traceback.format_exc()}")
        
        # Clean up temp file on error
        if temp_file:
            try:
                os.unlink(temp_file.name)
            except:
                pass
        
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/rules/stats')
def get_rule_stats():
    """Get YARA rules statistics"""
    if initialization_status != "ready":
        return jsonify({
            'success': False,
            'error': f'Service not ready (status: {initialization_status})'
        }), 503
    
    try:
        stats = yara_manager.get_rule_stats()
        return jsonify({
            'success': True,
            'statistics': stats
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/rules/list')
def list_rules():
    """List all rule files with details"""
    if initialization_status != "ready":
        return jsonify({
            'success': False,
            'error': f'Service not ready (status: {initialization_status})'
        }), 503
    
    try:
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)
        search = request.args.get('search', '', type=str).lower()
        directory = request.args.get('directory', '', type=str)
        
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
        rules_page = all_rules[start:end]
        pages = (total + per_page - 1) // per_page if total > 0 else 0
        
        return jsonify({
            'success': True,
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
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/rules/content/<path:rule_path>')
def get_rule_content(rule_path):
    """Get rule content for viewing"""
    if initialization_status != "ready":
        return jsonify({
            'success': False,
            'error': f'Service not ready (status: {initialization_status})'
        }), 503
    
    try:
        content = yara_manager.get_rule_content(rule_path)
        full_path = os.path.join(RULES_FOLDER, rule_path)
        
        return jsonify({
            'success': True,
            'content': content,
            'size': os.path.getsize(full_path),
            'path': rule_path
        })
        
    except FileNotFoundError:
        return jsonify({'success': False, 'error': 'Rule file not found'}), 404
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/rules/directories')
def get_directories():
    """Get available rule directories"""
    if initialization_status != "ready":
        return jsonify({
            'success': False,
            'error': f'Service not ready (status: {initialization_status})'
        }), 503
    
    try:
        directories = yara_manager.get_directories()
        return jsonify({
            'success': True,
            'directories': directories
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/rules/reload', methods=['POST'])
def reload_rules():
    """Reload all YARA rules"""
    if initialization_status != "ready":
        return jsonify({
            'success': False,
            'error': f'Service not ready (status: {initialization_status})'
        }), 503
    
    try:
        print("[YARA SERVICE] Reloading YARA rules...")
        reload_start = time.time()
        
        yara_manager.reload_rules()
        
        reload_time = time.time() - reload_start
        stats = yara_manager.get_rule_stats()
        
        print(f"[YARA SERVICE] Rules reloaded in {reload_time:.2f}s")
        
        return jsonify({
            'success': True,
            'message': 'YARA rules reloaded successfully',
            'reload_time': round(reload_time, 3),
            'statistics': stats
        })
        
    except Exception as e:
        print(f"[YARA SERVICE] Reload error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/status')
def get_status():
    """Get detailed service status"""
    uptime = time.time() - initialization_start_time if initialization_start_time else 0
    
    status_info = {
        'service': 'yara-scanner',
        'status': initialization_status,
        'uptime_seconds': round(uptime, 2),
        'timestamp': datetime.now().isoformat(),
        'rules_folder': RULES_FOLDER
    }
    
    if initialization_status == "ready" and yara_manager:
        stats = yara_manager.get_rule_stats()
        status_info.update({
            'yara_available': yara_manager.is_available(),
            'rules_loaded': stats.get('total_files', 0),
            'rules_skipped': stats.get('skipped_files', 0),
            'directories': stats.get('by_directory', {}),
            'total_directories': len(stats.get('by_directory', {}))
        })
    elif initialization_status == "error":
        status_info['error'] = initialization_error
    
    return jsonify(status_info)

@app.errorhandler(413)
def file_too_large(e):
    """Handle file too large errors"""
    return jsonify({'success': False, 'error': 'File too large (max 100MB)'}), 413

@app.errorhandler(500)
def internal_error(e):
    """Handle internal server errors"""
    return jsonify({'success': False, 'error': 'Internal server error'}), 500

def main():
    """Main entry point"""
    global initialization_start_time
    
    print("[YARA SERVICE] Starting YARA microservice...")
    print(f"[YARA SERVICE] Python path: {os.sys.path}")
    
    initialization_start_time = time.time()
    
    # Initialize YARA manager in background
    if initialize_yara_manager():
        print("[YARA SERVICE] ? Ready to serve requests")
    else:
        print("[YARA SERVICE] ? Failed initialization, but starting server anyway")
    
    setup_yara_logging()

    # Start Flask server
    port = int(os.environ.get('YARA_PORT', 5001))
    host = os.environ.get('YARA_HOST', '0.0.0.0')
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    print(f"[YARA SERVICE] Starting server on {host}:{port}")
    app.run(host=host, port=port, debug=debug)

if __name__ == '__main__':
    main()