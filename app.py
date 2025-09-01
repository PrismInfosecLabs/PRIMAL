import json
import os
import sys
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash

def setup_logging(app):
    """Configure application logging"""
    if not app.debug:  # Only in production
        # Ensure logs directory exists
        logs_dir = '/app/logs'
        os.makedirs(logs_dir, exist_ok=True)
        
        # Main application log
        file_handler = RotatingFileHandler(
            os.path.join(logs_dir, 'malware_analyzer.log'),
            maxBytes=10240000,  # 10MB
            backupCount=10
        )
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        
        # Analysis-specific log
        analysis_handler = RotatingFileHandler(
            os.path.join(logs_dir, 'analysis.log'),
            maxBytes=5242880,  # 5MB
            backupCount=5
        )
        analysis_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))
        analysis_handler.setLevel(logging.INFO)
        
        # Create analysis logger
        analysis_logger = logging.getLogger('analysis')
        analysis_logger.addHandler(analysis_handler)
        analysis_logger.setLevel(logging.INFO)
        
        app.logger.setLevel(logging.INFO)
        app.logger.info('Malware analyzer startup')

def ensure_directories_with_debug():
    """Ensure all required directories exist with detailed debugging"""
    directories = [
        '/app/data',
        '/app/uploads',
        '/app/reports',
        '/app/rules',
        '/app/logs'
    ]
    
    print("=== Directory Setup Debug ===")
    print(f"Running as user: {os.getuid() if hasattr(os, 'getuid') else 'unknown'}")
    print(f"Working directory: {os.getcwd()}")
    
    for directory in directories:
        try:
            # Create directory if it doesn't exist
            if not os.path.exists(directory):
                print(f"Creating directory: {directory}")
                os.makedirs(directory, exist_ok=True)
            else:
                print(f"Directory exists: {directory}")
            
            # Check permissions
            if os.path.exists(directory):
                stat_info = os.stat(directory)
                print(f"Directory {directory} - Mode: {oct(stat_info.st_mode)}, Owner: {stat_info.st_uid}")
                
                # Test write permissions
                test_file = os.path.join(directory, '.write_test')
                try:
                    with open(test_file, 'w') as f:
                        f.write('test')
                    os.remove(test_file)
                    print(f"? {directory} is writable")
                except Exception as write_error:
                    print(f"? Cannot write to {directory}: {write_error}")
                    # Try to fix permissions
                    try:
                        os.chmod(directory, 0o755)
                        print(f"Fixed permissions for {directory}")
                    except Exception as chmod_error:
                        print(f"Cannot fix permissions for {directory}: {chmod_error}")
                        
        except Exception as e:
            print(f"? Error with directory {directory}: {e}")
            sys.exit(1)
    
    print("=== Directory Setup Complete ===")

# CRITICAL: Set up directories BEFORE any imports that might use them
ensure_directories_with_debug()

# Import configuration modules
from config import (
    Config, 
    EnvironmentConfig, 
    config_manager,
    load_config, 
    save_config,
    get_db_connection,
    init_database
)

# Import service modules
from services import (
    MalwareAnalyzer,
    AntivirusScanner,
    ReportGenerator,
    ThreatHuntingService
)

# Import API blueprints
from api.files import files_bp
from api.analysis import analysis_bp
from api.reports import reports_bp
from api.rules import rules_bp
from api.containers import containers_bp
from api.config import config_bp
from api.threat_hunting import threat_hunting_bp

app = Flask(__name__)

# Configure Flask using the configuration system
flask_config = EnvironmentConfig.get_flask_config()
app.secret_key = flask_config['SECRET_KEY']
app.config.update(flask_config)

# Ensure directories exist
Config.ensure_directories()

# Initialize database - This should now work with proper lazy loading
print("Initializing database...")
try:
    init_database()
    print("? Database initialized successfully")
except Exception as db_error:
    print(f"? Database initialization failed: {db_error}")
    sys.exit(1)

# Initialize services
print("Initializing services...")
analyzer = MalwareAnalyzer()
av_scanner = AntivirusScanner()
report_generator = ReportGenerator()
threat_hunting_service = ThreatHuntingService()

# Register API blueprints
app.register_blueprint(files_bp)
app.register_blueprint(analysis_bp)
app.register_blueprint(reports_bp)
app.register_blueprint(rules_bp)
app.register_blueprint(containers_bp)
app.register_blueprint(config_bp)
app.register_blueprint(threat_hunting_bp)

# =============================================================================
# PAGE ROUTES (Non-API)
# =============================================================================

@app.route('/')
def index():
    """Main landing page"""
    return render_template('index.html')


@app.route('/browse')
def browse_results():
    """Browse all stored analysis results page"""
    return render_template('browse.html')


@app.route('/results/<int:file_id>')
def get_results(file_id):
    """Enhanced results page with stored data retrieval"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get file info
    cursor.execute('SELECT * FROM files WHERE id = ?', (file_id,))
    file_result = cursor.fetchone()
    
    if not file_result:
        conn.close()
        return "File not found", 404
    
    # Get analysis results
    cursor.execute('SELECT result_data FROM analysis_results WHERE file_id = ? ORDER BY created_at DESC LIMIT 1', (file_id,))
    analysis_result = cursor.fetchone()
    
    # Get YARA matches
    cursor.execute('''
        SELECT rule_name, namespace, meta_data, string_matches
        FROM yara_matches 
        WHERE file_id = ?
        ORDER BY created_at DESC
    ''', (file_id,))
    yara_matches = cursor.fetchall()
    
    # Get AV results with enhanced data
    cursor.execute('''
        SELECT engine_name, status, result, threat_name, scan_time, detections, 
               total_engines, threat_score, scan_id, data_id, analysis_url, 
               permalink, engine_details, metadata, created_at
        FROM av_results 
        WHERE file_id = ?
        ORDER BY created_at DESC
    ''', (file_id,))
    av_results = cursor.fetchall()
    
    # Get extracted strings summary
    cursor.execute('''
        SELECT string_type, category, COUNT(*) as count
        FROM extracted_strings 
        WHERE file_id = ?
        GROUP BY string_type, category
        ORDER BY count DESC
    ''', (file_id,))
    strings_summary = cursor.fetchall()
    
    conn.close()
    
    # Format file data
    file_data = {
        'id': file_result['id'],
        'filename': file_result['filename'],
        'sha256': file_result['sha256'],
        'sha1': file_result['sha1'],  # Ensure SHA1 is included
        'md5': file_result['md5'],
        'size': file_result['size'],
        'file_type': file_result['file_type'],
        'upload_time': file_result['upload_time'],
        'status': file_result['status']
    }
    
    # Format analysis data - Enhanced to ensure entropy is available
    analysis_data = {}
    if analysis_result and analysis_result['result_data']:
        try:
            analysis_data = json.loads(analysis_result['result_data'])
            # Debug print to ensure entropy analysis is present
            if 'entropy_analysis' in analysis_data:
                print(f"DEBUG: Entropy analysis found for file {file_id}: {analysis_data['entropy_analysis'].get('overall_entropy', 'N/A')}")
            else:
                print(f"DEBUG: No entropy analysis found for file {file_id}")
        except json.JSONDecodeError as e:
            print(f"DEBUG: Failed to parse analysis data for file {file_id}: {e}")
            analysis_data = {}
    else:
        print(f"DEBUG: No analysis result data found for file {file_id}")
    
    # Format YARA matches
    yara_data = []
    for match in yara_matches:
        yara_data.append({
            'rule': match['rule_name'],
            'namespace': match['namespace'],
            'meta': json.loads(match['meta_data']) if match['meta_data'] else {},
            'strings': json.loads(match['string_matches']) if match['string_matches'] else []
        })
    
    # Format AV results
    av_data = []
    for av in av_results:
        av_info = {
            'engine': av['engine_name'],
            'status': av['status'],
            'result': av['result'],
            'threat_name': av['threat_name'],
            'scan_time': av['scan_time'],
            'detections': av['detections'],
            'total_engines': av['total_engines'],
            'threat_score': av['threat_score'],
            'scan_id': av['scan_id'],
            'data_id': av['data_id'],
            'analysis_url': av['analysis_url'],
            'permalink': av['permalink'],
            'created_at': av['created_at']
        }
        
        # Parse additional data
        if av['engine_details']:
            try:
                av_info['engine_details'] = json.loads(av['engine_details'])
            except:
                pass
        
        if av['metadata']:
            try:
                av_info['metadata'] = json.loads(av['metadata'])
            except:
                pass
        
        av_data.append(av_info)
    
    # Format strings summary
    strings_data = []
    for string_info in strings_summary:
        strings_data.append({
            'type': string_info['string_type'],
            'category': string_info['category'],
            'count': string_info['count']
        })
    
    return render_template('enhanced_results.html', 
                         file_data=file_data,
                         analysis_data=analysis_data,
                         yara_matches=yara_data,
                         av_results=av_data,
                         strings_summary=strings_data)


@app.route('/rules')
def manage_rules():
    """YARA rules management page with pagination and search"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('search', '', type=str)
    directory = request.args.get('directory', '', type=str)
    
    rule_stats = analyzer.yara_manager.get_rule_stats()
    
    return render_template('rules.html', 
                         stats=rule_stats,
                         page=page,
                         per_page=per_page,
                         search=search,
                         directory=directory)


@app.route('/rules/reload', methods=['POST'])
def reload_rules():
    """Reload all YARA rules"""
    try:
        analyzer.yara_manager.reload_rules()
        stats = analyzer.yara_manager.get_rule_stats()
        
        message = f"? YARA rules reloaded successfully!"
        message += f" {stats.get('total_files', 0)} files loaded"
        if stats.get('skipped_files', 0) > 0:
            message += f", {stats.get('skipped_files', 0)} skipped"
        message += f" from {len(stats.get('by_directory', {}))} directories."
        
        flash(message)
    except Exception as e:
        flash(f'? Error reloading YARA rules: {str(e)}')
    
    return redirect(url_for('manage_rules'))


@app.route('/rules/upload', methods=['POST'])
def upload_rule():
    """Upload new YARA rule with optional subdirectory"""
    if 'rule_file' not in request.files:
        flash('? No rule file provided')
        return redirect(url_for('manage_rules'))
    
    file = request.files['rule_file']
    subdirectory = request.form.get('subdirectory', '').strip()
    
    if file.filename == '':
        flash('? No file selected')
        return redirect(url_for('manage_rules'))
    
    if file and (file.filename.endswith('.yar') or file.filename.endswith('.yara')):
        filename = file.filename
        
        # Handle subdirectory
        if subdirectory:
            # Sanitize subdirectory path
            subdirectory = subdirectory.replace('..', '').replace('/', os.sep).replace('\\', os.sep)
            target_dir = os.path.join(Config.RULES_FOLDER, subdirectory)
            os.makedirs(target_dir, exist_ok=True)
            file_path = os.path.join(target_dir, filename)
        else:
            file_path = os.path.join(Config.RULES_FOLDER, filename)
        
        try:
            file.save(file_path)
            
            # Reload YARA rules
            analyzer.yara_manager.reload_rules()
            
            location = f" in {subdirectory}/" if subdirectory else ""
            flash(f'? Rule {filename} uploaded successfully{location}')
        except Exception as e:
            flash(f'? Error uploading rule: {str(e)}')
    else:
        flash('? Please upload a .yar or .yara file')
    
    return redirect(url_for('manage_rules'))


@app.route('/av')
def manage_av():
    """AV engines management page with container support"""
    engines = av_scanner.get_engine_info()
    config = load_config()
    return render_template('av.html', engines=engines, config=config)


@app.route('/av/configure', methods=['POST'])
def configure_av():
    """Configure AV engines"""
    try:
        config = load_config()
        
        # Update API keys
        for key in ['virustotal_api_key', 'metadefender_api_key', 'hybrid_analysis_api_key']:
            if key in request.form and request.form[key].strip():
                config[key] = request.form[key].strip()
        
        # Update enabled engines
        for engine_id in ['clamav', 'virustotal', 'hybrid_analysis', 'metadefender']:
            config['enabled_engines'][engine_id] = f'{engine_id}_enabled' in request.form
        
        # Save configuration
        av_scanner.update_config(config)
        analyzer.update_config(config)
        
        flash('? AV configuration updated successfully!')
        
    except Exception as e:
        flash(f'? Error updating configuration: {str(e)}')
    
    return redirect(url_for('manage_av'))


@app.route('/av/update', methods=['POST'])
def update_av_signatures():
    """Update AV signatures"""
    engine = request.form.get('engine', 'clamav')
    
    try:
        if engine == 'clamav':
            # For containerized ClamAV, call the container's update endpoint
            if hasattr(analyzer, 'av_scanner') and hasattr(analyzer.av_scanner, 'update_container_signatures'):
                result = analyzer.av_scanner.update_container_signatures('clamav')
                
                if result.get('success'):
                    flash(f'?? ClamAV signatures updated successfully')
                else:
                    flash(f'? Failed to update ClamAV signatures: {result.get("error")}')
            else:
                # Fallback: try direct API call to container
                try:
                    import requests
                    clamav_url = os.environ.get('CLAMAV_URL', 'http://clamav-scanner:5000')
                    response = requests.post(f'{clamav_url}/update', timeout=300)
                    
                    if response.status_code == 200:
                        result = response.json()
                        if result.get('success'):
                            flash(f'?? ClamAV signatures updated successfully')
                        else:
                            flash(f'? Failed to update signatures: {result.get("error")}')
                    else:
                        flash(f'? Update request failed: HTTP {response.status_code}')
                        
                except Exception as api_error:
                    flash(f'? Error calling ClamAV container: {str(api_error)}')
        else:
            flash(f'?? {engine.upper()} signatures are updated automatically via API')
            
    except Exception as e:
        flash(f'? Error updating {engine.upper()}: {str(e)}')
    
    return redirect(url_for('manage_av'))


@app.route('/reports')
def reports_page():
    """Reports management page"""
    return render_template('reports.html')


@app.route('/threat-hunting')
def threat_hunting_page():
    """Threat hunting and IOC generation page"""
    return render_template('threat_hunting.html')


@app.route('/string-config')
def string_config_page():
    """String analysis configuration management page"""
    return render_template('string_config.html')

@app.route('/containers')
def containers_page():
    """Container monitoring dashboard"""
    return render_template('containers.html')
# =============================================================================
# DEBUG ROUTES (Consider moving to separate debug blueprint in future)
# =============================================================================

@app.route('/api/debug/columns')
def debug_columns():
    """Debug endpoint to check column structure"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT f.id, f.filename, f.sha256, f.md5, f.sha1, f.size, f.file_type, 
                   f.upload_time, f.status, ar.result_data,
                   COUNT(DISTINCT ym.id) as yara_matches,
                   COUNT(DISTINCT CASE WHEN av.status = 'infected' THEN av.id END) as av_detections,
                   COUNT(DISTINCT es.id) as extracted_strings
            FROM files f
            LEFT JOIN analysis_results ar ON f.id = ar.file_id AND ar.analysis_type = 'comprehensive_analysis'
            LEFT JOIN yara_matches ym ON f.id = ym.file_id
            LEFT JOIN av_results av ON f.id = av.file_id
            LEFT JOIN extracted_strings es ON f.id = es.file_id
            GROUP BY f.id, f.filename, f.sha256, f.md5, f.sha1, f.size, f.file_type, 
                     f.upload_time, f.status, ar.result_data
            ORDER BY f.upload_time DESC
            LIMIT 1
        ''')
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            # Convert Row object to dict for JSON serialization
            row_dict = dict(row)
            return jsonify({
                'columns': list(row.keys()),
                'sample_data': row_dict,
                'column_count': len(row.keys())
            })
        else:
            return jsonify({'message': 'No data found'})
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# =============================================================================
# ERROR HANDLERS
# =============================================================================

@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors"""
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    return render_template('500.html'), 500


# =============================================================================
# APPLICATION STARTUP
# =============================================================================

def create_app():
    """Application factory pattern for testing"""
    return app


if __name__ == '__main__':
    # Development server configuration
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    port = int(os.environ.get('FLASK_PORT', 8080))
    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    setup_logging(app)
    print(f"Starting Flask app on {host}:{port} (debug={debug_mode})")
    app.run(host=host, port=port, debug=debug_mode)