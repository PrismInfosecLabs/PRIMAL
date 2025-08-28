"""
File Management API Routes
Handles file upload, listing, deletion, and basic file operations
"""

import os
import json
import traceback
from flask import Blueprint, request, jsonify
from config import Config, get_db_connection
from services import MalwareAnalyzer

# Create blueprint for file management routes
files_bp = Blueprint('files', __name__, url_prefix='/api/files')

# Initialize services
analyzer = MalwareAnalyzer()


@files_bp.route('/upload', methods=['POST'])
def upload_file():
    """Enhanced file upload with better error handling and validation"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not file:
        return jsonify({'error': 'Invalid file'}), 400
    
    try:
        filename = file.filename
        
        # Basic file validation
        if len(filename) > 255:
            return jsonify({'error': 'Filename too long'}), 400
        
        # Check file size (limit to 100MB)
        file.seek(0, 2)  # Seek to end
        file_size = file.tell()
        file.seek(0)  # Reset to beginning
        
        if file_size > 100 * 1024 * 1024:  # 100MB
            return jsonify({'error': 'File too large (maximum 100MB)'}), 400
        
        if file_size == 0:
            return jsonify({'error': 'File is empty'}), 400
        
        # Save file with unique name if duplicate
        base_name, ext = os.path.splitext(filename)
        counter = 1
        unique_filename = filename
        
        while os.path.exists(os.path.join(Config.UPLOAD_FOLDER, unique_filename)):
            unique_filename = f"{base_name}_{counter}{ext}"
            counter += 1
        
        file_path = os.path.join(Config.UPLOAD_FOLDER, unique_filename)
        file.save(file_path)
        
        # Analyze the file using the service
        try:
            results = analyzer.analyze_file(file_path, unique_filename)
        except Exception as e:
            traceback.print_exc()
            return jsonify({'error': f'Analysis failed: {str(e)}'}), 500   
     
        if results['success']:
            return jsonify({
                'success': True,
                'file_id': results['file_id'],
                'results': results['results'],
                'filename': unique_filename
            })
        else:
            # Clean up file if analysis failed
            try:
                os.remove(file_path)
            except:
                pass
            return jsonify({'error': results['error']}), 500
            
    except Exception as e:
        # Clean up file if upload failed
        try:
            if 'file_path' in locals():
                os.remove(file_path)
        except:
            pass
        return jsonify({'error': f'Upload failed: {str(e)}'}), 500


@files_bp.route('/')
def list_files():
    """List recent files with enhanced data"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT f.id, f.filename, f.sha256, f.size, f.upload_time, f.status,
                   COUNT(DISTINCT ym.id) as yara_match_count,
                   COUNT(DISTINCT CASE WHEN av.status = 'infected' THEN av.id END) as av_detections,
                   COUNT(DISTINCT es.id) as interesting_strings
            FROM files f 
            LEFT JOIN yara_matches ym ON f.id = ym.file_id
            LEFT JOIN av_results av ON f.id = av.file_id
            LEFT JOIN extracted_strings es ON f.id = es.file_id
            GROUP BY f.id, f.filename, f.sha256, f.size, f.upload_time, f.status
            ORDER BY f.upload_time DESC 
            LIMIT 20
        ''')
        
        files = cursor.fetchall()
        conn.close()
        
        file_list = []
        for file in files:
            file_list.append({
                'id': file['id'],
                'filename': file['filename'],
                'sha256': file['sha256'][:16] + '...',  # Truncated for display
                'size': file['size'],
                'upload_time': file['upload_time'],
                'status': file['status'],
                'yara_matches': int(file['yara_match_count'] or 0),
                'av_detections': int(file['av_detections'] or 0),
                'interesting_strings': int(file['interesting_strings'] or 0)
            })
        
        return jsonify(file_list)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@files_bp.route('/browse')
def browse_files():
    """API endpoint for browsing files with pagination and filtering"""
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 100)
    search = request.args.get('search', '', type=str)
    status_filter = request.args.get('status', 'all', type=str)
    threat_filter = request.args.get('threat', 'all', type=str)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Build WHERE clause for files table only
        where_conditions = []
        params = []
        
        if search:
            where_conditions.append("(filename LIKE ? OR sha256 LIKE ?)")
            params.extend([f'%{search}%', f'%{search}%'])
        
        if status_filter != 'all':
            where_conditions.append("status = ?")
            params.append(status_filter)
        
        where_clause = ""
        if where_conditions:
            where_clause = "WHERE " + " AND ".join(where_conditions)
        
        # Get total count
        cursor.execute(f'SELECT COUNT(*) FROM files {where_clause}', params)
        total = cursor.fetchone()['COUNT(*)']
        
        # Get files first, then get stats separately
        offset = (page - 1) * per_page
        cursor.execute(f'''
            SELECT * FROM files 
            {where_clause}
            ORDER BY upload_time DESC
            LIMIT ? OFFSET ?
        ''', params + [per_page, offset])
        
        files = cursor.fetchall()
        
        # Format results and get stats for each file
        file_list = []
        for file in files:
            # Get YARA matches count
            cursor.execute('SELECT COUNT(*) FROM yara_matches WHERE file_id = ?', (file['id'],))
            yara_count = cursor.fetchone()['COUNT(*)'] or 0
            
            # Get AV detections count
            cursor.execute("SELECT COUNT(*) FROM av_results WHERE file_id = ? AND status = 'infected'", (file['id'],))
            av_count = cursor.fetchone()['COUNT(*)'] or 0
            
            # Get extracted strings count
            cursor.execute('SELECT COUNT(*) FROM extracted_strings WHERE file_id = ?', (file['id'],))
            strings_count = cursor.fetchone()['COUNT(*)'] or 0
            
            # Apply threat filter
            if threat_filter == 'infected' and av_count == 0:
                continue
            elif threat_filter == 'clean' and av_count > 0:
                continue
            
            threat_level = 'High' if av_count > 0 else 'Medium' if yara_count > 0 else 'Low'
            
            file_list.append({
                'id': file['id'],
                'filename': file['filename'],
                'sha256': file['sha256'],
                'sha256_short': file['sha256'][:16] + '...',
                'md5': file['md5'],
                'size': file['size'],
                'file_type': file['file_type'],
                'upload_time': file['upload_time'],
                'status': file['status'],
                'yara_matches': yara_count,
                'av_detections': av_count,
                'extracted_strings': strings_count,
                'threat_level': threat_level
            })
        
        # Calculate pagination info
        pages = (total + per_page - 1) // per_page
        
        return jsonify({
            'files': file_list,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total,
                'pages': pages,
                'has_prev': page > 1,
                'has_next': page < pages
            }
        })
        
    finally:
        conn.close()

@files_bp.route('/delete/<int:file_id>', methods=['DELETE'])
def delete_file(file_id):
    """Delete a file and all its analysis data using service"""
    try:
        result = analyzer.delete_file_analysis(file_id)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@files_bp.route('/list')
def list_all_files():
    """List all files with detailed information for selection"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT f.id, f.filename, f.sha256, f.md5, f.size, f.file_type, f.upload_time, f.status,
                   COUNT(DISTINCT ym.id) as yara_matches,
                   COUNT(DISTINCT CASE WHEN av.status = 'infected' THEN av.id END) as av_detections,
                   COUNT(DISTINCT es.id) as extracted_strings
            FROM files f 
            LEFT JOIN yara_matches ym ON f.id = ym.file_id
            LEFT JOIN av_results av ON f.id = av.file_id
            LEFT JOIN extracted_strings es ON f.id = es.file_id
            GROUP BY f.id
            ORDER BY f.upload_time DESC
        ''')
        
        files = cursor.fetchall()
        conn.close()
        
        file_list = []
        for file in files:
            file_list.append({
                'id': file['id'],
                'filename': file['filename'],
                'sha256': file['sha256'],
                'sha256_short': file['sha256'][:16] + '...',
                'md5': file['md5'],
                'size': file['size'],
                'file_type': file['file_type'],
                'upload_time': file['upload_time'],
                'status': file['status'],
                'yara_matches': int(file['yara_matches'] or 0),
                'av_detections': int(file['av_detections'] or 0),
                'extracted_strings': int(file['extracted_strings'] or 0),
                'threat_level': 'High' if int(file['av_detections'] or 0) > 0 else 'Medium' if int(file['yara_matches'] or 0) > 0 else 'Low'
            })
        
        return jsonify(file_list)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@files_bp.route('/<int:file_id>/av_results')
def get_file_av_results(file_id):
    """Get detailed AV results for a specific file"""
    try:
        # Use the service to get analysis results
        analysis_data = analyzer.get_analysis_results(file_id)
        
        if not analysis_data:
            return jsonify({'error': 'File not found'}), 404
        
        # Format AV results from the service response
        av_results = []
        for av_result in analysis_data['av_results']:
            av_info = {
                'engine': av_result['engine_name'],
                'status': av_result['status'],
                'result': av_result['result'],
                'threat_name': av_result['threat_name'],
                'scan_time': av_result['scan_time'],
                'detections': av_result['detections'],
                'total_engines': av_result['total_engines'],
                'threat_score': av_result['threat_score'],
                'scan_id': av_result['scan_id'],
                'data_id': av_result['data_id'],
                'analysis_url': av_result['analysis_url'],
                'permalink': av_result['permalink'],
                'created_at': av_result['created_at']
            }
            
            # Parse JSON fields if present
            for json_field in ['engine_details', 'metadata', 'raw_output']:
                if json_field in av_result and av_result[json_field]:
                    try:
                        av_info[json_field] = json.loads(av_result[json_field]) if isinstance(av_result[json_field], str) else av_result[json_field]
                    except (json.JSONDecodeError, TypeError):
                        av_info[json_field] = av_result[json_field]
            
            av_results.append(av_info)
        
        return jsonify(av_results)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@files_bp.route('/<int:file_id>/strings')
def get_file_strings(file_id):
    """Get extracted strings for a file"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT string_value, string_type, category, context
            FROM extracted_strings 
            WHERE file_id = ?
            ORDER BY string_type, category
        ''', (file_id,))
        
        strings = cursor.fetchall()
        conn.close()
        
        # Group by type and category
        grouped = {}
        for string_result in strings:
            string_val = string_result['string_value']
            string_type = string_result['string_type']
            category = string_result['category']
            context = string_result['context']
            
            if string_type not in grouped:
                grouped[string_type] = {}
            if category not in grouped[string_type]:
                grouped[string_type][category] = []
            
            grouped[string_type][category].append({
                'value': string_val,
                'context': context
            })
        
        return jsonify(grouped)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@files_bp.route('/<int:file_id>/details')
def get_file_details(file_id):
    """Get complete file details and analysis results"""
    try:
        analysis_data = analyzer.get_analysis_results(file_id)
        
        if not analysis_data:
            return jsonify({'error': 'File not found'}), 404
        
        return jsonify({
            'success': True,
            'data': analysis_data
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@files_bp.route('/stats')
def get_files_statistics():
    """Get file management statistics"""
    try:
        stats = analyzer.get_analysis_stats()
        
        return jsonify({
            'success': True,
            'statistics': stats
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@files_bp.route('/validate', methods=['POST'])
def validate_file_upload():
    """Validate a file before upload (useful for large files)"""
    try:
        if 'file' not in request.files:
            return jsonify({'valid': False, 'error': 'No file provided'}), 400
        
        file = request.files['file']
        
        # Check file size without fully uploading
        file.seek(0, 2)
        file_size = file.tell()
        file.seek(0)
        
        validation_result = {
            'valid': True,
            'filename': file.filename,
            'size': file_size,
            'warnings': [],
            'errors': []
        }
        
        # Validation checks
        if file_size == 0:
            validation_result['valid'] = False
            validation_result['errors'].append('File is empty')
        
        if file_size > 100 * 1024 * 1024:
            validation_result['valid'] = False
            validation_result['errors'].append('File too large (maximum 100MB)')
        
        if len(file.filename) > 255:
            validation_result['valid'] = False
            validation_result['errors'].append('Filename too long')
        
        # Warning for large files
        if file_size > 50 * 1024 * 1024:
            validation_result['warnings'].append('Large file - analysis may take several minutes')
        
        return jsonify(validation_result)
        
    except Exception as e:
        return jsonify({'valid': False, 'error': str(e)}), 500


@files_bp.route('/bulk-delete', methods=['POST'])
def bulk_delete_files():
    """Delete multiple files at once"""
    try:
        data = request.get_json()
        if not data or 'file_ids' not in data:
            return jsonify({'error': 'No file IDs provided'}), 400
        
        file_ids = data['file_ids']
        if not isinstance(file_ids, list):
            return jsonify({'error': 'file_ids must be a list'}), 400
        
        results = {
            'deleted': [],
            'failed': [],
            'total_requested': len(file_ids)
        }
        
        for file_id in file_ids:
            try:
                delete_result = analyzer.delete_file_analysis(file_id)
                if delete_result['success']:
                    results['deleted'].append(file_id)
                else:
                    results['failed'].append({'file_id': file_id, 'error': delete_result.get('error', 'Unknown error')})
            except Exception as e:
                results['failed'].append({'file_id': file_id, 'error': str(e)})
        
        return jsonify({
            'success': True,
            'results': results,
            'message': f"Deleted {len(results['deleted'])} files, {len(results['failed'])} failed"
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@files_bp.route('/search')
def search_files():
    """Search files by various criteria"""
    try:
        query = request.args.get('q', '')
        search_type = request.args.get('type', 'all')  # 'filename', 'hash', 'threat', 'all'
        limit = min(request.args.get('limit', 50, type=int), 100)
        
        if not query:
            return jsonify({'error': 'Search query required'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Build search query based on type
        if search_type == 'filename':
            where_clause = "WHERE f.filename LIKE ?"
            params = [f'%{query}%']
        elif search_type == 'hash':
            where_clause = "WHERE f.sha256 LIKE ? OR f.md5 LIKE ?"
            params = [f'%{query}%', f'%{query}%']
        elif search_type == 'threat':
            where_clause = """WHERE EXISTS (
                SELECT 1 FROM av_results av 
                WHERE av.file_id = f.id AND av.threat_name LIKE ?
            )"""
            params = [f'%{query}%']
        else:  # 'all'
            where_clause = """WHERE (
                f.filename LIKE ? OR f.sha256 LIKE ? OR f.md5 LIKE ? OR
                EXISTS (SELECT 1 FROM av_results av WHERE av.file_id = f.id AND av.threat_name LIKE ?)
            )"""
            params = [f'%{query}%', f'%{query}%', f'%{query}%', f'%{query}%']
        
        cursor.execute(f'''
            SELECT f.id, f.filename, f.sha256, f.md5, f.size, f.file_type, f.upload_time, f.status,
                   COUNT(DISTINCT ym.id) as yara_matches,
                   COUNT(DISTINCT CASE WHEN av.status = 'infected' THEN av.id END) as av_detections
            FROM files f 
            LEFT JOIN yara_matches ym ON f.id = ym.file_id
            LEFT JOIN av_results av ON f.id = av.file_id
            {where_clause}
            GROUP BY f.id
            ORDER BY f.upload_time DESC
            LIMIT ?
        ''', params + [limit])
        
        files = cursor.fetchall()
        conn.close()
        
        file_list = []
        for file in files:
            file_list.append({
                'id': file['id'],
                'filename': file['filename'],
                'sha256_short': file['sha256'][:16] + '...',
                'size': file['size'],
                'file_type': file['file_type'],
                'upload_time': file['upload_time'],
                'yara_matches': int(file['yara_matches'] or 0),
                'av_detections': int(file['av_detections'] or 0),
                'threat_level': 'High' if int(file['av_detections'] or 0) > 0 else 'Low'
            })
        
        return jsonify({
            'success': True,
            'query': query,
            'search_type': search_type,
            'results': file_list,
            'total_found': len(file_list)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500