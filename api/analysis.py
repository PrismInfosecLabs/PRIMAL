"""
Analysis API Routes
Handles file analysis, scanning, and analysis status endpoints
"""

import json
from datetime import datetime
from flask import Blueprint, request, jsonify
from config import Config, get_db_connection
from services import MalwareAnalyzer

# Create blueprint for analysis routes
analysis_bp = Blueprint('analysis', __name__, url_prefix='/api/analysis')

# Initialize services
analyzer = MalwareAnalyzer()


@analysis_bp.route('/status/<int:file_id>')
def check_analysis_status(file_id):
    """Check the status of submitted analyses"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get AV results with submitted status
        cursor.execute('''
            SELECT engine_name, status, scan_id, data_id, analysis_url, created_at
            FROM av_results 
            WHERE file_id = ? AND status = 'submitted'
            ORDER BY created_at DESC
        ''', (file_id,))
        
        submitted_analyses = cursor.fetchall()
        conn.close()
        
        status_info = []
        for analysis in submitted_analyses:
            status_info.append({
                'engine': analysis['engine_name'],
                'status': analysis['status'],
                'scan_id': analysis['scan_id'],
                'data_id': analysis['data_id'],
                'analysis_url': analysis['analysis_url'],
                'submitted_at': analysis['created_at']
            })
        
        return jsonify({
            'file_id': file_id,
            'submitted_analyses': status_info,
            'total_submitted': len(status_info)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@analysis_bp.route('/update/<int:file_id>', methods=['POST'])
def update_submitted_analyses(file_id):
    """Update analysis results for submitted files - Enhanced with better error handling"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get submitted analyses for this file
        cursor.execute('''
            SELECT id, engine_name, scan_id, data_id
            FROM av_results 
            WHERE file_id = ? AND status = 'submitted'
        ''', (file_id,))
        
        submitted_analyses = cursor.fetchall()
        
        # Always return a valid response structure, even if no submissions
        if not submitted_analyses:
            conn.close()
            return jsonify({
                'file_id': file_id,
                'updated_count': 0,
                'updates': [],
                'message': 'No submitted analyses found for this file'
            }), 200
        
        updated_count = 0
        updates = []
        
        for analysis_row in submitted_analyses:
            analysis_id = analysis_row['id']
            engine_name = analysis_row['engine_name']
            scan_id = analysis_row['scan_id']
            data_id = analysis_row['data_id']
            result = None
            
            try:
                if engine_name == 'VirusTotal' and scan_id:
                    result = analyzer.av_scanner.check_virustotal_result(scan_id)
                elif engine_name == 'MetaDefender' and data_id:
                    result = analyzer.av_scanner.check_metadefender_result(data_id)
                elif engine_name == 'Hybrid Analysis' and scan_id:
                    result = analyzer.av_scanner.check_hybrid_analysis_result(scan_id, data_id)
                
                if result and result.get('status') in ['infected', 'clean']:
                    # Update the database with new results
                    cursor.execute('''
                        UPDATE av_results 
                        SET status = ?, result = ?, threat_name = ?, detections = ?, 
                            total_engines = ?, threat_score = ?, raw_output = ?
                        WHERE id = ?
                    ''', (
                        result['status'],
                        result['result'],
                        result.get('threat_name'),
                        result.get('detections', 0),
                        result.get('total_engines', 1),
                        result.get('threat_score'),
                        json.dumps(result.get('raw_output', {})),
                        analysis_id
                    ))
                    
                    updated_count += 1
                    updates.append({
                        'engine': engine_name,
                        'status': result['status'],
                        'result': result['result'],
                        'threat_score': result.get('threat_score'),
                        'detections': result.get('detections', 0)
                    })
                elif result and result.get('status') == 'pending':
                    updates.append({
                        'engine': engine_name,
                        'status': 'pending',
                        'message': result.get('message', 'Still in progress')
                    })
                elif result and result.get('status') == 'error':
                    updates.append({
                        'engine': engine_name,
                        'status': 'error',
                        'message': result.get('message', 'Error checking result')
                    })
                else:
                    updates.append({
                        'engine': engine_name,
                        'status': 'pending',
                        'message': 'Analysis status unknown or still in progress'
                    })
                    
            except Exception as check_error:
                print(f"Error checking {engine_name} result: {check_error}")
                updates.append({
                    'engine': engine_name,
                    'status': 'error',
                    'message': f'Check failed: {str(check_error)}'
                })
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'file_id': file_id,
            'updated_count': updated_count,
            'updates': updates,
            'message': f'Checked {len(submitted_analyses)} submission(s), updated {updated_count} result(s)'
        })
        
    except Exception as e:
        print(f"Error in update_submitted_analyses: {e}")
        return jsonify({
            'file_id': file_id,
            'updated_count': 0,
            'updates': [],
            'error': str(e)
        }), 500


@analysis_bp.route('/scan/<int:file_id>', methods=['POST'])
def rescan_file(file_id):
    """Rescan file using service"""
    try:
        # Get scan types from request
        data = request.get_json() or {}
        scan_types = data.get('scan_types', ['av'])  # Default to AV rescan
        
        # Rescan using analyzer service
        result = analyzer.rescan_file(file_id, scan_types)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@analysis_bp.route('/strings/<int:file_id>')
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


@analysis_bp.route('/results/<int:file_id>')
def get_analysis_results(file_id):
    """Get comprehensive analysis results for a file"""
    try:
        # Use the service to get complete analysis data
        analysis_data = analyzer.get_analysis_results(file_id)
        
        if not analysis_data:
            return jsonify({'error': 'File not found'}), 404
        
        return jsonify({
            'success': True,
            'data': analysis_data
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analysis_bp.route('/rescan-yara/<int:file_id>', methods=['POST'])
def rescan_yara(file_id):
    """Rescan file with YARA rules only"""
    try:
        result = analyzer.rescan_file(file_id, scan_types=['yara'])
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@analysis_bp.route('/rescan-strings/<int:file_id>', methods=['POST'])
def rescan_strings(file_id):
    """Rescan file with string analysis only"""
    try:
        result = analyzer.rescan_file(file_id, scan_types=['strings'])
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@analysis_bp.route('/rescan-both/<int:file_id>', methods=['POST'])
def rescan_yara_and_strings(file_id):
    """Rescan file with both YARA and string analysis"""
    try:
        result = analyzer.rescan_file(file_id, scan_types=['yara', 'strings'])
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500