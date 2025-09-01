"""
Reports API Routes
Handles report generation, listing, and download endpoints
"""

import os
import json
from datetime import datetime
from flask import Blueprint, request, jsonify, send_from_directory
from config import Config
from services import ReportGenerator

# Create blueprint for reports routes
reports_bp = Blueprint('reports', __name__, url_prefix='/api/reports')

# Initialize services
report_generator = ReportGenerator()


@reports_bp.route('/generate', methods=['POST'])
def generate_report():
    """Generate comprehensive analysis report using service"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No request data provided'}), 400
            
        report_type = data.get('type', 'summary')
        date_from = data.get('date_from', '')
        date_to = data.get('date_to', '')
        file_ids = data.get('file_ids', [])
        
        # Generate report using service
        report = report_generator.generate_report(
            report_type, date_from, date_to, file_ids
        )
        
        # Save report using service
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"malware_analysis_report_{report_type}_{timestamp}.json"
        
        save_result = report_generator.save_report(
            report, filename, Config.REPORTS_FOLDER
        )
        
        if save_result['success']:
            return jsonify({
                'success': True,
                'report': report,
                'filename': filename,
                'download_url': f'/api/reports/download/{filename}'
            })
        else:
            return jsonify({'error': save_result['error']}), 500
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@reports_bp.route('/download/<filename>')
def download_report(filename):
    """Download generated report"""
    try:
        return send_from_directory(Config.REPORTS_FOLDER, filename, as_attachment=True)
    except Exception as e:
        return jsonify({'error': str(e)}), 404


@reports_bp.route('/list')
def list_reports():
    """List available reports"""
    try:
        reports = []
        
        if not os.path.exists(Config.REPORTS_FOLDER):
            os.makedirs(Config.REPORTS_FOLDER, exist_ok=True)
            
        for filename in os.listdir(Config.REPORTS_FOLDER):
            if filename.endswith('.json'):
                filepath = os.path.join(Config.REPORTS_FOLDER, filename)
                stat = os.stat(filepath)
                reports.append({
                    'filename': filename,
                    'size': stat.st_size,
                    'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                    'download_url': f'/api/reports/download/{filename}'
                })
        
        reports.sort(key=lambda x: x['created'], reverse=True)
        return jsonify(reports)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@reports_bp.route('/types')
def get_report_types():
    """Get available report types"""
    try:
        report_types = {
            'summary': {
                'name': 'Summary Report',
                'description': 'High-level overview of analysis results',
                'includes': ['file_count', 'threat_summary', 'detection_rates']
            },
            'detailed': {
                'name': 'Detailed Report', 
                'description': 'Comprehensive analysis with full details',
                'includes': ['all_results', 'yara_matches', 'av_details', 'strings_analysis']
            },
            'threats': {
                'name': 'Threats Report',
                'description': 'Focus on detected threats and malware',
                'includes': ['threat_analysis', 'iocs', 'risk_assessment']
            }
        }
        
        return jsonify({
            'success': True,
            'report_types': report_types
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@reports_bp.route('/template/<report_type>')
def get_report_template(report_type):
    """Get template structure for a report type"""
    try:
        template = report_generator.get_report_template(report_type)
        
        if not template:
            return jsonify({'error': 'Invalid report type'}), 400
        
        return jsonify({
            'success': True,
            'template': template,
            'report_type': report_type
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@reports_bp.route('/delete/<filename>', methods=['DELETE'])
def delete_report(filename):
    """Delete a generated report"""
    try:
        filepath = os.path.join(Config.REPORTS_FOLDER, filename)
        
        # Security check - ensure file is in reports folder
        if not os.path.commonpath([Config.REPORTS_FOLDER, filepath]) == Config.REPORTS_FOLDER:
            return jsonify({'error': 'Invalid file path'}), 400
        
        if not os.path.exists(filepath):
            return jsonify({'error': 'Report not found'}), 404
        
        os.remove(filepath)
        
        return jsonify({
            'success': True,
            'message': f'Report {filename} deleted successfully'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@reports_bp.route('/statistics')
def get_report_statistics():
    """Get report generation statistics"""
    try:
        stats = report_generator.get_report_statistics()
        
        return jsonify({
            'success': True,
            'statistics': stats
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500