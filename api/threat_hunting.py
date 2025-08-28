"""
Threat Hunting API Routes
Handles web requests for threat hunting functionality
"""

import json
from flask import Blueprint, request, jsonify, Response
from services import ThreatHuntingService, MalwareAnalyzer

# Create blueprint for threat hunting routes
threat_hunting_bp = Blueprint('threat_hunting', __name__, url_prefix='/api/threat-hunting')

# Initialize services
threat_hunting_service = ThreatHuntingService()
analyzer = MalwareAnalyzer()


@threat_hunting_bp.route('/<int:file_id>')
def get_threat_hunting_data(file_id):
    """Get threat hunting data for a specific file"""
    try:
        # Get analysis data using the service
        analysis_data = analyzer.get_analysis_results(file_id)
        
        if not analysis_data:
            return jsonify({'error': 'File not found'}), 404
        
        file_data = analysis_data['file_data']
        
        # Parse the latest analysis results
        latest_analysis = {}
        if analysis_data['analysis_results']:
            try:
                latest_analysis = json.loads(analysis_data['analysis_results'][0]['result_data'])
            except (json.JSONDecodeError, KeyError, IndexError):
                latest_analysis = {}
        
        # Generate threat hunting content using the service
        threat_data = threat_hunting_service.generate_all_threat_hunting_data(
            file_data, latest_analysis
        )
        
        return jsonify({
            'success': True,
            'file_data': file_data,
            **threat_data
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@threat_hunting_bp.route('/export/<int:file_id>/<export_type>')
def export_threat_hunting(file_id, export_type):
    """Export threat hunting content in various formats"""
    try:
        # Validate export type
        valid_types = ['kql', 'yara', 'iocs_json', 'iocs_csv', 'stix', 'misp']
        if export_type not in valid_types:
            return jsonify({
                'error': f'Invalid export type. Must be one of: {", ".join(valid_types)}'
            }), 400
        
        # Get analysis data
        analysis_data = analyzer.get_analysis_results(file_id)
        if not analysis_data:
            return jsonify({'error': 'File not found'}), 404
        
        file_data = analysis_data['file_data']
        
        # Parse the latest analysis results
        latest_analysis = {}
        if analysis_data['analysis_results']:
            try:
                latest_analysis = json.loads(analysis_data['analysis_results'][0]['result_data'])
            except (json.JSONDecodeError, KeyError, IndexError):
                latest_analysis = {}
        
        # Export using the service
        export_data = threat_hunting_service.export_threat_hunting_content(
            file_data, latest_analysis, export_type
        )
        
        # Create response with file download
        response = Response(export_data['content'], mimetype=export_data['mimetype'])
        response.headers['Content-Disposition'] = f'attachment; filename="{export_data["filename"]}"'
        return response
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@threat_hunting_bp.route('/bulk-export', methods=['POST'])
def bulk_export_threat_hunting():
    """Export threat hunting data for multiple files"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No request data provided'}), 400
        
        file_ids = data.get('file_ids', [])
        export_type = data.get('export_type', 'kql')
        
        if not file_ids:
            return jsonify({'error': 'No file IDs provided'}), 400
        
        if not isinstance(file_ids, list):
            return jsonify({'error': 'file_ids must be a list'}), 400
        
        # Validate export type
        valid_types = ['kql', 'yara', 'iocs_json', 'iocs_csv', 'stix', 'misp']
        if export_type not in valid_types:
            return jsonify({
                'error': f'Invalid export type. Must be one of: {", ".join(valid_types)}'
            }), 400
        
        # Generate threat hunting data for all files
        all_exports = []
        
        for file_id in file_ids[:50]:  # Limit to 50 files to prevent abuse
            try:
                # Get analysis data
                analysis_data = analyzer.get_analysis_results(file_id)
                if not analysis_data:
                    continue
                
                file_data = analysis_data['file_data']
                
                # Parse analysis results
                latest_analysis = {}
                if analysis_data['analysis_results']:
                    try:
                        latest_analysis = json.loads(analysis_data['analysis_results'][0]['result_data'])
                    except:
                        latest_analysis = {}
                
                # Generate export data
                export_data = threat_hunting_service.export_threat_hunting_content(
                    file_data, latest_analysis, export_type
                )
                
                all_exports.append({
                    'filename': file_data['filename'],
                    'file_id': file_id,
                    'content': export_data['content'],
                    'export_filename': export_data['filename']
                })
                
            except Exception as e:
                # Log error but continue with other files
                print(f"Error exporting file {file_id}: {e}")
                continue
        
        if not all_exports:
            return jsonify({'error': 'No files could be exported'}), 404
        
        # Combine all exports into a single file
        if export_type in ['kql', 'yara']:
            # Text-based formats - concatenate with separators
            combined_content = []
            for export in all_exports:
                combined_content.append(f"// ========== {export['filename']} ==========")
                combined_content.append(export['content'])
                combined_content.append("")  # Empty line separator
            
            final_content = '\n'.join(combined_content)
            mimetype = 'text/plain'
            filename = f"bulk_export_{export_type}_{len(all_exports)}_files.txt"
            
        elif export_type in ['iocs_json', 'stix', 'misp']:
            # JSON formats - create array or combined structure
            combined_data = []
            for export in all_exports:
                try:
                    export_json = json.loads(export['content'])
                    export_json['source_filename'] = export['filename']
                    combined_data.append(export_json)
                except:
                    continue
            
            final_content = json.dumps({
                'bulk_export': True,
                'export_type': export_type,
                'total_files': len(combined_data),
                'data': combined_data
            }, indent=2)
            mimetype = 'application/json'
            filename = f"bulk_export_{export_type}_{len(combined_data)}_files.json"
            
        elif export_type == 'iocs_csv':
            # CSV format - combine all CSV data
            csv_lines = ['indicator_type,indicator_value,category,confidence,source_file']
            
            for export in all_exports:
                lines = export['content'].split('\n')[1:]  # Skip header
                for line in lines:
                    if line.strip():
                        csv_lines.append(f"{line},{export['filename']}")
            
            final_content = '\n'.join(csv_lines)
            mimetype = 'text/csv'
            filename = f"bulk_export_iocs_{len(all_exports)}_files.csv"
        
        # Create response
        response = Response(final_content, mimetype=mimetype)
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@threat_hunting_bp.route('/templates')
def get_threat_hunting_templates():
    """Get available threat hunting templates and examples"""
    try:
        templates = {
            'kql_examples': {
                'file_hash_hunt': 'DeviceFileEvents | where SHA256 == "hash_here"',
                'network_hunt': 'DeviceNetworkEvents | where RemoteUrl contains "domain_here"',
                'process_hunt': 'DeviceProcessEvents | where ProcessCommandLine contains "suspicious_string"'
            },
            'yara_patterns': {
                'basic_structure': '''rule RuleName {
    meta:
        description = "Rule description"
        author = "Your name"
    
    strings:
        $string1 = "suspicious_string"
        $hex1 = { 48 65 6C 6C 6F }
    
    condition:
        any of them
}''',
                'malware_detection': '''rule MalwareFamily {
    meta:
        description = "Detects malware family"
    
    strings:
        $api1 = "CreateRemoteThread"
        $api2 = "VirtualAllocEx"
        $pattern = /http:\/\/[a-z0-9.-]+\.[a-z]{2,4}\/[a-z0-9]/
    
    condition:
        2 of ($api*) and $pattern
}'''
            },
            'ioc_formats': {
                'supported_formats': ['json', 'csv', 'stix', 'misp'],
                'csv_columns': ['indicator_type', 'indicator_value', 'category', 'confidence'],
                'json_structure': {
                    'metadata': {'generated_at': 'timestamp', 'source': 'lab'},
                    'indicators': {'file_indicators': {}, 'network_indicators': {}}
                }
            }
        }
        
        return jsonify({
            'success': True,
            'templates': templates
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@threat_hunting_bp.route('/statistics')
def get_threat_hunting_statistics():
    """Get threat hunting usage statistics"""
    try:
        # This could be enhanced to track actual usage statistics
        # For now, return basic statistics from the database
        
        stats = {
            'available_exports': ['kql', 'yara', 'iocs_json', 'iocs_csv', 'stix', 'misp'],
            'supported_platforms': ['Microsoft Defender', 'Splunk', 'YARA', 'MISP', 'STIX'],
            'total_exportable_files': analyzer.get_analysis_stats()['total_files'],
            'features': {
                'kql_generation': True,
                'yara_rule_generation': True,
                'ioc_extraction': True,
                'bulk_export': True,
                'multiple_formats': True
            }
        }
        
        return jsonify({
            'success': True,
            'statistics': stats
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@threat_hunting_bp.route('/validate', methods=['POST'])
def validate_threat_hunting_data():
    """Validate threat hunting rules or queries"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No request data provided'}), 400
        
        validation_type = data.get('type')  # 'yara', 'kql', 'ioc'
        content = data.get('content', '')
        
        if not validation_type or not content:
            return jsonify({'error': 'Missing type or content'}), 400
        
        validation_result = {
            'valid': False,
            'errors': [],
            'warnings': []
        }
        
        if validation_type == 'yara':
            # Basic YARA rule validation
            try:
                import yara
                # Try to compile the rule
                yara.compile(source=content)
                validation_result['valid'] = True
            except Exception as e:
                validation_result['errors'].append(f"YARA compilation error: {str(e)}")
        
        elif validation_type == 'kql':
            # Basic KQL validation (syntax checking)
            kql_keywords = [
                'where', 'project', 'extend', 'summarize', 'order', 'take', 'limit',
                'join', 'union', 'let', 'and', 'or', 'not', 'contains', 'startswith'
            ]
            
            if any(keyword in content.lower() for keyword in kql_keywords):
                validation_result['valid'] = True
            else:
                validation_result['warnings'].append("Query may not contain valid KQL keywords")
        
        elif validation_type == 'ioc':
            # Basic IOC format validation
            try:
                if content.startswith('{') and content.endswith('}'):
                    # JSON format
                    json.loads(content)
                    validation_result['valid'] = True
                elif ',' in content and '\n' in content:
                    # CSV format - basic check
                    lines = content.strip().split('\n')
                    if len(lines) > 1 and all(',' in line for line in lines[1:]):
                        validation_result['valid'] = True
                    else:
                        validation_result['errors'].append("Invalid CSV format")
                else:
                    validation_result['errors'].append("Unrecognized IOC format")
            except json.JSONDecodeError as e:
                validation_result['errors'].append(f"JSON parsing error: {str(e)}")
        
        else:
            return jsonify({'error': 'Invalid validation type'}), 400
        
        return jsonify({
            'success': True,
            'validation': validation_result
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500