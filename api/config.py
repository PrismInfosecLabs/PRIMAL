"""
Configuration API Routes
Handles string analysis configuration and other system settings
"""

import re
import json
from datetime import datetime
from flask import Blueprint, request, jsonify, Response
from config import Config
from services import MalwareAnalyzer

# Create blueprint for configuration routes
config_bp = Blueprint('config', __name__, url_prefix='/api/config')

# Initialize services
analyzer = MalwareAnalyzer()


@config_bp.route('/string-config', methods=['GET'])
def get_string_config():
    """Get current string analysis configuration"""
    try:
        # Use the service to get current configuration
        if hasattr(analyzer, 'string_extractor'):
            config_data = analyzer.string_extractor.get_config()
        else:
            # Fallback to default config
            config_data = Config.DEFAULT_STRING_CONFIG
        
        return jsonify({
            'success': True,
            'config': config_data
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@config_bp.route('/string-config', methods=['POST'])
def update_string_config():
    """Update string analysis configuration"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        # Validate configuration using service
        if hasattr(analyzer, 'string_extractor'):
            validation_result = analyzer.string_extractor.validate_config(data)
            
            if not validation_result['valid']:
                return jsonify({
                    'success': False, 
                    'error': 'Configuration validation failed',
                    'validation_errors': validation_result.get('errors', [])
                }), 400
            
            # Save configuration using service
            if analyzer.string_extractor.update_config(data):
                return jsonify({
                    'success': True,
                    'message': 'Configuration updated successfully'
                })
            else:
                return jsonify({
                    'success': False,
                    'error': 'Failed to save configuration'
                }), 500
        else:
            return jsonify({
                'success': False,
                'error': 'String extractor not available'
            }), 500
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@config_bp.route('/string-config/reset', methods=['POST'])
def reset_string_config():
    """Reset string analysis configuration to defaults"""
    try:
        # Reset configuration using service
        if hasattr(analyzer, 'string_extractor'):
            if analyzer.string_extractor.reset_config():
                return jsonify({
                    'success': True,
                    'message': 'Configuration reset to defaults',
                    'config': Config.DEFAULT_STRING_CONFIG
                })
            else:
                return jsonify({
                    'success': False,
                    'error': 'Failed to reset configuration'
                }), 500
        else:
            return jsonify({
                'success': False,
                'error': 'String extractor not available'
            }), 500
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@config_bp.route('/string-config/test', methods=['POST'])
def test_string_config():
    """Test regex patterns in configuration"""
    try:
        data = request.get_json()
        test_string = data.get('test_string', '')
        patterns = data.get('patterns', {})
        
        if not test_string:
            return jsonify({'success': False, 'error': 'No test string provided'}), 400
        
        results = {}
        for pattern_name, pattern_config in patterns.items():
            try:
                flags = 0
                for flag in pattern_config.get('flags', []):
                    if hasattr(re, flag):
                        flags |= getattr(re, flag)
                
                pattern = re.compile(pattern_config['pattern'], flags)
                matches = pattern.findall(test_string)
                
                results[pattern_name] = {
                    'matches': matches,
                    'count': len(matches),
                    'valid': True
                }
            except re.error as e:
                results[pattern_name] = {
                    'matches': [],
                    'count': 0,
                    'valid': False,
                    'error': str(e)
                }
        
        return jsonify({
            'success': True,
            'results': results,
            'test_string': test_string
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@config_bp.route('/string-config/backup')
def backup_string_config():
    """Create backup of current configuration"""
    try:
        # Get current configuration
        if hasattr(analyzer, 'string_extractor'):
            config_data = analyzer.string_extractor.get_config()
        else:
            config_data = Config.DEFAULT_STRING_CONFIG
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'string_analysis_config_backup_{timestamp}.json'
        
        response = Response(
            json.dumps(config_data, indent=2),
            mimetype='application/json'
        )
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@config_bp.route('/string-config/validate', methods=['POST'])
def validate_string_config():
    """Validate string configuration without saving"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        # Validate using service
        if hasattr(analyzer, 'string_extractor'):
            validation_result = analyzer.string_extractor.validate_config(data)
            
            return jsonify({
                'success': True,
                'validation': validation_result
            })
        else:
            # Basic validation fallback
            validation_result = {
                'valid': True,
                'errors': [],
                'warnings': []
            }
            
            # Basic checks
            if 'extraction_config' not in data:
                validation_result['valid'] = False
                validation_result['errors'].append('Missing extraction_config section')
            
            if 'patterns' not in data:
                validation_result['valid'] = False
                validation_result['errors'].append('Missing patterns section')
            
            return jsonify({
                'success': True,
                'validation': validation_result
            })
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@config_bp.route('/system')
def get_system_config():
    """Get system configuration settings"""
    try:
        # Get relevant system config that can be exposed via API
        system_config = {
            'upload_folder': Config.UPLOAD_FOLDER,
            'rules_folder': Config.RULES_FOLDER,
            'reports_folder': Config.REPORTS_FOLDER,
            'max_file_size': '100MB',
            'supported_file_types': ['*'],  # All file types supported
            'enabled_features': {
                'yara_scanning': True,
                'av_scanning': True,
                'string_extraction': True,
                'threat_hunting': True,
                'reporting': True
            }
        }
        
        return jsonify({
            'success': True,
            'config': system_config
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@config_bp.route('/av-config', methods=['GET'])
def get_av_config():
    """Get current AV configuration"""
    try:
        # Get AV configuration from service
        if hasattr(analyzer, 'av_scanner'):
            av_config = analyzer.av_scanner.get_engine_info()
            
            return jsonify({
                'success': True,
                'engines': av_config
            })
        else:
            return jsonify({
                'success': False,
                'error': 'AV scanner not available'
            }), 500
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@config_bp.route('/av-config', methods=['POST'])
def update_av_config():
    """Update AV configuration"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        # Update AV configuration using service
        if hasattr(analyzer, 'av_scanner'):
            result = analyzer.av_scanner.update_config(data)
            
            if result.get('success', True):
                return jsonify({
                    'success': True,
                    'message': 'AV configuration updated successfully'
                })
            else:
                return jsonify({
                    'success': False,
                    'error': result.get('error', 'Failed to update configuration')
                }), 500
        else:
            return jsonify({
                'success': False,
                'error': 'AV scanner not available'
            }), 500
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500