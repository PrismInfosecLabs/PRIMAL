"""
Antivirus Scanner Service
Coordinates antivirus scanning across multiple engines and provides unified interface
"""

import time
import hashlib
import requests
import subprocess
from urllib.parse import urljoin
from config import load_config, save_config
from av_services.container_manager import ContainerAVManager


class AntivirusScanner:
    """
    Coordinates antivirus scanning across multiple engines
    Wraps ContainerAVManager and provides additional scanning logic
    """
    
    def __init__(self, config=None):
        self.config = config or load_config()
        self.container_manager = ContainerAVManager(self.config)
        
        # Legacy engines configuration (for backwards compatibility)
        self.engines = {
            'clamav': {
                'name': 'ClamAV',
                'enabled': self.config['enabled_engines'].get('clamav', True),
                'type': 'container',
                'available': False
            },
            'virustotal': {
                'name': 'VirusTotal',
                'enabled': self.config['enabled_engines'].get('virustotal', True),
                'type': 'api',
                'api_key': self.config.get('virustotal_api_key', ''),
                'available': False
            },
            'hybrid_analysis': {
                'name': 'Hybrid Analysis',
                'enabled': self.config['enabled_engines'].get('hybrid_analysis', True),
                'type': 'api',
                'api_key': self.config.get('hybrid_analysis_api_key', ''),
                'available': False
            },
            'metadefender': {
                'name': 'MetaDefender',
                'enabled': self.config['enabled_engines'].get('metadefender', True),
                'type': 'api',
                'api_key': self.config.get('metadefender_api_key', ''),
                'available': False
            }
        }
        
        self.initialize_engines()
    
    def initialize_engines(self):
        """Initialize and check available AV engines"""
        print("Initializing antivirus engines...")
        
        # Use container manager's initialization
        self.container_manager.initialize_engines()
        
        # Update our engines status from container manager
        all_engines_info = self.container_manager.get_engine_info()
        for engine_id, engine_info in all_engines_info.items():
            if engine_id in self.engines:
                self.engines[engine_id]['available'] = engine_info['available']
                self.engines[engine_id]['version'] = engine_info.get('version', 'Unknown')
    
    def scan_file(self, file_path, engines_to_use=None):
        """
        Scan file with specified AV engines
        
        Args:
            file_path (str): Path to file to scan
            engines_to_use (list): List of engine IDs to use, or None for all available
            
        Returns:
            dict: Scan results from all engines
        """
        print(f"Starting AV scan of {file_path}")
        
        # Use container manager for actual scanning
        results = self.container_manager.scan_file(file_path, engines_to_use)
        
        # Add any additional processing or validation here
        processed_results = self._process_scan_results(results)
        
        print(f"AV scan completed. {len(processed_results)} engines scanned")
        return processed_results
    
    def _process_scan_results(self, results):
        """Process and validate scan results"""
        processed = {}
        
        for engine_id, result in results.items():
            # Ensure consistent result structure
            processed_result = {
                'engine': result.get('engine', engine_id),
                'status': result.get('status', 'unknown'),
                'result': result.get('result', 'No result'),
                'scan_time': result.get('scan_time', 0),
                'detections': result.get('detections', 0),
                'total_engines': result.get('total_engines', 1),
            }
            
            # Copy additional fields if present
            optional_fields = [
                'threat_name', 'threat_score', 'scan_id', 'data_id', 
                'analysis_url', 'permalink', 'scan_date', 'version',
                'detection_details', 'clean_engines', 'metadata', 'raw_output'
            ]
            
            for field in optional_fields:
                if field in result:
                    processed_result[field] = result[field]
            
            processed[engine_id] = processed_result
        
        return processed
    
    def update_config(self, new_config):
        """Update scanner configuration"""
        self.config = new_config
        save_config(new_config)
        
        # Update engine enabled status
        for engine_id in self.engines:
            if engine_id in new_config['enabled_engines']:
                self.engines[engine_id]['enabled'] = new_config['enabled_engines'][engine_id]
        
        # Update container manager
        self.container_manager.update_config(new_config)
        
        # Re-initialize engines
        self.initialize_engines()
        
        print("AV scanner configuration updated")
    
    def get_engine_info(self):
        """Get information about available engines"""
        return self.container_manager.get_engine_info()
    
    def get_detection_summary(self, scan_results):
        """Generate summary of all detection results"""
        total_engines = len([r for r in scan_results.values() 
                           if r['status'] not in ['unavailable', 'error', 'disabled']])
        total_detections = sum(r.get('detections', 0) for r in scan_results.values())
        
        engines_detected = len([r for r in scan_results.values() if r.get('detections', 0) > 0])
        
        summary = {
            'total_engines_scanned': total_engines,
            'engines_with_detections': engines_detected,
            'total_detections': total_detections,
            'detection_rate': round((engines_detected / total_engines * 100), 1) if total_engines > 0 else 0,
            'risk_level': 'High' if engines_detected >= 2 else 'Medium' if engines_detected == 1 else 'Low'
        }
        
        return summary
    
    def rescan_file(self, file_path, engines_to_use=None):
        """
        Rescan a file with specified engines
        Alias for scan_file for clarity
        """
        return self.scan_file(file_path, engines_to_use)
    
    def check_submitted_analyses(self, scan_results):
        """
        Check status of submitted analyses (VirusTotal, Hybrid Analysis, etc.)
        
        Args:
            scan_results (dict): Previous scan results containing scan IDs
            
        Returns:
            dict: Updated results for completed analyses
        """
        updated_results = {}
        
        for engine_id, result in scan_results.items():
            if result.get('status') == 'submitted':
                
                if engine_id == 'virustotal' and result.get('scan_id'):
                    updated = self.container_manager.check_virustotal_result(result['scan_id'])
                    if updated and updated.get('status') in ['infected', 'clean']:
                        updated_results[engine_id] = updated
                
                elif engine_id == 'hybrid_analysis' and result.get('scan_id'):
                    updated = self.container_manager.check_hybrid_analysis_result(
                        result['scan_id'], result.get('sha256')
                    )
                    if updated and updated.get('status') in ['infected', 'clean']:
                        updated_results[engine_id] = updated
                
                elif engine_id == 'metadefender' and result.get('data_id'):
                    updated = self.container_manager.check_metadefender_result(result['data_id'])
                    if updated and updated.get('status') in ['infected', 'clean']:
                        updated_results[engine_id] = updated
        
        return updated_results
    
    def update_signatures(self, engine_id='clamav'):
        """Update AV signatures for specified engine"""
        try:
            if engine_id == 'clamav':
                # Update ClamAV signatures via container
                result = self.container_manager.update_container_signatures('clamav')
                
                if result.get('success'):
                    return {
                        'success': True,
                        'message': f'{engine_id.upper()} signatures updated successfully',
                        'details': result
                    }
                else:
                    return {
                        'success': False,
                        'error': result.get('error', 'Unknown error'),
                        'details': result
                    }
            else:
                return {
                    'success': False,
                    'error': f'Signature updates not supported for {engine_id}'
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': f'Update failed: {str(e)}'
            }
    
    def get_engine_statistics(self):
        """Get statistics about engine usage and performance"""
        engine_info = self.get_engine_info()
        
        stats = {
            'total_engines': len(engine_info),
            'available_engines': sum(1 for info in engine_info.values() if info['available']),
            'enabled_engines': sum(1 for info in engine_info.values() if info['enabled']),
            'container_engines': sum(1 for info in engine_info.values() if info['type'] == 'container'),
            'api_engines': sum(1 for info in engine_info.values() if info['type'] == 'api'),
            'engines_detail': engine_info
        }
        
        return stats
    
    def test_engine_connectivity(self, engine_id=None):
        """Test connectivity to specified engine or all engines"""
        if engine_id:
            # Test specific engine
            engines_to_test = [engine_id] if engine_id in self.engines else []
        else:
            # Test all engines
            engines_to_test = list(self.engines.keys())
        
        test_results = {}
        
        for eid in engines_to_test:
            engine = self.engines[eid]
            
            if engine['type'] == 'container':
                # Test container connectivity
                try:
                    health_url = f"{self.container_manager.container_engines[eid]['url']}/health"
                    response = requests.get(health_url, timeout=10)
                    test_results[eid] = {
                        'available': response.status_code == 200,
                        'status': 'healthy' if response.status_code == 200 else f'HTTP {response.status_code}',
                        'response_time': response.elapsed.total_seconds()
                    }
                except Exception as e:
                    test_results[eid] = {
                        'available': False,
                        'status': f'Connection failed: {str(e)}',
                        'response_time': None
                    }
            
            elif engine['type'] == 'api':
                # Test API connectivity (simplified)
                test_results[eid] = {
                    'available': bool(engine.get('api_key')),
                    'status': 'API key configured' if engine.get('api_key') else 'API key missing',
                    'response_time': None
                }
        
        return test_results
    
    def get_supported_file_types(self):
        """Get list of file types supported by the scanner"""
        # This could be expanded based on engine capabilities
        return {
            'executables': ['.exe', '.dll', '.scr', '.com', '.bat', '.cmd'],
            'archives': ['.zip', '.rar', '.7z', '.tar', '.gz'],
            'documents': ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'],
            'scripts': ['.js', '.vbs', '.ps1', '.py', '.sh'],
            'images': ['.jpg', '.jpeg', '.png', '.gif', '.bmp'],
            'other': ['*']  # Scanner can handle any file type
        }
    
    def validate_file_for_scanning(self, file_path, max_size=100*1024*1024):
        """
        Validate that a file is suitable for AV scanning
        
        Args:
            file_path (str): Path to file
            max_size (int): Maximum file size in bytes (default 100MB)
            
        Returns:
            dict: Validation result with success status and any errors
        """
        try:
            if not os.path.exists(file_path):
                return {'valid': False, 'error': 'File does not exist'}
            
            file_size = os.path.getsize(file_path)
            
            if file_size == 0:
                return {'valid': False, 'error': 'File is empty'}
            
            if file_size > max_size:
                return {
                    'valid': False, 
                    'error': f'File too large ({file_size} bytes, max: {max_size})'
                }
            
            # Check if file is readable
            try:
                with open(file_path, 'rb') as f:
                    f.read(1)
            except Exception as e:
                return {'valid': False, 'error': f'File not readable: {str(e)}'}
            
            return {
                'valid': True,
                'file_size': file_size,
                'file_path': file_path
            }
            
        except Exception as e:
            return {'valid': False, 'error': f'Validation error: {str(e)}'}