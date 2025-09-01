"""
Container YARA Client
Simplified version of the container YARA manager for better organization
"""

import os
import json
import requests
import time
from datetime import datetime


class ContainerYaraClient:
    """Client for communicating with the containerized YARA service"""
    
    def __init__(self, yara_url=None):
        self.yara_url = yara_url or os.environ.get('YARA_URL', 'http://yara-scanner:5001')
        self.timeout = 300  # 5 minutes for rule compilation
        self.session = requests.Session()
        
        print(f"[YARA CLIENT] Initializing with URL: {self.yara_url}")
        self._wait_for_service()
    
    def _wait_for_service(self, max_retries=30, retry_delay=5):
        """Wait for YARA service to become available"""
        print(f"[YARA CLIENT] Waiting for YARA service...")
        
        for attempt in range(max_retries):
            try:
                response = self.session.get(f"{self.yara_url}/health", timeout=10)
                if response.status_code == 200:
                    health_data = response.json()
                    if health_data.get('status') == 'ready':
                        print(f"[YARA CLIENT] Service ready with {health_data.get('rules_loaded', 0)} rules")
                        return True
                    else:
                        print(f"[YARA CLIENT] Service status: {health_data.get('status')}")
                        
            except requests.exceptions.RequestException as e:
                print(f"[YARA CLIENT] Attempt {attempt + 1}/{max_retries} failed: {e}")
            
            if attempt < max_retries - 1:
                time.sleep(retry_delay)
        
        print(f"[YARA CLIENT] Service not ready after {max_retries} attempts")
        return False
    
    def scan_file(self, file_path):
        """Scan a file with YARA rules via the containerized service"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        try:
            print(f"[YARA CLIENT] Scanning file: {os.path.basename(file_path)}")
            
            # Try shared volume path first, then upload
            shared_file_path = self._get_shared_path(file_path)
            
            if shared_file_path and os.path.exists(shared_file_path):
                data = {'file_path': shared_file_path}
                response = self.session.post(f"{self.yara_url}/scan", data=data, timeout=self.timeout)
            else:
                with open(file_path, 'rb') as f:
                    files = {'file': f}
                    response = self.session.post(f"{self.yara_url}/scan", files=files, timeout=self.timeout)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    matches = result.get('matches', [])
                    scan_time = result.get('scan_time', 0)
                    print(f"[YARA CLIENT] Scan completed in {scan_time}s, found {len(matches)} matches")
                    return matches
                else:
                    error_msg = result.get('error', 'Unknown error')
                    raise Exception(f"YARA scan failed: {error_msg}")
            else:
                raise Exception(f"YARA service returned HTTP {response.status_code}")
                
        except requests.exceptions.Timeout:
            raise Exception("YARA scan timeout")
        except requests.exceptions.RequestException as e:
            raise Exception(f"Error communicating with YARA service: {str(e)}")
    
    def _get_shared_path(self, file_path):
        """Convert local file path to shared volume path"""
        uploads_dir = '/app/uploads'
        shared_files_dir = '/app/shared-files'
        
        if file_path.startswith(uploads_dir):
            import shutil
            filename = os.path.basename(file_path)
            shared_path = os.path.join(shared_files_dir, filename)
            
            try:
                os.makedirs(shared_files_dir, exist_ok=True)
                shutil.copy2(file_path, shared_path)
                return shared_path
            except Exception as e:
                print(f"[YARA CLIENT] Could not copy to shared path: {e}")
                return None
        
        return None
    
    def get_rule_stats(self):
        """Get YARA rules statistics"""
        try:
            response = self.session.get(f"{self.yara_url}/rules/stats", timeout=30)
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    return result.get('statistics', {})
            return {}
        except Exception as e:
            print(f"[YARA CLIENT] Error getting stats: {e}")
            return {}
    
    def list_rule_files(self):
        """List rule files"""
        try:
            response = self.session.get(f"{self.yara_url}/rules/list", timeout=30)
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    return result.get('rules', [])
            return []
        except Exception as e:
            print(f"[YARA CLIENT] Error listing rules: {e}")
            return []
    
    def get_directories(self):
        """Get rule directories"""
        try:
            response = self.session.get(f"{self.yara_url}/rules/directories", timeout=30)
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    return result.get('directories', ['root'])
            return ['root']
        except Exception as e:
            print(f"[YARA CLIENT] Error getting directories: {e}")
            return ['root']
    
    def get_rule_content(self, rule_path):
        """Get rule content"""
        try:
            response = self.session.get(f"{self.yara_url}/rules/content/{rule_path}", timeout=30)
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    return result.get('content', '')
            elif response.status_code == 404:
                raise FileNotFoundError("Rule file not found")
            elif response.status_code == 400:
                raise ValueError("Invalid rule path")
            
            raise Exception(f"Error retrieving rule content: HTTP {response.status_code}")
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Error communicating with YARA service: {str(e)}")
    
    def reload_rules(self):
        """Reload YARA rules"""
        try:
            print("[YARA CLIENT] Requesting rule reload...")
            response = self.session.post(f"{self.yara_url}/rules/reload", timeout=self.timeout)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    reload_time = result.get('reload_time', 0)
                    print(f"[YARA CLIENT] Rules reloaded in {reload_time}s")
                    return True
                else:
                    print(f"[YARA CLIENT] Reload failed: {result.get('error')}")
                    return False
            else:
                print(f"[YARA CLIENT] Reload failed: HTTP {response.status_code}")
                return False
                
        except Exception as e:
            print(f"[YARA CLIENT] Error reloading rules: {e}")
            return False
    
    def is_available(self):
        """Check if YARA service is available"""
        try:
            response = self.session.get(f"{self.yara_url}/health", timeout=10)
            if response.status_code == 200:
                health_data = response.json()
                return health_data.get('status') == 'ready'
            return False
        except Exception:
            return False
    
    def get_total_rules(self):
        """Get total number of rules loaded"""
        stats = self.get_rule_stats()
        return stats.get('total_files', 0)
    
    def get_skipped_rules(self):
        """Get number of skipped rules"""
        stats = self.get_rule_stats()
        return stats.get('skipped_files', 0)
    
    def get_service_status(self):
        """Get detailed service status"""
        try:
            response = self.session.get(f"{self.yara_url}/status", timeout=10)
            if response.status_code == 200:
                return response.json()
            else:
                return {
                    'service': 'yara-scanner',
                    'status': 'error',
                    'error': f'HTTP {response.status_code}'
                }
        except Exception as e:
            return {
                'service': 'yara-scanner', 
                'status': 'unreachable',
                'error': str(e)
            }
    
    def get_health_info(self):
        """Get health information for container monitoring"""
        try:
            response = self.session.get(f"{self.yara_url}/health", timeout=10)
            if response.status_code == 200:
                health_data = response.json()
                return {
                    'available': health_data.get('status') == 'ready',
                    'status': health_data.get('status', 'unknown'),
                    'service': health_data.get('service', 'yara-scanner'),
                    'rules_loaded': health_data.get('rules_loaded', 0),
                    'uptime_seconds': health_data.get('uptime_seconds', 0),
                    'version': 'Container Service',
                    'error': health_data.get('error')
                }
            else:
                return {
                    'available': False,
                    'status': 'error',
                    'service': 'yara-scanner',
                    'error': f'HTTP {response.status_code}',
                    'version': 'Container Service'
                }
        except Exception as e:
            return {
                'available': False,
                'status': 'unreachable',
                'service': 'yara-scanner',
                'error': str(e),
                'version': 'Container Service'
            }