"""
Container-based Antivirus Services Manager
Handles communication with containerized AV engines
"""

import os
import time
import hashlib
import requests
import json
import shutil
from datetime import datetime
from urllib.parse import urljoin
import logging

logger = logging.getLogger(__name__)

class ContainerAVManager:
    """Manages communication with containerized AV services"""
    
    def __init__(self, config):
        self.config = config
        self.shared_files_path = '/app/shared-files'
        self.container_engines = {
            'clamav': {
                'name': 'ClamAV',
                'url': os.environ.get('CLAMAV_URL', 'http://clamav-scanner:5000'),
                'enabled': config['enabled_engines'].get('clamav', True),
                'type': 'container',
                'timeout': 60
            }
        }
        
        self.remote_engines = {
            'virustotal': {
                'name': 'VirusTotal',
                'enabled': config['enabled_engines'].get('virustotal', True),
                'type': 'api',
                'api_key': config.get('virustotal_api_key', ''),
                'base_url': 'https://www.virustotal.com/vtapi/v2/',
                'rate_limit': 4,
                'last_request': 0
            },
            'hybrid_analysis': {
                'name': 'Hybrid Analysis',
                'enabled': config['enabled_engines'].get('hybrid_analysis', True),
                'type': 'api',
                'api_key': config.get('hybrid_analysis_api_key', ''),
                'base_url': 'https://hybrid-analysis.com/api/v2/',
                'rate_limit': 50
            },
            'metadefender': {
                'name': 'MetaDefender',
                'enabled': config['enabled_engines'].get('metadefender', True),
                'type': 'api',
                'api_key': config.get('metadefender_api_key', ''),
                'base_url': 'https://api.metadefender.com/v4/',
                'rate_limit': 10
            }
        }
        
        self.all_engines = {**self.container_engines, **self.remote_engines}
        self.initialize_engines()
    
    def initialize_engines(self):
        """Initialize and check all engines"""
        logger.info("🔍 Initializing antivirus engines...")
        
        # Check container engines
        for engine_id, engine in self.container_engines.items():
            self._check_container_engine(engine_id, engine)
        
        # Check remote engines (existing logic can be reused)
        for engine_id, engine in self.remote_engines.items():
            if engine['type'] == 'api':
                self._check_api_engine(engine_id, engine)
    
    def _check_container_engine(self, engine_id, engine):
        """Check if a containerized engine is available"""
        try:
            health_url = urljoin(engine['url'], '/health')
            print(f"Checking health endpoint: {health_url}")  # Debug logging
            
            response = requests.get(health_url, timeout=30)  # Increased timeout
            print(f"Health check response: {response.status_code}")  # Debug logging
            
            if response.status_code == 200:
                data = response.json()
                engine['available'] = data.get('status') in ['healthy', 'degraded']
                engine['version'] = data.get('version', 'Unknown')
                
                if engine['available']:
                    logger.info(f"? {engine['name']}: {engine['version']} (Container)")
                else:
                    logger.warning(f"?? {engine['name']}: Unhealthy status: {data.get('status')}")
            else:
                engine['available'] = False
                logger.warning(f"? {engine['name']}: HTTP {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            engine['available'] = False
            logger.error(f"? {engine['name']}: Request error - {str(e)}")
        except Exception as e:
            engine['available'] = False
            logger.error(f"? {engine['name']}: Unexpected error - {str(e)}")
    
    def _check_api_engine(self, engine_id, engine):
        """Check API-based engines (existing logic)"""
        if not engine.get('api_key'):
            engine['available'] = False
            logger.warning(f"⚠️ {engine['name']}: API key not configured")
            return
    
        try:
            if engine_id == 'virustotal':
                test_url = urljoin(engine['base_url'], 'file/report')
                params = {'apikey': engine['api_key'], 'resource': 'test'}
                response = requests.get(test_url, params=params, timeout=10)
                if response.status_code in [200, 204]:
                    engine['available'] = True
                    engine['version'] = 'API v2'
                    logger.info(f"✅ {engine['name']}: API connected")
                else:
                    engine['available'] = False
                    logger.warning(f"❌ {engine['name']}: API error {response.status_code}")
            else:
                engine['available'] = True
                engine['version'] = 'API'
                logger.info(f"✅ {engine['name']}: API key configured")
                
        except Exception as e:
            engine['available'] = False
            logger.error(f"❌ {engine['name']}: API error - {str(e)}")
    
    def scan_file(self, file_path, engines_to_use=None):
        """Scan file with specified engines"""
        if engines_to_use is None:
            engines_to_use = [eid for eid, engine in self.all_engines.items() 
                            if engine.get('available', False) and engine.get('enabled', False)]
        
        results = {}
        
        for engine_id in engines_to_use:
            if engine_id not in self.all_engines:
                continue
                
            engine = self.all_engines[engine_id]
            
            if not engine.get('available', False) or not engine.get('enabled', False):
                results[engine_id] = {
                    'engine': engine['name'],
                    'status': 'disabled' if not engine.get('enabled', False) else 'unavailable',
                    'result': 'Engine disabled' if not engine.get('enabled', False) else 'Engine not available',
                    'scan_time': 0
                }
                continue
            
            try:
                logger.info(f"🔍 Scanning with {engine['name']}...")
                
                if engine['type'] == 'container':
                    scan_result = self._scan_with_container(file_path, engine_id)
                elif engine['type'] == 'api':
                    scan_result = self._scan_with_api(file_path, engine_id)
                else:
                    scan_result = {
                        'engine': engine['name'],
                        'status': 'error',
                        'result': 'Unknown engine type',
                        'scan_time': 0
                    }
                
                results[engine_id] = scan_result
                
            except Exception as e:
                logger.error(f"Error scanning with {engine['name']}: {e}")
                results[engine_id] = {
                    'engine': engine['name'],
                    'status': 'error',
                    'result': f'Scan error: {str(e)}',
                    'scan_time': 0
                }
        
        return results
    
    def _scan_with_container(self, file_path, engine_id):
        """Scan file with a containerized engine"""
        engine = self.container_engines[engine_id]
        
        try:
            # Copy file to shared directory
            filename = f"scan_{int(time.time())}_{os.path.basename(file_path)}"
            shared_file_path = os.path.join(self.shared_files_path, filename)
            
            # Ensure shared directory exists
            os.makedirs(self.shared_files_path, exist_ok=True)
            
            # Copy file
            shutil.copy2(file_path, shared_file_path)
            
            try:
                # Make scan request
                scan_url = urljoin(engine['url'], '/scan')
                data = {'file_path': shared_file_path}
                
                response = requests.post(
                    scan_url, 
                    json=data, 
                    timeout=engine.get('timeout', 60)
                )
                
                if response.status_code == 200:
                    result = response.json()
                    if result.get('success', False):
                        return result
                    else:
                        return {
                            'engine': engine['name'],
                            'status': 'error',
                            'result': result.get('error', 'Unknown error'),
                            'scan_time': 0
                        }
                else:
                    return {
                        'engine': engine['name'],
                        'status': 'error',
                        'result': f'HTTP {response.status_code}',
                        'scan_time': 0
                    }
            finally:
                # Clean up shared file
                try:
                    os.remove(shared_file_path)
                except:
                    pass
                    
        except Exception as e:
            return {
                'engine': engine['name'],
                'status': 'error',
                'result': f'Container communication error: {str(e)}',
                'scan_time': 0
            }
    
    def _scan_with_api(self, file_path, engine_id):
        
        engine = self.remote_engines[engine_id]
        
        if engine_id == 'virustotal':
            return self._scan_virustotal(file_path, engine)
        elif engine_id == 'hybrid_analysis':
            return self._scan_hybrid_analysis(file_path, engine)
        elif engine_id == 'metadefender':
            return self._scan_metadefender(file_path, engine)
        else:
            return {
                'engine': engine['name'],
                'status': 'error',
                'result': 'API engine not implemented',
                'scan_time': 0
            }
    
    def _scan_virustotal(self, file_path, engine):
        """Scan with VirusTotal API - Upload file for analysis"""
        try:
            start_time = time.time()
            
            # Rate limiting
            now = time.time()
            if now - engine['last_request'] < (60 / engine['rate_limit']):
                sleep_time = (60 / engine['rate_limit']) - (now - engine['last_request'])
                time.sleep(sleep_time)
            
            # First, try to get existing report by hash
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            
            # Check if file exists in VirusTotal
            report_url = urljoin(engine['base_url'], 'file/report')
            params = {
                'apikey': engine['api_key'],
                'resource': file_hash,
                'allinfo': '1'
            }
            
            response = requests.get(report_url, params=params, timeout=30)
            engine['last_request'] = time.time()
            
            if response.status_code == 200:
                data = response.json()
                
                if data['response_code'] == 1:
                    # File found, return existing results
                    return self._format_virustotal_response(data, time.time() - start_time, engine['name'])
                elif data['response_code'] == 0:
                    # File not found, upload for scanning
                    return self._upload_to_virustotal(file_path, engine, start_time)
                else:
                    return self._format_virustotal_error(data, time.time() - start_time, engine['name'])
            else:
                return self._format_virustotal_http_error(response, time.time() - start_time, engine['name'])
                
        except Exception as e:
            return {
                'engine': engine['name'],
                'status': 'error',
                'result': f'Exception: {str(e)}',
                'scan_time': 0,
                'detections': 0
            }
    
    def _upload_to_virustotal(self, file_path, engine, start_time):
        """Upload file to VirusTotal for scanning"""
        try:
            # Upload file
            upload_url = urljoin(engine['base_url'], 'file/scan')
            
            filename = os.path.basename(file_path)
            with open(file_path, 'rb') as f:
                files = {'file': (filename, f, 'application/octet-stream')}
                params = {'apikey': engine['api_key']}
                
                response = requests.post(upload_url, files=files, params=params, timeout=120)
            
            engine['last_request'] = time.time()
            scan_time = time.time() - start_time
            
            if response.status_code == 200:
                data = response.json()
                
                if data['response_code'] == 1:
                    scan_id = data.get('scan_id', '')
                    permalink = data.get('permalink', '')
                    sha256 = data.get('sha256', '')
                    
                    # Create VirusTotal link
                    vt_link = f"https://www.virustotal.com/gui/file/{sha256}" if sha256 else permalink
                    
                    return {
                        'engine': engine['name'],
                        'status': 'submitted',
                        'result': f'File uploaded successfully for analysis',
                        'scan_time': round(scan_time, 2),
                        'detections': 0,
                        'scan_id': scan_id,
                        'sha256': sha256,
                        'permalink': permalink,
                        'analysis_url': vt_link,
                        'note': 'Analysis in progress - results available in a few minutes',
                        'raw_output': data
                    }
                else:
                    return {
                        'engine': engine['name'],
                        'status': 'error',
                        'result': f"Upload failed: {data.get('verbose_msg', 'Unknown error')}",
                        'scan_time': round(scan_time, 2),
                        'detections': 0,
                        'raw_output': data
                    }
            else:
                return self._format_virustotal_http_error(response, scan_time, engine['name'])
                
        except Exception as e:
            return {
                'engine': engine['name'],
                'status': 'error',
                'result': f'Upload error: {str(e)}',
                'scan_time': time.time() - start_time,
                'detections': 0
            }
    
    def _format_virustotal_response(self, data, scan_time, engine_name):
        """Format existing VirusTotal response"""
        positives = data.get('positives', 0)
        total = data.get('total', 0)
        scan_date = data.get('scan_date', '')
        sha256 = data.get('sha256', '')
        
        # Get detailed engine results
        scans = data.get('scans', {})
        detection_details = []
        clean_engines = []
        
        for av_name, result in scans.items():
            if result.get('detected'):
                threat_name = result.get('result', 'Malware')
                version = result.get('version', 'Unknown')
                detection_details.append({
                    'engine': av_name,
                    'threat': threat_name,
                    'version': version,
                    'update': result.get('update', '')
                })
            else:
                clean_engines.append({
                    'engine': av_name,
                    'version': result.get('version', 'Unknown'),
                    'update': result.get('update', '')
                })
        
        # Create VirusTotal link
        vt_link = f"https://www.virustotal.com/gui/file/{sha256}" if sha256 else data.get('permalink', '')
        
        # Get file metadata
        file_info = {
            'md5': data.get('md5', ''),
            'sha1': data.get('sha1', ''),
            'sha256': sha256,
            'ssdeep': data.get('ssdeep', ''),
            'file_type': data.get('type', ''),
            'size': data.get('size', 0),
            'first_seen': data.get('first_seen', ''),
            'last_seen': data.get('last_seen', ''),
            'times_submitted': data.get('times_submitted', 0)
        }
        
        if positives > 0:
            return {
                'engine': engine_name,
                'status': 'infected',
                'result': f'{positives}/{total} engines detected threats',
                'threat_name': detection_details[0]['threat'] if detection_details else 'Malware',
                'scan_time': round(scan_time, 2),
                'detections': positives,
                'total_engines': total,
                'detection_details': detection_details,
                'clean_engines': clean_engines,
                'scan_date': scan_date,
                'file_info': file_info,
                'permalink': data.get('permalink', ''),
                'analysis_url': vt_link,
                'sha256': sha256,
                'raw_output': data
            }
        else:
            return {
                'engine': engine_name,
                'status': 'clean',
                'result': f'Clean - 0/{total} engines detected threats',
                'scan_time': round(scan_time, 2),
                'detections': 0,
                'total_engines': total,
                'clean_engines': clean_engines,
                'scan_date': scan_date,
                'file_info': file_info,
                'permalink': data.get('permalink', ''),
                'analysis_url': vt_link,
                'sha256': sha256,
                'raw_output': data
            }
    
    def _format_virustotal_error(self, data, scan_time, engine_name):
        """Format VirusTotal error response"""
        if data['response_code'] == -2:
            return {
                'engine': engine_name,
                'status': 'pending',
                'result': 'File is queued for analysis on VirusTotal',
                'scan_time': round(scan_time, 2),
                'detections': 0,
                'note': 'Analysis in progress - check again later',
                'raw_output': data
            }
        else:
            return {
                'engine': engine_name,
                'status': 'error',
                'result': f"API response code: {data['response_code']}",
                'scan_time': round(scan_time, 2),
                'detections': 0,
                'raw_output': data
            }
    
    def _format_virustotal_http_error(self, response, scan_time, engine_name):
        """Format VirusTotal HTTP error response"""
        if response.status_code == 204:
            return {
                'engine': engine_name,
                'status': 'error',
                'result': 'Rate limit exceeded - try again later',
                'scan_time': round(scan_time, 2),
                'detections': 0,
                'raw_output': response.text
            }
        elif response.status_code == 403:
            return {
                'engine': engine_name,
                'status': 'error',
                'result': 'API key invalid or access forbidden',
                'scan_time': round(scan_time, 2),
                'detections': 0,
                'raw_output': response.text
            }
        else:
            return {
                'engine': engine_name,
                'status': 'error',
                'result': f'API error: HTTP {response.status_code}',
                'scan_time': round(scan_time, 2),
                'detections': 0,
                'raw_output': response.text
            }
    
    def check_virustotal_result(self, scan_id):
        """Check VirusTotal analysis result by scan ID"""
        try:
            engine = self.remote_engines['virustotal']
            
            if not engine.get('available', False) or not engine.get('api_key'):
                return None
            
            # Rate limiting
            now = time.time()
            if now - engine['last_request'] < (60 / engine['rate_limit']):
                sleep_time = (60 / engine['rate_limit']) - (now - engine['last_request'])
                time.sleep(sleep_time)
            
            # Check result
            report_url = urljoin(engine['base_url'], 'file/report')
            params = {
                'apikey': engine['api_key'],
                'resource': scan_id,
                'allinfo': '1'
            }
            
            response = requests.get(report_url, params=params, timeout=30)
            engine['last_request'] = time.time()
            
            if response.status_code == 200:
                data = response.json()
                
                if data['response_code'] == 1:
                    # Analysis complete
                    return self._format_virustotal_response(data, 0, engine['name'])
                elif data['response_code'] == -2:
                    # Still in queue
                    return {
                        'status': 'pending',
                        'message': 'Analysis still in progress'
                    }
                else:
                    # Not found or error
                    return {
                        'status': 'error',
                        'message': f"Analysis not found (code: {data['response_code']})"
                    }
            else:
                return {
                    'status': 'error',
                    'message': f"API error: HTTP {response.status_code}"
                }
                
        except Exception as e:
            return {
                'status': 'error',
                'message': f"Exception: {str(e)}"
            }

    def _scan_hybrid_analysis(self, file_path, engine):
        """Fixed Hybrid Analysis scan with better error handling"""
        try:
            start_time = time.time()
            
            # Calculate file hash first to check if it exists
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            
            # First, check if analysis already exists using GET /search/hash
            search_url = urljoin(engine['base_url'], 'search/hash')
            headers = {
                'api-key': engine['api_key'],
                'user-agent': 'Falcon Sandbox',
                'accept': 'application/json'
            }
            params = {'hash': file_hash}
            
            try:
                response = requests.get(search_url, headers=headers, params=params, timeout=30)
                
                if response.status_code == 200:
                    try:
                        search_data = response.json()
                        
                        # Check if we have existing results
                        if search_data and isinstance(search_data, list) and len(search_data) > 0:
                            # Use the most recent analysis
                            latest_analysis = search_data[0]
                            return self._format_hybrid_analysis_existing_result(latest_analysis, time.time() - start_time, engine['name'])
                        else:
                            # No existing results, proceed with file upload
                            return self._upload_to_hybrid_analysis(file_path, engine, start_time)
                    except (json.JSONDecodeError, TypeError, KeyError) as e:
                        print(f"Hybrid Analysis search JSON error: {e}")
                        # Try upload if search fails
                        return self._upload_to_hybrid_analysis(file_path, engine, start_time)
                else:
                    # Search failed, try upload anyway
                    print(f"Hybrid Analysis search failed with status {response.status_code}")
                    return self._upload_to_hybrid_analysis(file_path, engine, start_time)
                    
            except requests.RequestException as e:
                print(f"Hybrid Analysis search request error: {e}")
                # Try upload if search request fails
                return self._upload_to_hybrid_analysis(file_path, engine, start_time)
                
        except Exception as e:
            return {
                'engine': engine['name'],
                'status': 'error',
                'result': f'Exception: {str(e)}',
                'scan_time': 0,
                'detections': 0
            }

    def _upload_to_hybrid_analysis(self, file_path, engine, start_time):
        """Fixed upload to Hybrid Analysis with better error handling"""
        try:
            # Upload file using quick-scan endpoint (the original working approach)
            scan_url = urljoin(engine['base_url'], 'quick-scan/file')
            headers = {
                'api-key': engine['api_key'],
                'user-agent': 'Falcon Sandbox',
                'accept': 'application/json'
            }
            
            # Prepare file for upload
            filename = os.path.basename(file_path)
            with open(file_path, 'rb') as f:
                files = {
                    'file': (filename, f, 'application/octet-stream')
                }
                data = {
                    'scan_type': 'all'  # Scan with all available engines
                }
                
                response = requests.post(scan_url, headers=headers, files=files, data=data, timeout=120)
            
            scan_time = time.time() - start_time
            
            if response.status_code == 200:
                try:
                    data = response.json()
                except json.JSONDecodeError:
                    return {
                        'engine': engine['name'],
                        'status': 'error',
                        'result': 'Invalid JSON response from API',
                        'scan_time': round(scan_time, 2),
                        'detections': 0,
                        'raw_output': response.text
                    }
                
                # Extract basic information safely
                scan_id = data.get('id', '')
                sha256 = data.get('sha256', '')
                verdict = data.get('verdict', 'unknown')
                threat_score = data.get('threat_score', 0)
                threat_level = data.get('threat_level', 'no-threat')
                
                # Check if we have immediate results
                if 'scanners_v2' in data and data['scanners_v2']:
                    return self._format_hybrid_analysis_quick_scan_result(data, scan_time, engine['name'])
                elif threat_score is not None and threat_score > 0:
                    # We have a threat score, treat as completed analysis
                    return self._format_hybrid_analysis_completed_result(data, scan_time, engine['name'])
                else:
                    # File submitted for analysis
                    # Create Hybrid Analysis link
                    ha_link = f"https://www.hybrid-analysis.com/sample/{sha256}" if sha256 else f"https://www.hybrid-analysis.com/quick-scan/{scan_id}"
                    
                    return {
                        'engine': engine['name'],
                        'status': 'submitted',
                        'result': f'File uploaded successfully for analysis',
                        'scan_time': round(scan_time, 2),
                        'detections': 0,
                        'scan_id': scan_id,
                        'sha256': sha256,
                        'analysis_url': ha_link,
                        'note': 'Analysis in progress - results available in a few minutes',
                        'raw_output': data
                    }
            else:
                return self._format_hybrid_analysis_http_error(response, scan_time, engine['name'])
                
        except Exception as e:
            return {
                'engine': engine['name'],
                'status': 'error',
                'result': f'Upload error: {str(e)}',
                'scan_time': time.time() - start_time,
                'detections': 0
            }

    def _format_hybrid_analysis_existing_result(self, analysis_data, scan_time, engine_name):
        """Fixed formatting for existing Hybrid Analysis result"""
        try:
            job_id = analysis_data.get('job_id', '')
            sha256 = analysis_data.get('sha256', '')
            verdict = analysis_data.get('verdict', 'unknown')
            threat_score = analysis_data.get('threat_score', 0) or 0  # Handle None values
            threat_level = analysis_data.get('threat_level', 'no-threat') or 'no-threat'
            av_detect = analysis_data.get('av_detect', 0) or 0
            vt_detect = analysis_data.get('vt_detect', 0) or 0
            analysis_start_time = analysis_data.get('analysis_start_time', '')
            
            # Create Hybrid Analysis link
            ha_link = f"https://www.hybrid-analysis.com/sample/{sha256}" if sha256 else ""
            
            # Determine if infected based on multiple factors
            is_infected = (threat_score > 30 or 
                          verdict in ['malicious', 'suspicious'] or 
                          av_detect > 0)
            
            # Create detailed result description
            result_parts = []
            if av_detect > 0:
                result_parts.append(f"{av_detect} AV detections")
            if vt_detect > 0:
                result_parts.append(f"{vt_detect} VT detections")
            
            result_parts.append(f"Score: {threat_score}/100")
            result_text = ' | '.join(result_parts)
            
            if is_infected:
                return {
                    'engine': engine_name,
                    'status': 'infected',
                    'result': f'Threats detected - {result_text}',
                    'threat_name': threat_level.replace('-', ' ').title(),
                    'scan_time': round(scan_time, 2),
                    'detections': max(av_detect, vt_detect, 1),
                    'total_engines': 1,
                    'threat_score': threat_score,
                    'verdict': verdict,
                    'scan_id': job_id,
                    'sha256': sha256,
                    'analysis_url': ha_link,
                    'scan_date': analysis_start_time,
                    'raw_output': analysis_data
                }
            else:
                return {
                    'engine': engine_name,
                    'status': 'clean',
                    'result': f'Clean - {result_text}',
                    'scan_time': round(scan_time, 2),
                    'detections': 0,
                    'total_engines': 1,
                    'threat_score': threat_score,
                    'verdict': verdict,
                    'scan_id': job_id,
                    'sha256': sha256,
                    'analysis_url': ha_link,
                    'scan_date': analysis_start_time,
                    'raw_output': analysis_data
                }
                
        except Exception as e:
            print(f"Hybrid Analysis existing result formatting error: {e}")
            return {
                'engine': engine_name,
                'status': 'error',
                'result': f'Error parsing existing result: {str(e)}',
                'scan_time': round(scan_time, 2),
                'detections': 0,
                'raw_output': analysis_data
            }

    def _format_hybrid_analysis_completed_result(self, data, scan_time, engine_name):
        """Format completed analysis result (simplified)"""
        try:
            scan_id = data.get('id', '')
            sha256 = data.get('sha256', '')
            verdict = data.get('verdict', 'unknown')
            threat_score = data.get('threat_score', 0) or 0
            threat_level = data.get('threat_level', 'no-threat') or 'no-threat'
            
            # Create Hybrid Analysis link
            ha_link = f"https://www.hybrid-analysis.com/sample/{sha256}" if sha256 else f"https://www.hybrid-analysis.com/quick-scan/{scan_id}"
            
            # Determine overall status
            is_infected = (threat_score > 30 or verdict in ['malicious', 'suspicious'])
            
            result_text = f"Clean - 0/0 engines detected threats (Score: {threat_score}/100)"
            if is_infected:
                result_text = f"Threats detected (Score: {threat_score}/100)"
            
            return {
                'engine': engine_name,
                'status': 'infected' if is_infected else 'clean',
                'result': result_text,
                'threat_name': threat_level.replace('-', ' ').title() if is_infected else None,
                'scan_time': round(scan_time, 2),
                'detections': 1 if is_infected else 0,
                'total_engines': 1,
                'threat_score': threat_score,
                'verdict': verdict,
                'scan_id': scan_id,
                'sha256': sha256,
                'analysis_url': ha_link,
                'raw_output': data
            }
            
        except Exception as e:
            print(f"Hybrid Analysis completed result formatting error: {e}")
            return {
                'engine': engine_name,
                'status': 'error',
                'result': f'Error formatting result: {str(e)}',
                'scan_time': round(scan_time, 2),
                'detections': 0,
                'raw_output': data
            }

    def _format_hybrid_analysis_quick_scan_result(self, data, scan_time, engine_name):
        """Format quick scan result with better error handling"""
        try:
            scan_id = data.get('id', '')
            sha256 = data.get('sha256', '')
            verdict = data.get('verdict', 'unknown')
            threat_score = data.get('threat_score')
            # Don't default to 0 if None - keep it as None to indicate incomplete analysis
    
            if threat_score is None:
                threat_score = 0  # Only for display, but mark as incomplete
            
            # Check if analysis is actually complete
            finished = data.get('finished', False)
            state = data.get('state', '')
    
            # If analysis isn't finished, return as submitted status instead
            if not finished or state not in ['SUCCESS', 'COMPLETED']:
                return {
                    'engine': engine_name,
                    'status': 'submitted',
                     'result': 'Analysis submitted - threat score pending',
                    'scan_time': round(scan_time, 2),
                    'detections': 0,
                    'scan_id': data.get('id', ''),
                    'sha256': data.get('sha256', ''),
                    'analysis_url': f"https://www.hybrid-analysis.com/sample/{data.get('sha256', '')}",
                    'note': 'Full analysis in progress - threat score will be updated',
                    'raw_output': data
                 }

            # Create Hybrid Analysis link
            ha_link = f"https://www.hybrid-analysis.com/sample/{sha256}" if sha256 else f"https://www.hybrid-analysis.com/quick-scan/{scan_id}"
            
            # Check scanners_v2 for detection results
            scanners_v2 = data.get('scanners_v2', {})
            detection_count = 0
            total_scanners = 0
            
            if isinstance(scanners_v2, dict):
                for scanner_name, scanner_data in scanners_v2.items():
                    if isinstance(scanner_data, dict):
                        total_scanners += 1
                        status = scanner_data.get('status', 'unknown')
                        if status in ['detected', 'malicious', 'suspicious']:
                            detection_count += 1
            
            # Determine overall status
            is_infected = (threat_score > 30 or 
                          verdict in ['malicious', 'suspicious'] or 
                          detection_count > 0)
            
            # Create result summary
            if total_scanners > 0:
                result_text = f'{detection_count}/{total_scanners} scanners detected threats (Score: {threat_score}/100)'
            else:
                result_text = f'Clean - 0/0 engines detected threats (Score: {threat_score}/100)'
            
            return {
                'engine': engine_name,
                'status': 'infected' if is_infected else 'clean',
                'result': result_text,
                'threat_name': 'Malware' if is_infected else None,
                'scan_time': round(scan_time, 2),
                'detections': detection_count,
                'total_engines': max(total_scanners, 1),
                'threat_score': threat_score,
                'verdict': verdict,
                'scan_id': scan_id,
                'sha256': sha256,
                'analysis_url': ha_link,
                'raw_output': data
            }
            
        except Exception as e:
            print(f"Hybrid Analysis quick scan formatting error: {e}")
            return {
                'engine': engine_name,
                'status': 'error',
                'result': f'Error parsing quick scan: {str(e)}',
                'scan_time': round(scan_time, 2),
                'detections': 0,
                'raw_output': data
            }

    def _format_hybrid_analysis_http_error(self, response, scan_time, engine_name):
        """Format Hybrid Analysis HTTP error response"""
        if response.status_code == 401:
            return {
                'engine': engine_name,
                'status': 'error',
                'result': 'API authentication failed - check API key',
                'scan_time': round(scan_time, 2),
                'detections': 0,
                'raw_output': response.text
            }
        elif response.status_code == 403:
            return {
                'engine': engine_name,
                'status': 'error',
                'result': 'API access forbidden - check permissions or rate limits',
                'scan_time': round(scan_time, 2),
                'detections': 0,
                'raw_output': response.text
            }
        elif response.status_code == 413:
            return {
                'engine': engine_name,
                'status': 'error',
                'result': 'File too large for upload',
                'scan_time': round(scan_time, 2),
                'detections': 0,
                'raw_output': response.text
            }
        elif response.status_code == 429:
            return {
                'engine': engine_name,
                'status': 'error',
                'result': 'Rate limit exceeded - try again later',
                'scan_time': round(scan_time, 2),
                'detections': 0,
                'raw_output': response.text
            }
        else:
            return {
                'engine': engine_name,
                'status': 'error',
                'result': f'API error: HTTP {response.status_code}',
                'scan_time': round(scan_time, 2),
                'detections': 0,
                'raw_output': response.text[:200] if response.text else 'No response'
            }

    def check_hybrid_analysis_result(self, scan_id, sha256=None):
        """Check Hybrid Analysis result using proper API v2 endpoints"""
        try:
            print(f"=== HYBRID ANALYSIS DEBUG ===")
            print(f"scan_id: {scan_id}")
            print(f"sha256: {sha256}")
            
            engine = self.remote_engines['hybrid_analysis']
            
            if not engine.get('available', False) or not engine.get('api_key'):
                return {'status': 'error', 'message': 'Engine not available'}
            
            headers = {
                'api-key': engine['api_key'],
                'user-agent': 'Falcon Sandbox',
                'accept': 'application/json'
            }
            
            # ALWAYS try to get SHA256 first if we don't have it
            if not sha256 and scan_id:
                try:
                    result_url = urljoin(engine['base_url'], f'quick-scan/{scan_id}')
                    response = requests.get(result_url, headers=headers, timeout=30)
                    
                    if response.status_code == 200:
                        data = response.json()
                        sha256 = data.get('sha256')
                        print(f"DEBUG: Extracted SHA256: {sha256}")
                        
                except Exception as e:
                    print(f"DEBUG: SHA256 extraction error: {e}")
            
            # Now use the SHA256 for proper lookup
            if sha256:
                try:
                    overview_url = urljoin(engine['base_url'], f'overview/{sha256}')
                    print(f"DEBUG: Trying overview endpoint: {overview_url}")
                    
                    response = requests.get(overview_url, headers=headers, timeout=30)
                    print(f"DEBUG: overview response: {response.status_code}")
                    
                    if response.status_code == 200:
                        overview_data = response.json()
                        threat_score = overview_data.get('threat_score')
                        state = overview_data.get('state', '')
                        print(f"DEBUG: threat_score: {threat_score}, state: {state}")
                            
                        if threat_score is not None:
                            print("DEBUG: Returning completed analysis!")
                            return self._format_hybrid_analysis_overview_result(overview_data, 0, engine['name'])

                    else:
                        print(f"DEBUG: overview failed: {response.status_code}")
                        print(f"DEBUG: Response: {response.text[:200]}")
                
                
                except Exception as e:
                    print(f"DEBUG: overview exception: {e}")
            
            print("DEBUG: No completed analysis found, returning pending")
            return {'status': 'pending', 'message': 'Analysis still in progress'}
            
        except Exception as e:
            return {'status': 'error', 'message': f'Exception: {str(e)}'}            
            
    def _format_hybrid_analysis_overview_result(self, data, scan_time, engine_name):
        """Format result from /overview/{sha256} endpoint"""
        try:
            sha256 = data.get('sha256', '')
            threat_score = data.get('threat_score', 0) or 0
            verdict = data.get('verdict', 'unknown')
            av_detect = data.get('av_detect', 0) or 0
            vt_detect = data.get('vt_detect', 0) or 0
            analysis_start_time = data.get('analysis_start_time', '')
            
            # Get job_id for linking
            job_id = ''
            submissions = data.get('submissions', [])
            if submissions and len(submissions) > 0:
                job_id = submissions[0].get('job_id', '')
            
            # Create Hybrid Analysis link
            ha_link = f"https://www.hybrid-analysis.com/sample/{sha256}" if sha256 else ""
            
            # Determine if infected
            is_infected = (threat_score > 30 or 
                          verdict in ['malicious', 'suspicious'] or 
                          av_detect > 0)
            
            # Create detailed result description
            result_parts = []
            if av_detect > 0:
                result_parts.append(f"{av_detect} AV detections")
            if vt_detect > 0:
                result_parts.append(f"{vt_detect} VT detections")
            
            result_parts.append(f"Score: {threat_score}/100")
            result_text = ' | '.join(result_parts)
            
            if is_infected:
                return {
                    'engine': engine_name,
                    'status': 'infected',
                    'result': f'Threats detected - {result_text}',
                    'threat_name': verdict.replace('-', ' ').title() if verdict != 'unknown' else 'Malware',
                    'scan_time': round(scan_time, 2),
                    'detections': max(av_detect, vt_detect, 1),
                    'total_engines': 1,
                    'threat_score': threat_score,
                    'verdict': verdict,
                    'scan_id': job_id,
                    'sha256': sha256,
                    'analysis_url': ha_link,
                    'scan_date': analysis_start_time,
                    'raw_output': data
                }
            else:
                return {
                    'engine': engine_name,
                    'status': 'clean',
                    'result': f'Clean - {result_text}',
                    'scan_time': round(scan_time, 2),
                    'detections': 0,
                    'total_engines': 1,
                    'threat_score': threat_score,
                    'verdict': verdict,
                    'scan_id': job_id,
                    'sha256': sha256,
                    'analysis_url': ha_link,
                    'scan_date': analysis_start_time,
                    'raw_output': data
                }
                
        except Exception as e:
            print(f"Hybrid Analysis overview formatting error: {e}")
            return {
                'engine': engine_name,
                'status': 'error',
                'result': f'Error formatting overview result: {str(e)}',
                'scan_time': round(scan_time, 2),
                'detections': 0,
                'raw_output': data
            }

    def _scan_metadefender(self, file_path, engine):
        """Enhanced MetaDefender with upload support"""
        try:
            start_time = time.time()
            
            # Calculate file hash first
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            
            # Look up hash first
            lookup_url = urljoin(engine['base_url'], f'hash/{file_hash}')
            headers = {'apikey': engine['api_key']}
            
            response = requests.get(lookup_url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                # File found, return existing results
                data = response.json()
                return self._format_metadefender_response(data, time.time() - start_time, engine['name'])
            elif response.status_code == 404:
                # File not found, upload it
                return self._upload_to_metadefender(file_path, engine, start_time)
            else:
                return self._format_metadefender_http_error(response, time.time() - start_time, engine['name'])
                
        except Exception as e:
            return {
                'engine': engine['name'],
                'status': 'error',
                'result': f'Exception: {str(e)}',
                'scan_time': 0,
                'detections': 0
            }

    def _upload_to_metadefender(self, file_path, engine, start_time):
        """Upload file to MetaDefender"""
        try:
            upload_url = urljoin(engine['base_url'], 'file')
            headers = {
                'apikey': engine['api_key'],
                'content-type': 'application/octet-stream'
            }
            
            with open(file_path, 'rb') as f:
                response = requests.post(upload_url, data=f, headers=headers, timeout=120)
            
            scan_time = time.time() - start_time
            
            if response.status_code == 200:
                data = response.json()
                data_id = data.get('data_id', '')
                
                if data_id:
                    # Create MetaDefender link
                    md_link = f"https://metadefender.opswat.com/results/file/{data_id}/regular/overview"
                    
                    return {
                        'engine': engine['name'],
                        'status': 'submitted',
                        'result': f'File uploaded successfully for analysis',
                        'scan_time': round(scan_time, 2),
                        'detections': 0,
                        'data_id': data_id,
                        'analysis_url': md_link,
                        'note': 'Analysis in progress - results available in a few minutes',
                        'raw_output': data
                    }
                else:
                    return {
                        'engine': engine['name'],
                        'status': 'error',
                        'result': 'Upload succeeded but no data_id returned',
                        'scan_time': round(scan_time, 2),
                        'detections': 0,
                        'raw_output': data
                    }
            else:
                return self._format_metadefender_http_error(response, scan_time, engine['name'])
                
        except Exception as e:
            return {
                'engine': engine['name'],
                'status': 'error',
                'result': f'Upload error: {str(e)}',
                'scan_time': time.time() - start_time,
                'detections': 0
            }

    def _get_metadefender_result(self, data_id, engine):
        """Get MetaDefender result by data_id"""
        try:
            result_url = urljoin(engine['base_url'], f'file/{data_id}')
            headers = {'apikey': engine['api_key']}
            
            response = requests.get(result_url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                return self._format_metadefender_response(data, 0, engine['name'])
            else:
                return None
                
        except Exception as e:
            print(f"Error getting MetaDefender result: {e}")
            return None

    def _format_metadefender_response(self, data, scan_time, engine_name):
        """Enhanced MetaDefender response formatting"""
        try:
            scan_results = data.get('scan_results', {})
            scan_all_result_a = scan_results.get('scan_all_result_a', 'Clean')
            
            # Get detailed engine results
            scan_details = scan_results.get('scan_details', {})
            detection_details = []
            clean_engines = []
            positive_count = 0
            total_engines = len(scan_details)
            
            for engine_name_detail, result in scan_details.items():
                if result.get('scan_result_i') == 1:  # Detected
                    positive_count += 1
                    detection_details.append({
                        'engine': engine_name_detail,
                        'threat_found': result.get('threat_found', ''),
                        'scan_result': result.get('scan_result_i', 0)
                    })
                else:
                    clean_engines.append({
                        'engine': engine_name_detail,
                        'scan_result': result.get('scan_result_i', 0)
                    })
            
            # Get file info and data_id for linking
            file_info = data.get('file_info', {})
            data_id = file_info.get('data_id', '') or data.get('data_id', '')
            
            # Create MetaDefender link
            md_link = f"https://metadefender.opswat.com/results/file/{data_id}/regular/overview" if data_id else ""
            
            if scan_all_result_a != 'Clean' and positive_count > 0:
                top_threats = [d['threat_found'] for d in detection_details[:3] if d['threat_found']]
                
                return {
                    'engine': engine_name,
                    'status': 'infected',
                    'result': f'{positive_count}/{total_engines} engines detected threats',
                    'threat_name': top_threats[0] if top_threats else 'Malware',
                    'scan_time': round(scan_time, 2),
                    'detections': positive_count,
                    'total_engines': total_engines,
                    'detection_details': detection_details,
                    'clean_engines': clean_engines,
                    'data_id': data_id,
                    'analysis_url': md_link,
                    'raw_output': data
                }
            else:
                return {
                    'engine': engine_name,
                    'status': 'clean',
                    'result': f'Clean - {positive_count}/{total_engines} engines detected threats',
                    'scan_time': round(scan_time, 2),
                    'detections': positive_count,
                    'total_engines': total_engines,
                    'clean_engines': clean_engines,
                    'data_id': data_id,
                    'analysis_url': md_link,
                    'raw_output': data
                }
                
        except Exception as e:
            print(f"MetaDefender response formatting error: {e}")
            return {
                'engine': engine_name,
                'status': 'error',
                'result': f'Error parsing result: {str(e)}',
                'scan_time': round(scan_time, 2),
                'detections': 0,
                'raw_output': data
            }

    def check_metadefender_result(self, data_id):
        """Enhanced MetaDefender result checking"""
        try:
            engine = self.remote_engines['metadefender']
            
            if not engine.get('available', False) or not engine.get('api_key'):
                return None
            
            # Check result by data ID
            result_url = urljoin(engine['base_url'], f'file/{data_id}')
            headers = {'apikey': engine['api_key']}
            
            response = requests.get(result_url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                # Check if analysis is complete
                process_info = data.get('process_info', {})
                progress = process_info.get('progress_percentage', 0)
                
                if progress == 100:
                    # Analysis complete
                    return self._format_metadefender_response(data, 0, engine['name'])
                else:
                    # Still in progress
                    return {
                        'status': 'pending',
                        'message': f'Analysis in progress ({progress}% complete)'
                    }
            elif response.status_code == 404:
                return {
                    'status': 'error',
                    'message': 'Analysis not found (may have expired)'
                }
            else:
                return {
                    'status': 'error',
                    'message': f"API error: HTTP {response.status_code}"
                }
                
        except Exception as e:
            return {
                'status': 'error',
                'message': f"Exception: {str(e)}"
            }  
    
    def update_container_signatures(self, engine_id):
        """Update signatures for a containerized engine"""
        if engine_id not in self.container_engines:
            return {'success': False, 'error': 'Engine not found'}
        
        engine = self.container_engines[engine_id]
        
        try:
            update_url = urljoin(engine['url'], '/update')
            response = requests.post(update_url, timeout=300)
            
            if response.status_code == 200:
                return response.json()
            else:
                return {
                    'success': False,
                    'error': f'Update failed: HTTP {response.status_code}'
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': f'Update error: {str(e)}'
            }
    
    def get_engine_info(self):
        """Get information about all engines"""
        info = {}
        
        for engine_id, engine in self.all_engines.items():
            info[engine_id] = {
                'name': engine['name'],
                'type': engine['type'],
                'available': engine.get('available', False),
                'enabled': engine.get('enabled', False),
                'version': engine.get('version', 'Unknown'),
                'api_configured': bool(engine.get('api_key')) if engine['type'] == 'api' else True
            }
        
        return info
    
    def add_container_engine(self, engine_id, engine_config):
        """Add a new containerized engine"""
        self.container_engines[engine_id] = engine_config
        self.all_engines[engine_id] = engine_config
        self._check_container_engine(engine_id, engine_config)
    
    def update_config(self, new_config):
        """Update configuration"""
        self.config = new_config
        
        # Update enabled status
        for engine_id in self.all_engines:
            if engine_id in new_config['enabled_engines']:
                self.all_engines[engine_id]['enabled'] = new_config['enabled_engines'][engine_id]
        
        # Update API keys for remote engines
        for engine_id, engine in self.remote_engines.items():
            key_name = f"{engine_id}_api_key"
            if key_name in new_config:
                engine['api_key'] = new_config[key_name]
        
        # Re-initialize engines
        self.initialize_engines()
