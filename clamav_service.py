#!/usr/bin/env python3
"""
ClamAV Microservice - Improved Version
Provides a REST API for ClamAV scanning with better error handling
"""

import os
import time
import socket
import subprocess
import hashlib
from datetime import datetime
from flask import Flask, request, jsonify
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

SHARED_FILES_PATH = '/app/shared-files'
CLAMD_HOST = 'localhost'
CLAMD_PORT = 3310

class ClamAVScanner:
    def __init__(self):
        self.clamd_available = False
        self.version_info = None
        self.last_check = 0
        self._check_clamd_status()
    
    def _check_clamd_status(self):
        """Check if ClamAV daemon is running with better error handling"""
        # Don't check too frequently
        if time.time() - self.last_check < 5:
            return self.clamd_available
            
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((CLAMD_HOST, CLAMD_PORT))
            sock.close()
            
            if result == 0:
                self.clamd_available = True
                self._get_version_info()
                logger.info("? ClamAV daemon is available")
            else:
                self.clamd_available = False
                logger.warning(f"?? ClamAV daemon connection failed (code: {result})")
                
        except Exception as e:
            self.clamd_available = False
            logger.error(f"? Error checking ClamAV daemon: {e}")
        
        self.last_check = time.time()
        return self.clamd_available
    
    def _get_version_info(self):
        """Get ClamAV version information"""
        try:
            result = subprocess.run(['clamscan', '--version'], 
                                 capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                self.version_info = result.stdout.strip()
            else:
                self.version_info = "Unknown version"
        except Exception as e:
            logger.error(f"Error getting ClamAV version: {e}")
            self.version_info = "Version check failed"
    
    def _ping_clamd(self):
        """Send PING command to ClamAV daemon"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((CLAMD_HOST, CLAMD_PORT))
            sock.sendall(b'PING\n')
            response = sock.recv(1024).decode().strip()
            sock.close()
            return response == 'PONG'
        except Exception as e:
            logger.error(f"ClamAV PING failed: {e}")
            return False
    
    def scan_file(self, file_path):
        """Scan a file with ClamAV using multiple methods"""
        # Check daemon availability first
        if not self._check_clamd_status():
            return {
                'success': False,
                'error': 'ClamAV daemon not available',
                'engine': 'ClamAV',
                'status': 'error',
                'scan_time': 0,
                'debug_info': self._get_debug_info()
            }
        
        if not os.path.exists(file_path):
            return {
                'success': False,
                'error': 'File not found',
                'engine': 'ClamAV',
                'status': 'error',
                'scan_time': 0
            }
        
        start_time = time.time()
        
        # Try daemon scan first, then fallback to direct scan
        result = self._scan_with_daemon(file_path, start_time)
        if result.get('success') is False and 'daemon' in result.get('error', '').lower():
            logger.warning("Daemon scan failed, trying direct scan...")
            result = self._scan_direct(file_path, start_time)
        
        return result
    
    def _scan_with_daemon(self, file_path, start_time):
        """Scan using ClamAV daemon (faster)"""
        try:
            # Test daemon connection first
            if not self._ping_clamd():
                return {
                    'success': False,
                    'error': 'ClamAV daemon not responding to PING',
                    'engine': 'ClamAV',
                    'status': 'error',
                    'scan_time': time.time() - start_time
                }
            
            # Use clamdscan for daemon scanning
            cmd = ['clamdscan', '--no-summary', file_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            scan_time = time.time() - start_time
            
            # Calculate file hash for logging
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()[:16]
            
            logger.info(f"Daemon scanned file {file_hash} in {scan_time:.2f}s")
            
            if result.returncode == 0:
                # Clean file
                return {
                    'success': True,
                    'engine': 'ClamAV',
                    'status': 'clean',
                    'result': 'No threats detected',
                    'scan_time': round(scan_time, 2),
                    'detections': 0,
                    'version': self.version_info,
                    'scan_method': 'daemon',
                    'raw_output': result.stdout
                }
            elif result.returncode == 1:
                # Infected file
                lines = result.stdout.strip().split('\n')
                threat_line = next((line for line in lines if 'FOUND' in line), '')
                
                if threat_line:
                    threat_name = threat_line.split(':')[1].strip().replace(' FOUND', '')
                else:
                    threat_name = 'Unknown threat'
                
                return {
                    'success': True,
                    'engine': 'ClamAV',
                    'status': 'infected',
                    'result': threat_name,
                    'threat_name': threat_name,
                    'scan_time': round(scan_time, 2),
                    'detections': 1,
                    'version': self.version_info,
                    'scan_method': 'daemon',
                    'raw_output': result.stdout
                }
            else:
                # Error
                return {
                    'success': False,
                    'error': f'Daemon scan error (code {result.returncode}): {result.stderr}',
                    'engine': 'ClamAV',
                    'status': 'error',
                    'scan_time': round(scan_time, 2),
                    'raw_output': result.stderr
                }
                
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Daemon scan timeout (60s)',
                'engine': 'ClamAV',
                'status': 'timeout',
                'scan_time': 60
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Daemon scan exception: {str(e)}',
                'engine': 'ClamAV',
                'status': 'error',
                'scan_time': time.time() - start_time
            }
    
    def _scan_direct(self, file_path, start_time):
        """Scan using direct clamscan (slower but more reliable)"""
        try:
            # Use clamscan directly
            cmd = ['clamscan', '--no-summary', '--infected', file_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            scan_time = time.time() - start_time
            
            logger.info(f"Direct scan completed in {scan_time:.2f}s")
            
            if result.returncode == 0:
                # Clean file
                return {
                    'success': True,
                    'engine': 'ClamAV',
                    'status': 'clean',
                    'result': 'No threats detected',
                    'scan_time': round(scan_time, 2),
                    'detections': 0,
                    'version': self.version_info,
                    'scan_method': 'direct',
                    'raw_output': result.stdout
                }
            elif result.returncode == 1:
                # Infected file
                lines = result.stdout.strip().split('\n')
                threat_line = next((line for line in lines if 'FOUND' in line), '')
                
                if threat_line:
                    threat_name = threat_line.split(':')[1].strip().replace(' FOUND', '')
                else:
                    threat_name = 'Unknown threat'
                
                return {
                    'success': True,
                    'engine': 'ClamAV',
                    'status': 'infected',
                    'result': threat_name,
                    'threat_name': threat_name,
                    'scan_time': round(scan_time, 2),
                    'detections': 1,
                    'version': self.version_info,
                    'scan_method': 'direct',
                    'raw_output': result.stdout
                }
            else:
                # Error
                return {
                    'success': False,
                    'error': f'Direct scan error (code {result.returncode}): {result.stderr}',
                    'engine': 'ClamAV',
                    'status': 'error',
                    'scan_time': round(scan_time, 2),
                    'raw_output': result.stderr
                }
                
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Direct scan timeout (120s)',
                'engine': 'ClamAV',
                'status': 'timeout',
                'scan_time': 120
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Direct scan exception: {str(e)}',
                'engine': 'ClamAV',
                'status': 'error',
                'scan_time': time.time() - start_time
            }
    
    def _get_debug_info(self):
        """Get debug information for troubleshooting"""
        debug_info = {
            'clamd_available': self.clamd_available,
            'version': self.version_info,
            'last_check': self.last_check
        }
        
        # Check if ClamAV processes are running
        try:
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=5)
            clamd_processes = [line for line in result.stdout.split('\n') if 'clam' in line.lower()]
            debug_info['processes'] = clamd_processes
        except:
            debug_info['processes'] = ['Unable to check processes']
        
        # Check if port is open
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((CLAMD_HOST, CLAMD_PORT))
            sock.close()
            debug_info['port_3310_open'] = (result == 0)
        except:
            debug_info['port_3310_open'] = False
        
        return debug_info

# Initialize scanner
scanner = ClamAVScanner()

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint with detailed status"""
    scanner._check_clamd_status()
    
    status = 'healthy' if scanner.clamd_available else 'unhealthy'
    
    response = {
        'status': status,
        'service': 'ClamAV Scanner',
        'version': scanner.version_info,
        'clamd_available': scanner.clamd_available,
        'timestamp': datetime.now().isoformat()
    }
    
    # Add debug info if unhealthy
    if not scanner.clamd_available:
        response['debug'] = scanner._get_debug_info()
    
    return jsonify(response)

@app.route('/scan', methods=['POST'])
def scan_file():
    """Scan a file endpoint"""
    try:
        data = request.get_json()
        
        if not data or 'file_path' not in data:
            return jsonify({
                'success': False,
                'error': 'file_path parameter required'
            }), 400
        
        file_path = data['file_path']
        
        # Ensure file path is within shared directory for security
        if not file_path.startswith(SHARED_FILES_PATH):
            return jsonify({
                'success': False,
                'error': 'Invalid file path'
            }), 400
        
        result = scanner.scan_file(file_path)
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in scan endpoint: {e}")
        return jsonify({
            'success': False,
            'error': f'Internal error: {str(e)}'
        }), 500

@app.route('/scan/upload', methods=['POST'])
def scan_upload():
    """Upload and scan file endpoint"""
    try:
        if 'file' not in request.files:
            return jsonify({
                'success': False,
                'error': 'No file provided'
            }), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({
                'success': False,
                'error': 'No file selected'
            }), 400
        
        # Save file to shared directory
        filename = f"scan_{int(time.time())}_{file.filename}"
        file_path = os.path.join(SHARED_FILES_PATH, filename)
        
        # Ensure shared directory exists
        os.makedirs(SHARED_FILES_PATH, exist_ok=True)
        
        file.save(file_path)
        
        try:
            # Scan the file
            result = scanner.scan_file(file_path)
            result['filename'] = filename
            return jsonify(result)
        finally:
            # Clean up temporary file
            try:
                os.remove(file_path)
            except:
                pass
        
    except Exception as e:
        logger.error(f"Error in scan upload endpoint: {e}")
        return jsonify({
            'success': False,
            'error': f'Internal error: {str(e)}'
        }), 500

@app.route('/update', methods=['POST'])
def update_signatures():
    """Update ClamAV signatures"""
    try:
        start_time = time.time()
        result = subprocess.run(['freshclam'], capture_output=True, text=True, timeout=300)
        update_time = time.time() - start_time
        
        if result.returncode == 0:
            logger.info(f"ClamAV signatures updated successfully in {update_time:.2f}s")
            # Restart daemon after update
            scanner._check_clamd_status()
            return jsonify({
                'success': True,
                'message': 'Signatures updated successfully',
                'update_time': round(update_time, 2),
                'output': result.stdout
            })
        else:
            logger.error(f"Failed to update ClamAV signatures: {result.stderr}")
            return jsonify({
                'success': False,
                'error': 'Failed to update signatures',
                'output': result.stderr
            }), 500
            
    except subprocess.TimeoutExpired:
        return jsonify({
            'success': False,
            'error': 'Update timeout (300s)'
        }), 500
    except Exception as e:
        logger.error(f"Error updating signatures: {e}")
        return jsonify({
            'success': False,
            'error': f'Update error: {str(e)}'
        }), 500

@app.route('/status', methods=['GET'])
def get_status():
    """Get ClamAV service status with detailed information"""
    scanner._check_clamd_status()
    
    return jsonify({
        'service': 'ClamAV Scanner',
        'version': scanner.version_info,
        'clamd_available': scanner.clamd_available,
        'uptime': time.time() - start_time if 'start_time' in globals() else 0,
        'timestamp': datetime.now().isoformat(),
        'debug': scanner._get_debug_info()
    })

@app.route('/debug', methods=['GET'])
def debug_info():
    """Get detailed debug information"""
    return jsonify(scanner._get_debug_info())

if __name__ == '__main__':
    start_time = time.time()
    logger.info("?? Starting ClamAV microservice...")
    
    # Wait for ClamAV daemon to be ready
    max_wait = 60
    wait_time = 0
    while wait_time < max_wait:
        scanner._check_clamd_status()
        if scanner.clamd_available:
            break
        time.sleep(2)
        wait_time += 2
    
    if not scanner.clamd_available:
        logger.warning("?? ClamAV daemon not available after waiting, starting anyway...")
        logger.info("?? Debug info: %s", scanner._get_debug_info())
    
    app.run(host='0.0.0.0', port=5000, debug=False)