"""
Database configuration and initialization for the malware analysis lab
Handles database setup, connections, and utility functions
"""

import sqlite3
import json
import os
from datetime import datetime
from .settings import Config


class DatabaseManager:
    """Manages database connections and initialization"""
    
    def __init__(self, db_path=None):
        self.db_path = db_path or Config.DATABASE_PATH
        self.init_database()
    
    def get_connection(self):
        """Get database connection with Row factory for named columns"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # This allows accessing columns by name
        return conn
    
    def init_database(self):
        """Initialize SQLite database with enhanced schema for analysis results storage"""
        # Ensure directory exists
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Files table - stores basic file information
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                sha256 TEXT UNIQUE NOT NULL,
                md5 TEXT NOT NULL,
                size INTEGER NOT NULL,
                file_type TEXT,
                upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'pending'
            )
        ''')
        
        # Analysis results table - stores comprehensive analysis data
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS analysis_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id INTEGER,
                analysis_type TEXT NOT NULL,
                result_data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (file_id) REFERENCES files (id)
            )
        ''')
        
        # YARA matches table - stores YARA rule matches
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS yara_matches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id INTEGER,
                rule_name TEXT NOT NULL,
                namespace TEXT,
                meta_data TEXT,
                string_matches TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (file_id) REFERENCES files (id)
            )
        ''')
        
        # Enhanced AV results table - stores detailed antivirus scan results
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS av_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id INTEGER,
                engine_name TEXT NOT NULL,
                status TEXT NOT NULL,
                result TEXT,
                threat_name TEXT,
                scan_time REAL,
                detections INTEGER DEFAULT 0,
                total_engines INTEGER DEFAULT 1,
                threat_score INTEGER,
                scan_id TEXT,
                data_id TEXT,
                scan_date TEXT,
                analysis_url TEXT,
                permalink TEXT,
                sha256 TEXT,
                engine_details TEXT,
                metadata TEXT,
                raw_output TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (file_id) REFERENCES files (id)
            )
        ''')
        
        # Extracted strings table - stores interesting strings found in files
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS extracted_strings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id INTEGER,
                string_value TEXT NOT NULL,
                string_type TEXT,
                category TEXT,
                context TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (file_id) REFERENCES files (id)
            )
        ''')
        
        # Create indexes for better query performance
        self._create_indexes(cursor)
        
        conn.commit()
        conn.close()
    
    def _create_indexes(self, cursor):
        """Create database indexes for better query performance"""
        indexes = [
            'CREATE INDEX IF NOT EXISTS idx_files_sha256 ON files(sha256)',
            'CREATE INDEX IF NOT EXISTS idx_files_upload_time ON files(upload_time)', 
            'CREATE INDEX IF NOT EXISTS idx_av_results_file_id ON av_results(file_id)',
            'CREATE INDEX IF NOT EXISTS idx_av_results_status ON av_results(status)',
            'CREATE INDEX IF NOT EXISTS idx_yara_matches_file_id ON yara_matches(file_id)',
            'CREATE INDEX IF NOT EXISTS idx_extracted_strings_file_id ON extracted_strings(file_id)',
            'CREATE INDEX IF NOT EXISTS idx_analysis_results_file_id ON analysis_results(file_id)'
        ]
        
        for index_sql in indexes:
            cursor.execute(index_sql)


class DatabaseHelpers:
    """Database helper functions for storing and retrieving analysis data"""
    
    @staticmethod
    def store_av_results_enhanced(cursor, file_id, av_results):
        """Store AV results with enhanced fields - SAFE version with error handling"""
        if not av_results:
            print("No AV results to store")
            return
        
        for engine_id, av_result in av_results.items():
            try:
                if not isinstance(av_result, dict):
                    print(f"Skipping invalid AV result for {engine_id}: not a dict")
                    continue
                
                # Extract detailed engine information if available
                engine_details = None
                metadata = None
                
                if 'detection_details' in av_result or 'clean_engines' in av_result:
                    try:
                        engine_details = json.dumps({
                            'detection_details': av_result.get('detection_details', []),
                            'clean_engines': av_result.get('clean_engines', [])
                        })
                    except Exception as e:
                        print(f"Error serializing engine details for {engine_id}: {e}")
                        engine_details = None
                
                if 'metadata' in av_result or 'file_info' in av_result or 'scanner_results' in av_result:
                    try:
                        metadata = json.dumps({
                            'metadata': av_result.get('metadata', {}),
                            'file_info': av_result.get('file_info', {}),
                            'engine_results': av_result.get('engine_results', {}),
                            'scanner_results': av_result.get('scanner_results', [])
                        })
                    except Exception as e:
                        print(f"Error serializing metadata for {engine_id}: {e}")
                        metadata = None
                
                # Safely serialize raw_output
                raw_output = None
                try:
                    if 'raw_output' in av_result:
                        raw_output = json.dumps(av_result.get('raw_output'))
                except Exception as e:
                    print(f"Error serializing raw_output for {engine_id}: {e}")
                    raw_output = json.dumps({'error': 'Serialization failed'})
                
                # Insert with safe value extraction
                cursor.execute('''
                    INSERT INTO av_results (
                        file_id, engine_name, status, result, threat_name, scan_time, 
                        detections, total_engines, threat_score, scan_id, data_id, scan_date,
                        analysis_url, permalink, sha256, engine_details, metadata, raw_output
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    file_id, 
                    av_result.get('engine', 'Unknown'), 
                    av_result.get('status', 'unknown'), 
                    av_result.get('result', 'No result'), 
                    av_result.get('threat_name'), 
                    av_result.get('scan_time', 0), 
                    av_result.get('detections', 0),
                    av_result.get('total_engines', 1), 
                    av_result.get('threat_score'),
                    av_result.get('scan_id'), 
                    av_result.get('data_id'), 
                    av_result.get('scan_date'),
                    av_result.get('analysis_url'), 
                    av_result.get('permalink'), 
                    av_result.get('sha256'),
                    engine_details, 
                    metadata, 
                    raw_output
                ))
                
                print(f"Successfully stored AV result for {engine_id}")
                
            except Exception as e:
                print(f"Error storing AV result for {engine_id}: {e}")
                # Try to store a minimal error record
                try:
                    cursor.execute('''
                        INSERT INTO av_results (
                            file_id, engine_name, status, result, scan_time, detections
                        )
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (
                        file_id, 
                        engine_id, 
                        'error', 
                        f'Storage error: {str(e)}', 
                        0, 
                        0
                    ))
                except Exception as e2:
                    print(f"Failed to store error record for {engine_id}: {e2}")
                    continue


class ReportGenerator:
    """Handles generation of different types of reports from database data"""
    
    @staticmethod
    def generate_summary_report(files_data, cursor):
        """Generate summary report using named columns"""
        total_files = len(files_data)
        infected_files = sum(1 for f in files_data if int(f['av_detections'] or 0) > 0)
        yara_matches = sum(int(f['yara_matches'] or 0) for f in files_data)
        
        # File type distribution
        file_types = {}
        for f in files_data:
            file_type = f['file_type'] or 'Unknown'
            file_types[file_type] = file_types.get(file_type, 0) + 1
        
        # AV engine summary
        cursor.execute('''
            SELECT engine_name, status, COUNT(*) as count
            FROM av_results
            GROUP BY engine_name, status
            ORDER BY engine_name, status
        ''')
        av_summary = cursor.fetchall()
        
        # Top threats
        cursor.execute('''
            SELECT threat_name, COUNT(*) as count
            FROM av_results
            WHERE threat_name IS NOT NULL AND threat_name != ''
            GROUP BY threat_name
            ORDER BY count DESC
            LIMIT 10
        ''')
        top_threats = cursor.fetchall()
        
        return {
            'report_type': 'Summary Report',
            'generated_at': datetime.now().isoformat(),
            'summary': {
                'total_files_analyzed': total_files,
                'infected_files': infected_files,
                'clean_files': total_files - infected_files,
                'infection_rate': round((infected_files / total_files * 100), 2) if total_files > 0 else 0,
                'total_yara_matches': yara_matches,
                'total_strings_extracted': sum(int(f['extracted_strings'] or 0) for f in files_data)
            },
            'file_types': dict(file_types),
            'av_engine_summary': [{'engine': av[0], 'status': av[1], 'count': av[2]} for av in av_summary],
            'top_threats': [{'threat': t[0], 'count': t[1]} for t in top_threats],
            'analysis_period': {
                'from': min(f['upload_time'] for f in files_data) if files_data else None,
                'to': max(f['upload_time'] for f in files_data) if files_data else None
            }
        }
    
    @staticmethod
    def generate_detailed_report(files_data, cursor):
        """Generate detailed report using named columns"""
        files_details = []
        
        for f in files_data:
            file_id = f['id']
            
            # Get YARA matches for this file
            cursor.execute('''
                SELECT rule_name, meta_data, string_matches
                FROM yara_matches WHERE file_id = ?
            ''', (file_id,))
            yara_matches = cursor.fetchall()
            
            # Get AV results for this file
            cursor.execute('''
                SELECT engine_name, status, result, threat_name, scan_time
                FROM av_results WHERE file_id = ?
            ''', (file_id,))
            av_results = cursor.fetchall()
            
            # Get interesting strings for this file
            cursor.execute('''
                SELECT string_type, category, COUNT(*) as count
                FROM extracted_strings WHERE file_id = ?
                GROUP BY string_type, category
            ''', (file_id,))
            string_summary = cursor.fetchall()
            
            # Parse analysis data safely
            analysis_data = {}
            try:
                if f['result_data']:
                    analysis_data = json.loads(f['result_data'])
            except (json.JSONDecodeError, TypeError) as e:
                print(f"Error parsing analysis data for file {file_id}: {e}")
                analysis_data = {}
            
            files_details.append({
                'file_id': file_id,
                'filename': f['filename'],
                'sha256': f['sha256'],
                'md5': f['md5'],
                'size': f['size'],
                'file_type': f['file_type'],
                'upload_time': f['upload_time'],
                'analysis_data': analysis_data,
                'yara_matches': [{'rule': y[0], 'meta': json.loads(y[1]) if y[1] else {}} for y in yara_matches],
                'av_results': [{'engine': av[0], 'status': av[1], 'result': av[2], 'threat': av[3], 'time': av[4]} for av in av_results],
                'string_summary': [{'type': s[0], 'category': s[1], 'count': s[2]} for s in string_summary]
            })
        
        return {
            'report_type': 'Detailed Report',
            'generated_at': datetime.now().isoformat(),
            'files': files_details
        }
    
    @staticmethod
    def generate_threats_report(files_data, cursor):
        """Generate threats-focused report using named columns"""
        # Only include files with detections
        threat_files = [f for f in files_data if int(f['av_detections'] or 0) > 0]
        
        threats_analysis = []
        
        for f in threat_files:
            file_id = f['id']
            
            # Get all threats detected for this file
            cursor.execute('''
                SELECT engine_name, threat_name, result, scan_time, raw_output
                FROM av_results 
                WHERE file_id = ? AND status = 'infected'
            ''', (file_id,))
            threats = cursor.fetchall()
            
            # Get YARA rule matches
            cursor.execute('''
                SELECT rule_name, meta_data
                FROM yara_matches WHERE file_id = ?
            ''', (file_id,))
            yara_threats = cursor.fetchall()
            
            # Get suspicious strings
            cursor.execute('''
                SELECT string_value, category
                FROM extracted_strings 
                WHERE file_id = ? AND string_type IN ('suspicious', 'api_call')
                LIMIT 20
            ''', (file_id,))
            suspicious_strings = cursor.fetchall()
            
            threats_analysis.append({
                'file_id': file_id,
                'filename': f['filename'],
                'sha256': f['sha256'],
                'file_type': f['file_type'],
                'upload_time': f['upload_time'],
                'av_threats': [{'engine': t[0], 'threat': t[1], 'details': t[2]} for t in threats],
                'yara_rules': [{'rule': y[0], 'meta': json.loads(y[1]) if y[1] else {}} for y in yara_threats],
                'suspicious_indicators': [{'value': s[0], 'type': s[1]} for s in suspicious_strings],
                'threat_level': 'High' if len(threats) >= 3 else 'Medium' if len(threats) >= 1 else 'Low'
            })
        
        # Threat statistics
        cursor.execute('''
            SELECT threat_name, COUNT(*) as count
            FROM av_results
            WHERE threat_name IS NOT NULL AND threat_name != '' AND status = 'infected'
            GROUP BY threat_name
            ORDER BY count DESC
        ''')
        threat_stats = cursor.fetchall()
        
        return {
            'report_type': 'Threats Report',
            'generated_at': datetime.now().isoformat(),
            'summary': {
                'total_threat_files': len(threat_files),
                'unique_threats': len(threat_stats),
                'highest_risk_files': len([f for f in threats_analysis if f['threat_level'] == 'High'])
            },
            'threat_statistics': [{'threat': t[0], 'occurrences': t[1]} for t in threat_stats],
            'threat_analysis': threats_analysis
        }


class DatabaseQueries:
    """Common database queries used throughout the application"""
    
    @staticmethod
    def get_file_by_id(cursor, file_id):
        """Get file information by ID"""
        cursor.execute('SELECT * FROM files WHERE id = ?', (file_id,))
        return cursor.fetchone()
    
    @staticmethod
    def get_file_by_hash(cursor, sha256):
        """Get file information by SHA256 hash"""
        cursor.execute('SELECT * FROM files WHERE sha256 = ?', (sha256,))
        return cursor.fetchone()
    
    @staticmethod
    def get_analysis_results(cursor, file_id, analysis_type=None):
        """Get analysis results for a file"""
        if analysis_type:
            cursor.execute('''
                SELECT result_data FROM analysis_results 
                WHERE file_id = ? AND analysis_type = ?
                ORDER BY created_at DESC LIMIT 1
            ''', (file_id, analysis_type))
        else:
            cursor.execute('''
                SELECT analysis_type, result_data, created_at 
                FROM analysis_results 
                WHERE file_id = ?
                ORDER BY created_at DESC
            ''', (file_id,))
        return cursor.fetchall()
    
    @staticmethod
    def get_yara_matches(cursor, file_id):
        """Get YARA matches for a file"""
        cursor.execute('''
            SELECT rule_name, namespace, meta_data, string_matches, created_at
            FROM yara_matches 
            WHERE file_id = ?
            ORDER BY created_at DESC
        ''', (file_id,))
        return cursor.fetchall()
    
    @staticmethod
    def get_av_results(cursor, file_id):
        """Get AV scan results for a file"""
        cursor.execute('''
            SELECT engine_name, status, result, threat_name, scan_time, detections, 
                   total_engines, threat_score, scan_id, data_id, analysis_url, 
                   permalink, engine_details, metadata, raw_output, created_at
            FROM av_results 
            WHERE file_id = ?
            ORDER BY created_at DESC
        ''', (file_id,))
        return cursor.fetchall()
    
    @staticmethod
    def get_extracted_strings(cursor, file_id, string_type=None, limit=None):
        """Get extracted strings for a file"""
        query = '''
            SELECT string_value, string_type, category, context, created_at
            FROM extracted_strings 
            WHERE file_id = ?
        '''
        params = [file_id]
        
        if string_type:
            query += ' AND string_type = ?'
            params.append(string_type)
        
        query += ' ORDER BY created_at DESC'
        
        if limit:
            query += ' LIMIT ?'
            params.append(limit)
        
        cursor.execute(query, params)
        return cursor.fetchall()
    
    @staticmethod
    def get_files_with_analysis_summary(cursor, where_clause="", params=None, limit=None):
        """Get files with analysis summary data"""
        query = '''
            SELECT f.id, f.filename, f.sha256, f.md5, f.size, f.file_type, 
                   f.upload_time, f.status, ar.result_data,
                   COUNT(DISTINCT ym.id) as yara_matches,
                   COUNT(DISTINCT CASE WHEN av.status = 'infected' THEN av.id END) as av_detections,
                   COUNT(DISTINCT es.id) as extracted_strings
            FROM files f
            LEFT JOIN analysis_results ar ON f.id = ar.file_id AND ar.analysis_type = 'comprehensive_analysis'
            LEFT JOIN yara_matches ym ON f.id = ym.file_id
            LEFT JOIN av_results av ON f.id = av.file_id
            LEFT JOIN extracted_strings es ON f.id = es.file_id
        '''
        
        if where_clause:
            query += f' {where_clause}'
        
        query += '''
            GROUP BY f.id, f.filename, f.sha256, f.md5, f.size, f.file_type, 
                     f.upload_time, f.status, ar.result_data
            ORDER BY f.upload_time DESC
        '''
        
        if limit:
            query += f' LIMIT {limit}'
        
        cursor.execute(query, params or [])
        return cursor.fetchall()
    
    @staticmethod
    def delete_file_and_related_data(cursor, file_id):
        """Delete a file and all its related analysis data"""
        # Delete from related tables first (they use file_id as foreign key)
        related_tables = ['extracted_strings', 'av_results', 'yara_matches', 'analysis_results']
    
        for table in related_tables:
            cursor.execute(f'DELETE FROM {table} WHERE file_id = ?', (file_id,))
    
        # Delete from files table last (it uses id as primary key, not file_id)
        cursor.execute('DELETE FROM files WHERE id = ?', (file_id,))
    
    @staticmethod
    def store_analysis_result(cursor, file_id, analysis_type, result_data):
        """Store analysis result data"""
        cursor.execute('''
            INSERT INTO analysis_results (file_id, analysis_type, result_data)
            VALUES (?, ?, ?)
        ''', (file_id, analysis_type, json.dumps(result_data)))
    
    @staticmethod
    def store_yara_matches(cursor, file_id, yara_matches):
        """Store YARA rule matches"""
        for match in yara_matches:
            cursor.execute('''
                INSERT INTO yara_matches (file_id, rule_name, namespace, meta_data, string_matches)
                VALUES (?, ?, ?, ?, ?)
            ''', (file_id, match['rule'], match['namespace'], 
                  json.dumps(match['meta']), json.dumps(match['strings'])))
    
    @staticmethod
    def store_extracted_strings(cursor, file_id, string_results):
        """Store extracted strings with categorization"""
        interesting_strings = []
        
        # Add pattern matches
        for pattern_type, matches in string_results.get('patterns', {}).items():
            for match in matches[:10]:  # Limit per pattern type
                interesting_strings.append((match, 'pattern', pattern_type, ''))
        
        # Add API calls
        for api_call in string_results.get('api_calls', [])[:20]:
            interesting_strings.append((
                api_call['api'], 
                'api_call', 
                api_call['category'], 
                api_call['context'][:200]
            ))
        
        # Add suspicious strings
        for sus_string in string_results.get('categorized', {}).get('suspicious', [])[:10]:
            interesting_strings.append((sus_string, 'suspicious', 'suspicious', ''))
        
        # Insert interesting strings
        for string_val, string_type, category, context in interesting_strings:
            cursor.execute('''
                INSERT INTO extracted_strings (file_id, string_value, string_type, category, context)
                VALUES (?, ?, ?, ?, ?)
            ''', (file_id, string_val, string_type, category, context))
        
        return len(interesting_strings)


_db_manager = None
_db_manager_lock = threading.Lock() if 'threading' in dir() else None

def get_db_manager():
    """Get database manager with thread-safe lazy initialization"""
    global _db_manager
    
    if _db_manager is None:
        # Import threading here to avoid circular imports
        import threading
        
        if _db_manager_lock is None:
            globals()['_db_manager_lock'] = threading.Lock()
        
        with _db_manager_lock:
            if _db_manager is None:  # Double-check locking pattern
                _db_manager = DatabaseManager()
    
    return _db_manager

def get_db_connection():
    """Get database connection - backward compatible function"""
    return get_db_manager().get_connection()

def init_database():
    """Initialize database - backward compatible function"""
    return get_db_manager().init_database()

# Create the missing db_manager instance that __init__.py expects
db_manager = get_db_manager()

# Helper function aliases for backward compatibility (keep your existing ones)
store_av_results_enhanced = DatabaseHelpers.store_av_results_enhanced
generate_summary_report_robust = ReportGenerator.generate_summary_report
generate_detailed_report_robust = ReportGenerator.generate_detailed_report
generate_threats_report_robust = ReportGenerator.generate_threats_report