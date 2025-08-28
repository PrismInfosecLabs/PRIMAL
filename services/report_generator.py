"""
Report Generation Service
Handles generation of different types of analysis reports
"""

import os
import json
from datetime import datetime
from config import get_db_connection


class ReportGenerator:
    """Generates various types of analysis reports from database data"""
    
    def __init__(self):
        pass
    
    def generate_report(self, report_type, date_from=None, date_to=None, file_ids=None):
        """
        Generate comprehensive analysis report
        
        Args:
            report_type (str): Type of report ('summary', 'detailed', 'threats')
            date_from (str): Start date filter (ISO format)
            date_to (str): End date filter (ISO format) 
            file_ids (list): Specific file IDs to include in report
            
        Returns:
            dict: Generated report data
        """
        if report_type not in ['summary', 'detailed', 'threats']:
            raise ValueError('Invalid report type. Must be: summary, detailed, or threats')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Build query based on parameters
            where_clause, params = self._build_query_filters(date_from, date_to, file_ids)
            
            # Get file data with analysis summary
            files_data = self._get_files_with_analysis_summary(cursor, where_clause, params)
            
            if not files_data:
                raise ValueError('No files found matching the criteria')
            
            # Generate report based on type
            if report_type == 'summary':
                report = self._generate_summary_report(files_data, cursor)
            elif report_type == 'detailed':
                report = self._generate_detailed_report(files_data, cursor)
            elif report_type == 'threats':
                report = self._generate_threats_report(files_data, cursor)
            
            return report
            
        finally:
            conn.close()
    
    def _build_query_filters(self, date_from, date_to, file_ids):
        """Build WHERE clause and parameters for database query"""
        where_conditions = []
        params = []
        
        if file_ids:
            if not isinstance(file_ids, list) or not all(isinstance(fid, int) for fid in file_ids):
                raise ValueError('Invalid file_ids format')
            placeholders = ','.join(['?' for _ in file_ids])
            where_conditions.append(f"f.id IN ({placeholders})")
            params.extend(file_ids)
        else:
            if date_from:
                where_conditions.append("f.upload_time >= ?")
                params.append(date_from)
                
            if date_to:
                where_conditions.append("f.upload_time <= ?")
                params.append(date_to)
        
        where_clause = ""
        if where_conditions:
            where_clause = "WHERE " + " AND ".join(where_conditions)
        
        return where_clause, params
    
    def _get_files_with_analysis_summary(self, cursor, where_clause, params):
        """Get files with analysis summary data"""
        query = f'''
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
            {where_clause}
            GROUP BY f.id, f.filename, f.sha256, f.md5, f.size, f.file_type, 
                     f.upload_time, f.status, ar.result_data
            ORDER BY f.upload_time DESC
        '''
        
        cursor.execute(query, params)
        return cursor.fetchall()
    
    def _generate_summary_report(self, files_data, cursor):
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
        
        # Time-based analysis
        cursor.execute('''
            SELECT DATE(upload_time) as date, COUNT(*) as files
            FROM files
            WHERE id IN ({})
            GROUP BY DATE(upload_time)
            ORDER BY date DESC
            LIMIT 30
        '''.format(','.join(['?' for _ in files_data])), 
        [f['id'] for f in files_data])
        daily_stats = cursor.fetchall()
        
        return {
            'report_type': 'Summary Report',
            'generated_at': datetime.now().isoformat(),
            'summary': {
                'total_files_analyzed': total_files,
                'infected_files': infected_files,
                'clean_files': total_files - infected_files,
                'infection_rate': round((infected_files / total_files * 100), 2) if total_files > 0 else 0,
                'total_yara_matches': yara_matches,
                'total_strings_extracted': sum(int(f['extracted_strings'] or 0) for f in files_data),
                'average_file_size': round(sum(f['size'] for f in files_data) / total_files, 2) if total_files > 0 else 0
            },
            'file_types': dict(file_types),
            'av_engine_summary': [{'engine': av[0], 'status': av[1], 'count': av[2]} for av in av_summary],
            'top_threats': [{'threat': t[0], 'count': t[1]} for t in top_threats],
            'daily_statistics': [{'date': d[0], 'files': d[1]} for d in daily_stats],
            'analysis_period': {
                'from': min(f['upload_time'] for f in files_data) if files_data else None,
                'to': max(f['upload_time'] for f in files_data) if files_data else None
            }
        }
    
    def _generate_detailed_report(self, files_data, cursor):
        """Generate detailed report using named columns"""
        files_details = []
        
        for f in files_data:
            file_id = f['id']
            
            # Get YARA matches for this file
            cursor.execute('''
                SELECT rule_name, namespace, meta_data, string_matches, created_at
                FROM yara_matches WHERE file_id = ?
                ORDER BY created_at DESC
            ''', (file_id,))
            yara_matches = cursor.fetchall()
            
            # Get AV results for this file
            cursor.execute('''
                SELECT engine_name, status, result, threat_name, scan_time, detections, 
                       total_engines, threat_score, analysis_url, created_at
                FROM av_results WHERE file_id = ?
                ORDER BY created_at DESC
            ''', (file_id,))
            av_results = cursor.fetchall()
            
            # Get interesting strings summary for this file
            cursor.execute('''
                SELECT string_type, category, COUNT(*) as count,
                       GROUP_CONCAT(string_value, ' | ') as examples
                FROM extracted_strings WHERE file_id = ?
                GROUP BY string_type, category
                ORDER BY count DESC
            ''', (file_id,))
            string_summary = cursor.fetchall()
            
            # Parse analysis data safely
            analysis_data = {}
            try:
                if f['result_data']:
                    analysis_data = json.loads(f['result_data'])
            except (json.JSONDecodeError, TypeError) as e:
                analysis_data = {'error': f'Failed to parse analysis data: {str(e)}'}
            
            # Calculate risk score
            risk_score = self._calculate_risk_score(av_results, yara_matches, string_summary)
            
            files_details.append({
                'file_id': file_id,
                'filename': f['filename'],
                'sha256': f['sha256'],
                'md5': f['md5'],
                'size': f['size'],
                'file_type': f['file_type'],
                'upload_time': f['upload_time'],
                'risk_score': risk_score,
                'analysis_data': analysis_data,
                'yara_matches': [
                    {
                        'rule': y['rule_name'], 
                        'namespace': y['namespace'],
                        'meta': json.loads(y['meta_data']) if y['meta_data'] else {},
                        'created_at': y['created_at']
                    } for y in yara_matches
                ],
                'av_results': [
                    {
                        'engine': av['engine_name'], 
                        'status': av['status'], 
                        'result': av['result'], 
                        'threat': av['threat_name'],
                        'scan_time': av['scan_time'],
                        'detections': av['detections'],
                        'analysis_url': av['analysis_url'],
                        'created_at': av['created_at']
                    } for av in av_results
                ],
                'string_summary': [
                    {
                        'type': s['string_type'], 
                        'category': s['category'], 
                        'count': s['count'],
                        'examples': s['examples'][:200] if s['examples'] else ''  # Limit examples
                    } for s in string_summary
                ]
            })
        
        return {
            'report_type': 'Detailed Report',
            'generated_at': datetime.now().isoformat(),
            'total_files': len(files_details),
            'files': files_details
        }
    
    def _generate_threats_report(self, files_data, cursor):
        """Generate threats-focused report using named columns"""
        # Only include files with detections
        threat_files = [f for f in files_data if int(f['av_detections'] or 0) > 0]
        
        threats_analysis = []
        all_threats = []
        
        for f in threat_files:
            file_id = f['id']
            
            # Get all threats detected for this file
            cursor.execute('''
                SELECT engine_name, threat_name, result, scan_time, threat_score, analysis_url
                FROM av_results 
                WHERE file_id = ? AND status = 'infected'
                ORDER BY threat_score DESC NULLS LAST, detections DESC
            ''', (file_id,))
            threats = cursor.fetchall()
            
            # Get YARA rule matches
            cursor.execute('''
                SELECT rule_name, namespace, meta_data, created_at
                FROM yara_matches WHERE file_id = ?
                ORDER BY created_at DESC
            ''', (file_id,))
            yara_threats = cursor.fetchall()
            
            # Get suspicious strings
            cursor.execute('''
                SELECT string_value, category, string_type
                FROM extracted_strings 
                WHERE file_id = ? AND string_type IN ('suspicious', 'api_call')
                ORDER BY string_type, category
                LIMIT 20
            ''', (file_id,))
            suspicious_strings = cursor.fetchall()
            
            # Calculate threat level
            threat_level = self._calculate_threat_level(threats, yara_threats, suspicious_strings)
            
            # Collect all threats for overall statistics
            for threat in threats:
                if threat['threat_name']:
                    all_threats.append(threat['threat_name'])
            
            threats_analysis.append({
                'file_id': file_id,
                'filename': f['filename'],
                'sha256': f['sha256'],
                'file_type': f['file_type'],
                'file_size': f['size'],
                'upload_time': f['upload_time'],
                'threat_level': threat_level,
                'av_threats': [
                    {
                        'engine': t['engine_name'], 
                        'threat': t['threat_name'], 
                        'details': t['result'],
                        'score': t['threat_score'],
                        'analysis_url': t['analysis_url']
                    } for t in threats
                ],
                'yara_rules': [
                    {
                        'rule': y['rule_name'], 
                        'namespace': y['namespace'],
                        'meta': json.loads(y['meta_data']) if y['meta_data'] else {}
                    } for y in yara_threats
                ],
                'suspicious_indicators': [
                    {
                        'value': s['string_value'], 
                        'type': s['category'],
                        'category': s['string_type']
                    } for s in suspicious_strings
                ]
            })
        
        # Generate threat statistics
        cursor.execute('''
            SELECT threat_name, COUNT(*) as count, AVG(threat_score) as avg_score
            FROM av_results
            WHERE threat_name IS NOT NULL AND threat_name != '' AND status = 'infected'
            GROUP BY threat_name
            ORDER BY count DESC, avg_score DESC NULLS LAST
            LIMIT 20
        ''')
        threat_stats = cursor.fetchall()
        
        # Threat family analysis
        threat_families = self._analyze_threat_families(all_threats)
        
        # Sort threats by level
        threats_analysis.sort(key=lambda x: {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}.get(x['threat_level'], 0), reverse=True)
        
        return {
            'report_type': 'Threats Report',
            'generated_at': datetime.now().isoformat(),
            'summary': {
                'total_threat_files': len(threat_files),
                'total_clean_files': len(files_data) - len(threat_files),
                'unique_threats': len(threat_stats),
                'critical_risk_files': len([f for f in threats_analysis if f['threat_level'] == 'Critical']),
                'high_risk_files': len([f for f in threats_analysis if f['threat_level'] == 'High']),
                'medium_risk_files': len([f for f in threats_analysis if f['threat_level'] == 'Medium']),
                'low_risk_files': len([f for f in threats_analysis if f['threat_level'] == 'Low'])
            },
            'threat_statistics': [
                {
                    'threat': t['threat_name'], 
                    'occurrences': t['count'],
                    'avg_score': round(t['avg_score'], 2) if t['avg_score'] else 0
                } for t in threat_stats
            ],
            'threat_families': threat_families,
            'threat_analysis': threats_analysis
        }
    
    def _calculate_risk_score(self, av_results, yara_matches, string_summary):
        """Calculate risk score for a file based on analysis results"""
        score = 0
        
        # AV detections (40% of score)
        infected_engines = len([r for r in av_results if r['status'] == 'infected'])
        if infected_engines > 0:
            score += min(40, infected_engines * 10)
        
        # YARA matches (30% of score)
        if yara_matches:
            score += min(30, len(yara_matches) * 5)
        
        # Suspicious strings (20% of score)
        suspicious_strings = sum(s['count'] for s in string_summary if s['string_type'] == 'suspicious')
        if suspicious_strings > 0:
            score += min(20, suspicious_strings * 2)
        
        # API calls (10% of score)
        api_calls = sum(s['count'] for s in string_summary if s['string_type'] == 'api_call')
        if api_calls > 0:
            score += min(10, api_calls * 1)
        
        return min(100, score)
    
    def _calculate_threat_level(self, threats, yara_matches, suspicious_strings):
        """Calculate threat level based on analysis results"""
        if len(threats) >= 3 or any(t.get('threat_score', 0) and t['threat_score'] > 80 for t in threats):
            return 'Critical'
        elif len(threats) >= 2 or len(yara_matches) >= 3:
            return 'High'
        elif len(threats) >= 1 or len(yara_matches) >= 1 or len(suspicious_strings) >= 5:
            return 'Medium'
        else:
            return 'Low'
    
    def _analyze_threat_families(self, threat_names):
        """Analyze threat families from threat names"""
        families = {}
        
        common_families = [
            'trojan', 'virus', 'worm', 'adware', 'spyware', 'ransomware',
            'backdoor', 'rootkit', 'keylogger', 'botnet', 'downloader'
        ]
        
        for threat in threat_names:
            threat_lower = threat.lower()
            family_found = False
            
            for family in common_families:
                if family in threat_lower:
                    families[family] = families.get(family, 0) + 1
                    family_found = True
                    break
            
            if not family_found:
                families['other'] = families.get('other', 0) + 1
        
        return dict(sorted(families.items(), key=lambda x: x[1], reverse=True))
    
    def save_report(self, report_data, report_filename, reports_folder):
        """Save report to file"""
        try:
            os.makedirs(reports_folder, exist_ok=True)
            filepath = os.path.join(reports_folder, report_filename)
            
            with open(filepath, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)
            
            return {
                'success': True,
                'filepath': filepath,
                'filename': report_filename,
                'size': os.path.getsize(filepath)
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def list_saved_reports(self, reports_folder):
        """List all saved report files"""
        try:
            if not os.path.exists(reports_folder):
                return []
            
            reports = []
            for filename in os.listdir(reports_folder):
                if filename.endswith('.json'):
                    filepath = os.path.join(reports_folder, filename)
                    stat = os.stat(filepath)
                    
                    # Try to get report type from filename or content
                    report_type = 'Unknown'
                    if 'summary' in filename.lower():
                        report_type = 'Summary'
                    elif 'detailed' in filename.lower():
                        report_type = 'Detailed'
                    elif 'threats' in filename.lower():
                        report_type = 'Threats'
                    
                    reports.append({
                        'filename': filename,
                        'type': report_type,
                        'size': stat.st_size,
                        'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        'download_url': f'/api/reports/download/{filename}'
                    })
            
            # Sort by creation time, newest first
            reports.sort(key=lambda x: x['created'], reverse=True)
            return reports
            
        except Exception as e:
            raise Exception(f'Failed to list reports: {str(e)}')
    
    def delete_report(self, filename, reports_folder):
        """Delete a saved report file"""
        try:
            filepath = os.path.join(reports_folder, filename)
            
            # Security check - ensure filename doesn't contain path traversal
            if '..' in filename or '/' in filename or '\\' in filename:
                raise ValueError('Invalid filename')
            
            if not os.path.exists(filepath):
                raise FileNotFoundError('Report not found')
            
            os.remove(filepath)
            
            return {
                'success': True,
                'message': f'Report {filename} deleted successfully'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_report_statistics(self):
        """Get statistics about the reporting system"""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Database statistics
            cursor.execute('SELECT COUNT(*) as total FROM files')
            total_files = cursor.fetchone()['total']
            
            cursor.execute('SELECT COUNT(DISTINCT DATE(upload_time)) as days FROM files')
            active_days = cursor.fetchone()['days']
            
            cursor.execute('SELECT COUNT(*) as total FROM av_results WHERE status = "infected"')
            total_detections = cursor.fetchone()['total']
            
            cursor.execute('SELECT COUNT(*) as total FROM yara_matches')
            total_yara_matches = cursor.fetchone()['total']
            
            return {
                'database_stats': {
                    'total_files': total_files,
                    'active_days': active_days,
                    'total_detections': total_detections,
                    'total_yara_matches': total_yara_matches,
                    'avg_files_per_day': round(total_files / active_days, 2) if active_days > 0 else 0
                },
                'available_report_types': ['summary', 'detailed', 'threats'],
                'supported_formats': ['json']
            }
            
        finally:
            conn.close()