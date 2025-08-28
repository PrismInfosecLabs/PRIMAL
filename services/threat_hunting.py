"""
Threat Hunting Services
Generates KQL queries, YARA rules, and IOCs for threat hunting
"""

import os
import re
import json
from datetime import datetime


class ThreatHuntingGenerator:
    """Generates KQL queries for threat hunting based on analysis results"""
    
    def __init__(self):
        self.kql_templates = {
            'file_hash': '''
// Hunt for file by hash
DeviceFileEvents
| where SHA256 == "{sha256}" or SHA1 == "{sha1}" or MD5 == "{md5}"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName
| order by Timestamp desc
''',
            'file_name': '''
// Hunt for file by name
DeviceFileEvents
| where FileName =~ "{filename}" or FileName contains "{basename}"
| where SHA256 != "{sha256}"  // Exclude our known sample
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName
| order by Timestamp desc
''',
            'network_indicators': '''
// Hunt for network indicators from file analysis
DeviceNetworkEvents
| where RemoteUrl has_any ({urls}) or RemoteIP has_any ({ips})
| project Timestamp, DeviceName, ActionType, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName
| order by Timestamp desc

DeviceProcessEvents
| where ProcessCommandLine has_any ({domains}) or ProcessCommandLine has_any ({urls})
| project Timestamp, DeviceName, ProcessCommandLine, FileName, SHA256, InitiatingProcessFileName
| order by Timestamp desc
''',
            'registry_hunt': '''
// Hunt for registry modifications
DeviceRegistryEvents
| where RegistryKey has_any ({registry_keys})
| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
| order by Timestamp desc
''',
            'process_behavior': '''
// Hunt for suspicious process behavior
DeviceProcessEvents
| where ProcessCommandLine has_any ({suspicious_strings}) 
    or FileName has_any ({api_calls})
| where SHA256 != "{sha256}"  // Exclude our known sample
| project Timestamp, DeviceName, FileName, ProcessCommandLine, SHA256, ParentProcessName
| order by Timestamp desc
''',
            'file_creation': '''
// Hunt for file creation in suspicious locations
DeviceFileEvents
| where ActionType == "FileCreated"
| where FolderPath has_any ({file_paths}) or FileName has_any ({suspicious_names})
| where SHA256 != "{sha256}"  // Exclude our known sample
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName
| order by Timestamp desc
'''
        }

    def generate_kql_queries(self, file_data, analysis_data):
        """Generate KQL queries for threat hunting"""
        queries = {}
        
        # Extract indicators from analysis
        indicators = self._extract_indicators(analysis_data)
        
        # Generate file hash query
        queries['file_hash'] = self.kql_templates['file_hash'].format(
            sha256=file_data['sha256'],
            sha1=analysis_data.get('file_info', {}).get('sha1', ''),
            md5=file_data['md5'],
            filename=file_data['filename']
        )
        
        # Generate file name query
        basename = file_data['filename'].split('.')[0] if '.' in file_data['filename'] else file_data['filename']
        queries['file_name'] = self.kql_templates['file_name'].format(
            filename=file_data['filename'],
            basename=basename,
            sha256=file_data['sha256']
        )
        
        # Generate network indicators query if we have network IOCs
        if indicators['urls'] or indicators['ips'] or indicators['domains']:
            urls_list = '", "'.join(indicators['urls'][:10])  # Limit to top 10
            ips_list = '", "'.join(indicators['ips'][:10])
            domains_list = '", "'.join(indicators['domains'][:10])
            
            queries['network_indicators'] = self.kql_templates['network_indicators'].format(
                urls=f'"{urls_list}"' if urls_list else '""',
                ips=f'"{ips_list}"' if ips_list else '""',
                domains=f'"{domains_list}"' if domains_list else '""'
            )
        
        # Generate registry hunt query if we have registry keys
        if indicators['registry_keys']:
            reg_keys = '", "'.join(indicators['registry_keys'][:10])
            queries['registry_hunt'] = self.kql_templates['registry_hunt'].format(
                registry_keys=f'"{reg_keys}"'
            )
        
        # Generate process behavior query if we have API calls or suspicious strings
        if indicators['api_calls'] or indicators['suspicious_strings']:
            api_calls_list = '", "'.join(indicators['api_calls'][:10])
            suspicious_list = '", "'.join(indicators['suspicious_strings'][:10])
            
            queries['process_behavior'] = self.kql_templates['process_behavior'].format(
                api_calls=f'"{api_calls_list}"' if api_calls_list else '""',
                suspicious_strings=f'"{suspicious_list}"' if suspicious_list else '""',
                sha256=file_data['sha256']
            )
        
        # Generate file creation query if we have file paths
        if indicators['file_paths']:
            paths_list = '", "'.join(indicators['file_paths'][:10])
            names_list = '", "'.join([os.path.basename(p) for p in indicators['file_paths'][:10]])
            
            queries['file_creation'] = self.kql_templates['file_creation'].format(
                file_paths=f'"{paths_list}"' if paths_list else '""',
                suspicious_names=f'"{names_list}"' if names_list else '""',
                sha256=file_data['sha256']
            )
        
        return queries

    def _extract_indicators(self, analysis_data):
        """Extract indicators from analysis data"""
        indicators = {
            'urls': [],
            'ips': [],
            'domains': [],
            'registry_keys': [],
            'file_paths': [],
            'api_calls': [],
            'suspicious_strings': []
        }
        
        # Extract from string analysis
        string_analysis = analysis_data.get('string_analysis', {})
        patterns = string_analysis.get('patterns', {})
        
        if 'urls' in patterns:
            indicators['urls'] = patterns['urls'][:20]
        if 'ips' in patterns:
            indicators['ips'] = patterns['ips'][:20]
        if 'domains' in patterns:
            indicators['domains'] = patterns['domains'][:20]
        if 'registry_keys' in patterns:
            indicators['registry_keys'] = patterns['registry_keys'][:20]
        if 'file_paths' in patterns:
            indicators['file_paths'] = patterns['file_paths'][:20]
        
        # Extract API calls
        api_calls = string_analysis.get('api_calls', [])
        indicators['api_calls'] = [api['api'] for api in api_calls[:20]]
        
        # Extract suspicious strings
        categorized = string_analysis.get('categorized', {})
        if 'suspicious' in categorized:
            indicators['suspicious_strings'] = categorized['suspicious'][:20]
        
        return indicators


class YaraRuleGenerator:
    """Generates YARA rules based on analysis results"""
    
    def __init__(self):
        self.rule_template = '''rule {rule_name}
{{
    meta:
        description = "{description}"
        author = "Personal Malware Lab"
        date = "{date}"
        version = "1.0"
        hash_md5 = "{md5}"
        hash_sha256 = "{sha256}"
        file_type = "{file_type}"
        file_size = {file_size}

    strings:
{strings_section}

    condition:
        {condition}
}}'''

    def generate_yara_rule(self, file_data, analysis_data):
        """Generate YARA rule for the file"""
        rule_name = self._generate_rule_name(file_data['filename'])
        date = datetime.now().strftime('%Y-%m-%d')
        
        # Extract strings for the rule
        strings_section, condition = self._build_strings_and_condition(analysis_data)
        
        # Generate description
        description = self._generate_description(file_data, analysis_data)
        
        rule = self.rule_template.format(
            rule_name=rule_name,
            description=description,
            date=date,
            md5=file_data['md5'],
            sha256=file_data['sha256'],
            file_type=file_data['file_type'],
            file_size=file_data['size'],
            strings_section=strings_section,
            condition=condition
        )
        
        return rule

    def _generate_rule_name(self, filename):
        """Generate a valid YARA rule name"""
        # Remove extension and clean up name
        name = os.path.splitext(filename)[0]
        # Replace invalid characters with underscore
        name = re.sub(r'[^a-zA-Z0-9_]', '_', name)
        # Ensure it starts with a letter
        if name and not name[0].isalpha():
            name = 'File_' + name
        return name or 'Unknown_File'

    def _build_strings_and_condition(self, analysis_data):
        """Build strings section and condition for YARA rule"""
        strings = []
        string_vars = []
        
        # Get string analysis data
        string_analysis = analysis_data.get('string_analysis', {})
        patterns = string_analysis.get('patterns', {})
        api_calls = string_analysis.get('api_calls', [])
        categorized = string_analysis.get('categorized', {})
        
        string_count = 0
        
        # Add suspicious strings
        if 'suspicious' in categorized:
            for sus_str in categorized['suspicious'][:5]:
                if len(sus_str) >= 4:  # Minimum length
                    var_name = f'$suspicious_{string_count}'
                    strings.append(f'        {var_name} = "{self._escape_string(sus_str)}"')
                    string_vars.append(var_name)
                    string_count += 1
        
        # Add API calls
        for api in api_calls[:5]:
            var_name = f'$api_{string_count}'
            strings.append(f'        {var_name} = "{api["api"]}" nocase')
            string_vars.append(var_name)
            string_count += 1
        
        # Add network indicators
        for pattern_type in ['urls', 'domains', 'ips']:
            if pattern_type in patterns:
                for indicator in patterns[pattern_type][:3]:
                    var_name = f'${pattern_type}_{string_count}'
                    strings.append(f'        {var_name} = "{self._escape_string(indicator)}" nocase')
                    string_vars.append(var_name)
                    string_count += 1
        
        # Add registry keys
        if 'registry_keys' in patterns:
            for reg_key in patterns['registry_keys'][:3]:
                var_name = f'$registry_{string_count}'
                strings.append(f'        {var_name} = "{self._escape_string(reg_key)}" nocase')
                string_vars.append(var_name)
                string_count += 1
        
        # If we don't have enough strings, add some unique long strings
        if string_count < 3 and 'long' in categorized:
            for long_str in categorized['long'][:5]:
                if len(long_str) >= 10:
                    var_name = f'$unique_{string_count}'
                    strings.append(f'        {var_name} = "{self._escape_string(long_str)}"')
                    string_vars.append(var_name)
                    string_count += 1
                    if string_count >= 5:
                        break
        
        # Build condition
        if string_count >= 3:
            condition = f'{string_count} of them'
        elif string_count >= 1:
            condition = 'any of them'
        else:
            # Fallback to file size if no strings found
            condition = 'filesize > 0'
            strings.append('        // No unique strings found, using filesize condition')
        
        strings_section = '\n'.join(strings) if strings else '        // No strings defined'
        
        return strings_section, condition

    def _escape_string(self, s):
        """Escape string for YARA rule"""
        # Basic escaping for YARA strings
        s = s.replace('\\', '\\\\')
        s = s.replace('"', '\\"')
        s = s.replace('\n', '\\n')
        s = s.replace('\r', '\\r')
        s = s.replace('\t', '\\t')
        return s

    def _generate_description(self, file_data, analysis_data):
        """Generate rule description"""
        description = f"Detects {file_data['filename']}"
        
        # Add context based on analysis
        yara_matches = analysis_data.get('yara_matches', [])
        av_results = analysis_data.get('av_results', {})
        
        threats = []
        for engine, result in av_results.items():
            if result.get('status') == 'infected' and result.get('threat_name'):
                threats.append(result['threat_name'])
        
        if threats:
            description += f" (detected as: {', '.join(threats[:3])})"
        elif yara_matches:
            description += f" (YARA matches: {', '.join([m['rule'] for m in yara_matches[:3]])})"
        
        return description


class IOCGenerator:
    """Generates Indicators of Compromise in multiple formats"""
    
    def __init__(self):
        pass

    def generate_iocs(self, file_data, analysis_data):
        """Generate IOCs in multiple formats"""
        iocs = {
            'file_indicators': self._generate_file_indicators(file_data),
            'network_indicators': self._generate_network_indicators(analysis_data),
            'behavioral_indicators': self._generate_behavioral_indicators(analysis_data),
            'registry_indicators': self._generate_registry_indicators(analysis_data)
        }
        
        return {
            'json': self._format_as_json(iocs, file_data),
            'csv': self._format_as_csv(iocs),
            'stix': self._format_as_stix(iocs, file_data),
            'misp': self._format_as_misp(iocs, file_data)
        }

    def _generate_file_indicators(self, file_data):
        """Generate file-based indicators"""
        return {
            'md5': file_data['md5'],
            'sha256': file_data['sha256'],
            'filename': file_data['filename'],
            'file_size': file_data['size'],
            'file_type': file_data['file_type']
        }

    def _generate_network_indicators(self, analysis_data):
        """Extract network indicators"""
        patterns = analysis_data.get('string_analysis', {}).get('patterns', {})
        return {
            'urls': patterns.get('urls', [])[:10],
            'domains': patterns.get('domains', [])[:10],
            'ips': patterns.get('ips', [])[:10]
        }

    def _generate_behavioral_indicators(self, analysis_data):
        """Extract behavioral indicators"""
        api_calls = analysis_data.get('string_analysis', {}).get('api_calls', [])
        suspicious = analysis_data.get('string_analysis', {}).get('categorized', {}).get('suspicious', [])
        
        return {
            'api_calls': [api['api'] for api in api_calls[:10]],
            'suspicious_strings': suspicious[:10]
        }

    def _generate_registry_indicators(self, analysis_data):
        """Extract registry indicators"""
        patterns = analysis_data.get('string_analysis', {}).get('patterns', {})
        return {
            'registry_keys': patterns.get('registry_keys', [])[:10]
        }

    def _format_as_json(self, iocs, file_data):
        """Format IOCs as JSON"""
        return {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'source': 'Personal Malware Lab',
                'filename': file_data['filename'],
                'sha256': file_data['sha256']
            },
            'indicators': iocs
        }

    def _format_as_csv(self, iocs):
        """Format IOCs as CSV data"""
        csv_lines = ['indicator_type,indicator_value,category,confidence']
        
        # File indicators
        for key, value in iocs['file_indicators'].items():
            if value:
                csv_lines.append(f'file,{value},{key},high')
        
        # Network indicators
        for url in iocs['network_indicators']['urls']:
            csv_lines.append(f'network,{url},url,medium')
        for domain in iocs['network_indicators']['domains']:
            csv_lines.append(f'network,{domain},domain,medium')
        for ip in iocs['network_indicators']['ips']:
            csv_lines.append(f'network,{ip},ip,medium')
        
        # Registry indicators
        for reg_key in iocs['registry_indicators']['registry_keys']:
            csv_lines.append(f'registry,{reg_key},registry_key,medium')
        
        return '\n'.join(csv_lines)

    def _format_as_stix(self, iocs, file_data):
        """Format IOCs as STIX 2.1 (simplified)"""
        return {
            'type': 'bundle',
            'id': f"bundle--{file_data['sha256'][:36]}",
            'spec_version': '2.1',
            'objects': [
                {
                    'type': 'malware',
                    'id': f"malware--{file_data['sha256'][:36]}",
                    'created': datetime.now().isoformat() + 'Z',
                    'modified': datetime.now().isoformat() + 'Z',
                    'name': file_data['filename'],
                    'is_family': False,
                    'capabilities': ['spies-on-users'] if iocs['behavioral_indicators']['api_calls'] else []
                },
                {
                    'type': 'file',
                    'id': f"file--{file_data['sha256'][:36]}",
                    'hashes': {
                        'MD5': file_data['md5'],
                        'SHA-256': file_data['sha256']
                    },
                    'size': file_data['size'],
                    'name': file_data['filename']
                }
            ]
        }

    def _format_as_misp(self, iocs, file_data):
        """Format IOCs as MISP JSON (simplified)"""
        return {
            'Event': {
                'info': f"Malware analysis: {file_data['filename']}",
                'threat_level_id': '2',  # Medium
                'analysis': '2',  # Completed
                'Attribute': [
                    {
                        'category': 'Payload delivery',
                        'type': 'md5',
                        'value': file_data['md5'],
                        'to_ids': True
                    },
                    {
                        'category': 'Payload delivery', 
                        'type': 'sha256',
                        'value': file_data['sha256'],
                        'to_ids': True
                    },
                    {
                        'category': 'Payload delivery',
                        'type': 'filename',
                        'value': file_data['filename'],
                        'to_ids': True
                    }
                ]
            }
        }


class ThreatHuntingService:
    """Combined threat hunting service that coordinates all threat hunting capabilities"""
    
    def __init__(self):
        self.kql_generator = ThreatHuntingGenerator()
        self.yara_generator = YaraRuleGenerator()
        self.ioc_generator = IOCGenerator()
    
    def generate_all_threat_hunting_data(self, file_data, analysis_data):
        """Generate all threat hunting artifacts for a file"""
        return {
            'kql_queries': self.kql_generator.generate_kql_queries(file_data, analysis_data),
            'yara_rule': self.yara_generator.generate_yara_rule(file_data, analysis_data),
            'iocs': self.ioc_generator.generate_iocs(file_data, analysis_data)
        }
    
    def export_threat_hunting_content(self, file_data, analysis_data, export_type):
        """Export specific type of threat hunting content"""
        threat_data = self.generate_all_threat_hunting_data(file_data, analysis_data)
        filename_base = file_data['filename'].replace('.', '_')
        
        if export_type == 'kql':
            content = '\n\n'.join([f'// {name.replace("_", " ").title()}\n{query}' 
                                 for name, query in threat_data['kql_queries'].items()])
            filename = f'{filename_base}_kql_queries.txt'
            mimetype = 'text/plain'
            
        elif export_type == 'yara':
            content = threat_data['yara_rule']
            filename = f'{filename_base}.yar'
            mimetype = 'text/plain'
            
        elif export_type == 'iocs_json':
            content = json.dumps(threat_data['iocs']['json'], indent=2)
            filename = f'{filename_base}_iocs.json'
            mimetype = 'application/json'
            
        elif export_type == 'iocs_csv':
            content = threat_data['iocs']['csv']
            filename = f'{filename_base}_iocs.csv'
            mimetype = 'text/csv'
            
        elif export_type == 'stix':
            content = json.dumps(threat_data['iocs']['stix'], indent=2)
            filename = f'{filename_base}_stix.json'
            mimetype = 'application/json'
            
        elif export_type == 'misp':
            content = json.dumps(threat_data['iocs']['misp'], indent=2)
            filename = f'{filename_base}_misp.json'
            mimetype = 'application/json'
            
        else:
            raise ValueError('Invalid export type')
        
        return {
            'content': content,
            'filename': filename,
            'mimetype': mimetype
        }