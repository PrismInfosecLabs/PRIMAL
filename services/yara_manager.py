"""
YARA Rules Management Service
Handles loading, compiling, and scanning with YARA rules
"""

import os
import glob
import yara
import json
from datetime import datetime


class YaraManager:
    """Manages YARA rule loading, compilation, and scanning"""
    
    def __init__(self, rules_folder):
        self.rules_folder = rules_folder
        self.compiled_rules = None
        self.rule_stats = {}
        self.load_rules()
    
    def load_rules(self):
        """Load and compile all YARA rules with enhanced error handling"""
        try:
            rule_files = {}
            
            # Recursively find all .yar and .yara files
            yar_files = glob.glob(os.path.join(self.rules_folder, "**", "*.yar"), recursive=True) + \
                       glob.glob(os.path.join(self.rules_folder, "**", "*.yara"), recursive=True)
            
            if not yar_files:
                print("No YARA rules found. Creating sample rules...")
                self.create_sample_rules()
                yar_files = glob.glob(os.path.join(self.rules_folder, "**", "*.yar"), recursive=True)
            
            # Validate each rule file individually first
            valid_files = []
            skipped_files = []
            
            for rule_file in yar_files:
                validation_result = self._validate_rule_file(rule_file)
                if validation_result['valid']:
                    valid_files.append(rule_file)
                else:
                    print(f"?? Skipping {os.path.basename(rule_file)}: {validation_result['reason']}")
                    skipped_files.append(rule_file)
            
            # Create unique identifiers for valid rules
            for rule_file in valid_files:
                rel_path = os.path.relpath(rule_file, self.rules_folder)
                rule_name = rel_path.replace(os.sep, '_').replace('.yar', '').replace('.yara', '')
                
                # Ensure no naming conflicts
                counter = 1
                original_name = rule_name
                while rule_name in rule_files:
                    rule_name = f"{original_name}_{counter}"
                    counter += 1
                
                rule_files[rule_name] = rule_file
            
            if rule_files:
                # Try to compile all valid rules
                compilation_result = self._compile_rules_safely(rule_files)
                
                if compilation_result['success']:
                    self.compiled_rules = compilation_result['compiled_rules']
                    successful_files = compilation_result['successful_files']
                    
                    # Store statistics
                    self.rule_stats = {
                        'total_files': len(successful_files),
                        'skipped_files': len(skipped_files) + len(compilation_result['failed_files']),
                        'by_directory': {},
                        'files': {name: path for name, path in rule_files.items() 
                                 if path in successful_files},
                        'skipped': skipped_files + compilation_result['failed_files']
                    }
                    
                    # Count rules by directory
                    for rule_file in successful_files:
                        rel_path = os.path.relpath(rule_file, self.rules_folder)
                        directory = os.path.dirname(rel_path) if os.path.dirname(rel_path) else 'root'
                        if directory not in self.rule_stats['by_directory']:
                            self.rule_stats['by_directory'][directory] = 0
                        self.rule_stats['by_directory'][directory] += 1
                    
                    print(f"? Loaded {len(successful_files)} YARA rule files from {len(self.rule_stats['by_directory'])} directories")
                    if compilation_result['failed_files']:
                        print(f"?? Skipped {len(compilation_result['failed_files'])} files due to compilation errors")
                    
                    for directory, count in self.rule_stats['by_directory'].items():
                        print(f"  ?? {directory}: {count} files")
                else:
                    print("? No valid YARA rules could be compiled")
                    self.compiled_rules = None
            else:
                print("No valid YARA rules to compile")
                
        except Exception as e:
            print(f"? Error loading YARA rules: {e}")
            self.compiled_rules = None

    def _validate_rule_file(self, rule_file):
        """Validate individual rule file"""
        try:
            # Check if file is readable
            with open(rule_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Check for problematic includes
            if self.has_problematic_includes(rule_file):
                return {'valid': False, 'reason': 'Missing include dependencies'}
            
            # Try to compile individual file
            try:
                yara.compile(source=content)
                return {'valid': True, 'reason': 'File validates successfully'}
            except yara.SyntaxError as e:
                return {'valid': False, 'reason': f'YARA syntax error: {str(e)}'}
            except Exception as e:
                return {'valid': False, 'reason': f'Compilation error: {str(e)}'}
                
        except Exception as e:
            return {'valid': False, 'reason': f'File read error: {str(e)}'}

    def _compile_rules_safely(self, rule_files):
        """Attempt to compile rules with fallback strategies"""
        # First, try to compile all rules together
        try:
            compiled_rules = yara.compile(filepaths=rule_files)
            return {
                'success': True,
                'compiled_rules': compiled_rules,
                'successful_files': list(rule_files.values()),
                'failed_files': []
            }
        except Exception as e:
            print(f"? Bulk compilation failed: {e}")
            print("?? Attempting individual rule compilation...")
            
            # If bulk compilation fails, try individual files
            return self._compile_rules_individually(rule_files)

    def _compile_rules_individually(self, rule_files):
        """Compile rules one by one to isolate problematic files"""
        successful_rules = {}
        failed_files = []
        
        for rule_name, rule_path in rule_files.items():
            try:
                # Test individual compilation
                with open(rule_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                yara.compile(source=content)
                successful_rules[rule_name] = rule_path
                
            except Exception as e:
                print(f"? Failed to compile {os.path.basename(rule_path)}: {e}")
                failed_files.append(rule_path)
        
        if successful_rules:
            try:
                # Compile the successful rules together
                compiled_rules = yara.compile(filepaths=successful_rules)
                return {
                    'success': True,
                    'compiled_rules': compiled_rules,
                    'successful_files': list(successful_rules.values()),
                    'failed_files': failed_files
                }
            except Exception as e:
                print(f"? Even filtered compilation failed: {e}")
                return {
                    'success': False,
                    'compiled_rules': None,
                    'successful_files': [],
                    'failed_files': list(rule_files.values())
                }
        else:
            return {
                'success': False,
                'compiled_rules': None,
                'successful_files': [],
                'failed_files': list(rule_files.values())
            }

    def has_problematic_includes(self, rule_file):
        """Enhanced include checking with better path resolution"""
        try:
            with open(rule_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Look for include statements
            import re
            includes = re.findall(r'include\s+"([^"]+)"', content)
            
            for include_path in includes:
                # Check multiple possible locations
                possible_paths = [
                    os.path.join(os.path.dirname(rule_file), include_path),  # Relative to rule file
                    os.path.join(self.rules_folder, include_path),           # Relative to rules root
                    os.path.join(self.rules_folder, include_path.lstrip('./')), # Strip leading ./
                ]
                
                found = False
                for path in possible_paths:
                    if os.path.exists(path):
                        found = True
                        break
                
                if not found:
                    print(f"?? Missing include in {os.path.basename(rule_file)}: {include_path}")
                    return True
            
            return False
            
        except Exception as e:
            print(f"Error checking includes in {rule_file}: {e}")
            return True
    
    def get_rule_stats(self):
        """Get statistics about loaded rules"""
        return self.rule_stats
    
    def list_rule_files(self):
        """Get detailed list of all rule files (including skipped ones)"""
        rule_files = glob.glob(os.path.join(self.rules_folder, "**", "*.yar"), recursive=True) + \
                    glob.glob(os.path.join(self.rules_folder, "**", "*.yara"), recursive=True)
        
        rules_info = []
        skipped_files = self.rule_stats.get('skipped', [])
        
        for rule_file in rule_files:
            rel_path = os.path.relpath(rule_file, self.rules_folder)
            directory = os.path.dirname(rel_path) if os.path.dirname(rel_path) else 'root'
            is_skipped = rule_file in skipped_files
            
            try:
                with open(rule_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    rule_count = content.count('rule ')
            except:
                content = "Error reading file"
                rule_count = 0
            
            rules_info.append({
                'filename': os.path.basename(rule_file),
                'relative_path': rel_path,
                'directory': directory,
                'full_path': rule_file,
                'size': os.path.getsize(rule_file),
                'content': content,
                'estimated_rules': rule_count,
                'is_skipped': is_skipped,
                'status': 'Skipped (include issues)' if is_skipped else 'Loaded'
            })
        
        # Sort by directory then filename
        rules_info.sort(key=lambda x: (x['directory'], x['filename']))
        return rules_info
    
    def create_sample_rules(self):
        """Create sample YARA rules for testing"""
        sample_rules = {
            'suspicious_strings.yar': '''
rule SuspiciousStrings
{
    meta:
        description = "Detects suspicious strings in files"
        author = "Personal Lab"
        date = "2025-01-01"
        
    strings:
        $s1 = "CreateRemoteThread" nocase
        $s2 = "VirtualAllocEx" nocase
        $s3 = "WriteProcessMemory" nocase
        $s4 = "SetWindowsHookEx" nocase
        $s5 = /HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run/
        $s6 = "cmd.exe /c" nocase
        $s7 = "powershell.exe" nocase
        
    condition:
        any of ($s*)
}
''',
            'malware_families.yar': '''
rule Generic_Malware_Keywords
{
    meta:
        description = "Generic malware keywords"
        author = "Personal Lab"
        
    strings:
        $a1 = "ransomware" nocase
        $a2 = "trojan" nocase
        $a3 = "backdoor" nocase
        $a4 = "keylogger" nocase
        $a5 = "botnet" nocase
        $a6 = "crypter" nocase
        
    condition:
        any of ($a*)
}

rule Suspicious_Network_Activity
{
    meta:
        description = "Detects suspicious network-related strings"
        
    strings:
        $n1 = "POST" nocase
        $n2 = "GET" nocase
        $n3 = "HTTP" nocase
        $n4 = /[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}/
        $n5 = "socket" nocase
        $n6 = "connect" nocase
        
    condition:
        3 of ($n*)
}
'''
        }
        
        # Ensure rules folder exists
        os.makedirs(self.rules_folder, exist_ok=True)
        
        for filename, content in sample_rules.items():
            rule_path = os.path.join(self.rules_folder, filename)
            with open(rule_path, 'w') as f:
                f.write(content)
            print(f"? Created sample rule: {filename}")
    
    def scan_file(self, file_path):
        """Scan a file with YARA rules"""
        if not self.compiled_rules:
            print(f'[DEBUG] Compiled rules available: {self.compiled_rules is not None}')
            print(f'[DEBUG] Scanning file: {file_path}')
            return []

    
        try:
            matches = self.compiled_rules.match(file_path)
            print(f'[DEBUG] Matches found: {[m.rule for m in matches]}')
        
            results = []  # MOVED TO CORRECT POSITION
        
            for match in matches:
                print(f'[DEBUG] Rule: {match.rule}, Namespace: {match.namespace}')
            
                # Try to find the source file for this rule
                source_file = "Unknown"
                for rule_name, file_path_rule in self.rule_stats.get('files', {}).items():
                    if rule_name == match.namespace:
                        source_file = os.path.relpath(file_path_rule, self.rules_folder)
                        break
            
                match_data = {
                    'rule': match.rule,
                    'namespace': match.namespace,
                    'source_file': source_file,
                    'meta': dict(match.meta),
                    'strings': []
                }
            
                for string_match in match.strings:
                    match_data['strings'].append({
                        'identifier': string_match.identifier,
                        'instances': [
                            {
                                'offset': instance.offset,
                                'length': instance.matched_length,
                                'matched_data': instance.matched_data.decode('utf-8', errors='ignore')[:100]
                            }
                            for instance in string_match.instances
                        ]
                    })
            
                results.append(match_data) 
        
            return results
        
        except Exception as e:
            print(f"? Error scanning file with YARA: {e}")
            return []
    
    def reload_rules(self):
        """Reload YARA rules (useful after adding new rules)"""
        self.load_rules()
    
    def get_directories(self):
        """Get list of directories containing rules"""
        directories = set(['root'])  # Always include root
        
        if self.rule_stats and 'by_directory' in self.rule_stats:
            directories.update(self.rule_stats['by_directory'].keys())
        
        return sorted(list(directories))
    
    def get_rule_content(self, rule_path):
        """Get content of a specific rule file"""
        full_path = os.path.join(self.rules_folder, rule_path)
        
        # Security check - ensure path is within rules folder
        if not os.path.commonpath([self.rules_folder, full_path]) == self.rules_folder:
            raise ValueError("Invalid path - outside rules directory")
        
        if not os.path.exists(full_path):
            raise FileNotFoundError("Rule file not found")
        
        try:
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            raise IOError(f"Cannot read file: {str(e)}")
    
    def is_available(self):
        """Check if YARA rules are available and compiled"""
        return self.compiled_rules is not None
    
    def get_total_rules(self):
        """Get total number of rule files loaded"""
        return self.rule_stats.get('total_files', 0)
    
    def get_skipped_rules(self):
        """Get number of rule files skipped"""
        return self.rule_stats.get('skipped_files', 0)