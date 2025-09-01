"""
String Analysis Service
Handles configurable string extraction and analysis from binary files
"""

import re
import os
from config import config_manager


class StringAnalysisConfig:
    """Manages string analysis configuration"""
    
    def __init__(self, config_path=None):
        self.config_path = config_path
        self.config = config_manager.load_string_config()
        
    def load_config(self):
        """Load string analysis configuration"""
        self.config = config_manager.load_string_config()
        return self.config
    
    def save_config(self, config=None):
        """Save configuration to file"""
        config_to_save = config or self.config
        success = config_manager.save_string_config(config_to_save)
        if success and config:
            self.config = config
        return success
    
    def get_compiled_patterns(self):
        """Get compiled regex patterns from configuration"""
        patterns = {}
        
        for pattern_name, pattern_config in self.config['regex_patterns'].items():
            if not pattern_config.get('enabled', True):
                continue
                
            try:
                flags = 0
                for flag in pattern_config.get('flags', []):
                    if hasattr(re, flag):
                        flags |= getattr(re, flag)
                
                patterns[pattern_name] = re.compile(pattern_config['pattern'], flags)
            except Exception as e:
                print(f"Error compiling pattern {pattern_name}: {e}")
                
        return patterns
    
    def get_api_calls_list(self):
        """Get enabled API calls list"""
        api_calls = []
        
        for group_name, group_config in self.config['api_calls'].items():
            if group_config.get('enabled', True):
                api_calls.extend(group_config['calls'])
                
        return api_calls
    
    def get_suspicious_keywords(self):
        """Get enabled suspicious keywords"""
        keywords = []
        
        for group_name, group_config in self.config['suspicious_keywords'].items():
            if group_config.get('enabled', True):
                keywords.extend(group_config['keywords'])
                
        return keywords
    
    def get_api_category(self, api_call):
        """Get category for an API call"""
        for group_name, group_config in self.config['api_calls'].items():
            if api_call in group_config['calls']:
                return group_config['category']
        return 'Other'
    
    def validate_config(self, config):
        """Validate configuration structure and patterns"""
        return config_manager.validate_string_config(config)


class ConfigurableStringExtractor:
    """Extracts and analyzes strings from files using configurable patterns"""
    
    def __init__(self, config_path=None):
        self.config_manager = StringAnalysisConfig(config_path)
        
    def reload_config(self):
        """Reload configuration from file"""
        self.config_manager = StringAnalysisConfig(self.config_manager.config_path)
    
    def extract_strings(self, file_path, min_length=None, max_strings=None):
        """Extract strings from file using configuration"""
        try:
            # Get settings from configuration
            settings = self.config_manager.config['extraction_settings']
            min_length = min_length or settings.get('min_string_length', 4)
            max_strings = max_strings or settings.get('max_strings_per_file', 1000)
            
            with open(file_path, 'rb') as f:
                data = f.read()
            
            all_strings = []
            
            # Extract ASCII strings if enabled
            if settings.get('enable_ascii_extraction', True):
                ascii_strings = self._extract_ascii_strings(data, min_length)
                all_strings.extend(ascii_strings)
            
            # Extract Unicode strings if enabled
            if settings.get('enable_unicode_extraction', True):
                unicode_strings = self._extract_unicode_strings(data, min_length, settings)
                all_strings.extend(unicode_strings)
            
            # Remove duplicates and limit
            all_strings = list(set(all_strings))
            if len(all_strings) > max_strings:
                all_strings.sort(key=len, reverse=True)
                all_strings = all_strings[:max_strings]
            
            # Categorize strings
            categorized = self._categorize_strings(all_strings)
            
            # Find patterns
            patterns_found = self._find_patterns(all_strings)
            
            # Find API calls
            api_calls_found = self._find_api_calls(all_strings)
            
            return {
                'total_strings': len(all_strings),
                'all_strings': all_strings,
                'categorized': categorized,
                'patterns': patterns_found,
                'api_calls': api_calls_found,
                'summary': self._generate_summary(categorized, patterns_found, api_calls_found),
                'config_version': self.config_manager.config['metadata'].get('version', '1.0')
            }
            
        except Exception as e:
            return {
                'error': f'String extraction failed: {str(e)}',
                'total_strings': 0,
                'all_strings': [],
                'categorized': {},
                'patterns': {},
                'api_calls': [],
                'config_version': self.config_manager.config['metadata'].get('version', '1.0')
            }
    
    def _extract_ascii_strings(self, data, min_length):
        """Extract ASCII strings from binary data"""
        strings = []
        current_string = ""
        
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current_string += chr(byte)
            else:
                if len(current_string) >= min_length:
                    strings.append(current_string)
                current_string = ""
        
        if len(current_string) >= min_length:
            strings.append(current_string)
        
        return strings
    
    def _extract_unicode_strings(self, data, min_length, settings):
        """Extract Unicode strings from binary data"""
        strings = []
        current_string = ""
        ascii_ratio_threshold = settings.get('ascii_ratio_threshold', 0.7)
        
        try:
            for i in range(0, len(data) - 1, 2):
                char = data[i:i+2]
                try:
                    decoded = char.decode('utf-16le')
                    if decoded.isprintable() and ord(decoded) < 127 and decoded not in '\r\n\t\x00':
                        current_string += decoded
                    else:
                        if len(current_string) >= min_length:
                            strings.append(current_string)
                        current_string = ""
                except:
                    if len(current_string) >= min_length:
                        strings.append(current_string)
                    current_string = ""
        except:
            pass
        
        if len(current_string) >= min_length:
            strings.append(current_string)
        
        # Filter by ASCII ratio
        filtered_strings = []
        for s in strings:
            ascii_ratio = sum(1 for c in s if ord(c) < 128) / len(s)
            if ascii_ratio > ascii_ratio_threshold:
                filtered_strings.append(s)
        
        return filtered_strings
    
    def _categorize_strings(self, strings):
        """Categorize strings using configuration"""
        categories = {
            'short': [], 'medium': [], 'long': [],
            'numeric': [], 'mixed': [], 'uppercase': [],
            'paths': [], 'suspicious': []
        }
        
        # Get category configurations
        length_based = self.config_manager.config['string_categories']['length_based']
        content_based = self.config_manager.config['string_categories']['content_based']
        
        # Get suspicious keywords
        suspicious_keywords = self.config_manager.get_suspicious_keywords()
        
        for s in strings:
            length = len(s)
            lower_s = s.lower()
            
            # Length-based categorization
            for category, config in length_based.items():
                if config['min_length'] <= length <= config['max_length']:
                    categories[category].append(s)
                    break
            
            # Content-based categorization
            if s.isdigit():
                categories['numeric'].append(s)
            elif s.isupper() and length > 3:
                categories['uppercase'].append(s)
            elif '\\' in s or '/' in s:
                categories['paths'].append(s)
            elif any(keyword in lower_s for keyword in suspicious_keywords):
                categories['suspicious'].append(s)
            else:
                categories['mixed'].append(s)
        
        # Remove duplicates and limit
        for category in categories:
            categories[category] = list(set(categories[category]))[:100]
        
        return categories
    
    def _find_patterns(self, strings):
        """Find patterns using configured regex"""
        patterns_found = {}
        text = ' '.join(strings)
        
        compiled_patterns = self.config_manager.get_compiled_patterns()
        
        for pattern_name, pattern in compiled_patterns.items():
            matches = pattern.findall(text)
            if matches:
                unique_matches = list(set(matches))[:20]
                patterns_found[pattern_name] = unique_matches
        
        return patterns_found
    
    def _find_api_calls(self, strings):
        """Find API calls using configuration"""
        found_apis = []
        api_calls = self.config_manager.get_api_calls_list()
        
        for s in strings:
            for api in api_calls:
                if api.lower() in s.lower():
                    found_apis.append({
                        'api': api,
                        'context': s,
                        'category': self.config_manager.get_api_category(api)
                    })
        
        # Remove duplicates
        seen_apis = set()
        unique_apis = []
        for api_info in found_apis:
            if api_info['api'] not in seen_apis:
                unique_apis.append(api_info)
                seen_apis.add(api_info['api'])
        
        return unique_apis[:50]
    
    def _generate_summary(self, categorized, patterns, api_calls):
        """Generate summary of findings"""
        summary = []
        
        total_interesting = sum(len(v) for k, v in categorized.items() if k in ['suspicious', 'long', 'paths'])
        if total_interesting > 0:
            summary.append(f"Found {total_interesting} potentially interesting strings")
        
        if patterns:
            pattern_types = list(patterns.keys())
            summary.append(f"Detected patterns: {', '.join(pattern_types)}")
        
        if api_calls:
            categories = list(set(api['category'] for api in api_calls))
            summary.append(f"Found {len(api_calls)} API calls in categories: {', '.join(categories)}")
        
        return summary
    
    def get_config(self):
        """Get current configuration"""
        return self.config_manager.config
    
    def update_config(self, new_config):
        """Update configuration"""
        return self.config_manager.save_config(new_config)
    
    def validate_config(self, config):
        """Validate configuration"""
        return self.config_manager.validate_config(config)
    
    def test_patterns(self, test_string, patterns=None):
        """Test regex patterns against a test string"""
        if patterns is None:
            patterns = self.config_manager.config['regex_patterns']
        
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
        
        return results
    
    def get_extraction_stats(self):
        """Get statistics about the current configuration"""
        config = self.config_manager.config
        
        stats = {
            'enabled_patterns': sum(1 for p in config['regex_patterns'].values() if p.get('enabled', True)),
            'total_patterns': len(config['regex_patterns']),
            'enabled_api_groups': sum(1 for g in config['api_calls'].values() if g.get('enabled', True)),
            'total_api_calls': sum(len(g['calls']) for g in config['api_calls'].values() if g.get('enabled', True)),
            'enabled_keyword_groups': sum(1 for g in config['suspicious_keywords'].values() if g.get('enabled', True)),
            'total_keywords': sum(len(g['keywords']) for g in config['suspicious_keywords'].values() if g.get('enabled', True)),
            'extraction_settings': config.get('extraction_settings', {})
        }
        
        return stats
    
    def reset_to_defaults(self):
        """Reset configuration to defaults"""
        return config_manager.reset_to_defaults('string')