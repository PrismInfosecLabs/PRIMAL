"""
Configuration management for the malware analysis lab
Centralizes all configuration logic and provides a clean interface
"""

import os
import json
from datetime import datetime
from pathlib import Path


class Config:
    """Main configuration class for the malware analysis lab"""
    
    # Directory paths
    UPLOAD_FOLDER = '/app/uploads'
    REPORTS_FOLDER = '/app/reports'
    RULES_FOLDER = '/app/rules'
    DATABASE_PATH = '/app/data/malware_analysis.db'
    CONFIG_PATH = '/app/data/config.json'
    STRING_CONFIG_PATH = '/app/data/string_analysis_config.json'
    
    # Flask configuration
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')
    
    # Default configuration for AV engines
    DEFAULT_CONFIG = {
        'virustotal_api_key': os.environ.get('VIRUSTOTAL_API_KEY', ''),
        'metadefender_api_key': os.environ.get('METADEFENDER_API_KEY', ''),
        'hybrid_analysis_api_key': os.environ.get('HYBRID_ANALYSIS_API_KEY', ''),
        'enabled_engines': {
            'clamav': True,
            'virustotal': True,
            'hybrid_analysis': True,
            'metadefender': True
        }
    }
    
    # Default string analysis configuration
    DEFAULT_STRING_CONFIG = {
        "metadata": {
            "version": "1.0",
            "last_updated": datetime.now().isoformat(),
            "description": "String analysis configuration for malware analysis"
        },
        "regex_patterns": {
            "urls": {
                "pattern": r'https?://[^\s<>"{}|\\^`\[\]]+',
                "flags": ["IGNORECASE"],
                "description": "HTTP/HTTPS URLs",
                "category": "network",
                "enabled": True
            },
            "ips": {
                "pattern": r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
                "flags": [],
                "description": "IPv4 addresses",
                "category": "network",
                "enabled": True
            },
            "emails": {
                "pattern": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                "flags": [],
                "description": "Email addresses",
                "category": "network",
                "enabled": True
            },
            "file_paths_windows": {
                "pattern": r'[A-Za-z]:\\[^<>:"|?*\n\r]+',
                "flags": ["IGNORECASE"],
                "description": "Windows file paths",
                "category": "filesystem",
                "enabled": True
            },
            "file_paths_unix": {
                "pattern": r'/[^<>:"|?*\n\r]+',
                "flags": [],
                "description": "Unix/Linux file paths",
                "category": "filesystem",
                "enabled": True
            },
            "registry_keys": {
                "pattern": r'HKEY_[A-Z_]+\\[^<>:"|?*\n\r]+',
                "flags": ["IGNORECASE"],
                "description": "Windows registry keys",
                "category": "registry",
                "enabled": True
            },
            "domains": {
                "pattern": r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
                "flags": [],
                "description": "Domain names",
                "category": "network",
                "enabled": True
            },
            "bitcoin_addresses": {
                "pattern": r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
                "flags": [],
                "description": "Bitcoin addresses",
                "category": "cryptocurrency",
                "enabled": True
            },
            "ethereum_addresses": {
                "pattern": r'\b0x[a-fA-F0-9]{40}\b',
                "flags": [],
                "description": "Ethereum addresses",
                "category": "cryptocurrency",
                "enabled": True
            },
            "base64": {
                "pattern": r'[A-Za-z0-9+/]{20,}={0,2}',
                "flags": [],
                "description": "Base64 encoded strings",
                "category": "encoding",
                "enabled": True
            },
            "hex_strings": {
                "pattern": r'\b[0-9a-fA-F]{8,}\b',
                "flags": [],
                "description": "Hexadecimal strings",
                "category": "encoding",
                "enabled": True
            },
            "credit_cards": {
                "pattern": r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
                "flags": [],
                "description": "Credit card numbers",
                "category": "financial",
                "enabled": False
            },
            "phone_numbers": {
                "pattern": r'\b\+?[\d\s\-\(\)]{10,}\b',
                "flags": [],
                "description": "Phone numbers",
                "category": "personal",
                "enabled": False
            }
        },
        "api_calls": {
            "file_operations": {
                "calls": [
                    "CreateFile", "CreateFileA", "CreateFileW", "WriteFile", "ReadFile", 
                    "DeleteFile", "DeleteFileA", "DeleteFileW", "FindFirstFile", 
                    "FindNextFile", "CopyFile", "MoveFile"
                ],
                "description": "File manipulation APIs",
                "category": "File Operations",
                "enabled": True
            },
            "process_manipulation": {
                "calls": [
                    "CreateProcess", "CreateProcessA", "CreateProcessW", "OpenProcess", 
                    "TerminateProcess", "WriteProcessMemory", "ReadProcessMemory", 
                    "CreateRemoteThread", "VirtualAllocEx", "VirtualProtectEx"
                ],
                "description": "Process manipulation APIs",
                "category": "Process Manipulation",
                "enabled": True
            },
            "registry_access": {
                "calls": [
                    "RegCreateKey", "RegCreateKeyA", "RegCreateKeyW", "RegSetValue", 
                    "RegSetValueA", "RegSetValueW", "RegDeleteKey", "RegDeleteValue", 
                    "RegOpenKey", "RegOpenKeyA", "RegOpenKeyW", "RegQueryValue"
                ],
                "description": "Registry manipulation APIs",
                "category": "Registry Access",
                "enabled": True
            },
            "network_activity": {
                "calls": [
                    "InternetOpen", "InternetOpenA", "InternetOpenW", "InternetConnect", 
                    "HttpOpenRequest", "HttpSendRequest", "URLDownloadToFile", 
                    "WSAStartup", "socket", "connect", "send", "recv"
                ],
                "description": "Network communication APIs",
                "category": "Network Activity",
                "enabled": True
            },
            "cryptography": {
                "calls": [
                    "CryptEncrypt", "CryptDecrypt", "CryptHashData", "CryptGenKey", 
                    "CryptCreateHash", "CryptAcquireContext", "CryptReleaseContext"
                ],
                "description": "Cryptographic APIs",
                "category": "Cryptography",
                "enabled": True
            },
            "system_info": {
                "calls": [
                    "GetSystemDirectory", "GetWindowsDirectory", "GetTempPath", 
                    "GetModuleHandle", "GetCommandLine", "GetCurrentProcess", 
                    "GetSystemInfo", "GetVersionEx"
                ],
                "description": "System information APIs",
                "category": "System Information",
                "enabled": True
            },
            "persistence": {
                "calls": [
                    "CreateService", "StartService", "OpenService", "SetWindowsHook", 
                    "SetWindowsHookEx", "CreateMutex", "CreateEvent", "WinExec", 
                    "ShellExecute", "ShellExecuteA", "ShellExecuteW"
                ],
                "description": "Persistence mechanism APIs",
                "category": "Persistence",
                "enabled": True
            }
        },
        "suspicious_keywords": {
            "malware_terms": {
                "keywords": [
                    "password", "admin", "root", "login", "auth", "token", "key",
                    "decrypt", "encrypt", "payload", "shell", "cmd", "powershell",
                    "download", "upload", "backdoor", "trojan", "virus", "malware",
                    "keylog", "stealer", "ransomware", "bitcoin", "wallet"
                ],
                "description": "Common malware-related terms",
                "category": "suspicious",
                "enabled": True
            },
            "persistence_terms": {
                "keywords": [
                    "startup", "autorun", "service", "scheduled", "task", "registry",
                    "hklm", "hkcu", "run", "runonce", "winlogon", "userinit"
                ],
                "description": "Persistence-related terms",
                "category": "suspicious",
                "enabled": True
            },
            "evasion_terms": {
                "keywords": [
                    "antivirus", "firewall", "sandbox", "vm", "virtual", "debug",
                    "ollydbg", "wireshark", "procmon", "process monitor", "immunity"
                ],
                "description": "Anti-analysis and evasion terms",
                "category": "suspicious",
                "enabled": True
            }
        },
        "string_categories": {
            "length_based": {
                "short": {"min_length": 4, "max_length": 10, "description": "Short strings"},
                "medium": {"min_length": 11, "max_length": 50, "description": "Medium strings"},
                "long": {"min_length": 51, "max_length": 999999, "description": "Long strings"}
            },
            "content_based": {
                "numeric": {"pattern": r'^\d+$', "description": "Numeric strings"},
                "uppercase": {"pattern": r'^[A-Z\s]+$', "description": "Uppercase strings"},
                "mixed": {"pattern": r'^[A-Za-z0-9\s]+$', "description": "Mixed alphanumeric"}
            }
        },
        "extraction_settings": {
            "min_string_length": 4,
            "max_strings_per_file": 1000,
            "ascii_ratio_threshold": 0.7,
            "enable_unicode_extraction": True,
            "enable_ascii_extraction": True
        }
    }
    
    @classmethod
    def ensure_directories(cls):
        """Ensure all required directories exist"""
        directories = [
            cls.UPLOAD_FOLDER,
            cls.REPORTS_FOLDER, 
            cls.RULES_FOLDER,
            '/app/data',
            '/app/logs'
        ]
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)


class ConfigManager:
    """Manages loading and saving of configuration files"""
    
    def __init__(self):
        self.config_path = Config.CONFIG_PATH
        self.string_config_path = Config.STRING_CONFIG_PATH
        
    def load_config(self):
        """Load main configuration from file"""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    config = json.load(f)
                    # Merge with defaults for any missing keys
                    for key, value in Config.DEFAULT_CONFIG.items():
                        if key not in config:
                            config[key] = value
                    return config
            else:
                return Config.DEFAULT_CONFIG.copy()
        except Exception as e:
            print(f"Error loading config: {e}")
            return Config.DEFAULT_CONFIG.copy()
    
    def save_config(self, config):
        """Save main configuration to file"""
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            
            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving config: {e}")
            return False
    
    def load_string_config(self):
        """Load string analysis configuration from file"""
        try:
            if os.path.exists(self.string_config_path):
                with open(self.string_config_path, 'r') as f:
                    config = json.load(f)
                    # Merge with defaults for any missing keys
                    return self._merge_with_defaults(config, Config.DEFAULT_STRING_CONFIG)
            else:
                # Create default config file
                self.save_string_config(Config.DEFAULT_STRING_CONFIG)
                return Config.DEFAULT_STRING_CONFIG.copy()
        except Exception as e:
            print(f"Error loading string analysis config: {e}")
            return Config.DEFAULT_STRING_CONFIG.copy()
    
    def save_string_config(self, config):
        """Save string analysis configuration to file"""
        try:
            # Update metadata
            if 'metadata' not in config:
                config['metadata'] = {}
            config['metadata']['last_updated'] = datetime.now().isoformat()
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(self.string_config_path), exist_ok=True)
            
            with open(self.string_config_path, 'w') as f:
                json.dump(config, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving string analysis config: {e}")
            return False
    
    def _merge_with_defaults(self, config, defaults):
        """Deep merge loaded config with defaults to ensure all keys exist"""
        merged = defaults.copy()
        
        for section, section_data in config.items():
            if section in merged:
                if isinstance(section_data, dict) and isinstance(merged[section], dict):
                    merged[section].update(section_data)
                else:
                    merged[section] = section_data
            else:
                merged[section] = section_data
                
        return merged
    
    def validate_string_config(self, config):
        """Validate string analysis configuration structure and patterns"""
        import re
        
        errors = []
        
        # Check required sections
        required_sections = ['regex_patterns', 'api_calls', 'suspicious_keywords', 'extraction_settings']
        for section in required_sections:
            if section not in config:
                errors.append(f"Missing required section: {section}")
        
        # Validate regex patterns
        if 'regex_patterns' in config:
            for pattern_name, pattern_config in config['regex_patterns'].items():
                if 'pattern' not in pattern_config:
                    errors.append(f"Pattern {pattern_name} missing 'pattern' field")
                else:
                    try:
                        re.compile(pattern_config['pattern'])
                    except re.error as e:
                        errors.append(f"Invalid regex in {pattern_name}: {e}")
        
        # Validate extraction settings
        if 'extraction_settings' in config:
            settings = config['extraction_settings']
            if 'min_string_length' in settings:
                if not isinstance(settings['min_string_length'], int) or settings['min_string_length'] < 1:
                    errors.append("min_string_length must be a positive integer")
        
        return errors
    
    def reset_to_defaults(self, config_type='main'):
        """Reset configuration to defaults"""
        if config_type == 'main':
            return self.save_config(Config.DEFAULT_CONFIG.copy())
        elif config_type == 'string':
            return self.save_string_config(Config.DEFAULT_STRING_CONFIG.copy())
        else:
            raise ValueError("config_type must be 'main' or 'string'")


class EnvironmentConfig:
    """Handles environment-specific configuration"""
    
    @staticmethod
    def get_flask_config():
        """Get Flask-specific configuration"""
        return {
            'SECRET_KEY': Config.SECRET_KEY,
            'DEBUG': os.environ.get('FLASK_ENV') == 'development',
            'TESTING': os.environ.get('TESTING', 'false').lower() == 'true'
        }
    
    @staticmethod
    def get_container_urls():
        """Get container service URLs"""
        return {
            'clamav': os.environ.get('CLAMAV_URL', 'http://clamav-scanner:5000'),
            'shared_files_path': '/app/shared-files'
        }
    
    @staticmethod
    def get_security_settings():
        """Get security-related settings"""
        return {
            'max_file_size': 100 * 1024 * 1024,  # 100MB
            'max_filename_length': 255,
            'allowed_extensions': None,  # None = allow all
            'scan_timeout': 300  # 5 minutes
        }


# Global configuration instance for easy import
config_manager = ConfigManager()

# Convenience functions for backward compatibility
def load_config():
    """Load main configuration - backward compatible function"""
    return config_manager.load_config()

def save_config(config):
    """Save main configuration - backward compatible function"""
    return config_manager.save_config(config)

def load_string_config():
    """Load string analysis configuration"""
    return config_manager.load_string_config()

def save_string_config(config):
    """Save string analysis configuration"""
    return config_manager.save_string_config(config)