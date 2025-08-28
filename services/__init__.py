"""
Services package for the malware analysis lab
Contains all business logic and analysis components
"""

from .yara_manager import YaraManager
from .string_extractor import ConfigurableStringExtractor, StringAnalysisConfig
from .av_scanner import AntivirusScanner
from .report_generator import ReportGenerator
from .threat_hunting import (
    ThreatHuntingGenerator,
    YaraRuleGenerator, 
    IOCGenerator,
    ThreatHuntingService
)
from .malware_analyzer import MalwareAnalyzer, FileAnalyzer

__all__ = [
    # YARA management
    'YaraManager',
    
    # String analysis
    'ConfigurableStringExtractor',
    'StringAnalysisConfig',
    
    # Antivirus scanning
    'AntivirusScanner',
    
    # Report generation
    'ReportGenerator',
    
    # Threat hunting
    'ThreatHuntingGenerator',
    'YaraRuleGenerator',
    'IOCGenerator', 
    'ThreatHuntingService',
    
    # Main analysis
    'MalwareAnalyzer',
    'FileAnalyzer'
]