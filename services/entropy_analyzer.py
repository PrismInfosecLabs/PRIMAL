import math
import os
from collections import Counter

class EntropyAnalyzer:
    """Dedicated entropy analysis for malware detection"""
    
    def __init__(self):
        self.block_size = 1024
        self.suspicious_threshold = 7.2
        self.low_entropy_threshold = 1.0
    
    def calculate_shannon_entropy(self, data):
        """Calculate Shannon entropy for given data"""
        if not data:
            return 0.0
        
        byte_counts = Counter(data)
        data_len = len(data)
        entropy = 0.0
        
        for count in byte_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def analyze_file(self, file_path):
        """Complete entropy analysis of a file"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        results = {
            'file_path': file_path,
            'file_size': os.path.getsize(file_path),
            'overall_entropy': 0.0,
            'entropy_blocks': [],
            'suspicious_regions': [],
            'analysis_summary': {
                'is_packed': False,
                'has_encrypted_sections': False,
                'entropy_variance': 0.0,
                'suspicious_block_count': 0
            }
        }
        
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Overall entropy
            results['overall_entropy'] = round(self.calculate_shannon_entropy(file_data), 3)
            
            # Block analysis
            block_entropies = []
            offset = 0
            
            for i in range(0, len(file_data), self.block_size):
                block_data = file_data[i:i + self.block_size]
                if len(block_data) < 64:
                    continue
                
                block_entropy = self.calculate_shannon_entropy(block_data)
                block_entropies.append(block_entropy)
                
                block_info = {
                    'offset': hex(offset),
                    'size': len(block_data),
                    'entropy': round(block_entropy, 3),
                    'classification': self._classify_entropy(block_entropy)
                }
                
                results['entropy_blocks'].append(block_info)
                
                # Track suspicious regions
                if block_entropy > self.suspicious_threshold:
                    results['suspicious_regions'].append({
                        'start_offset': hex(offset),
                        'end_offset': hex(offset + len(block_data)),
                        'entropy': round(block_entropy, 3),
                        'reason': 'High entropy - possibly packed/encrypted'
                    })
                
                offset += len(block_data)
            
            # Analysis summary
            if block_entropies:
                mean_entropy = sum(block_entropies) / len(block_entropies)
                variance = sum((e - mean_entropy) ** 2 for e in block_entropies) / len(block_entropies)
                
                results['analysis_summary'].update({
                    'is_packed': results['overall_entropy'] > 7.0,
                    'has_encrypted_sections': len(results['suspicious_regions']) > 0,
                    'entropy_variance': round(variance, 3),
                    'suspicious_block_count': len(results['suspicious_regions']),
                    'mean_block_entropy': round(mean_entropy, 3)
                })
            
            return results
            
        except Exception as e:
            raise Exception(f"Entropy analysis failed: {str(e)}")
    
    def _classify_entropy(self, entropy):
        """Classify entropy value"""
        if entropy > 7.5:
            return "high"  # Likely packed/encrypted
        elif entropy > 6.0:
            return "medium-high"  # Mixed content
        elif entropy > 3.0:
            return "medium"  # Normal executable content
        elif entropy > 1.0:
            return "low"  # Text or structured data
        else:
            return "very-low"  # Padding or repeated data