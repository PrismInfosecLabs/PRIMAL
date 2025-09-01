#!/usr/bin/env python3
"""
Fix YARA Include Issues
This script fixes broken include statements in YARA rules
"""

import os
import re
import glob
import shutil
from pathlib import Path

def fix_yara_includes(rules_folder):
    """Fix broken include statements in YARA rules"""
    print(f"🔧 Fixing YARA includes in {rules_folder}")
    
    # Find all YARA files
    yar_files = glob.glob(os.path.join(rules_folder, "**", "*.yar"), recursive=True) + \
               glob.glob(os.path.join(rules_folder, "**", "*.yara"), recursive=True)
    
    fixed_count = 0
    removed_count = 0
    
    for rule_file in yar_files:
        try:
            with open(rule_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            original_content = content
            
            # Find include statements
            includes = re.findall(r'include\s+"([^"]+)"', content)
            
            for include_path in includes:
                # Check if include file exists
                rule_dir = os.path.dirname(rule_file)
                full_include_path = os.path.join(rule_dir, include_path)
                alt_path = os.path.join(rules_folder, include_path)
                
                if not os.path.exists(full_include_path) and not os.path.exists(alt_path):
                    print(f"  ❌ Removing broken include: {include_path} from {os.path.basename(rule_file)}")
                    # Comment out the broken include
                    content = content.replace(f'include "{include_path}"', f'// include "{include_path}" // REMOVED - FILE NOT FOUND')
                    removed_count += 1
            
            # Write back if changed
            if content != original_content:
                with open(rule_file, 'w', encoding='utf-8') as f:
                    f.write(content)
                fixed_count += 1
                
        except Exception as e:
            print(f"  ⚠️ Error processing {rule_file}: {e}")
    
    print(f"✅ Fixed {fixed_count} files, removed {removed_count} broken includes")

def clean_problematic_rules(rules_folder):
    """Remove or fix rules that are known to cause issues"""
    print(f"🧹 Cleaning problematic rules in {rules_folder}")
    
    problematic_patterns = [
        "WShell_THOR_Webshells.yar",
        "MALW_AZORULT.yar",
        # Add more problematic files as needed
    ]
    
    for pattern in problematic_patterns:
        files = glob.glob(os.path.join(rules_folder, "**", pattern), recursive=True)
        for file_path in files:
            try:
                # Move to backup instead of deleting
                backup_path = file_path + ".backup"
                shutil.move(file_path, backup_path)
                print(f"  📦 Moved problematic rule to backup: {os.path.basename(file_path)}")
            except Exception as e:
                print(f"  ⚠️ Error handling {file_path}: {e}")

def create_minimal_rules(rules_folder):
    """Create minimal working YARA rules if none exist"""
    minimal_rules_file = os.path.join(rules_folder, "minimal_rules.yar")
    
    if not os.path.exists(minimal_rules_file):
        minimal_rules = '''
rule SuspiciousExecutable
{
    meta:
        description = "Detects suspicious executable patterns"
        author = "PRIMAL v2.0"
        
    strings:
        $mz = { 4D 5A }
        $pe = "PE"
        
    condition:
        $mz at 0 and $pe
}

rule SuspiciousStrings
{
    meta:
        description = "Detects suspicious strings"
        author = "PRIMAL v2.0"
        
    strings:
        $s1 = "CreateRemoteThread" nocase
        $s2 = "VirtualAllocEx" nocase
        $s3 = "WriteProcessMemory" nocase
        
    condition:
        any of them
}
'''
        
        with open(minimal_rules_file, 'w') as f:
            f.write(minimal_rules)
        print(f"✅ Created minimal rules file: {minimal_rules_file}")

if __name__ == "__main__":
    rules_folder = "/app/rules"
    
    print("🔍 YARA Rules Diagnostic and Fix Tool")
    print("=" * 50)
    
    # Check if rules folder exists
    if not os.path.exists(rules_folder):
        print(f"❌ Rules folder not found: {rules_folder}")
        os.makedirs(rules_folder, exist_ok=True)
        print(f"✅ Created rules folder: {rules_folder}")
    
    # Create minimal rules first
    create_minimal_rules(rules_folder)
    
    # Clean problematic rules
    clean_problematic_rules(rules_folder)
    
    # Fix includes
    fix_yara_includes(rules_folder)
    
    print("✅ YARA rules cleanup completed!")
