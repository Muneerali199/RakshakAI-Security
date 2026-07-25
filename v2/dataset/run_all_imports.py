#!/usr/bin/env python3
"""Run all dataset importers sequentially for Phase B enhancement."""
import subprocess
import sys
from pathlib import Path

IMPORTS = [
    ("convert_crossvul.py", "CrossVul multi-language"),
    ("convert_morefixes.py", "MoreFixes (60K patches)"),
    ("convert_datadog.py", "DataDog malicious packages"),
    ("convert_purplellama.py", "PurpleLlama CyberSecEval"),
]

def main():
    base_dir = Path(__file__).parent / "importers"
    
    print("=" * 80)
    print("RakshakAI v2 Dataset Imports — Building World-Class Security Dataset")
    print("=" * 80)
    
    for script, desc in IMPORTS:
        script_path = base_dir / script
        if not script_path.exists():
            print(f"\n❌ SKIP: {script} (not found)")
            continue
            
        print(f"\n{'='*80}")
        print(f"▶ Running: {desc}")
        print(f"  Script: {script}")
        print(f"{'='*80}\n")
        
        try:
            result = subprocess.run(
                [sys.executable, str(script_path)],
                cwd=str(script_path.parent.parent.parent),
                capture_output=False,
                text=True,
            )
            
            if result.returncode == 0:
                print(f"\n✓ SUCCESS: {desc}")
            else:
                print(f"\n❌ FAILED: {desc} (exit code: {result.returncode})")
                print("Continuing with next importer...")
                
        except Exception as e:
            print(f"\n❌ ERROR running {script}: {e}")
            print("Continuing with next importer...")
    
    print(f"\n{'='*80}")
    print("✓ All imports completed!")
    print(f"{'='*80}\n")
    print("Next steps:")
    print("  1. python v2/dataset/dedup_global.py")
    print("  2. python v2/dataset/extract_hard_negatives.py")
    print("  3. python v2/dataset/generate_explanations.py")
    print("  4. python v2/dataset/build_phase_b.py")
    print("  5. python v2/dataset/audit_quality_v2.py")

if __name__ == "__main__":
    main()
