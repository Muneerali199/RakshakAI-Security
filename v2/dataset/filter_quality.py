#!/usr/bin/env python3
"""Filter out placeholder code, keep only real samples."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from v2.dataset.schema import write_jsonl

def is_placeholder(code: str) -> bool:
    """Check if code is a placeholder."""
    if not code or len(code.strip()) < 100:
        return True
    
    placeholder_markers = [
        "// GitHub Advisory",
        "See advisory",
        "Needs code extraction",
        "// See references for code"
    ]
    
    return any(marker in code for marker in placeholder_markers)

def filter_clean_dir():
    """Filter clean directory samples."""
    clean_dir = Path("v2/inputs/datasets/clean")
    filtered_dir = Path("v2/inputs/datasets/clean_filtered")
    filtered_dir.mkdir(exist_ok=True)
    
    total_in = 0
    total_out = 0
    
    for jsonl_file in clean_dir.rglob("*.jsonl"):
        samples_out = []
        
        with open(jsonl_file) as f:
            for line in f:
                total_in += 1
                try:
                    sample = json.loads(line)
                    
                    code = sample.get("vulnerable_code", "")
                    
                    if is_placeholder(code):
                        continue
                    
                    samples_out.append(sample)
                except:
                    continue
        
        if samples_out:
            # Preserve directory structure
            rel_path = jsonl_file.relative_to(clean_dir)
            out_file = filtered_dir / rel_path
            out_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(out_file, "w") as f:
                for s in samples_out:
                    f.write(json.dumps(s) + "\n")
        
        total_out += len(samples_out)
    
    return total_in, total_out

if __name__ == "__main__":
    print("Filtering placeholder code from clean directory...")
    
    total_in, total_out = filter_clean_dir()
    
    print(f"\nFiltered: {total_in:,} → {total_out:,} ({total_out/total_in*100:.1f}%)")
    print(f"Removed {total_in - total_out:,} placeholder samples")
    
    # Replace old clean dir with filtered
    import shutil
    clean_dir = Path("v2/inputs/datasets/clean")
    clean_backup = Path("v2/inputs/datasets/clean_backup")
    filtered_dir = Path("v2/inputs/datasets/clean_filtered")
    
    if clean_backup.exists():
        shutil.rmtree(clean_backup)
    
    shutil.move(str(clean_dir), str(clean_backup))
    shutil.move(str(filtered_dir), str(clean_dir))
    
    print(f"\n✅ Replaced clean directory (backup at clean_backup)")
