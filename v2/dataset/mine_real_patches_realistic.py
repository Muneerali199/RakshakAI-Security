#!/usr/bin/env python3
"""
Realistic patch mining that actually works.
Extracts patches from existing dataset sources where they already exist.
"""
import json
from pathlib import Path
from collections import defaultdict

def mine_from_existing_sources():
    """Mine patches from raw datasets that have them but weren't extracted."""
    
    raw_dir = Path("inputs/datasets/raw")
    patches_found = []
    
    # Sources known to have patches
    patch_sources = [
        "cvefixes", "github_advisory", "bigvul", "primevul", 
        "devign", "crossvul", "osv"
    ]
    
    print("🔍 Mining patches from raw dataset files...")
    
    for jsonl_file in raw_dir.glob("*.jsonl"):
        source = jsonl_file.stem
        
        if not any(ps in source for ps in patch_sources):
            continue
            
        print(f"  Checking {jsonl_file.name}...")
        count = 0
        
        try:
            for line in open(jsonl_file):
                d = json.loads(line)
                
                # Look for patch fields
                patch = d.get('patched_code') or d.get('fixed_code') or d.get('patch')
                vuln = d.get('vulnerable_code') or d.get('buggy_code')
                
                if patch and vuln and len(str(patch)) > 50:
                    patches_found.append({
                        'id': d.get('id'),
                        'source': source,
                        'vulnerable_code': vuln,
                        'patched_code': patch,
                        'language': d.get('language'),
                        'cwe': d.get('cwe')
                    })
                    count += 1
        except:
            pass
            
        if count > 0:
            print(f"    ✅ Found {count:,} patches")
    
    return patches_found

def merge_into_clean():
    """Merge found patches into clean_all.jsonl."""
    
    patches = mine_from_existing_sources()
    print(f"\n✅ Total patches mined: {len(patches):,}")
    
    if len(patches) == 0:
        print("⚠️  No additional patches found in raw datasets")
        return
    
    # Create lookup
    patch_map = {p['id']: p['patched_code'] for p in patches if p.get('id')}
    
    # Merge into clean_all
    clean_path = Path("inputs/datasets/consolidated/clean_all.jsonl")
    output_path = Path("inputs/datasets/consolidated/clean_all_with_real_patches.jsonl")
    
    updated = 0
    with open(output_path, 'w') as out:
        for line in open(clean_path):
            d = json.loads(line)
            
            # Update if we have a patch for this ID
            if d['id'] in patch_map and not d.get('patched_code'):
                d['patched_code'] = patch_map[d['id']]
                updated += 1
            
            out.write(json.dumps(d) + '\n')
    
    print(f"✅ Updated {updated:,} samples with real patches")
    print(f"📁 Saved to: {output_path}")
    
    # Calculate new coverage
    vuln = sum(1 for line in open(output_path) if json.loads(line).get('is_vulnerable'))
    patched = sum(1 for line in open(output_path) 
                  if json.loads(line).get('is_vulnerable') and 
                     json.loads(line).get('patched_code'))
    
    print(f"\n📊 New patch coverage: {patched}/{vuln} = {patched/vuln*100:.1f}%")

if __name__ == "__main__":
    merge_into_clean()
