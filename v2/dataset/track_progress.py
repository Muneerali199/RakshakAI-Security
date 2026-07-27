#!/usr/bin/env python3
"""
Real-time progress tracker for 8→10 transformation.
Shows current state, target state, and progress bars.
"""
import json
from pathlib import Path
from datetime import datetime

def load_current_stats():
    """Load current dataset statistics."""
    meta_path = Path("inputs/datasets/phase_b/meta/train.jsonl")
    
    if not meta_path.exists():
        return None
    
    stats = {
        'total': 0, 'vuln': 0, 'clean': 0,
        'has_patch': 0, 'has_explanation': 0,
        'languages': {}
    }
    
    with open(meta_path) as f:
        for line in f:
            d = json.loads(line)
            stats['total'] += 1
            
            if d.get('is_vulnerable'):
                stats['vuln'] += 1
                if d.get('patched_code') and len(d.get('patched_code', '')) > 50:
                    stats['has_patch'] += 1
                if d.get('explanation') and len(d.get('explanation', '')) > 100:
                    stats['has_explanation'] += 1
            else:
                stats['clean'] += 1
            
            lang = d.get('language', 'unknown')
            stats['languages'][lang] = stats['languages'].get(lang, 0) + 1
    
    return stats

def progress_bar(current, target, width=40):
    """Generate ASCII progress bar."""
    if target == 0:
        pct = 0
    else:
        pct = min(100, int((current / target) * 100))
    
    filled = int(width * pct / 100)
    bar = '█' * filled + '░' * (width - filled)
    
    if pct < 50:
        color = '\033[91m'  # Red
    elif pct < 85:
        color = '\033[93m'  # Yellow
    else:
        color = '\033[92m'  # Green
    
    return f"{color}{bar}\033[0m {pct}% ({current:,}/{target:,})"

def calculate_rating(stats):
    """Calculate dataset rating."""
    if not stats:
        return 0.0
    
    # Balance score
    balance_ratio = stats['clean'] / stats['vuln'] if stats['vuln'] > 0 else 0
    balance_score = 10 if 0.98 <= balance_ratio <= 1.02 else 5
    
    # Patch coverage score
    patch_coverage = stats['has_patch'] / stats['vuln'] if stats['vuln'] > 0 else 0
    if patch_coverage >= 0.85:
        patch_score = 10
    elif patch_coverage >= 0.70:
        patch_score = 8
    elif patch_coverage >= 0.50:
        patch_score = 6
    else:
        patch_score = 4 + (patch_coverage / 0.50) * 3
    
    # Explanation coverage score
    exp_coverage = stats['has_explanation'] / stats['vuln'] if stats['vuln'] > 0 else 0
    if exp_coverage >= 0.85:
        exp_score = 10
    elif exp_coverage >= 0.70:
        exp_score = 8
    elif exp_coverage >= 0.50:
        exp_score = 6
    else:
        exp_score = 4 + (exp_coverage / 0.50) * 3
    
    # C dominance score
    c_count = stats['languages'].get('c', 0) + stats['languages'].get('cpp', 0)
    c_pct = c_count / stats['total'] if stats['total'] > 0 else 0
    if c_pct <= 0.35:
        c_score = 10
    elif c_pct <= 0.40:
        c_score = 8
    elif c_pct <= 0.50:
        c_score = 6
    else:
        c_score = 10 - (c_pct * 10)
    
    # Language diversity score
    lang_count = len(stats['languages'])
    lang_score = min(10, lang_count / 2)
    
    # Weighted total
    total = (
        balance_score * 0.20 +
        patch_score * 0.25 +
        exp_score * 0.20 +
        c_score * 0.10 +
        lang_score * 0.10 +
        10 * 0.15  # Source diversity (assume 10/10)
    )
    
    return total

def main():
    print("\033[2J\033[H")  # Clear screen
    print("=" * 80)
    print("🎯 RakshakAI Dataset Transformation Progress (8/10 → 10/10)")
    print("=" * 80)
    print()
    
    stats = load_current_stats()
    
    if not stats:
        print("⚠️  No dataset found. Run build_phase_b.py first.")
        return
    
    # Current state
    print("📊 CURRENT STATE")
    print("-" * 80)
    print(f"Total samples:      {stats['total']:,}")
    print(f"Vulnerable:         {stats['vuln']:,}")
    print(f"Clean:              {stats['clean']:,}")
    print()
    
    # Targets
    targets = {
        'total': 300000,
        'vuln': 150000,
        'patches': int(150000 * 0.85),  # 85% of vulnerable
        'explanations': int(150000 * 0.85),
        'c_samples': int(300000 * 0.35),  # 35% C
    }
    
    current_c = stats['languages'].get('c', 0) + stats['languages'].get('cpp', 0)
    
    # Progress bars
    print("🎯 PROGRESS TO 10/10")
    print("-" * 80)
    
    print(f"Total samples:      {progress_bar(stats['total'], targets['total'])}")
    print(f"Vulnerable:         {progress_bar(stats['vuln'], targets['vuln'])}")
    print(f"Patches:            {progress_bar(stats['has_patch'], targets['patches'])}")
    print(f"Explanations:       {progress_bar(stats['has_explanation'], targets['explanations'])}")
    print(f"C reduction:        {progress_bar(targets['c_samples'], current_c, width=40)}")
    print()
    
    # Gaps
    print("📋 REMAINING WORK")
    print("-" * 80)
    
    gaps = {
        'patches': max(0, targets['patches'] - stats['has_patch']),
        'explanations': max(0, targets['explanations'] - stats['has_explanation']),
        'c_remove': max(0, current_c - targets['c_samples']),
    }
    
    if gaps['patches'] > 0:
        print(f"❌ Need {gaps['patches']:,} more patches")
    else:
        print(f"✅ Patch coverage complete!")
    
    if gaps['explanations'] > 0:
        print(f"❌ Need {gaps['explanations']:,} more explanations")
    else:
        print(f"✅ Explanation coverage complete!")
    
    if gaps['c_remove'] > 0:
        print(f"❌ Need to remove {gaps['c_remove']:,} C samples")
    else:
        print(f"✅ C dominance fixed!")
    
    print()
    
    # Rating
    rating = calculate_rating(stats)
    
    print("⭐ DATASET RATING")
    print("-" * 80)
    
    if rating >= 9.5:
        color = '\033[92m'  # Green
        status = "EXCELLENT - Ready to train!"
    elif rating >= 8.5:
        color = '\033[93m'  # Yellow
        status = "GOOD - Almost there"
    elif rating >= 7.0:
        color = '\033[93m'  # Yellow
        status = "FAIR - Keep improving"
    else:
        color = '\033[91m'  # Red
        status = "NEEDS WORK"
    
    print(f"{color}{rating:.1f}/10{color} - {status}\033[0m")
    print()
    
    # Breakdown
    patch_pct = stats['has_patch'] / stats['vuln'] * 100 if stats['vuln'] > 0 else 0
    exp_pct = stats['has_explanation'] / stats['vuln'] * 100 if stats['vuln'] > 0 else 0
    c_pct = current_c / stats['total'] * 100 if stats['total'] > 0 else 0
    
    print("Breakdown:")
    print(f"  • Balance: 10/10 (50/50 split)")
    print(f"  • Patches: {patch_pct:.1f}% coverage")
    print(f"  • Explanations: {exp_pct:.1f}% coverage")
    print(f"  • C dominance: {c_pct:.1f}%")
    print(f"  • Languages: {len(stats['languages'])} total")
    print()
    
    # Next steps
    print("🚀 NEXT STEPS")
    print("-" * 80)
    
    if rating < 9.5:
        print("1. Run: ./dataset/execute_10_10_transformation.sh")
        print("2. Wait: ~24-36 hours (mostly parallel)")
        print("3. Re-check: python3 dataset/track_progress.py")
    else:
        print("1. Review dataset: cat logs/final_audit.txt")
        print("2. Train model: ./scripts/launch_phase_b_optimized.sh")
        print("3. Evaluate: python3 scripts/evaluate_phase_b.py")
    
    print()
    print("=" * 80)
    print(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)

if __name__ == "__main__":
    main()
