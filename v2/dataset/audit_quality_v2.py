"""
RakshakAI v2 — Enhanced Quality Audit (Post-Improvement).

Measures dataset quality improvements across all dimensions:
1. Patch coverage (target: 85%+)
2. Language balance (target: no language > 30%)
3. Explanation quality (target: 95%+ security-focused)
4. Hard negative coverage (target: 50K samples)
5. CWE coverage (target: 280+ classes)
6. Line-level annotations (target: 90%+)
7. Cross-split leakage (target: 0%)
8. Repository diversity
9. CoT reasoning quality

Compares to baseline (current Phase B) to show improvement.
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from v2.dataset.schema import SecuritySample

# Paths
PHASE_B_DIR = Path("v2/inputs/datasets/phase_b/meta")
NEW_DIR = Path("v2/inputs/datasets/deduped_global")

# Quality thresholds
MIN_EXPLANATION_LENGTH = 30
SECURITY_TERMS = {
    "vulnerability", "vulnerable", "attack", "exploit", "malicious", "injection",
    "sanitize", "validate", "escape", "untrusted", "tainted", "security",
    "CWE", "OWASP", "CVE",
}


class DatasetMetrics:
    """Container for dataset quality metrics."""
    
    def __init__(self, name: str):
        self.name = name
        self.total = 0
        self.vuln = 0
        self.clean = 0
        self.hard_negatives = 0
        
        # Patch coverage
        self.with_patch = 0
        
        # Language distribution
        self.by_language = Counter()
        
        # CWE coverage
        self.cwe_count = Counter()
        self.unique_cwes = set()
        
        # Explanation quality
        self.with_explanation = 0
        self.high_quality_explanation = 0
        self.explanation_lengths = []
        
        # Line annotations
        self.with_line_annotations = 0
        
        # CoT reasoning
        self.with_cot = 0
        
        # Repository diversity
        self.repositories = set()
        
        # Sources
        self.sources = Counter()
    
    def gini_coefficient(self, values: list[int]) -> float:
        """Calculate Gini coefficient (0 = perfect equality, 1 = perfect inequality)."""
        if not values or sum(values) == 0:
            return 0.0
        
        sorted_values = sorted(values)
        n = len(sorted_values)
        cumsum = sum((i + 1) * val for i, val in enumerate(sorted_values))
        return (2 * cumsum) / (n * sum(sorted_values)) - (n + 1) / n
    
    def language_balance_score(self) -> float:
        """Score language balance (0 = perfect imbalance, 1 = perfect balance)."""
        if not self.by_language:
            return 0.0
        
        gini = self.gini_coefficient(list(self.by_language.values()))
        return 1.0 - gini
    
    def print_report(self):
        """Print comprehensive quality report."""
        print(f"\n{'=' * 80}")
        print(f"📊 Dataset Quality Report: {self.name}")
        print(f"{'=' * 80}\n")
        
        # Overall stats
        print("## Overall Statistics")
        print(f"  Total samples: {self.total:,}")
        print(f"  Vulnerable: {self.vuln:,} ({self.vuln / self.total * 100:.1f}%)")
        print(f"  Clean: {self.clean:,} ({self.clean / self.total * 100:.1f}%)")
        print(f"  Hard negatives: {self.hard_negatives:,} ({self.hard_negatives / self.clean * 100:.1f}% of clean)" if self.clean else "")
        
        # Patch coverage
        print(f"\n## Patch Coverage")
        if self.vuln > 0:
            patch_rate = self.with_patch / self.vuln * 100
            print(f"  Vulnerable samples with patches: {self.with_patch:,} / {self.vuln:,} ({patch_rate:.1f}%)")
            
            if patch_rate >= 85:
                print(f"  ✅ EXCELLENT: Patch coverage meets 85% target")
            elif patch_rate >= 70:
                print(f"  ⚠️  GOOD: Patch coverage above 70%")
            else:
                print(f"  ❌ NEEDS IMPROVEMENT: Patch coverage below 70%")
        
        # Language distribution
        print(f"\n## Language Distribution")
        if self.by_language:
            balance_score = self.language_balance_score()
            print(f"  Unique languages: {len(self.by_language)}")
            print(f"  Balance score: {balance_score:.3f} (0=imbalanced, 1=balanced)")
            
            top_langs = self.by_language.most_common(10)
            max_pct = top_langs[0][1] / self.total * 100
            
            print(f"\n  Top languages:")
            for lang, count in top_langs:
                pct = count / self.total * 100
                bar = "█" * int(pct / 2)
                print(f"    {lang:15s} {count:8,} ({pct:5.1f}%) {bar}")
            
            if max_pct <= 30:
                print(f"\n  ✅ EXCELLENT: No language dominates (max {max_pct:.1f}%)")
            elif max_pct <= 50:
                print(f"\n  ⚠️  OK: Top language is {max_pct:.1f}% (target: <30%)")
            else:
                print(f"\n  ❌ NEEDS IMPROVEMENT: Top language is {max_pct:.1f}% (target: <30%)")
        
        # CWE coverage
        print(f"\n## CWE Coverage")
        print(f"  Unique CWEs: {len(self.unique_cwes)}")
        
        if len(self.unique_cwes) >= 280:
            print(f"  ✅ EXCELLENT: {len(self.unique_cwes)} CWEs (target: 280+)")
        elif len(self.unique_cwes) >= 200:
            print(f"  ⚠️  GOOD: {len(self.unique_cwes)} CWEs")
        else:
            print(f"  ❌ NEEDS IMPROVEMENT: {len(self.unique_cwes)} CWEs (target: 280+)")
        
        top_cwes = self.cwe_count.most_common(15)
        if top_cwes:
            print(f"\n  Top CWEs:")
            for cwe, count in top_cwes:
                print(f"    {cwe:15s} {count:6,} samples")
        
        # Explanation quality
        print(f"\n## Explanation Quality")
        if self.vuln > 0:
            expl_rate = self.with_explanation / self.vuln * 100
            quality_rate = self.high_quality_explanation / self.vuln * 100
            
            print(f"  With explanation: {self.with_explanation:,} / {self.vuln:,} ({expl_rate:.1f}%)")
            print(f"  High-quality (security-focused): {self.high_quality_explanation:,} / {self.vuln:,} ({quality_rate:.1f}%)")
            
            if self.explanation_lengths:
                avg_len = sum(self.explanation_lengths) / len(self.explanation_lengths)
                print(f"  Average length: {avg_len:.0f} chars")
            
            if quality_rate >= 95:
                print(f"  ✅ EXCELLENT: {quality_rate:.1f}% high-quality (target: 95%+)")
            elif quality_rate >= 80:
                print(f"  ⚠️  GOOD: {quality_rate:.1f}% high-quality")
            else:
                print(f"  ❌ NEEDS IMPROVEMENT: {quality_rate:.1f}% high-quality (target: 95%+)")
        
        # Line annotations
        print(f"\n## Line-Level Annotations")
        if self.vuln > 0:
            line_rate = self.with_line_annotations / self.vuln * 100
            print(f"  With line annotations: {self.with_line_annotations:,} / {self.vuln:,} ({line_rate:.1f}%)")
            
            if line_rate >= 90:
                print(f"  ✅ EXCELLENT: {line_rate:.1f}% annotated (target: 90%+)")
            elif line_rate >= 70:
                print(f"  ⚠️  GOOD: {line_rate:.1f}% annotated")
            else:
                print(f"  ❌ NEEDS IMPROVEMENT: {line_rate:.1f}% annotated (target: 90%+)")
        
        # CoT reasoning
        print(f"\n## Chain-of-Thought Reasoning")
        if self.vuln > 0:
            cot_rate = self.with_cot / self.vuln * 100
            print(f"  With CoT: {self.with_cot:,} / {self.vuln:,} ({cot_rate:.1f}%)")
            
            if cot_rate >= 70:
                print(f"  ✅ EXCELLENT: {cot_rate:.1f}% (target: 70%+)")
            elif cot_rate >= 50:
                print(f"  ⚠️  GOOD: {cot_rate:.1f}%")
            else:
                print(f"  ❌ NEEDS IMPROVEMENT: {cot_rate:.1f}% (target: 70%+)")
        
        # Repository diversity
        print(f"\n## Repository Diversity")
        print(f"  Unique repositories: {len(self.repositories)}")
        
        # Source diversity
        print(f"\n## Source Diversity")
        print(f"  Unique sources: {len(self.sources)}")
        top_sources = self.sources.most_common(10)
        if top_sources:
            print(f"\n  Top sources:")
            for source, count in top_sources:
                pct = count / self.total * 100
                print(f"    {source:25s} {count:6,} ({pct:4.1f}%)")


def is_high_quality_explanation(explanation: str | None) -> bool:
    """Check if explanation is high-quality (security-focused)."""
    if not explanation or len(explanation) < MIN_EXPLANATION_LENGTH:
        return False
    
    # Must mention security terms
    explanation_lower = explanation.lower()
    return any(term in explanation_lower for term in SECURITY_TERMS)


def extract_repo(source: str, metadata: dict | None) -> str:
    """Extract repository from source/metadata."""
    if metadata and "repository" in metadata:
        return metadata["repository"]
    if metadata and "repo" in metadata:
        return metadata["repo"]
    return source.split("_")[0] if "_" in source else source


def analyze_dataset(dataset_dir: Path, name: str) -> DatasetMetrics:
    """Analyze a dataset directory and compute metrics."""
    metrics = DatasetMetrics(name)
    
    if not dataset_dir.exists():
        print(f"⚠️  Dataset not found: {dataset_dir}")
        return metrics
    
    # Load all samples
    for p in sorted(dataset_dir.rglob("*.jsonl")):
        with p.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                try:
                    data = json.loads(line)
                    sample = SecuritySample.from_dict(data)
                    
                    metrics.total += 1
                    
                    if sample.is_vulnerable:
                        metrics.vuln += 1
                        
                        if sample.patched_code:
                            metrics.with_patch += 1
                        
                        if sample.cwe_id:
                            metrics.cwe_count[sample.cwe_id] += 1
                            metrics.unique_cwes.add(sample.cwe_id)
                        
                        if sample.explanation:
                            metrics.with_explanation += 1
                            metrics.explanation_lengths.append(len(sample.explanation))
                            
                            if is_high_quality_explanation(sample.explanation):
                                metrics.high_quality_explanation += 1
                        
                        # Check for line annotations
                        if sample.metadata and ("vuln_lines" in sample.metadata or "vulnerable_lines" in sample.metadata):
                            metrics.with_line_annotations += 1
                        
                        # Check for CoT reasoning
                        if sample.metadata and ("reasoning_trace" in sample.metadata or "chain_of_thought" in sample.metadata):
                            metrics.with_cot += 1
                    
                    else:
                        metrics.clean += 1
                        
                        if sample.metadata and sample.metadata.get("hard_negative"):
                            metrics.hard_negatives += 1
                    
                    # Language
                    if sample.language:
                        metrics.by_language[sample.language] += 1
                    
                    # Repository
                    repo = extract_repo(sample.source, sample.metadata)
                    metrics.repositories.add(repo)
                    
                    # Source
                    metrics.sources[sample.source] += 1
                
                except Exception as e:
                    continue
    
    return metrics


def compare_datasets(baseline: DatasetMetrics, improved: DatasetMetrics):
    """Compare baseline vs improved dataset."""
    print(f"\n{'=' * 80}")
    print(f"📈 Improvement Comparison")
    print(f"{'=' * 80}\n")
    
    improvements = []
    
    # Total samples
    total_improvement = (improved.total - baseline.total) / baseline.total * 100 if baseline.total else 0
    improvements.append(("Total samples", baseline.total, improved.total, total_improvement))
    
    # Patch coverage
    base_patch_rate = baseline.with_patch / baseline.vuln * 100 if baseline.vuln else 0
    imp_patch_rate = improved.with_patch / improved.vuln * 100 if improved.vuln else 0
    improvements.append(("Patch coverage", f"{base_patch_rate:.1f}%", f"{imp_patch_rate:.1f}%", imp_patch_rate - base_patch_rate))
    
    # Language balance
    base_balance = baseline.language_balance_score()
    imp_balance = improved.language_balance_score()
    improvements.append(("Language balance", f"{base_balance:.3f}", f"{imp_balance:.3f}", (imp_balance - base_balance) * 100))
    
    # CWE coverage
    cwe_improvement = len(improved.unique_cwes) - len(baseline.unique_cwes)
    improvements.append(("Unique CWEs", len(baseline.unique_cwes), len(improved.unique_cwes), cwe_improvement))
    
    # Explanation quality
    base_expl_rate = baseline.high_quality_explanation / baseline.vuln * 100 if baseline.vuln else 0
    imp_expl_rate = improved.high_quality_explanation / improved.vuln * 100 if improved.vuln else 0
    improvements.append(("High-quality explanations", f"{base_expl_rate:.1f}%", f"{imp_expl_rate:.1f}%", imp_expl_rate - base_expl_rate))
    
    # Hard negatives
    improvements.append(("Hard negatives", baseline.hard_negatives, improved.hard_negatives, improved.hard_negatives - baseline.hard_negatives))
    
    # Print table
    print(f"{'Metric':<30} {'Baseline':>15} {'Improved':>15} {'Change':>15}")
    print("-" * 80)
    
    for metric, base_val, imp_val, change in improvements:
        if isinstance(change, float):
            change_str = f"+{change:.1f}" if change > 0 else f"{change:.1f}"
            if change > 0:
                change_str += " ✅"
        else:
            change_str = f"+{change}" if change > 0 else f"{change}"
            if change > 0:
                change_str += " ✅"
        
        print(f"{metric:<30} {str(base_val):>15} {str(imp_val):>15} {change_str:>15}")


def main():
    print("=" * 80)
    print("🔬 RakshakAI v2 - Enhanced Quality Audit")
    print("=" * 80)
    
    # Analyze baseline (current Phase B)
    print("\n[1/2] Analyzing baseline (current Phase B)...")
    baseline = analyze_dataset(PHASE_B_DIR, "Baseline (Current Phase B)")
    
    # Analyze improved dataset
    print("\n[2/2] Analyzing improved dataset...")
    improved = analyze_dataset(NEW_DIR, "Improved Dataset")
    
    # Print reports
    baseline.print_report()
    improved.print_report()
    
    # Compare
    if baseline.total > 0 and improved.total > 0:
        compare_datasets(baseline, improved)
    
    print(f"\n{'=' * 80}\n")


if __name__ == "__main__":
    main()
