"""
Download Tier 1 high-value datasets for RakshakAI Phase B v2.

These datasets are critical for improving patch coverage and language balance.
All are MIT/CC0 licensed and have high-quality vuln+patch pairs.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

# Tier 1 datasets with download commands
DATASETS = {
    "morefixes": {
        "name": "MoreFixes (2026)",
        "url": "hf:datasets/Asteriska/MoreFixes",
        "command": ["huggingface-cli", "download", "Asteriska/MoreFixes", "--repo-type=dataset", "--local-dir=v2/inputs/datasets/raw/morefixes"],
        "expected_samples": 60000,
        "patch_coverage": 1.0,
        "languages": ["C", "C++", "Python", "Java", "JavaScript", "Go", "Rust", "PHP", "Ruby", "C#"],
        "cwes": 200,
    },
    "syncve": {
        "name": "SynCVE (2026)",
        "url": "hf:datasets/CUHK/SynCVE",
        "command": ["huggingface-cli", "download", "CUHK/SynCVE", "--repo-type=dataset", "--local-dir=v2/inputs/datasets/raw/syncve"],
        "expected_samples": 72000,
        "patch_coverage": 1.0,
        "languages": ["Multi (134K CVEs)"],
        "cwes": 134,
    },
    "juliet": {
        "name": "Juliet Test Suite 1.3",
        "url": "https://samate.nist.gov/SARD/testsuite.php",
        "command": ["wget", "-O", "v2/inputs/datasets/raw/juliet.zip", "https://samate.nist.gov/SRD/testsuites/juliet/Juliet_Test_Suite_v1.3_for_C_Cpp.zip"],
        "expected_samples": 60000,
        "patch_coverage": 1.0,
        "languages": ["C", "C++", "Java"],
        "cwes": 118,
        "note": "CC0 license - completely unrestricted use",
    },
    "datadog_malicious": {
        "name": "Datadog Malicious Packages",
        "url": "git:https://github.com/DataDog/malicious-software-packages-dataset",
        "command": ["git", "clone", "--depth=1", "https://github.com/DataDog/malicious-software-packages-dataset.git", "v2/inputs/datasets/raw/datadog_malicious"],
        "expected_samples": 15000,
        "patch_coverage": 0.0,
        "languages": ["Python", "JavaScript", "Ruby", "Rust"],
        "cwes": 10,
        "note": "Supply chain attacks - unique CWE-1104 coverage",
    },
    "securityeval2": {
        "name": "SecurityEval2",
        "url": "git:https://github.com/xiaohu-art/SecurityEval2",
        "command": ["git", "clone", "--depth=1", "https://github.com/xiaohu-art/SecurityEval2.git", "v2/inputs/datasets/raw/securityeval2"],
        "expected_samples": 1400,
        "patch_coverage": 0.8,
        "languages": ["Python"],
        "cwes": 75,
    },
    "patcheval": {
        "name": "PatchEval",
        "url": "git:https://github.com/patcheval/patcheval-dataset",
        "command": ["git", "clone", "--depth=1", "https://github.com/patcheval/patcheval-dataset.git", "v2/inputs/datasets/raw/patcheval"],
        "expected_samples": 800,
        "patch_coverage": 1.0,
        "languages": ["Go", "JavaScript", "Python"],
        "cwes": 200,
        "note": "Critical for Go/JS language balance",
    },
    "sevra": {
        "name": "SEVRA",
        "url": "hf:datasets/gao-hongnan/sevra-dataset",
        "command": ["huggingface-cli", "download", "gao-hongnan/sevra-dataset", "--repo-type=dataset", "--local-dir=v2/inputs/datasets/raw/sevra"],
        "expected_samples": 2000,
        "patch_coverage": 1.0,
        "languages": ["C", "C++", "JavaScript"],
        "cwes": 159,
    },
    "oss_fuzz": {
        "name": "OSS-Fuzz Bugs",
        "url": "git:https://github.com/google/oss-fuzz",
        "command": ["git", "clone", "--depth=1", "https://github.com/google/oss-fuzz.git", "v2/inputs/datasets/raw/oss_fuzz"],
        "expected_samples": 3000,
        "patch_coverage": 0.8,
        "languages": ["C", "C++", "Go"],
        "cwes": 50,
        "note": "Real bugs without CVEs - fills gap",
    },
}


def check_prerequisites():
    """Check if required tools are installed."""
    tools = ["huggingface-cli", "git", "wget"]
    missing = []
    for tool in tools:
        try:
            subprocess.run([tool, "--version"], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            missing.append(tool)
    
    if missing:
        print(f"❌ Missing required tools: {', '.join(missing)}")
        print("\nInstall with:")
        if "huggingface-cli" in missing:
            print("  pip install huggingface-hub")
        if "wget" in missing:
            print("  brew install wget  # macOS")
        sys.exit(1)


def download_dataset(key: str, info: dict) -> bool:
    """Download a single dataset."""
    print(f"\n{'=' * 80}")
    print(f"📦 Downloading: {info['name']}")
    print(f"   URL: {info['url']}")
    print(f"   Expected samples: {info['expected_samples']:,}")
    print(f"   Patch coverage: {info['patch_coverage']:.0%}")
    print(f"   Languages: {', '.join(info['languages'])}")
    print(f"   CWEs: {info['cwes']}")
    if "note" in info:
        print(f"   Note: {info['note']}")
    print(f"{'=' * 80}\n")
    
    # Check if already downloaded
    output_dir = Path(info['command'][-1])
    if output_dir.exists() and any(output_dir.iterdir()):
        print(f"✅ Already exists: {output_dir}")
        response = input("   Re-download? (y/N): ").strip().lower()
        if response != 'y':
            print("   Skipping...")
            return True
    
    # Create output directory
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    
    # Execute download command
    try:
        result = subprocess.run(
            info['command'],
            check=True,
            capture_output=True,
            text=True,
        )
        print(f"✅ Downloaded successfully: {output_dir}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Download failed: {e}")
        print(f"   stdout: {e.stdout}")
        print(f"   stderr: {e.stderr}")
        return False


def generate_download_report(results: dict[str, bool]):
    """Generate a summary report."""
    report_path = Path("v2/dataset/download_tier1_report.json")
    
    summary = {
        "total_datasets": len(DATASETS),
        "successful": sum(results.values()),
        "failed": sum(not v for v in results.values()),
        "expected_total_samples": sum(d["expected_samples"] for d in DATASETS.values()),
        "datasets": {
            key: {
                **info,
                "downloaded": results[key],
                "output_dir": str(info['command'][-1]),
            }
            for key, info in DATASETS.items()
        },
    }
    
    with report_path.open("w") as f:
        json.dump(summary, f, indent=2)
    
    print(f"\n{'=' * 80}")
    print("📊 Download Summary")
    print(f"{'=' * 80}")
    print(f"Total datasets: {summary['total_datasets']}")
    print(f"✅ Successful: {summary['successful']}")
    print(f"❌ Failed: {summary['failed']}")
    print(f"Expected samples: {summary['expected_total_samples']:,}")
    print(f"\nReport saved: {report_path}")
    print(f"{'=' * 80}\n")


def main():
    print("🚀 RakshakAI Phase B v2 - Tier 1 Dataset Download")
    print("=" * 80)
    
    # Check prerequisites
    check_prerequisites()
    
    # Download each dataset
    results = {}
    for key, info in DATASETS.items():
        try:
            results[key] = download_dataset(key, info)
        except KeyboardInterrupt:
            print("\n\n⚠️  Download interrupted by user")
            results[key] = False
            break
        except Exception as e:
            print(f"❌ Unexpected error downloading {key}: {e}")
            results[key] = False
    
    # Generate report
    generate_download_report(results)
    
    # Next steps
    print("\n📋 Next Steps:")
    print("1. Run importers to convert to SecuritySample format:")
    print("   python v2/dataset/importers/convert_morefixes.py")
    print("   python v2/dataset/importers/convert_syncve.py")
    print("   ...")
    print("\n2. Extract hard negatives:")
    print("   python v2/dataset/extract_hard_negatives.py")
    print("\n3. Clean and deduplicate:")
    print("   python v2/dataset/clean_v2.py")


if __name__ == "__main__":
    main()
