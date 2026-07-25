#!/usr/bin/env python3
"""Example: scan a file for vulnerabilities using RakshakAI."""
import sys
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from rakshakai.inference import RakshakInference

def main():
    if len(sys.argv) < 2:
        print("Usage: python scan_file.py <file_path>")
        sys.exit(1)

    filepath = sys.argv[1]
    with open(filepath) as f:
        code = f.read()

    # Auto-detect language from extension
    ext = Path(filepath).suffix.lower()
    lang_map = {".py": "python", ".js": "javascript", ".ts": "typescript",
                ".java": "java", ".php": "php", ".go": "go", ".rb": "ruby"}
    language = lang_map.get(ext, "python")

    # Load model and scan
    engine = RakshakInference()
    issues = engine.scan_file(code, language)

    if not issues:
        print(f"✅ No issues found in {filepath}")
        return

    print(f"🔍 Found {len(issues)} issue(s) in {filepath}:")
    for issue in issues:
        print(f"  Line {issue['line']:4d} | [{issue['severity']:8s}] "
              f"{issue['type']:25s} (conf: {issue['confidence']:.2f})")


if __name__ == "__main__":
    main()
