"""
RakshakAI v2 — Generate high-quality security explanations.

Problem: ~22K explanations are Chrome commit messages ("Fix crash in..."), not security analysis.

Solution: Generate structured security explanations using GPT-4o or Claude Sonnet for:
1. Samples with low-quality explanations (< 30 chars, commit messages, etc.)
2. Samples with no explanation
3. Samples where explanation doesn't mention security terms

Output: Enhanced dataset with explanation_source: llm_generated flag
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from v2.dataset.schema import SecuritySample, read_jsonl, write_jsonl  # noqa: E402

try:
    from anthropic import Anthropic
    HAVE_ANTHROPIC = True
except ImportError:
    HAVE_ANTHROPIC = False

try:
    from openai import OpenAI
    HAVE_OPENAI = True
except ImportError:
    HAVE_OPENAI = False

try:
    import subprocess
    HAVE_OLLAMA = True
except ImportError:
    HAVE_OLLAMA = False


# Configuration
CLEAN_DIR = Path("v2/inputs/datasets/clean")
OUT_DIR = Path("v2/inputs/datasets/clean_with_explanations")
OUT_DIR.mkdir(parents=True, exist_ok=True)

# LLM config
DEFAULT_MODEL = "claude-3-5-sonnet-20241022"  # or "gpt-4o"
BATCH_SIZE = 50
MAX_TOKENS = 800
RATE_LIMIT_DELAY = 1.0  # seconds between requests

# Quality thresholds
MIN_EXPLANATION_LENGTH = 30
MAX_EXPLANATION_LENGTH = 1000
SECURITY_TERMS = {
    "vulnerability", "vulnerable", "attack", "exploit", "malicious", "injection",
    "sanitize", "validate", "escape", "untrusted", "tainted", "security",
    "CWE", "OWASP", "CVE", "buffer overflow", "XSS", "SQL injection",
}

# Commit message patterns to filter
COMMIT_NOISE_PATTERNS = [
    r"^fix crash",
    r"^fix typo",
    r"^update",
    r"^refactor",
    r"^merge",
    r"^bump version",
    r"^add test",
    r"^remove unused",
    r"^clean up",
]

stats = {
    "total": 0,
    "needs_explanation": 0,
    "generated": 0,
    "skipped_high_quality": 0,
    "errors": 0,
}


def is_low_quality_explanation(explanation: str | None) -> bool:
    """Check if explanation is low quality and needs regeneration."""
    if not explanation or len(explanation) < MIN_EXPLANATION_LENGTH:
        return True
    
    if len(explanation) > MAX_EXPLANATION_LENGTH:
        return True
    
    # Check for commit message patterns
    for pattern in COMMIT_NOISE_PATTERNS:
        if re.match(pattern, explanation.lower()):
            return True
    
    # Check if it mentions security concepts
    explanation_lower = explanation.lower()
    has_security_term = any(term in explanation_lower for term in SECURITY_TERMS)
    
    return not has_security_term


def generate_explanation_prompt(sample: SecuritySample) -> str:
    """Create a prompt for generating security explanation."""
    prompt = f"""You are a security researcher analyzing vulnerable code. Provide a technical security analysis.

**Vulnerable Code:**
```{sample.language.lower()}
{sample.code[:2000]}  # truncate if too long
```

**Vulnerability Type:** {sample.vulnerability_type or sample.cwe_id or "Unknown"}
**CWE:** {sample.cwe_id or "Not specified"}
**Severity:** {sample.severity}

**Instructions:**
Write a concise technical explanation (150-400 words) that covers:
1. What is the vulnerability? (1-2 sentences)
2. How can an attacker exploit it? (specific attack scenario)
3. What is the root cause? (why does the code allow this?)
4. How does the patch fix it? (if patch is provided)

Requirements:
- Be specific and technical (not generic)
- Reference actual code elements (variables, functions, lines)
- Use security terminology correctly
- Focus on the SECURITY impact, not general code quality
- Do NOT include fix code in the explanation (that goes in patched_code field)

**Your explanation:**"""

    if sample.patched_code:
        prompt += f"""

**Patched Code (for context):**
```{sample.language.lower()}
{sample.patched_code[:2000]}
```
"""
    
    return prompt


def generate_with_ollama(prompt: str, model_name: str = "qwen2.5-coder:1.5b") -> str | None:
    """Generate explanation using local Ollama (NO API KEY NEEDED)."""
    if not HAVE_OLLAMA:
        print("⚠️  Ollama not available")
        return None
    
    try:
        import subprocess
        result = subprocess.run(
            ["ollama", "run", model_name, prompt],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            print(f"❌ Ollama error: {result.stderr}")
            return None
    
    except Exception as e:
        print(f"❌ Ollama error: {e}")
        return None


def generate_with_claude(prompt: str, api_key: str) -> str | None:
    """Generate explanation using Claude."""
    if not HAVE_ANTHROPIC:
        print("⚠️  anthropic package not installed. Run: pip install anthropic")
        return None
    
    try:
        client = Anthropic(api_key=api_key)
        
        message = client.messages.create(
            model=DEFAULT_MODEL if "claude" in DEFAULT_MODEL else "claude-3-5-sonnet-20241022",
            max_tokens=MAX_TOKENS,
            temperature=0.3,
            messages=[
                {"role": "user", "content": prompt}
            ],
        )
        
        return message.content[0].text.strip()
    
    except Exception as e:
        print(f"❌ Claude API error: {e}")
        return None


def generate_with_openai(prompt: str, api_key: str) -> str | None:
    """Generate explanation using OpenAI."""
    if not HAVE_OPENAI:
        print("⚠️  openai package not installed. Run: pip install openai")
        return None
    
    try:
        client = OpenAI(api_key=api_key)
        
        response = client.chat.completions.create(
            model="gpt-4o" if "gpt" in DEFAULT_MODEL else DEFAULT_MODEL,
            max_tokens=MAX_TOKENS,
            temperature=0.3,
            messages=[
                {"role": "system", "content": "You are a security researcher analyzing vulnerable code."},
                {"role": "user", "content": prompt},
            ],
        )
        
        return response.choices[0].message.content.strip()
    
    except Exception as e:
        print(f"❌ OpenAI API error: {e}")
        return None


def generate_explanation(sample: SecuritySample, api_key: str, model: str) -> str | None:
    """Generate explanation for a sample."""
    prompt = generate_explanation_prompt(sample)
    
    if "ollama" in model.lower() or not api_key:
        # Use local Ollama (NO API KEY NEEDED)
        model_name = model.split(":")[-1] if ":" in model else "qwen2.5-coder:1.5b"
        return generate_with_ollama(prompt, model_name)
    elif "claude" in model.lower():
        return generate_with_claude(prompt, api_key)
    elif "gpt" in model.lower():
        return generate_with_openai(prompt, api_key)
    else:
        print(f"⚠️  Unknown model: {model}, trying Ollama...")
        return generate_with_ollama(prompt)


def process_file(input_path: Path, api_key: str, model: str, dry_run: bool = False):
    """Process a single JSONL file."""
    samples = []
    
    # Read samples
    with input_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            try:
                data = json.loads(line)
                sample = SecuritySample.from_dict(data)
                samples.append(sample)
                stats["total"] += 1
            except Exception as e:
                print(f"⚠️  Parse error: {e}")
                continue
    
    # Process each sample
    enhanced_samples = []
    batch_count = 0
    
    for sample in samples:
        # Skip non-vulnerable samples
        if not sample.is_vulnerable:
            enhanced_samples.append(sample)
            continue
        
        # Check if explanation needs improvement
        if not is_low_quality_explanation(sample.explanation):
            enhanced_samples.append(sample)
            stats["skipped_high_quality"] += 1
            continue
        
        stats["needs_explanation"] += 1
        
        if dry_run:
            print(f"   Would generate explanation for: {sample.id}")
            enhanced_samples.append(sample)
            continue
        
        # Generate new explanation
        print(f"   Generating explanation for: {sample.id} ({sample.cwe_id or 'no CWE'})")
        
        new_explanation = generate_explanation(sample, api_key, model)
        
        if new_explanation:
            # Update sample
            sample.explanation = new_explanation
            if sample.metadata is None:
                sample.metadata = {}
            sample.metadata["explanation_source"] = "llm_generated"
            sample.metadata["explanation_model"] = model
            sample.metadata["original_explanation"] = sample.explanation if sample.explanation else None
            
            stats["generated"] += 1
        else:
            stats["errors"] += 1
        
        enhanced_samples.append(sample)
        
        # Rate limiting
        batch_count += 1
        if batch_count % BATCH_SIZE == 0:
            print(f"   Processed {batch_count}/{stats['needs_explanation']} (sleeping {RATE_LIMIT_DELAY}s)...")
            time.sleep(RATE_LIMIT_DELAY)
    
    # Write output
    output_path = OUT_DIR / input_path.name
    write_jsonl(output_path, [s.to_dict() for s in enhanced_samples])
    print(f"✅ Wrote: {output_path}")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate high-quality security explanations")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="LLM model to use (claude-3-5-sonnet-20241022 or gpt-4o)")
    parser.add_argument("--api-key", help="API key (or set ANTHROPIC_API_KEY / OPENAI_API_KEY env var)")
    parser.add_argument("--dry-run", action="store_true", help="Just check what would be generated")
    parser.add_argument("--limit", type=int, help="Limit number of files to process")
    args = parser.parse_args()
    
    # Get API key
    api_key = args.api_key
    if not api_key:
        if "claude" in args.model.lower():
            api_key = os.getenv("ANTHROPIC_API_KEY")
        elif "gpt" in args.model.lower():
            api_key = os.getenv("OPENAI_API_KEY")
    
    if not api_key and not args.dry_run:
        print("❌ API key required. Set --api-key or ANTHROPIC_API_KEY/OPENAI_API_KEY env var")
        sys.exit(1)
    
    print("=" * 80)
    print("📝 RakshakAI v2 - Generate High-Quality Explanations")
    print("=" * 80)
    print(f"Model: {args.model}")
    print(f"Dry run: {args.dry_run}")
    print(f"Input: {CLEAN_DIR}")
    print(f"Output: {OUT_DIR}")
    print("=" * 80 + "\n")
    
    # Process files
    files = sorted(CLEAN_DIR.rglob("*.jsonl"))
    if args.limit:
        files = files[:args.limit]
    
    for i, file_path in enumerate(files, 1):
        print(f"\n[{i}/{len(files)}] Processing: {file_path.name}")
        process_file(file_path, api_key, args.model, args.dry_run)
    
    # Summary
    print("\n" + "=" * 80)
    print("📊 Generation Summary")
    print("=" * 80)
    print(f"Total samples: {stats['total']:,}")
    print(f"High-quality (kept): {stats['skipped_high_quality']:,}")
    print(f"Needed explanation: {stats['needs_explanation']:,}")
    print(f"Generated: {stats['generated']:,}")
    print(f"Errors: {stats['errors']:,}")
    print("=" * 80 + "\n")
    
    if not args.dry_run and stats['generated'] > 0:
        # Estimate cost
        if "claude" in args.model.lower():
            # Claude Sonnet: $3/MTok input, $15/MTok output
            est_cost = (stats['generated'] * 2500 * 3 / 1_000_000) + (stats['generated'] * 500 * 15 / 1_000_000)
            print(f"💰 Estimated cost: ${est_cost:.2f}")
        elif "gpt-4o" in args.model.lower():
            # GPT-4o: $2.50/MTok input, $10/MTok output
            est_cost = (stats['generated'] * 2500 * 2.5 / 1_000_000) + (stats['generated'] * 500 * 10 / 1_000_000)
            print(f"💰 Estimated cost: ${est_cost:.2f}")


if __name__ == "__main__":
    main()
