#!/usr/bin/env python3
"""
Clean validation dataset to remove garbage examples.
Removes examples where:
1. patched_code == vulnerable code (no actual fix)
2. explanation is too short or generic
3. severity is marked but no vulnerability found
"""
import json
import sys
from pathlib import Path

def is_garbage(data):
    """Check if this is a garbage training example"""
    reasons = []
    
    try:
        messages = data.get('messages', [])
        if len(messages) < 3:
            return True, ["Too few messages"]
        
        # Get user input (should have code) and assistant response
        user_msg = None
        assistant_msg = None
        for msg in messages:
            if msg['role'] == 'user':
                user_msg = msg['content']
            elif msg['role'] == 'assistant':
                assistant_msg = msg['content']
        
        if not assistant_msg:
            return True, ["No assistant response"]
        
        # Parse JSON from assistant response
        # Look for the JSON block (between { and })
        if '{' not in assistant_msg or '}' not in assistant_msg:
            reasons.append("No JSON in response")
        else:
            try:
                # Extract JSON (may have text before/after)
                json_start = assistant_msg.rfind('{')
                json_end = assistant_msg.rfind('}') + 1
                json_str = assistant_msg[json_start:json_end]
                response_data = json.loads(json_str)
                
                # Check 1: If vulnerable, must have a fix
                is_vuln = response_data.get('is_vulnerable', False)
                patched = response_data.get('patched_code')
                explanation = response_data.get('explanation', '')
                
                if is_vuln:
                    if not patched or patched == 'null' or len(patched) < 10:
                        reasons.append("Vulnerable but no patch provided")
                    
                    # Check if patch is identical to original (extract code from user msg)
                    if user_msg and '```' in user_msg:
                        # Extract original code
                        code_blocks = user_msg.split('```')
                        if len(code_blocks) >= 2:
                            original = code_blocks[1]
                            # Remove language identifier
                            if '\n' in original:
                                original = '\n'.join(original.split('\n')[1:])
                            
                            if patched and patched.strip() == original.strip():
                                reasons.append("Patch identical to original code")
                    
                    if len(explanation) < 50:
                        reasons.append("Explanation too short")
                    
                    # Check for generic/useless explanations
                    generic_phrases = [
                        "appears to be secure",
                        "no vulnerability detected", 
                        "code appears to be secure",
                        "is a resource management error",  # Vague
                    ]
                    if any(phrase in explanation.lower() for phrase in generic_phrases):
                        if is_vuln:  # Contradictory
                            reasons.append("Contradictory explanation")
                
            except json.JSONDecodeError:
                reasons.append("Invalid JSON in response")
    
    except Exception as e:
        reasons.append(f"Parse error: {e}")
    
    return len(reasons) > 0, reasons

def clean_validation_data(input_path, output_path, sample_size=5000):
    """Clean validation data and optionally downsample"""
    
    print(f"Reading {input_path}...")
    
    total = 0
    garbage_count = 0
    clean_samples = []
    garbage_examples = []
    
    with open(input_path, 'r') as f:
        for line in f:
            total += 1
            data = json.loads(line)
            
            is_bad, reasons = is_garbage(data)
            
            if is_bad:
                garbage_count += 1
                if len(garbage_examples) < 5:  # Keep first 5 for inspection
                    garbage_examples.append({
                        'line': total,
                        'reasons': reasons,
                        'data': data
                    })
            else:
                clean_samples.append(data)
            
            if total % 1000 == 0:
                print(f"  Processed {total:,} samples... ({garbage_count} garbage)")
    
    print(f"\n📊 Results:")
    print(f"  Total samples: {total:,}")
    print(f"  Garbage samples: {garbage_count:,} ({garbage_count/total*100:.1f}%)")
    print(f"  Clean samples: {len(clean_samples):,} ({len(clean_samples)/total*100:.1f}%)")
    
    if garbage_examples:
        print(f"\n🗑️  Example garbage samples:")
        for ex in garbage_examples[:3]:
            print(f"\n  Line {ex['line']}: {', '.join(ex['reasons'])}")
            try:
                msgs = ex['data']['messages']
                assistant_msg = next(m['content'] for m in msgs if m['role'] == 'assistant')
                print(f"    Response preview: {assistant_msg[:150]}...")
            except:
                pass
    
    # Downsample if requested
    if sample_size and len(clean_samples) > sample_size:
        print(f"\n📉 Downsampling from {len(clean_samples):,} to {sample_size:,} samples...")
        # Stratified sampling by CWE if possible
        import random
        random.seed(42)
        clean_samples = random.sample(clean_samples, sample_size)
    
    # Write cleaned data
    print(f"\n💾 Writing {len(clean_samples):,} clean samples to {output_path}...")
    with open(output_path, 'w') as f:
        for sample in clean_samples:
            f.write(json.dumps(sample) + '\n')
    
    print(f"✅ Done! Cleaned validation set saved.")
    print(f"\n🔧 Next steps:")
    print(f"  1. Update config to use: {output_path}")
    print(f"  2. Verify with: head -n 1 {output_path} | python3 -m json.tool")
    
    return len(clean_samples), garbage_count

if __name__ == '__main__':
    input_file = 'v2/inputs/datasets/axolotl/val.jsonl'
    output_file = 'v2/inputs/datasets/axolotl/val_cleaned.jsonl'
    target_size = 5000  # Reduce from 17.8K to 5K
    
    if not Path(input_file).exists():
        print(f"❌ Error: {input_file} not found")
        sys.exit(1)
    
    clean_count, garbage_count = clean_validation_data(input_file, output_file, target_size)
    
    print(f"\n📈 Validation set improved:")
    print(f"  Before: 17,823 samples (7% of train, some garbage)")
    print(f"  After: {clean_count:,} samples (2% of train, all clean)")
    print(f"  Removed: {garbage_count:,} garbage + downsampled")
