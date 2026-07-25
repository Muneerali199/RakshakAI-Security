#!/bin/bash
# Prepare dataset tarball for Lightning with CLEANED validation data
set -e

echo "📦 Creating dataset tarball for Lightning upload..."
echo ""

cd v2/inputs/datasets/axolotl

# Check if cleaned validation exists
if [ ! -f val_cleaned.jsonl ]; then
    echo "❌ Error: val_cleaned.jsonl not found"
    echo "Run: python3 v2/scripts/clean_validation_data.py"
    exit 1
fi

# Create tarball with cleaned data
echo "Compressing datasets..."
tar czf /tmp/axolotl_dataset_v2_FIXED.tar.gz \
    train_250k.jsonl \
    val_cleaned.jsonl \
    dpo_train.jsonl

SIZE=$(du -h /tmp/axolotl_dataset_v2_FIXED.tar.gz | cut -f1)
echo "✅ Created: /tmp/axolotl_dataset_v2_FIXED.tar.gz ($SIZE)"

echo ""
echo "📊 Contents:"
echo "  • train_250k.jsonl:   $(wc -l < train_250k.jsonl | xargs printf "%'d") samples"
echo "  • val_cleaned.jsonl:  $(wc -l < val_cleaned.jsonl | xargs printf "%'d") samples"
echo "  • dpo_train.jsonl:    $(wc -l < dpo_train.jsonl | xargs printf "%'d") samples"

echo ""
echo "🚀 Next steps:"
echo "  1. SCP to Lightning:"
echo "     scp /tmp/axolotl_dataset_v2_FIXED.tar.gz your-lightning-instance:~/"
echo ""
echo "  2. Update _remote_run_14b_FIXED.sh to extract:"
echo "     tar xzf ~/axolotl_dataset_v2_FIXED.tar.gz -C ~/RakshakAI/v2/inputs/datasets/axolotl/"
echo ""
echo "  3. The remote script should rename val_cleaned.jsonl → val.jsonl"
echo "     or update configs to use val_cleaned.jsonl"
