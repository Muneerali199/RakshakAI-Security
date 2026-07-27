#!/bin/bash
# ╔══════════════════════════════════════════════════════════════╗
# ║           RakshakAI Production Training Launch               ║
# ║           Final Pre-Flight Check & Launch Command            ║
# ╚══════════════════════════════════════════════════════════════╝

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║              RAKSHAKAI PRODUCTION TRAINING                   ║"
echo "║              Final Readiness Check                           ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

all_checks_passed=true

echo "🔍 Running pre-flight checks..."
echo ""

# Check 1: Datasets on HuggingFace
echo -n "1. Datasets on HuggingFace... "
python3 << 'EOF' > /dev/null 2>&1
from huggingface_hub import HfApi
api = HfApi()
files = api.list_repo_files("Muneerali199/rakshak-cwe-v3-data", repo_type="dataset")
required = ["train_87k_with_reasoning.jsonl", "val_cleaned.jsonl", "dpo_train.jsonl"]
assert all(f in files for f in required)
EOF
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ PASS${NC}"
else
    echo -e "${RED}❌ FAIL${NC}"
    all_checks_passed=false
fi

# Check 2: Production configs exist
echo -n "2. Production configs... "
if [ -f "v2/configs/lightning_14b_sft_PRODUCTION.yaml" ] && [ -f "v2/configs/lightning_14b_dpo_PRODUCTION.yaml" ]; then
    echo -e "${GREEN}✅ PASS${NC}"
else
    echo -e "${RED}❌ FAIL${NC}"
    all_checks_passed=false
fi

# Check 3: Configs use reasoning dataset
echo -n "3. Configs use reasoning dataset... "
if grep -q "train_87k_with_reasoning.jsonl" v2/configs/lightning_14b_sft_PRODUCTION.yaml; then
    echo -e "${GREEN}✅ PASS${NC}"
else
    echo -e "${RED}❌ FAIL${NC}"
    all_checks_passed=false
fi

# Check 4: Production training script exists
echo -n "4. Production training script... "
if [ -f "v2/scripts/train_production.sh" ]; then
    echo -e "${GREEN}✅ PASS${NC}"
else
    echo -e "${RED}❌ FAIL${NC}"
    all_checks_passed=false
fi

# Check 5: Lightning shot script configured correctly
echo -n "5. Lightning launcher configured... "
if grep -q "train_production.sh" v2/scripts/lightning_shot.sh; then
    echo -e "${GREEN}✅ PASS${NC}"
else
    echo -e "${RED}❌ FAIL${NC}"
    all_checks_passed=false
fi

# Check 6: HF_TOKEN is set (optional but recommended)
echo -n "6. HF_TOKEN environment variable... "
if [ -n "$HF_TOKEN" ]; then
    echo -e "${GREEN}✅ SET${NC}"
else
    echo -e "${YELLOW}⚠️  NOT SET${NC} (models won't auto-upload)"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ "$all_checks_passed" = true ]; then
    echo -e "${GREEN}${BOLD}✅ ALL CHECKS PASSED - READY FOR TRAINING!${NC}"
    echo ""
    echo "📊 Training Configuration:"
    echo "  • Model: Qwen2.5-Coder-14B-Instruct"
    echo "  • Dataset: 259,269 samples (250K + 9K reasoning traces)"
    echo "  • Validation: 5,000 clean samples"
    echo "  • DPO: 6,979 preference pairs, 2 epochs"
    echo "  • Instance: A100 80GB @ \$2.50/hour"
    echo "  • Duration: ~5.2 hours"
    echo "  • Cost: ~\$13.00 / \$14 budget"
    echo ""
    echo "🚀 LAUNCH COMMAND:"
    echo ""
    echo -e "${BLUE}${BOLD}bash v2/scripts/lightning_shot.sh s_abc123@ssh.lightning.ai 14b${NC}"
    echo ""
    echo "📝 Replace 's_abc123@ssh.lightning.ai' with your actual Lightning SSH host"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "📊 Monitor training:"
    echo "  ssh s_abc123@ssh.lightning.ai"
    echo "  tail -f ~/train_sft.log    # SFT progress"
    echo "  tail -f ~/train_dpo.log    # DPO progress"
    echo ""
    echo "⏱️  Expected timeline:"
    echo "  [0-10m]   Setup, dependency installation"
    echo "  [10m-3.7h] SFT training (259K samples)"
    echo "  [3.7h-5.3h] DPO training (7K pairs, 2 epochs)"
    echo "  [5.3h] Upload to HuggingFace"
    echo ""
    echo "✅ Expected final metrics:"
    echo "  SFT loss: ~1.18-1.25 (train), ~1.24-1.30 (val)"
    echo "  DPO loss: ~0.33-0.38"
    echo ""
    echo "🎯 After training completes:"
    echo "  python3 v2/scripts/benchmark_vs_big_models.py"
    echo ""
else
    echo -e "${RED}❌ PRE-FLIGHT CHECKS FAILED${NC}"
    echo ""
    echo "Please fix the issues above before launching training."
    echo ""
    echo "For detailed troubleshooting, run:"
    echo "  python3 v2/scripts/pre_training_audit.py"
    exit 1
fi
