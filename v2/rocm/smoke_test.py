"""
Smoke test: verify the MI300X + ROCm + bitsandbytes + flash-attn stack
before any expensive training run. Must pass 100%.
"""
import os
import sys
import torch

FAIL = []
OK = []


def check(name, fn):
    try:
        fn()
        OK.append(name)
        print(f"[OK]   {name}")
    except Exception as e:  # noqa: BLE001
        FAIL.append((name, repr(e)))
        print(f"[FAIL] {name}: {e}")


# 1. Torch sees GPU
def _t():
    assert torch.cuda.is_available(), "torch.cuda.is_available() is False"
    n = torch.cuda.device_count()
    assert n == 1, f"expected 1 GPU, got {n}"
check("PyTorch sees 1 GPU", _t)


# 2. MI300X
def _m():
    name = torch.cuda.get_device_name(0)
    assert "MI300" in name, f"device is {name}, not MI300X"
    mem = torch.cuda.get_device_properties(0).total_memory / 1024**3
    assert mem >= 180, f"only {mem:.1f} GB, MI300X should be ~192 GB"
check("GPU is MI300X with ~192 GB", _m)


# 3. bf16 matmul
def _b():
    a = torch.randn(1024, 1024, device="cuda", dtype=torch.bfloat16)
    b = torch.randn(1024, 1024, device="cuda", dtype=torch.bfloat16)
    c = a @ b
    torch.cuda.synchronize()
    assert c.shape == (1024, 1024)
    assert c.dtype == torch.bfloat16
check("bf16 matmul works", _b)


# 4. bitsandbytes NF4
def _q():
    import bitsandbytes as bnb
    x = torch.randn(64, 4096, device="cuda", dtype=torch.bfloat16)
    q4 = bnb.nn.Linear4bit(4096, 4096, compute_dtype=torch.bfloat16, quant_type="nf4").cuda()
    y = q4(x)
    assert y.shape == (64, 4096)
check("bitsandbytes NF4 quantize+dequantize works", _q)


# 5. flash-attn 2
def _f():
    from flash_attn import flash_attn_func
    q = torch.randn(1, 256, 8, 64, device="cuda", dtype=torch.bfloat16)
    k = torch.randn(1, 256, 8, 64, device="cuda", dtype=torch.bfloat16)
    v = torch.randn(1, 256, 8, 64, device="cuda", dtype=torch.bfloat16)
    out = flash_attn_func(q, k, v, causal=True)
    assert out.shape == q.shape
check("flash-attn 2 attention works", _f)


# 6. single-token optimizer step
def _o():
    import bitsandbytes as bnb
    w = torch.nn.Linear(64, 64, bias=False).cuda()
    opt = bnb.optim.PagedAdamW8bit(w.parameters(), lr=1e-4)
    x = torch.randn(8, 64, device="cuda")
    y = w(x).sum()
    y.backward()
    opt.step()
    opt.zero_grad()
check("paged AdamW 8-bit optimizer step works", _o)


print()
if FAIL:
    print(f"[FATAL] {len(FAIL)} checks failed:")
    for n, e in FAIL:
        print(f"  - {n}: {e}")
    sys.exit(1)
print(f"[all-good] {len(OK)} checks passed; safe to start training.")
