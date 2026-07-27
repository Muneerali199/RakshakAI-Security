"""
RakshakAI — Custom Lightweight Transformer for Code Vulnerability Detection
Built from scratch in pure PyTorch. No transformers library dependency.
~7.3M parameters — 17x smaller than CodeBERT (125M)
"""
from __future__ import annotations
import math
import torch
import torch.nn as nn
import torch.nn.functional as F


class SinusoidalPositionalEncoding(nn.Module):
    def __init__(self, d_model: int, max_len: int = 512):
        super().__init__()
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2).float() * (-math.log(10000.0) / d_model))
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        pe = pe.unsqueeze(0)
        self.register_buffer("pe", pe)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return x + self.pe[:, : x.size(1), :]


class MultiHeadAttention(nn.Module):
    def __init__(self, d_model: int = 256, num_heads: int = 8, dropout: float = 0.1):
        super().__init__()
        assert d_model % num_heads == 0
        self.d_model = d_model
        self.num_heads = num_heads
        self.d_head = d_model // num_heads

        self.qkv = nn.Linear(d_model, 3 * d_model, bias=False)
        self.out = nn.Linear(d_model, d_model, bias=False)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor, mask: torch.Tensor | None = None) -> torch.Tensor:
        B, L, D = x.shape

        qkv = self.qkv(x)
        q, k, v = qkv.chunk(3, dim=-1)

        q = q.view(B, L, self.num_heads, self.d_head).transpose(1, 2)
        k = k.view(B, L, self.num_heads, self.d_head).transpose(1, 2)
        v = v.view(B, L, self.num_heads, self.d_head).transpose(1, 2)

        scale = self.d_head ** 0.5
        attn = (q @ k.transpose(-2, -1)) / scale

        if mask is not None:
            mask_bool = (mask == 0)
            if mask_bool.dim() < attn.dim():
                mask_bool = mask_bool.view(mask_bool.size(0), 1, 1, -1)
            mask_bool = mask_bool.expand(-1, self.num_heads, attn.size(2), -1)
            attn = attn.masked_fill(mask_bool, float("-inf"))

        attn = F.softmax(attn, dim=-1)
        attn = self.dropout(attn)

        out = attn @ v
        out = out.transpose(1, 2).contiguous().view(B, L, D)
        out = self.out(out)
        return out


class FeedForward(nn.Module):
    def __init__(self, d_model: int = 256, d_ff: int = 512, dropout: float = 0.1):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(d_model, d_ff),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(d_ff, d_model),
            nn.Dropout(dropout),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


class TransformerBlock(nn.Module):
    def __init__(self, d_model: int = 256, num_heads: int = 8, d_ff: int = 512, dropout: float = 0.1):
        super().__init__()
        self.attention = MultiHeadAttention(d_model, num_heads, dropout)
        self.norm1 = nn.LayerNorm(d_model)
        self.ffn = FeedForward(d_model, d_ff, dropout)
        self.norm2 = nn.LayerNorm(d_model)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor, mask: torch.Tensor | None = None) -> torch.Tensor:
        x = x + self.dropout(self.attention(self.norm1(x), mask))
        x = x + self.dropout(self.ffn(self.norm2(x)))
        return x


class RakshakLightweightTransformer(nn.Module):
    """
    Lightweight Transformer for vulnerability detection.

    Architecture:
      - Token embedding: vocab_size → d_model
      - Sinusoidal positional encoding
      - 6× Transformer blocks (MHA + FFN)
      - Mean pooling + MLP classification head
      - 21 output classes (vulnerability types)

    Configuration:
      vocab_size=16000, d_model=256, num_heads=8,
      d_ff=512, num_layers=6, num_classes=21
    """
    def __init__(
        self,
        vocab_size: int = 16000,
        d_model: int = 256,
        num_heads: int = 8,
        d_ff: int = 512,
        num_layers: int = 6,
        num_classes: int = 21,
        max_len: int = 512,
        dropout: float = 0.1,
        pad_token_id: int = 0,
    ):
        super().__init__()
        self.d_model = d_model
        self.pad_token_id = pad_token_id

        self.embedding = nn.Embedding(vocab_size, d_model, padding_idx=pad_token_id)
        self.pos_encoding = SinusoidalPositionalEncoding(d_model, max_len)
        self.dropout = nn.Dropout(dropout)

        self.blocks = nn.ModuleList([
            TransformerBlock(d_model, num_heads, d_ff, dropout)
            for _ in range(num_layers)
        ])

        self.norm = nn.LayerNorm(d_model)
        self.classifier = nn.Sequential(
            nn.Linear(d_model, d_model // 2),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(d_model // 2, num_classes),
        )

        self._init_weights()

    def _init_weights(self):
        for p in self.parameters():
            if p.dim() > 1:
                nn.init.normal_(p, mean=0.0, std=0.02)

    def forward(self, input_ids: torch.Tensor, attention_mask: torch.Tensor | None = None) -> torch.Tensor:
        x = self.embedding(input_ids) * math.sqrt(self.d_model)
        x = self.pos_encoding(x)
        x = self.dropout(x)

        if attention_mask is None:
            attention_mask = (input_ids != self.pad_token_id).unsqueeze(1).unsqueeze(2)

        for block in self.blocks:
            x = block(x, attention_mask)

        x = self.norm(x)

        # Mean pooling over non-pad tokens
        if attention_mask is not None:
            mask = attention_mask.squeeze(1).squeeze(1).float().unsqueeze(-1)
            x = (x * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1)
        else:
            x = x.mean(dim=1)

        logits = self.classifier(x)
        return logits

    @torch.no_grad()
    def predict(self, input_ids: torch.Tensor, attention_mask: torch.Tensor | None = None) -> tuple[torch.Tensor, torch.Tensor]:
        self.eval()
        logits = self.forward(input_ids, attention_mask)
        probs = F.softmax(logits, dim=-1)
        scores, preds = probs.max(dim=-1)
        return preds, scores

    def count_params(self) -> dict:
        total = sum(p.numel() for p in self.parameters())
        trainable = sum(p.numel() for p in self.parameters() if p.requires_grad)
        return {"total": total, "trainable": trainable}

    @classmethod
    def tiny(cls, **kwargs):
        """Ultra-lightweight config: ~2.5M params, runs on any CPU."""
        defaults = dict(vocab_size=8000, d_model=128, num_heads=4, d_ff=256, num_layers=4)
        defaults.update(kwargs)
        return cls(**defaults)

    @classmethod
    def small(cls, **kwargs):
        """Balanced config: ~7.3M params, good accuracy/speed tradeoff."""
        defaults = dict(vocab_size=16000, d_model=256, num_heads=8, d_ff=512, num_layers=6)
        defaults.update(kwargs)
        return cls(**defaults)

    @classmethod
    def medium(cls, **kwargs):
        """Higher capacity: ~18M params, best accuracy."""
        defaults = dict(vocab_size=32000, d_model=384, num_heads=12, d_ff=768, num_layers=8)
        defaults.update(kwargs)
        return cls(**defaults)
