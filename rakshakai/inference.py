"""
RakshakAI — Inference engine. Fast prediction on code snippets.
"""
import json
from pathlib import Path
from typing import Optional

import torch
import torch.nn.functional as F

from rakshakai.model import RakshakLightweightTransformer
from rakshakai.tokenizer import RakshakTokenizer
from rakshakai.data import ID2LABEL, LABEL2ID, SEVERITY_MAP, CWE_MAP


MODEL_DIR = Path(__file__).parent.parent / "models" / "rakshakai-v1"


class RakshakInference:
    """Lightweight inference engine for code vulnerability detection."""

    def __init__(self, model_path: Optional[str] = None,
                 tokenizer_path: Optional[str] = None,
                 device: str = "cpu"):
        self.device = torch.device(device)

        model_path = model_path or str(MODEL_DIR / "best_model.pt")
        tokenizer_path = tokenizer_path or str(MODEL_DIR.parent.parent / "models" / "rakshak_tokenizer.json")

        ckpt = torch.load(model_path, map_location=self.device)
        cfg = ckpt["config"]

        self.model = RakshakLightweightTransformer(
            vocab_size=cfg["vocab_size"],
            d_model=cfg["d_model"],
            num_heads=cfg["num_heads"],
            d_ff=cfg["d_ff"],
            num_layers=cfg["num_layers"],
            num_classes=cfg["num_classes"],
            max_len=cfg["max_length"],
            pad_token_id=0,
        )
        self.model.load_state_dict(ckpt["model_state_dict"])
        self.model.to(self.device)
        self.model.eval()

        self.tokenizer = RakshakTokenizer.load(tokenizer_path)
        self.id2label = cfg.get("id2label", ID2LABEL)

    @torch.no_grad()
    def predict(self, code: str, language: str = "python") -> dict:
        """Predict vulnerability for a code snippet."""
        text = f"[{language}] {code}"
        input_ids = self.tokenizer.encode(text, 256)
        attn_mask = [1 if t != self.tokenizer.pad_id else 0 for t in input_ids]

        inp = torch.tensor([input_ids], device=self.device)
        mask = torch.tensor([attn_mask], device=self.device)

        logits = self.model(inp, mask)
        probs = F.softmax(logits, dim=-1)
        score, pred = probs.max(dim=-1)

        label_id = pred.item()
        label = self.id2label.get(str(label_id), self.id2label.get(label_id, "CLEAN"))

        # Top-5 predictions
        top5_scores, top5_ids = probs.topk(5)
        top5 = [
            {
                "label": self.id2label.get(str(i.item()), self.id2label.get(i.item(), "?")),
                "confidence": round(s.item(), 3),
            }
            for i, s in zip(top5_ids[0], top5_scores[0])
        ]

        return {
            "label": label,
            "confidence": round(score.item(), 3),
            "top5": top5,
            "is_vulnerable": label != "CLEAN",
        }

    @torch.no_grad()
    def scan_file(self, code: str, language: str, window_size: int = 5) -> list[dict]:
        """Scan a full file by sliding window."""
        lines = code.split("\n")
        issues = []
        seen = set()

        for i in range(0, len(lines), max(1, window_size // 2)):
            snippet = "\n".join(lines[i:i + window_size])
            if len(snippet.strip()) < 5:
                continue

            result = self.predict(snippet, language)
            label = result["label"]
            confidence = result["confidence"]

            if label == "CLEAN" or confidence < 0.75:
                continue
            if label in seen:
                continue
            seen.add(label)

            issues.append({
                "type": label,
                "severity": SEVERITY_MAP.get(label, "info"),
                "confidence": confidence,
                "line": i + 1,
                "message": f"{label.replace('_', ' ').title()} Detected",
                "cwe": CWE_MAP.get(label, "CWE-000"),
            })

        return issues
