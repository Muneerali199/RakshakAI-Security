"""
RakshakAI — Training pipeline with class-weighted loss.
"""
import os
import sys
import time
import json
import random
import logging
import argparse
from pathlib import Path
from datetime import datetime

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader

from rakshakai.model import RakshakLightweightTransformer
from rakshakai.tokenizer import RakshakTokenizer
from rakshakai.data import (
    VulnerabilityDatasetGenerator,
    CodeDataset,
    NUM_CLASSES,
    LABEL2ID,
    ID2LABEL,
)

logger = logging.getLogger("rakshakai.train")


def train(config: dict) -> float:
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info(f"Device: {device}")
    logger.info(f"Config: {json.dumps(config, indent=2)}")

    # ── Dataset ──
    logger.info("Generating dataset...")
    gen = VulnerabilityDatasetGenerator()
    samples = gen.generate(config["num_samples"])
    random.shuffle(samples)

    n = len(samples)
    n_train = int(n * config["train_split"])
    n_val = int(n * config["val_split"])
    train_s, val_s, test_s = samples[:n_train], samples[n_train:n_train+n_val], samples[n_train+n_val:]
    logger.info(f"Train: {len(train_s)}, Val: {len(val_s)}, Test: {len(test_s)}")

    # ── Tokenizer ──
    tok_path = config.get("tokenizer_path", "models/rakshak_tokenizer.json")
    if os.path.exists(tok_path):
        tokenizer = RakshakTokenizer.load(tok_path)
        logger.info(f"Loaded tokenizer from {tok_path}")
    else:
        tokenizer = RakshakTokenizer(vocab_size=config["vocab_size"])
        tokenizer.train([s["code"] for s in samples])
        Path(tok_path).parent.mkdir(parents=True, exist_ok=True)
        tokenizer.save(tok_path)

    # ── DataLoaders ──
    train_ds = CodeDataset(train_s, tokenizer, config["max_length"])
    val_ds = CodeDataset(val_s, tokenizer, config["max_length"])
    test_ds = CodeDataset(test_s, tokenizer, config["max_length"])

    # Class-weighted loss
    class_weights = train_ds.get_class_weights().to(device)
    logger.info(f"Class weights: {class_weights.tolist()}")

    train_loader = DataLoader(train_ds, batch_size=config["batch_size"], shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=config["batch_size"])
    test_loader = DataLoader(test_ds, batch_size=config["batch_size"])

    # ── Model ──
    model = RakshakLightweightTransformer(
        vocab_size=config["vocab_size"],
        d_model=config["d_model"],
        num_heads=config["num_heads"],
        d_ff=config["d_ff"],
        num_layers=config["num_layers"],
        num_classes=NUM_CLASSES,
        max_len=config["max_length"],
        dropout=config["dropout"],
        pad_token_id=tokenizer.pad_id,
    )
    resume_path = config.get("resume")
    if resume_path and os.path.exists(resume_path):
        ckpt = torch.load(resume_path, map_location="cpu")
        model.load_state_dict(ckpt["model_state_dict"])
        logger.info(f"Resumed from {resume_path} (epoch {ckpt.get('epoch', '?')})")
    params = sum(p.numel() for p in model.parameters())
    logger.info(f"Model: {params:,} params")

    # ── Optimizer ──
    optimizer = torch.optim.AdamW(
        model.parameters(), lr=config["lr"], weight_decay=config.get("weight_decay", 0.01)
    )
    total_steps = len(train_loader) * config["epochs"]
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=total_steps)

    ce_loss = nn.CrossEntropyLoss(weight=class_weights)
    best_acc = 0.0
    output_dir = Path(config["output_dir"])
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("=" * 60)
    logger.info("TRAINING")
    logger.info("=" * 60)

    for epoch in range(config["epochs"]):
        model.train()
        t0 = time.time()
        total_loss = 0

        for batch in train_loader:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["labels"].to(device)

            optimizer.zero_grad()
            logits = model(input_ids, attention_mask)
            loss = ce_loss(logits, labels)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            scheduler.step()
            total_loss += loss.item()

        # Validation
        model.eval()
        val_loss, correct, total = 0, 0, 0
        with torch.no_grad():
            for batch in val_loader:
                input_ids = batch["input_ids"].to(device)
                attention_mask = batch["attention_mask"].to(device)
                labels = batch["labels"].to(device)
                logits = model(input_ids, attention_mask)
                loss = F.cross_entropy(logits, labels)
                val_loss += loss.item()
                preds = logits.argmax(dim=-1)
                correct += (preds == labels).sum().item()
                total += labels.size(0)

        train_loss = total_loss / len(train_loader)
        val_loss = val_loss / len(val_loader)
        acc = correct / total
        elapsed = time.time() - t0

        logger.info(
            f"Epoch {epoch+1:2d}/{config['epochs']} | "
            f"Train: {train_loss:.4f} | Val: {val_loss:.4f} | "
            f"Acc: {acc:.4f} ({correct}/{total}) | {elapsed:.1f}s"
        )

        if acc > best_acc:
            best_acc = acc
            torch.save({
                "epoch": epoch,
                "model_state_dict": model.state_dict(),
                "optimizer_state_dict": optimizer.state_dict(),
                "best_acc": best_acc,
                "config": {
                    "vocab_size": config["vocab_size"],
                    "d_model": config["d_model"],
                    "num_heads": config["num_heads"],
                    "d_ff": config["d_ff"],
                    "num_layers": config["num_layers"],
                    "num_classes": NUM_CLASSES,
                    "max_length": config["max_length"],
                    "label2id": LABEL2ID,
                    "id2label": ID2LABEL,
                },
            }, output_dir / "best_model.pt")
            logger.info(f"  → Best model (acc: {best_acc:.4f})")

    # ── Test ──
    logger.info("=" * 60)
    logger.info("TESTING")
    logger.info("=" * 60)
    model.eval()
    correct, total = 0, 0
    all_preds, all_labels = [], []
    with torch.no_grad():
        for batch in test_loader:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["labels"].to(device)
            logits = model(input_ids, attention_mask)
            preds = logits.argmax(dim=-1)
            correct += (preds == labels).sum().item()
            total += labels.size(0)
            all_preds.extend(preds.cpu().tolist())
            all_labels.extend(labels.cpu().tolist())

    test_acc = correct / total
    logger.info(f"Test accuracy: {test_acc:.4f} ({correct}/{total})")

    # Per-class report
    from sklearn.metrics import classification_report
    try:
        report = classification_report(
            all_labels, all_preds,
            target_names=[ID2LABEL[i] for i in range(NUM_CLASSES)],
            zero_division=0,
        )
        logger.info(f"Per-class:\n{report}")
    except ImportError:
        logger.info("Install scikit-learn for per-class report")

    logger.info(f"Best val acc: {best_acc:.4f}")
    logger.info(f"Test acc: {test_acc:.4f}")
    logger.info(f"Model: {output_dir / 'best_model.pt'}")
    return best_acc


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--num-samples", type=int, default=8000)
    parser.add_argument("--train-split", type=float, default=0.8)
    parser.add_argument("--val-split", type=float, default=0.1)
    parser.add_argument("--vocab-size", type=int, default=8000)
    parser.add_argument("--d-model", type=int, default=192)
    parser.add_argument("--num-heads", type=int, default=6)
    parser.add_argument("--d-ff", type=int, default=384)
    parser.add_argument("--num-layers", type=int, default=4)
    parser.add_argument("--dropout", type=float, default=0.15)
    parser.add_argument("--batch-size", type=int, default=12)
    parser.add_argument("--lr", type=float, default=3e-4)
    parser.add_argument("--weight-decay", type=float, default=0.01)
    parser.add_argument("--epochs", type=int, default=25)
    parser.add_argument("--max-length", type=int, default=256)
    parser.add_argument("--output-dir", type=str, default="models/rakshakai-v1/")
    parser.add_argument("--tokenizer-path", type=str, default="models/rakshak_tokenizer.json")
    parser.add_argument("--resume", type=str, default=None,
                        help="Path to checkpoint to resume/fine-tune from")

    args = parser.parse_args()
    config = vars(args)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(f"training_{datetime.now():%Y%m%d_%H%M%S}.log"),
        ],
    )

    train(config)
