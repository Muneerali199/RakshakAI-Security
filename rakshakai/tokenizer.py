"""
RakshakAI — Custom BPE Tokenizer for Code
Trained from scratch on source code. No HuggingFace dependency.
"""
from __future__ import annotations
import re
import json
from collections import Counter
from pathlib import Path


class RakshakTokenizer:
    def __init__(self, vocab_size: int = 8000):
        self.vocab_size = vocab_size
        self.merges = {}
        self.vocab = {}
        self.char_to_id = {}
        self.id_to_char = {}

    def _get_stats(self, words: list[list[str]]) -> dict:
        pairs = Counter()
        for word in words:
            for i in range(len(word) - 1):
                pairs[(word[i], word[i + 1])] += 1
        return pairs

    def _merge(self, words: list[list[str]], pair, new_token: str) -> list[list[str]]:
        result = []
        for word in words:
            new_word = []
            i = 0
            while i < len(word):
                if i < len(word) - 1 and (word[i], word[i + 1]) == pair:
                    new_word.append(new_token)
                    i += 2
                else:
                    new_word.append(word[i])
                    i += 1
            result.append(new_word)
        return result

    def train(self, texts: list[str]):
        chars = set()
        for text in texts:
            chars.update(text)

        # Start with character-level vocabulary
        self.char_to_id = {c: i for i, c in enumerate(sorted(chars))}
        self.id_to_char = {i: c for c, i in self.char_to_id.items()}
        next_id = len(self.char_to_id)

        # Convert texts to list of character lists
        words = [list(text) for text in texts]

        # Learn BPE merges
        self.merges = {}
        while next_id < self.vocab_size:
            stats = self._get_stats(words)
            if not stats:
                break

            best_pair = max(stats, key=stats.get)
            new_token = f"<merge_{next_id}>"
            self.merges[best_pair] = new_token
            words = self._merge(words, best_pair, new_token)
            next_id += 1

            if next_id % 1000 == 0:
                print(f"  BPE tokens learned: {next_id}/{self.vocab_size}")

        # Build final vocab
        self._build_vocab()
        print(f"Tokenizer trained. Vocab size: {len(self.vocab)}")

    def _build_vocab(self):
        # Character tokens
        self.vocab = {char: idx for char, idx in self.char_to_id.items()}
        next_id = len(self.vocab)
        # Merged tokens
        for pair, token in self.merges.items():
            self.vocab[token] = next_id
            next_id += 1
        # Special tokens
        self.vocab["<PAD>"] = next_id
        self.vocab["<UNK>"] = next_id + 1
        self.vocab["<CLS>"] = next_id + 2
        self.vocab["<SEP>"] = next_id + 3

        self.pad_id = self.vocab["<PAD>"]
        self.unk_id = self.vocab["<UNK>"]
        self.cls_id = self.vocab["<CLS>"]
        self.sep_id = self.vocab["<SEP>"]

    def encode(self, text: str, max_length: int = 256) -> list[int]:
        tokens = [self.cls_id]
        words = [list(text)]

        # Apply BPE merges greedily
        changed = True
        while changed:
            changed = False
            stats = self._get_stats(words)
            for pair, token in sorted(self.merges.items(), key=lambda x: len(x[0][0]) + len(x[0][1]), reverse=True):
                if pair in stats and stats[pair] > 0:
                    words = self._merge(words, pair, token)
                    changed = True
                    break

        # Convert to IDs
        for char in words[0] if words else []:
            if len(tokens) >= max_length - 1:
                break
            token_id = self.vocab.get(char, self.unk_id)
            tokens.append(token_id)

        tokens.append(self.sep_id)

        # Pad
        if len(tokens) < max_length:
            tokens.extend([self.pad_id] * (max_length - len(tokens)))

        return tokens[:max_length]

    def decode(self, ids: list[int]) -> str:
        id_to_token = {v: k for k, v in self.vocab.items()}
        tokens = []
        for tid in ids:
            if tid in id_to_token:
                token = id_to_token[tid]
                if token in ("<PAD>", "<UNK>", "<CLS>", "<SEP>"):
                    continue
                if token.startswith("<merge_"):
                    continue
                tokens.append(token)
        return "".join(tokens)

    def save(self, path: str):
        data = {
            "vocab_size": self.vocab_size,
            "char_to_id": self.char_to_id,
            "id_to_char": {str(k): v for k, v in self.id_to_char.items()},
            "merges": {str(k): v for k, v in self.merges.items()},
            "vocab": {k: v for k, v in self.vocab.items()},
        }
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f)
        print(f"Tokenizer saved to {path}")

    @classmethod
    def load(cls, path: str):
        with open(path) as f:
            data = json.load(f)

        tok = cls(data["vocab_size"])
        tok.char_to_id = data["char_to_id"]
        tok.id_to_char = {int(k): v for k, v in data["id_to_char"].items()}
        tok.merges = {eval(k): v for k, v in data["merges"].items()}
        tok.vocab = data["vocab"]
        tok.pad_id = tok.vocab.get("<PAD>", 0)
        tok.unk_id = tok.vocab.get("<UNK>", 1)
        tok.cls_id = tok.vocab.get("<CLS>", 2)
        tok.sep_id = tok.vocab.get("<SEP>", 3)
        return tok
