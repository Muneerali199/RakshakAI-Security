"""
RakshakAI — India's First Security AI.

Lightweight transformer model for code vulnerability detection.
Built from scratch in pure PyTorch. ~1.5M-7.3M parameters.
"""

from rakshakai.model import RakshakLightweightTransformer
from rakshakai.tokenizer import RakshakTokenizer

__version__ = "0.3.0"
__all__ = [
    "RakshakLightweightTransformer",
    "RakshakTokenizer",
]
