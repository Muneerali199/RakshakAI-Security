"""Allow running as: python -m rakshakai"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from rakshak_cli import main
main()
