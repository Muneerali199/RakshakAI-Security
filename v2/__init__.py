"""RakshakAI v2 — top-level package.

Subpackages:
  dataset    - data preparation pipeline (download, clean, dedup, instruct, pack)
  deploy     - FastAPI server + CLI
  rocm       - ROCm/MI300X setup, Dockerfile, smoke test, env script
  integrations - VS Code extension and GitHub Action
  scripts    - thin wrappers; import the actual logic from dataset/, deploy/, etc.
"""
__version__ = "2.0.0"
