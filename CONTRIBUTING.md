# Contributing to RakshakAI

We welcome contributions! Here's how to help:

## Development Setup

```bash
git clone https://github.com/Muneerali199/RakshakAI
cd RakshakAI
pip install -r requirements.txt
```

## Adding Vulnerability Patterns

Add new templates to `rakshakai/data.py`:
- Follow the existing `TEMPLATES` dict format
- Include code in multiple languages (Python, JavaScript, Java, PHP)
- Map to the correct CWE

## Testing

```bash
python -m pytest tests/
```

## Pull Request Process

1. Fork the repo and create a feature branch
2. Add your changes
3. Run the tests
4. Submit a PR with a clear description

## Code of Conduct

Be respectful and constructive. This is an open-source community effort.
