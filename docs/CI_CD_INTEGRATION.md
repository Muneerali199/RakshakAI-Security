# CI/CD Integration Guide

RakshakAI can be integrated into your CI/CD pipeline to automatically scan for vulnerabilities on every commit, PR, or deployment.

## Quick Start

### GitHub Actions

Create `.github/workflows/security.yml`:

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install RakshakAI
        run: |
          pip install -e .
      
      - name: Scan for vulnerabilities
        run: |
          rakshakai scan src/ --json --fail-on critical,high --model rakshak
        env:
          NVIDIA_NIM_KEY: ${{ secrets.NVIDIA_NIM_KEY }}
      
      - name: Upload SARIF results
        if: always()
        run: |
          rakshak-ci scan src/ --format sarif > results.sarif
        
      - name: Upload to GitHub Security
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### GitLab CI

Create `.gitlab-ci.yml`:

```yaml
security_scan:
  image: python:3.11
  stage: test
  script:
    - pip install -e .
    - rakshakai scan src/ --json --fail-on critical,high
  artifacts:
    reports:
      sast: results.sarif
  only:
    - merge_requests
    - main
```

### CircleCI

Create `.circleci/config.yml`:

```yaml
version: 2.1

jobs:
  security:
    docker:
      - image: cimg/python:3.11
    steps:
      - checkout
      - run:
          name: Install RakshakAI
          command: pip install -e .
      - run:
          name: Scan for vulnerabilities
          command: rakshakai scan src/ --json --fail-on critical,high
      - store_artifacts:
          path: results.json

workflows:
  main:
    jobs:
      - security
```

---

## Headless JSON Mode

RakshakAI supports a fully headless mode for CI/CD:

```bash
# Scan a single file
rakshakai scan api.py --json --no-interactive

# Scan a directory
rakshakai scan src/ --json --model deepseek

# Fail on specific severity levels
rakshakai scan src/ --json --fail-on critical,high

# Custom model
rakshakai scan src/ --json --model gpt-4o
```

### Exit Codes

- `0` - No vulnerabilities found (or only low/info)
- `1` - Vulnerabilities found matching `--fail-on` criteria
- `2` - Error (invalid arguments, file not found, etc.)

### JSON Output Format

```json
{
  "scanned": 42,
  "vulnerable": 5,
  "results": [
    {
      "file": "src/api.py",
      "cwe": "CWE-89",
      "severity": "critical",
      "confidence": 0.95,
      "description": "SQL injection vulnerability in login function",
      "line": 45,
      "status": "done"
    }
  ],
  "summary": {
    "scanned": 42,
    "vulnerable": 5,
    "critical": 2,
    "high": 3,
    "medium": 0,
    "low": 0,
    "errors": 0
  }
}
```

---

## SARIF Output (GitHub Code Scanning)

For native GitHub Security tab integration:

```bash
rakshak-ci scan src/ --format sarif > results.sarif
```

Upload to GitHub:

```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## Pre-Commit Hook

Block commits with critical vulnerabilities:

```bash
# Install hook
rakshakai /precommit install

# Hook will run on every commit
git commit -m "feat: new API endpoint"
# → Scanning staged files...
# → ✓ No critical vulnerabilities
```

Uninstall:

```bash
rakshakai /precommit uninstall
```

---

## Docker

Run in a container:

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY . .

RUN pip install -e .

CMD ["rakshakai", "scan", "src/", "--json"]
```

Build and run:

```bash
docker build -t rakshak-scanner .
docker run -v $(pwd):/app rakshak-scanner
```

---

## Environment Variables

```bash
# Model selection
export RAKSHAK_MODEL=deepseek

# API keys (if using non-rakshak models)
export NVIDIA_NIM_KEY=nvapi-xxx
export OPENAI_API_KEY=sk-xxx
export ANTHROPIC_API_KEY=sk-ant-xxx

# Custom endpoint (optional)
export RAKSHAK_ENDPOINT=https://custom-endpoint.com
```

---

## Advanced Configuration

### Custom Severity Thresholds

```bash
# Fail only on critical
rakshakai scan src/ --json --fail-on critical

# Fail on critical and high
rakshakai scan src/ --json --fail-on critical,high

# Fail on any vulnerability
rakshakai scan src/ --json --fail-on critical,high,medium,low
```

### Multi-Model Parallel Scanning

```bash
# Run 3 models in parallel for consensus
rakshakai scan src/ --json --parallel rakshak,deepseek,gpt-4o
```

### Rate Limiting

```bash
# Limit concurrent file scans
rakshakai scan src/ --json --workers 2
```

---

## Performance Tips

1. **Use `rakshak` model for speed** - 100x faster than LLM-only
2. **Scan only changed files in PR**:
   ```bash
   git diff --name-only origin/main...HEAD | xargs rakshakai scan --json
   ```
3. **Cache results** - RakshakAI auto-caches identical files
4. **Exclude test files** - Add `.rakshakignore`:
   ```
   tests/
   *_test.py
   node_modules/
   ```

---

## Example Pipelines

### Python Project

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install -e .
      - run: rakshakai scan src/ --json --fail-on critical,high
```

### Node.js Project

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install rakshakai
      - run: rakshakai scan lib/ src/ --json --fail-on critical,high --model deepseek
```

### Monorepo

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        service: [api, frontend, worker]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install rakshakai
      - run: rakshakai scan services/${{ matrix.service }} --json --fail-on critical,high
```

---

## Troubleshooting

### "Model not found"

Ensure API keys are set:

```bash
export NVIDIA_NIM_KEY=your-key-here
```

Or use the default `rakshak` model (no key needed).

### "Scan timed out"

Increase timeout:

```bash
rakshakai scan src/ --json --timeout 600  # 10 minutes
```

### "Too many files"

Use `.rakshakignore`:

```
node_modules/
dist/
build/
*.min.js
```

---

## Support

- 📖 Docs: https://rakshak.ai/docs
- 💬 Discord: https://discord.gg/rakshak
- 🐛 Issues: https://github.com/yourusername/RakshakAI/issues

---

**Next:** [Multi-Agent Orchestration Guide](./MULTI_AGENT.md)
