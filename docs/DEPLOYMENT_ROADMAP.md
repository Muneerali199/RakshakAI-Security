# RakshakAI v2 — Production Deployment Roadmap

> **Objective:** Graduated deployment from local development → low-cost cloud → public API → enterprise

---

## Phase 1: Local Inference (developer setup)

**Goal:** Run RakshakAI v2 on a developer machine within 15 minutes.

### Options

#### A. Ollama (recommended for macOS/Linux desktop)

```bash
ollama run rakshakai-v2
```

| Setting | Value |
|---------|-------|
| Quantization | GGUF Q5_K_M |
| RAM required | 8–12 GB |
| Disk | 4.5 GB (GGUF file) |
| Latency (Apple M2) | 8–15 s per scan |
| Offline capable | Yes |

#### B. llama.cpp (cross-platform)

```bash
./llama-cli -m rakshakai-v2-Q5_K_M.gguf \
  -p "Analyze this code for vulnerabilities..." \
  -n 512
```

#### C. Python + Transformers (development only)

```bash
pip install transformers torch accelerate bitsandbytes
python v2/deploy/cli.py scan path/to/file.py
```

### Deliverables

- [ ] GGUF file published on HuggingFace
- [ ] Ollama Modelfile in repo (`v2/deploy/Modelfile.rakshakai-v2`)
- [ ] CLI tool (`v2/deploy/cli.py`): `scan | review | generate | server | health`
- [ ] Quickstart: "Run in 5 minutes" section in README

---

## Phase 2: Low-Cost Cloud Deployment (₹0–₹1,000/month)

**Goal:** Hosted API for personal/team use at minimal cost.

### Option A: HuggingFace Inference Endpoints (free tier)

| Tier | Specs | Cost |
|------|-------|------|
| Serverless (CPU) | 1 CPU, slow | Free |
| Serverless (GPU) | T4 16GB | ~$0.60/hr |
| Dedicated (GPU) | A10G 24GB | ~$1.00/hr |

Recommended: Dedicated A10G with AWQ 4-bit model.

### Option B: RunPod / Vast.ai spot instances

| Provider | GPU | Cost/hr |
|----------|-----|---------|
| RunPod | RTX 3090 24GB | ~$0.45 |
| RunPod | RTX 4090 24GB | ~$0.60 |
| Vast.ai | RTX 3090 24GB | ~$0.30 |

**Monthly estimate (part-time use):**

| Usage | Hours | Cost |
|-------|-------|------|
| Personal (10 hrs/week) | 40 | ~₹1,000–$18 |
| Team (40 hrs/week) | 160 | ~$48–$72 |
| Full-time API (24/7) | 720 | ~$216–$432 |

### Option C: AMD MI300X spot (when available)

| Provider | Cost/hr | Notes |
|----------|---------|-------|
| AMD Developer Cloud | $2.00 | Currently out of capacity |
| RunPod MI300X | $2.39 | ROCm 6.1+, community spot |

### Deliverables

- [ ] Dockerfile for inference server
- [ ] vLLM configuration (AWQ, 4-bit)
- [ ] FastAPI server with:
  - `POST /v2/scan` — single file scan
  - `POST /v2/review` — PR/diff review
  - `POST /v2/generate` — secure code generation
  - `POST /v2/batch` — batch file scanning
  - `GET /v2/health` — health check
- [ ] Docker Compose or Kubernetes manifest
- [ ] Cost tracking dashboard (simple)

---

## Phase 3: Public API

**Goal:** Production-grade API for external users.

### Architecture

```
Client → Cloudflare (DDoS protection, caching)
       → Load balancer (HAProxy / Nginx)
       → API gateway (rate limiting, auth)
       → vLLM workers (AWQ, 4-bit, 1× MI300X each)
       → Result cache (Redis)
       → Postgres (usage logs, analytics)
```

### API pricing model

| Tier | Requests/day | Rate limit | Price |
|------|-------------|------------|-------|
| Free | 100 | 1 req/s | ₹0 |
| Developer | 1,000 | 5 req/s | ₹500/mo |
| Team | 10,000 | 20 req/s | ₹5,000/mo |
| Enterprise | Unlimited | Custom | Custom |

### Key decisions

- **Authentication:** API key (Bearer token)
- **Caching:** Identical code scans return cached results (TTL: 24h)
- **Model:** AWQ 4-bit, vLLM, 1× MI300X
- **Target latency:** p95 ≤ 2.5s

### Deliverables

- [ ] API key management system
- [ ] Rate limiter middleware
- [ ] Usage-tracking backend
- [ ] Caching layer (Redis)
- [ ] OpenAPI / Swagger spec
- [ ] On-prem deployment option (Docker Compose)

---

## Phase 4: Enterprise Deployment

**Goal:** Self-hosted deployment for enterprise security teams.

### Requirements

| Requirement | Solution |
|-------------|----------|
| Air-gapped deployment | Docker Compose or Kubernetes with offline model loading |
| SSO / SAML | Keycloak or Okta integration |
| Audit logging | All scan results logged to ELK or Splunk |
| RBAC | Admin / Reviewer / Developer roles |
| SLA (99.5%) | Multi-replica vLLM + load balancer |
| Data residency | Deploy within customer VPC |
| Compliance | SOC 2 / ISO 27001 evidence package |

### Enterprise features

- **On-premise scanning:** All code stays within customer network
- **Batch repository scan:** `POST /v2/scan-repo` — scans entire repo with chunking
- **CI/CD integration:** GitHub Actions, GitLab CI, Jenkins plugins
- **Custom rules:** Allow security teams to add custom CWE patterns
- **Dashboard:** Web UI for scan history, vulnerability trends, team analytics

### Pricing model

| Tier | Price | Includes |
|------|-------|----------|
| Self-hosted Starter | ₹1,20,000/yr | 5 seats, 5 repos, email support |
| Self-hosted Pro | ₹3,60,000/yr | 20 seats, unlimited repos, Slack support, SSO |
| Enterprise | Custom | Unlimited, air-gapped, dedicated support |

### Deliverables

- [ ] Kubernetes Helm chart
- [ ] Air-gapped installation guide
- [ ] SSO integration (Keycloak / SAML / OAuth)
- [ ] Audit logging integration (ELK / Splunk)
- [ ] Enterprise support SLA framework
- [ ] RBAC implementation

---

## Infrastructure cost comparison

| Phase | Setup cost | Monthly cost | Users |
|-------|-----------|-------------|-------|
| 1. Local (Ollama) | $0 | $0 | 1 developer |
| 2. Low-cost cloud | $0–$50 | $5–$50 | 1–5 developers |
| 3. Public API (MVP) | $500 | $200–$500 | 50–500 users |
| 4. Enterprise | $5,000 | $1,000–$5,000 | 50–500 users |

---

## Decision framework

```
Do you have a GPU?
├── Yes (local)
│   └── Use Transformers or vLLM → Phase 1
└── No
    ├── Can you run Ollama?
    │   ├── Yes → GGUF via Ollama → Phase 1 (CPU)
    │   └── No
    │       ├── Budget < $10/mo?
    │       │   ├── Yes → HuggingFace free tier → Phase 2
    │       │   └── No → Spot GPU instance → Phase 2
    │       └── Enterprise?
    │           └── Yes → Phase 4 (self-hosted)
```
