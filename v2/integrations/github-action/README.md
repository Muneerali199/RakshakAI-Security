# RakshakAI v2 — GitHub Action

Posts a structured security review on every PR by calling the RakshakAI v2
server's `/v2/review` endpoint on every changed file.

## Inputs

| Input | Default | Description |
|---|---|---|
| `server_url` | `http://localhost:8080` | URL of the running RakshakAI v2 server |
| `fail_on` | `none` | Fails the action if any finding is at or above this severity |
| `comment_on_pr` | `true` | Whether to post a comment on the PR |
| `languages` | `""` | Optional comma-separated file extensions to include |

## Outputs

| Output | Description |
|---|---|
| `findings_count` | Total findings |
| `critical_count` | Critical-severity findings |
| `high_count` | High-severity findings |
| `report_json` | Full JSON report |

## Example workflow

```yaml
name: RakshakAI Security Review
on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  review:
    runs-on: ubuntu-latest
    services:
      rakshakai:
        image: your-registry/rakshakai-v2-server:rocm6.2
        ports: ['8080:8080']
    steps:
      - uses: actions/checkout@v4
      - uses: Muneerali199/RakshakAI/v2/integrations/github-action@main
        with:
          server_url: http://rakshakai:8080
          fail_on: high
          comment_on_pr: 'true'
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## Build

```bash
cd v2/integrations/github-action
npm install
npm run build
npm run package
# → dist/index.js  (commit this for `runs.using: 'node20'`)
```
