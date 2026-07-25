import * as core from '@actions/core';
import * as github from '@actions/github';
import axios from 'axios';

interface Finding {
  vulnerability: string | null;
  cwe: string | null;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | null;
  confidence: number;
  root_cause: string | null;
  attack_scenario: string | null;
  secure_fix: string | null;
  patched_code: string | null;
  references: string[];
}

interface ReviewResponse {
  finding: Finding;
  engine: string;
  latency_ms: number;
}

function languageFromPath(path: string): string {
  if (path.endsWith('.py'))   return 'python';
  if (path.endsWith('.ts'))   return 'typescript';
  if (path.endsWith('.js'))   return 'javascript';
  if (path.endsWith('.java')) return 'java';
  if (path.endsWith('.go'))   return 'go';
  if (path.endsWith('.rs'))   return 'rust';
  if (path.endsWith('.c'))    return 'c';
  if (path.endsWith('.cpp') || path.endsWith('.cc') || path.endsWith('.cxx')) return 'cpp';
  if (path.endsWith('.rb'))   return 'ruby';
  if (path.endsWith('.php'))  return 'php';
  if (path.endsWith('.cs'))   return 'csharp';
  return 'text';
}

async function run(): Promise<void> {
  const serverUrl = core.getInput('server_url', { required: true });
  const failOn = (core.getInput('fail_on') || 'none').toLowerCase();
  const commentOnPr = (core.getInput('comment_on_pr') || 'true').toLowerCase() === 'true';
  const langFilter = (core.getInput('languages') || '')
    .split(',').map(s => s.trim()).filter(Boolean);

  const ctx = github.context;
  if (!ctx.payload.pull_request) {
    core.warning('No pull_request in context; nothing to do.');
    return;
  }
  const pr = ctx.payload.pull_request;
  const octokit = github.getOctokit(process.env.GITHUB_TOKEN || '');

  core.info(`Fetching files for PR #${pr.number}`);
  const files = await octokit.paginate(octokit.rest.pulls.listFiles, {
    owner: ctx.repo.owner,
    repo: ctx.repo.repo,
    pull_number: pr.number,
    per_page: 100,
  });

  const reviews: Array<{ path: string; language: string; response: ReviewResponse }> = [];
  for (const f of files) {
    if (langFilter.length && !langFilter.some(g => f.filename.endsWith(g))) continue;
    if (!f.patch) continue;
    const language = languageFromPath(f.filename);
    try {
      const r = await axios.post<ReviewResponse>(
        `${serverUrl}/v2/review`,
        { diff: f.patch, language, filename: f.filename },
        { timeout: 180_000 }
      );
      reviews.push({ path: f.filename, language, response: r.data });
    } catch (e: any) {
      core.warning(`RakshakAI review failed for ${f.filename}: ${e?.message || e}`);
    }
  }

  const findings = reviews
    .map(r => r.response?.finding)
    .filter(f => f && f.cwe) as Finding[];

  const counts = {
    critical: findings.filter(f => f.severity === 'critical').length,
    high:     findings.filter(f => f.severity === 'high').length,
    medium:   findings.filter(f => f.severity === 'medium').length,
    low:      findings.filter(f => f.severity === 'low').length,
    info:     findings.filter(f => f.severity === 'info').length,
  };

  core.setOutput('findings_count', String(findings.length));
  core.setOutput('critical_count', String(counts.critical));
  core.setOutput('high_count', String(counts.high));
  core.setOutput('report_json', JSON.stringify({ counts, findings, reviews }, null, 2));

  if (commentOnPr) {
    const body = renderComment(findings, reviews, counts);
    await octokit.rest.issues.createComment({
      owner: ctx.repo.owner,
      repo: ctx.repo.repo,
      issue_number: pr.number,
      body,
    });
  }

  const failMap: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, none: 99 };
  const threshold = failMap[failOn] ?? 99;
  const triggered = (counts.critical >= 1 && failMap.critical <= threshold)
                 || (counts.high     >= 1 && failMap.high     <= threshold)
                 || (counts.medium   >= 1 && failMap.medium   <= threshold)
                 || (counts.low      >= 1 && failMap.low      <= threshold);
  if (triggered) {
    core.setFailed(`RakshakAI v2 reported findings at or above "${failOn}".`);
  }
}

function renderComment(findings: Finding[], reviews: any[], counts: any): string {
  if (!findings.length) {
    return `## RakshakAI v2 — Security Review\n\nNo vulnerabilities detected.`;
  }
  const lines: string[] = [];
  lines.push(`## RakshakAI v2 — Security Review`);
  lines.push('');
  lines.push(`| Severity | Count |`);
  lines.push(`|---|---|`);
  lines.push(`| Critical | ${counts.critical} |`);
  lines.push(`| High     | ${counts.high} |`);
  lines.push(`| Medium   | ${counts.medium} |`);
  lines.push(`| Low      | ${counts.low} |`);
  lines.push(`| Info     | ${counts.info} |`);
  lines.push('');
  for (const r of reviews) {
    const f = r.response?.finding;
    if (!f || !f.cwe) continue;
    lines.push(`### \`${r.path}\` — ${f.cwe} (${f.severity?.toUpperCase()})`);
    lines.push(`**${f.vulnerability || 'Vulnerability'}**  •  confidence \`${f.confidence}\``);
    if (f.root_cause)      lines.push(`- **Root cause:** ${f.root_cause}`);
    if (f.attack_scenario) lines.push(`- **Attack scenario:** ${f.attack_scenario}`);
    if (f.secure_fix)      lines.push(`- **Secure fix:** ${f.secure_fix}`);
    if (f.patched_code) {
      lines.push('');
      lines.push('```');
      lines.push(f.patched_code);
      lines.push('```');
    }
    if (f.references && f.references.length) {
      lines.push('');
      lines.push('References:');
      for (const ref of f.references) lines.push(`- ${ref}`);
    }
    lines.push('');
  }
  return lines.join('\n');
}

run().catch(e => core.setFailed(e instanceof Error ? e.message : String(e)));
