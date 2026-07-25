"""Scanner test suite — known-vulnerable snippets with expected CWE labels.

Run against every prompt/model change to catch silent regressions.
Each snippet is a minimal reproduction of a real vulnerability class.

Usage:
    python -m v2.cli.test_scanner              # run all tests
    python -m v2.cli.test_scanner --model gpt-4o  # test specific model
    python -m v2.cli.test_scanner --json        # machine-readable output
"""
from __future__ import annotations
import argparse
import json
import sys
import time
from pathlib import Path
from dataclasses import dataclass

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from v2.cli.llm import registry, chat_sync
from v2.cli.prompts import get_scan_messages


@dataclass
class TestCase:
    name: str
    language: str
    code: str
    expected_cwe: str  # CWE ID (e.g., "CWE-78")
    expected_severity: str  # "critical", "high", "medium", "low"
    description: str


# ── Known-vulnerable snippets ──────────────────────────────────

TEST_CASES = [
    TestCase(
        name="sql_injection",
        language="c",
        code='''void query(char *user_input) {
    char sql[256];
    snprintf(sql, sizeof(sql), "SELECT * FROM users WHERE id = %s", user_input);
    sqlite3_exec(db, sql, NULL, NULL, NULL);
}''',
        expected_cwe="CWE-89",
        expected_severity="critical",
        description="SQL injection via string formatting",
    ),
    TestCase(
        name="buffer_overflow",
        language="c",
        code='''void copy_input(char *input) {
    char buffer[64];
    strcpy(buffer, input);
    printf("Copied: %s\\n", buffer);
}''',
        expected_cwe="CWE-120",
        expected_severity="critical",
        description="Buffer overflow via unchecked strcpy",
    ),
    TestCase(
        name="format_string",
        language="c",
        code='''void log_user(char *username) {
    printf(username);
}''',
        expected_cwe="CWE-134",
        expected_severity="high",
        description="Format string vulnerability",
    ),
    TestCase(
        name="use_after_free",
        language="c",
        code='''void process() {
    char *ptr = malloc(128);
    free(ptr);
    // ... some code ...
    strcpy(ptr, "use after free");
}''',
        expected_cwe="CWE-416",
        expected_severity="critical",
        description="Use after free",
    ),
    TestCase(
        name="path_traversal",
        language="python",
        code='''def read_file(filename):
    path = "/data/" + filename
    with open(path) as f:
        return f.read()''',
        expected_cwe="CWE-22",
        expected_severity="high",
        description="Path traversal via unsanitized input",
    ),
    TestCase(
        name="xss_reflected",
        language="javascript",
        code='''function showName(name) {
    document.getElementById("output").innerHTML = "Hello, " + name;
}''',
        expected_cwe="CWE-79",
        expected_severity="high",
        description="Reflected XSS via innerHTML",
    ),
    TestCase(
        name="hardcoded_secret",
        language="python",
        code='''DATABASE_PASSWORD = "super_secret_123"
API_KEY = "nvapi-abc123def456"

def connect():
    return db.connect(password=DATABASE_PASSWORD)''',
        expected_cwe="CWE-798",
        expected_severity="high",
        description="Hardcoded credentials",
    ),
    TestCase(
        name="command_injection",
        language="python",
        code='''import os
def ping(host):
    os.system("ping -c 1 " + host)''',
        expected_cwe="CWE-78",
        expected_severity="critical",
        description="OS command injection",
    ),
    TestCase(
        name="integer_overflow",
        language="c",
        code='''void allocate(int count) {
    int size = count * sizeof(void*);
    char *buf = malloc(size);
}''',
        expected_cwe="CWE-190",
        expected_severity="high",
        description="Integer overflow leading to heap buffer overflow",
    ),
    TestCase(
        name="race_condition",
        language="c",
        code='''void withdraw(int amount) {
    if (balance >= amount) {
        // TOCTOU: balance could change here
        balance -= amount;
        transfer(owner, amount);
    }
}''',
        expected_cwe="CWE-362",
        expected_severity="medium",
        description="TOCTOU race condition",
    ),
    TestCase(
        name="null_pointer",
        language="c",
        code='''void process(char *data) {
    int len = strlen(data);
    data[len] = '\\0';
}''',
        expected_cwe="CWE-476",
        expected_severity="medium",
        description="Null pointer dereference potential",
    ),
    TestCase(
        name="sql_injection_python",
        language="python",
        code='''def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)''',
        expected_cwe="CWE-89",
        expected_severity="critical",
        description="SQL injection in Python",
    ),
]


def run_test(tc: TestCase, model: str) -> dict:
    """Run a single test case against the model. Returns test result."""
    cfg = registry.get(model)
    messages = get_scan_messages(f"```\n{tc.code}\n```", model)

    start = time.time()
    try:
        response = chat_sync(messages, cfg)
        dur_ms = int((time.time() - start) * 1000)

        import re
        match = re.search(r'```(?:json)?\n(.*?)\n```', response, re.DOTALL)
        data = {}
        if match:
            try:
                data = json.loads(match.group(1))
            except json.JSONDecodeError:
                pass

        vulns = data.get("vulnerabilities", [])
        detected_cwe = vulns[0].get("cwe", "") if vulns else ""
        detected_sev = vulns[0].get("severity", "").lower() if vulns else ""

        # Check if the correct CWE family was detected
        expected_family = tc.expected_cwe.split("-")[1]  # e.g., "89"
        detected_family = detected_cwe.split("-")[-1] if detected_cwe else ""

        cwe_match = expected_family == detected_family or expected_cwe == detected_cwe
        sev_match = detected_sev == tc.expected_severity

        return {
            "name": tc.name,
            "language": tc.language,
            "expected_cwe": tc.expected_cwe,
            "detected_cwe": detected_cwe,
            "cwe_match": cwe_match,
            "expected_severity": tc.expected_severity,
            "detected_severity": detected_sev,
            "severity_match": sev_match,
            "pass": cwe_match,  # pass if correct CWE family detected
            "duration_ms": dur_ms,
            "response_preview": response[:200],
        }
    except Exception as e:
        return {
            "name": tc.name,
            "language": tc.language,
            "expected_cwe": tc.expected_cwe,
            "detected_cwe": "",
            "cwe_match": False,
            "expected_severity": tc.expected_severity,
            "detected_severity": "",
            "severity_match": False,
            "pass": False,
            "duration_ms": int((time.time() - start) * 1000),
            "error": str(e),
        }


def main():
    parser = argparse.ArgumentParser(description="RakshakAI scanner test suite")
    parser.add_argument("--model", "-m", default="deepseek", help="Model to test")
    parser.add_argument("--json", action="store_true", help="Machine-readable output")
    parser.add_argument("--test", "-t", help="Run specific test by name")
    args = parser.parse_args()

    cases = TEST_CASES
    if args.test:
        cases = [tc for tc in TEST_CASES if tc.name == args.test]
        if not cases:
            print(f"Test '{args.test}' not found. Available: {', '.join(tc.name for tc in TEST_CASES)}")
            sys.exit(1)

    if not args.json:
        print(f"Testing {len(cases)} cases with model={args.model}\n")

    results = []
    passed = 0
    failed = 0

    for tc in cases:
        result = run_test(tc, args.model)
        results.append(result)
        if result["pass"]:
            passed += 1
        else:
            failed += 1

        if not args.json:
            status = "PASS" if result["pass"] else "FAIL"
            cwe_info = f"{result['detected_cwe']} (expected {result['expected_cwe']})"
            print(f"  [{status}] {tc.name}: {cwe_info}  {result['duration_ms']}ms")

    if args.json:
        output = {
            "model": args.model,
            "total": len(results),
            "passed": passed,
            "failed": failed,
            "precision": round(passed / len(results), 3) if results else 0,
            "results": results,
        }
        print(json.dumps(output, indent=2))
    else:
        print(f"\n{'='*40}")
        print(f"  Passed: {passed}/{len(results)}  Failed: {failed}")
        print(f"  Precision: {passed/len(results):.1%}" if results else "  No tests run")
        sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
