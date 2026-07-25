"""Tests for rakshak_cli.py"""
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import rakshak_cli as cli


def test_content_hash():
    h1 = cli.content_hash("hello world")
    h2 = cli.content_hash("hello world")
    h3 = cli.content_hash("different")
    assert h1 == h2
    assert h1 != h3
    assert len(h1) == 16


def test_guess_language():
    assert cli.guess_language("foo.py") == "python"
    assert cli.guess_language("foo.js") == "javascript"
    assert cli.guess_language("foo.rs") == "rust"
    assert cli.guess_language("foo.unknown") == "text"


def test_local_vuln_match_sql():
    result = cli._local_vuln_match('SELECT * FROM users WHERE id = "' + ' + user_input')
    assert result is not None
    assert "SQL injection" in result[0]
    assert result[1] == "CWE-89"


def test_local_vuln_match_clean():
    result = cli._local_vuln_match("print('hello world')")
    assert result is None


def test_cmd_health_no_server():
    with tempfile.TemporaryDirectory() as tmp:
        cfg = {**cli.DEFAULT_CONFIG, "v1_url": f"http://127.0.0.1:19999"}
        args = cli.argparse.Namespace(url=None, format="json")
        rc = cli.cmd_health(args, cfg)
        assert rc == 1


def test_print_sarif():
    issues = [
        {"line": 10, "cweId": "CWE-89", "severity": "critical", "message": "SQL Injection"},
    ]
    result = json.loads(cli.print_sarif(issues, "test.py"))
    assert result["version"] == "2.1.0"
    assert len(result["runs"][0]["results"]) == 1
    assert result["runs"][0]["results"][0]["ruleId"] == "CWE-89"


def test_cache_roundtrip():
    with tempfile.TemporaryDirectory() as tmp:
        orig = cli.CACHE_FILE
        cli.CACHE_FILE = Path(tmp) / "cache.json"
        try:
            cli.cache_set(__file__, [{"test": True}])
            assert cli.cache_get(__file__) == [{"test": True}]

            stats = cli.cache_stats()
            assert stats["total_files"] == 1
            assert stats["with_issues"] == 1
        finally:
            cli.CACHE_FILE = orig


def test_config_defaults():
    cfg = cli.load_config()
    assert cfg["mock"] is True
    assert cfg["format"] == "table"
    assert cfg["timeout"] == 120


def test_cmd_generate_local():
    cfg = cli.DEFAULT_CONFIG.copy()
    args = cli.argparse.Namespace(prompt="secure file upload in python", language="python",
                                  format="table")
    rc = cli.cmd_generate(args, cfg)
    assert rc == 0


def test_cmd_review_local():
    cfg = cli.DEFAULT_CONFIG.copy()
    with tempfile.NamedTemporaryFile(mode="w", suffix=".diff", delete=False) as f:
        f.write('+ os.system("rm -rf /")')
        f.flush()
        args = cli.argparse.Namespace(path=f.name, language="python", format="table")
        rc = cli.cmd_review(args, cfg)
        assert rc == 0


def test_cmd_generate_v2_fallback():
    """When v2 server is not reachable, local fallback should kick in."""
    cfg = cli.DEFAULT_CONFIG.copy()
    cfg["v2_url"] = "http://127.0.0.1:1"  # unreachable
    args = cli.argparse.Namespace(prompt="database query", language="python", format="json")
    rc = cli.cmd_generate(args, cfg)
    assert rc == 0


def test_output_flag_json():
    cfg = cli.DEFAULT_CONFIG.copy()
    cfg["mock"] = True
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write('password = "supersecret"')
        f.flush()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as out:
            # scan with --output flag — should write to file
            args = cli.argparse.Namespace(
                path=f.name, format="json", language=None,
                output=out.name, exclude=None, no_cache=True,
            )
            with patch.object(cli, "api_post") as mock_api:
                mock_api.return_value = {
                    "issues": [{"line": 1, "message": "HARDCODED_SECRET Detected",
                                "severity": "high", "category": "HARDCODED_SECRET",
                                "cweId": "CWE-798", "confidence": 0.95}]
                }
                rc = cli.cmd_scan(args, cfg)
                assert rc == 0
            written = json.loads(Path(out.name).read_text())
            assert len(written) == 1
            assert written[0]["cweId"] == "CWE-798"
