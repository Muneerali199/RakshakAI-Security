"""Auto-test runner - detects and runs appropriate test framework.

Supports:
- pytest (Python)
- jest/npm test (JavaScript/TypeScript)
- cargo test (Rust)
- go test (Go)
- mvn test (Java)
- dotnet test (C#)
"""
from __future__ import annotations
import os
import subprocess
from pathlib import Path
from typing import Optional, List
from dataclasses import dataclass
from enum import Enum


class TestFramework(Enum):
    """Supported test frameworks."""
    PYTEST = "pytest"
    JEST = "jest"
    NPM = "npm"
    CARGO = "cargo"
    GO = "go"
    MAVEN = "mvn"
    DOTNET = "dotnet"
    UNKNOWN = "unknown"


@dataclass
class TestResult:
    """Test execution result."""
    framework: TestFramework
    passed: bool
    output: str
    tests_run: int
    tests_passed: int
    tests_failed: int
    duration_seconds: float
    command: str


class TestRunner:
    """Automatically detects and runs test frameworks."""
    
    def __init__(self, workspace_root: str = "."):
        self.workspace_root = os.path.abspath(workspace_root)
    
    def detect_framework(self) -> TestFramework:
        """Detect which test framework is in use."""
        root = Path(self.workspace_root)
        
        # Python - pytest
        if (root / "pytest.ini").exists() or \
           (root / "pyproject.toml").exists() or \
           any(root.rglob("test_*.py")) or \
           any(root.rglob("*_test.py")):
            if self._is_installed("pytest"):
                return TestFramework.PYTEST
        
        # JavaScript/TypeScript - jest or npm test
        if (root / "package.json").exists():
            package_json = root / "package.json"
            try:
                import json
                with open(package_json) as f:
                    data = json.load(f)
                    if "jest" in data.get("devDependencies", {}) or \
                       "jest" in data.get("dependencies", {}):
                        return TestFramework.JEST
                    if "scripts" in data and "test" in data["scripts"]:
                        return TestFramework.NPM
            except Exception:
                pass
        
        # Rust - cargo test
        if (root / "Cargo.toml").exists():
            return TestFramework.CARGO
        
        # Go - go test
        if any(root.rglob("go.mod")):
            return TestFramework.GO
        
        # Java - Maven
        if (root / "pom.xml").exists():
            return TestFramework.MAVEN
        
        # C# - dotnet test
        if any(root.rglob("*.csproj")) or any(root.rglob("*.sln")):
            return TestFramework.DOTNET
        
        return TestFramework.UNKNOWN
    
    def run_tests(self, file_filter: Optional[str] = None, verbose: bool = False) -> TestResult:
        """Run tests for the detected framework."""
        framework = self.detect_framework()
        
        if framework == TestFramework.PYTEST:
            return self._run_pytest(file_filter, verbose)
        elif framework == TestFramework.JEST:
            return self._run_jest(file_filter, verbose)
        elif framework == TestFramework.NPM:
            return self._run_npm_test(verbose)
        elif framework == TestFramework.CARGO:
            return self._run_cargo_test(verbose)
        elif framework == TestFramework.GO:
            return self._run_go_test(file_filter, verbose)
        elif framework == TestFramework.MAVEN:
            return self._run_maven_test(verbose)
        elif framework == TestFramework.DOTNET:
            return self._run_dotnet_test(verbose)
        else:
            return TestResult(
                framework=TestFramework.UNKNOWN,
                passed=False,
                output="No test framework detected",
                tests_run=0,
                tests_passed=0,
                tests_failed=0,
                duration_seconds=0,
                command="",
            )
    
    def _run_pytest(self, file_filter: Optional[str], verbose: bool) -> TestResult:
        """Run pytest."""
        cmd = ["pytest"]
        if file_filter:
            cmd.append(file_filter)
        if verbose:
            cmd.append("-v")
        else:
            cmd.append("-q")
        cmd.extend(["--tb=short", "--color=yes"])
        
        return self._execute_command(TestFramework.PYTEST, cmd)
    
    def _run_jest(self, file_filter: Optional[str], verbose: bool) -> TestResult:
        """Run jest."""
        cmd = ["npx", "jest"]
        if file_filter:
            cmd.append(file_filter)
        if verbose:
            cmd.append("--verbose")
        
        return self._execute_command(TestFramework.JEST, cmd)
    
    def _run_npm_test(self, verbose: bool) -> TestResult:
        """Run npm test."""
        cmd = ["npm", "test"]
        return self._execute_command(TestFramework.NPM, cmd)
    
    def _run_cargo_test(self, verbose: bool) -> TestResult:
        """Run cargo test."""
        cmd = ["cargo", "test"]
        if not verbose:
            cmd.append("--quiet")
        
        return self._execute_command(TestFramework.CARGO, cmd)
    
    def _run_go_test(self, file_filter: Optional[str], verbose: bool) -> TestResult:
        """Run go test."""
        cmd = ["go", "test"]
        if verbose:
            cmd.append("-v")
        if file_filter:
            cmd.append(file_filter)
        else:
            cmd.append("./...")
        
        return self._execute_command(TestFramework.GO, cmd)
    
    def _run_maven_test(self, verbose: bool) -> TestResult:
        """Run Maven test."""
        cmd = ["mvn", "test"]
        if not verbose:
            cmd.append("-q")
        
        return self._execute_command(TestFramework.MAVEN, cmd)
    
    def _run_dotnet_test(self, verbose: bool) -> TestResult:
        """Run dotnet test."""
        cmd = ["dotnet", "test"]
        if verbose:
            cmd.append("--verbosity", "normal")
        else:
            cmd.append("--verbosity", "quiet")
        
        return self._execute_command(TestFramework.DOTNET, cmd)
    
    def _execute_command(self, framework: TestFramework, cmd: List[str]) -> TestResult:
        """Execute test command and parse results."""
        import time
        
        start = time.time()
        try:
            result = subprocess.run(
                cmd,
                cwd=self.workspace_root,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
            )
            elapsed = time.time() - start
            
            output = result.stdout + result.stderr
            passed = result.returncode == 0
            
            # Parse test counts
            tests_run, tests_passed, tests_failed = self._parse_test_counts(
                framework, output
            )
            
            return TestResult(
                framework=framework,
                passed=passed,
                output=output,
                tests_run=tests_run,
                tests_passed=tests_passed,
                tests_failed=tests_failed,
                duration_seconds=round(elapsed, 2),
                command=" ".join(cmd),
            )
        
        except subprocess.TimeoutExpired:
            return TestResult(
                framework=framework,
                passed=False,
                output="Test execution timed out after 5 minutes",
                tests_run=0,
                tests_passed=0,
                tests_failed=0,
                duration_seconds=300,
                command=" ".join(cmd),
            )
        except Exception as e:
            return TestResult(
                framework=framework,
                passed=False,
                output=f"Error running tests: {e}",
                tests_run=0,
                tests_passed=0,
                tests_failed=0,
                duration_seconds=0,
                command=" ".join(cmd),
            )
    
    def _parse_test_counts(self, framework: TestFramework, output: str) -> tuple[int, int, int]:
        """Parse test counts from output."""
        import re
        
        if framework == TestFramework.PYTEST:
            # pytest output: "5 passed, 2 failed in 1.23s"
            match = re.search(r'(\d+) passed', output)
            passed = int(match.group(1)) if match else 0
            match = re.search(r'(\d+) failed', output)
            failed = int(match.group(1)) if match else 0
            return passed + failed, passed, failed
        
        elif framework == TestFramework.JEST:
            # jest output: "Tests: 2 failed, 5 passed, 7 total"
            match = re.search(r'Tests:.*?(\d+) total', output)
            total = int(match.group(1)) if match else 0
            match = re.search(r'(\d+) passed', output)
            passed = int(match.group(1)) if match else 0
            match = re.search(r'(\d+) failed', output)
            failed = int(match.group(1)) if match else 0
            return total, passed, failed
        
        elif framework == TestFramework.CARGO:
            # cargo output: "test result: ok. 5 passed; 0 failed; 0 ignored"
            match = re.search(r'(\d+) passed', output)
            passed = int(match.group(1)) if match else 0
            match = re.search(r'(\d+) failed', output)
            failed = int(match.group(1)) if match else 0
            return passed + failed, passed, failed
        
        elif framework == TestFramework.GO:
            # go output: "ok" or "FAIL"
            # Count "PASS" and "FAIL" lines
            passed = len(re.findall(r'^PASS', output, re.MULTILINE))
            failed = len(re.findall(r'^FAIL', output, re.MULTILINE))
            return passed + failed, passed, failed
        
        # Default: try to extract numbers
        match = re.search(r'(\d+) passed', output, re.IGNORECASE)
        passed = int(match.group(1)) if match else 0
        match = re.search(r'(\d+) failed', output, re.IGNORECASE)
        failed = int(match.group(1)) if match else 0
        return passed + failed, passed, failed
    
    def _is_installed(self, command: str) -> bool:
        """Check if command is installed."""
        try:
            subprocess.run(
                [command, "--version"],
                capture_output=True,
                timeout=2,
            )
            return True
        except (subprocess.SubprocessError, FileNotFoundError):
            return False


# Example usage
if __name__ == "__main__":
    import sys
    
    runner = TestRunner()
    framework = runner.detect_framework()
    
    print(f"Detected framework: {framework.value}")
    
    if framework != TestFramework.UNKNOWN:
        print("Running tests...")
        result = runner.run_tests(verbose=True)
        
        print(f"\nCommand: {result.command}")
        print(f"Passed: {result.passed}")
        print(f"Tests: {result.tests_run} run, {result.tests_passed} passed, {result.tests_failed} failed")
        print(f"Duration: {result.duration_seconds}s")
        print(f"\n{result.output}")
        
        sys.exit(0 if result.passed else 1)
    else:
        print("No test framework detected")
        sys.exit(2)
