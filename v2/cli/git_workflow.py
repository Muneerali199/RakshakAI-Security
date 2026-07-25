"""Git Workflow — commit, review, PR, branch management.
Like Claude Code's git integration commands."""
from __future__ import annotations
import os, subprocess, json, re
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field


@dataclass
class GitStatus:
    branch: str
    dirty: bool
    staged: list[str]
    unstaged: list[str]
    untracked: list[str]
    ahead: int
    behind: int


@dataclass
class CommitSuggestion:
    type: str  # feat, fix, docs, refactor, test, chore, security
    scope: Optional[str]
    message: str
    body: Optional[str] = None


def get_status() -> Optional[GitStatus]:
    try:
        branch = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True, timeout=5,
        ).stdout.strip()

        status_out = subprocess.run(
            ["git", "status", "--porcelain"],
            capture_output=True, text=True, timeout=5,
        ).stdout.strip()

        staged = []
        unstaged = []
        untracked = []
        for line in status_out.split("\n"):
            if not line.strip():
                continue
            code = line[:2]
            filepath = line[3:]
            if code == "??":
                untracked.append(filepath)
            elif code[0] != " ":
                staged.append(filepath)
            if code[1] != " ":
                unstaged.append(filepath)

        # Check ahead/behind
        ahead = behind = 0
        try:
            r = subprocess.run(
                ["git", "rev-list", "--left-right", "--count", "HEAD...@{upstream}"],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0:
                parts = r.stdout.strip().split()
                if len(parts) == 2:
                    ahead, behind = int(parts[0]), int(parts[1])
        except Exception:
            pass

        return GitStatus(
            branch=branch or "detached",
            dirty=bool(status_out),
            staged=staged,
            unstaged=unstaged,
            untracked=untracked,
            ahead=ahead,
            behind=behind,
        )
    except Exception:
        return None


def stage_files(files: list[str]) -> tuple[bool, str]:
    try:
        r = subprocess.run(
            ["git", "add", "--"] + files,
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0:
            return True, f"Staged {len(files)} file(s)"
        return False, r.stderr[:200]
    except Exception as e:
        return False, str(e)


def stage_all() -> tuple[bool, str]:
    try:
        r = subprocess.run(
            ["git", "add", "-A"],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0:
            return True, "Staged all changes"
        return False, r.stderr[:200]
    except Exception as e:
        return False, str(e)


def commit(message: str, body: Optional[str] = None) -> tuple[bool, str]:
    """Create a git commit with the given message."""
    try:
        full_msg = message
        if body:
            full_msg = f"{message}\n\n{body}"

        r = subprocess.run(
            ["git", "commit", "-m", full_msg],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0:
            # Extract short hash
            hash_match = re.search(r"\[[\w/]+ ([a-f0-9]+)\]", r.stdout)
            commit_hash = hash_match.group(1) if hash_match else "unknown"
            return True, f"Committed as {commit_hash}"
        return False, r.stderr[:300]
    except Exception as e:
        return False, str(e)


def amend(message: Optional[str] = None) -> tuple[bool, str]:
    """Amend last commit."""
    try:
        cmd = ["git", "commit", "--amend"]
        if message:
            cmd.extend(["-m", message])
        else:
            cmd.append("--no-edit")
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            return True, "Amended last commit"
        return False, r.stderr[:200]
    except Exception as e:
        return False, str(e)


def diff(files: Optional[list[str]] = None) -> str:
    try:
        cmd = ["git", "diff"]
        if files:
            cmd.extend(["--"] + files)
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return r.stdout[:10000]
    except Exception:
        return ""


def diff_staged() -> str:
    try:
        r = subprocess.run(
            ["git", "diff", "--cached"],
            capture_output=True, text=True, timeout=10,
        )
        return r.stdout[:10000]
    except Exception:
        return ""


def get_log(limit: int = 10) -> list[dict]:
    try:
        r = subprocess.run(
            ["git", "log", f"--{limit}", "--format=%H|%s|%an|%ar"],
            capture_output=True, text=True, timeout=5,
        )
        commits = []
        for line in r.stdout.strip().split("\n"):
            if "|" in line:
                parts = line.split("|", 3)
                commits.append({
                    "hash": parts[0][:8],
                    "message": parts[1],
                    "author": parts[2],
                    "date": parts[3],
                })
        return commits
    except Exception:
        return []


def suggest_commit_message(diff_text: str, model: Optional[str] = None) -> str:
    """Use AI to suggest a commit message from diff."""
    from v2.cli.llm import registry, chat_sync

    cfg = registry.get(model or "groq-llama-8b")
    msgs = [
        {
            "role": "system",
            "content": "You are a git commit message generator. "
                       "Given a diff, generate a concise conventional commit message "
                       "(type(scope): description). Keep the first line under 72 chars. "
                       "Add a body if the change is complex. "
                       "Format: type(scope): description\n\nbody",
        },
        {"role": "user", "content": f"Generate a commit message for:\n\n{diff_text[:3000]}"},
    ]
    try:
        return chat_sync(msgs, cfg).strip()
    except Exception:
        return "chore: update"


def create_pr(
    title: str,
    body: str = "",
    base: str = "main",
    head: Optional[str] = None,
) -> tuple[bool, str]:
    """Create a GitHub PR using gh CLI."""
    try:
        cmd = ["gh", "pr", "create", "--title", title, "--base", base]
        if body:
            cmd.extend(["--body", body])
        if head:
            cmd.extend(["--head", head])
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            return True, r.stdout.strip()
        return False, r.stderr[:300]
    except FileNotFoundError:
        return False, "gh CLI not installed. Install with: brew install gh"
    except Exception as e:
        return False, str(e)


def get_current_diff_for_commit() -> tuple[str, str]:
    """Get staged diff, or unstaged diff if nothing staged."""
    staged = diff_staged()
    if staged:
        return staged, "staged"
    return diff(), "unstaged"
