"""Dynamic Skill Loader - Load agent skills from GitHub and local filesystem.

Skills are loaded from:
1. Local ~/.rakshakai/skills/
2. Project .rakshakai/skills/
3. GitHub repos (cached locally)
"""
from __future__ import annotations
import os
import re
import json
import hashlib
import requests
from pathlib import Path
from typing import Optional, Callable
from dataclasses import dataclass, field


@dataclass
class Skill:
    """A loaded agent skill."""
    name: str
    description: str
    source: str  # github, local, builtin
    version: str
    instructions: str  # The actual skill content
    tools_required: list[str] = field(default_factory=list)
    examples: list[dict] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    
    def matches_task(self, task: str) -> float:
        """Calculate relevance score (0-1) for a given task."""
        task_lower = task.lower()
        desc_lower = self.description.lower()
        
        # Simple keyword matching (would use embeddings in production)
        keywords = re.findall(r'\w+', desc_lower)
        task_words = set(re.findall(r'\w+', task_lower))
        
        matches = sum(1 for kw in keywords if kw in task_words)
        return min(matches / max(len(task_words), 1), 1.0)


class SkillRegistry:
    """Registry for discovering, loading, and managing agent skills."""
    
    SKILL_REPOS = [
        ("anthropics/skills", "skills"),  # 18 skills: webapp-testing, pdf, docx, xlsx, pptx, canvas-design, etc.
    ]
    
    def __init__(self, cache_dir: Optional[str] = None):
        self.cache_dir = Path(cache_dir or os.path.expanduser("~/.rakshakai/skills"))
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        self.skills: dict[str, Skill] = {}
        self._load_builtin_skills()
        self._load_local_skills()
    
    def _load_builtin_skills(self):
        """Load built-in fallback skills (always available)."""
        builtins = [
            Skill(
                name="code-review",
                description="Review source code for security vulnerabilities, bugs, and best practices",
                source="builtin",
                version="1.0.0",
                instructions="Review code for: SQL injection, XSS, buffer overflows, command injection, hardcoded secrets, path traversal, insecure crypto, race conditions, memory leaks. Output CWE + severity + fix.",
                tools_required=["file_ops", "web_search"],
            ),
            Skill(
                name="web-research",
                description="Search the web for documentation, tutorials, and current information",
                source="builtin",
                version="1.0.0",
                instructions="Use web_search to find relevant information. Summarize findings with sources. Verify information from multiple sources.",
                tools_required=["web_search", "http"],
            ),
            Skill(
                name="file-operations",
                description="Read, write, and organize files and directories",
                source="builtin",
                version="1.0.0",
                instructions="Use file_ops to read/write/list files. Always verify file exists before reading. Create parent directories when writing.",
                tools_required=["file_ops"],
            ),
            Skill(
                name="github-collaboration",
                description="Interact with GitHub: search repos, list issues, create issues, browse code",
                source="builtin",
                version="1.0.0",
                instructions="Use github tool for repo operations. Respect rate limits. Cache results when possible.",
                tools_required=["github", "http"],
            ),
            Skill(
                name="shell-commands",
                description="Run safe shell commands for development tasks",
                source="builtin",
                version="1.0.0",
                instructions="Use shell tool for: git operations, npm/pip commands, file listing, grep/search. Never run destructive commands.",
                tools_required=["shell"],
            ),
            Skill(
                name="vulnerability-scan",
                description="Scan source code for security vulnerabilities using static analysis",
                source="builtin",
                version="2.0.0",
                instructions="Use the scanner module to analyze code. Report CWE IDs with severity and confidence scores. Suggest fixes.",
                tools_required=["file_ops", "shell"],
            ),
            Skill(
                name="ui-design",
                description="Design and generate UI components using Tailwind CSS, HTML, and modern frameworks",
                source="builtin",
                version="1.0.0",
                instructions="Create responsive, accessible UI components. Use Tailwind CSS utility classes. Consider: layout, color scheme, typography, spacing, responsive breakpoints, dark mode.",
                tools_required=["file_ops", "web_search"],
            ),
            Skill(
                name="documentation",
                description="Write clear technical documentation, READMEs, API docs, and guides",
                source="builtin",
                version="1.0.0",
                instructions="Write documentation that is: clear, concise, well-structured. Include: purpose, installation, usage, API reference, examples, troubleshooting.",
                tools_required=["file_ops"],
            ),
        ]
        for skill in builtins:
            self.skills[skill.name] = skill

    def _load_local_skills(self):
        """Load skills from local filesystem."""
        # Check project-local skills
        project_skills = Path(".rakshakai/skills")
        if project_skills.exists():
            self._scan_directory(project_skills, source="local")
        
        # Check user global skills
        self._scan_directory(self.cache_dir, source="local")
    
    def _scan_directory(self, path: Path, source: str):
        """Scan directory for SKILL.md files."""
        for skill_file in path.rglob("SKILL.md"):
            try:
                skill = self._parse_skill_file(skill_file, source)
                if skill:
                    self.skills[skill.name] = skill
            except Exception:
                pass  # Skip malformed skills
    
    def _parse_skill_file(self, path: Path, source: str) -> Optional[Skill]:
        """Parse a SKILL.md file."""
        content = path.read_text(encoding="utf-8")
        
        # Extract frontmatter metadata
        meta_match = re.search(r'^---\n(.*?)\n---', content, re.DOTALL)
        metadata = {}
        
        if meta_match:
            # Simple YAML parser for common fields
            for line in meta_match.group(1).split('\n'):
                if ':' in line:
                    key, val = line.split(':', 1)
                    metadata[key.strip()] = val.strip().strip('"\'')
        
        # Extract description
        desc_match = re.search(r'## Description\n+(.*?)(?:\n##|$)', content, re.DOTALL)
        description = desc_match.group(1).strip() if desc_match else ""
        
        # Extract tools required
        tools_match = re.search(r'## Tools\n+(.*?)(?:\n##|$)', content, re.DOTALL)
        tools = []
        if tools_match:
            tools = [t.strip('- ').strip() for t in tools_match.group(1).split('\n') if t.strip()]
        
        name = metadata.get('name', path.parent.name)
        
        return Skill(
            name=name,
            description=description or metadata.get('description', ''),
            source=source,
            version=metadata.get('version', '1.0.0'),
            instructions=content,
            tools_required=tools,
            metadata=metadata,
        )
    
    def fetch_from_github(
        self,
        repo: str,
        skill_path: Optional[str] = None,
        force_update: bool = False,
    ) -> list[Skill]:
        """Fetch skills from GitHub repository."""
        cache_key = hashlib.md5(f"{repo}:{skill_path or ''}".encode()).hexdigest()[:12]
        cache_path = self.cache_dir / f"github_{cache_key}"
        
        # Use cache if available
        if cache_path.exists() and not force_update:
            return self._load_cached_github_skills(cache_path)
        
        # Fetch from GitHub API
        skills = []
        try:
            skills = self._fetch_github_skills_api(repo, skill_path)
            
            # Cache the results
            cache_path.mkdir(parents=True, exist_ok=True)
            for skill in skills:
                skill_file = cache_path / f"{skill.name}.json"
                skill_file.write_text(json.dumps({
                    "name": skill.name,
                    "description": skill.description,
                    "version": skill.version,
                    "instructions": skill.instructions,
                    "tools_required": skill.tools_required,
                    "metadata": skill.metadata,
                }))
        except Exception as e:
            # Silently fail, use cache if available
            if cache_path.exists():
                return self._load_cached_github_skills(cache_path)
        
        return skills
    
    def _fetch_github_skills_api(
        self,
        repo: str,
        skill_path: Optional[str] = None,
    ) -> list[Skill]:
        """Fetch skills using GitHub API."""
        base_url = f"https://api.github.com/repos/{repo}/contents"
        url = f"{base_url}/{skill_path}" if skill_path else base_url
        
        # Use GitHub token if available
        headers = {}
        gh_token = os.environ.get("GITHUB_TOKEN")
        if gh_token:
            headers["Authorization"] = f"token {gh_token}"
        
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code != 200:
            return []
        
        items = response.json()
        skills = []
        
        for item in items:
            if item["name"] == "SKILL.md":
                # Download skill file
                skill_content = requests.get(item["download_url"], timeout=10).text
                skill = self._parse_skill_content(skill_content, f"github:{repo}")
                if skill:
                    skills.append(skill)
            elif item["type"] == "dir" and skill_path is None:
                # Recursively scan subdirectories (limit depth)
                sub_skills = self._fetch_github_skills_api(repo, item["path"])
                skills.extend(sub_skills)
        
        return skills
    
    def _parse_skill_content(self, content: str, source: str) -> Optional[Skill]:
        """Parse skill content from string."""
        # Similar to _parse_skill_file but works with string content
        meta_match = re.search(r'^---\n(.*?)\n---', content, re.DOTALL)
        metadata = {}
        
        if meta_match:
            for line in meta_match.group(1).split('\n'):
                if ':' in line:
                    key, val = line.split(':', 1)
                    metadata[key.strip()] = val.strip().strip('"\'')
        
        desc_match = re.search(r'## Description\n+(.*?)(?:\n##|$)', content, re.DOTALL)
        description = desc_match.group(1).strip() if desc_match else ""
        
        tools_match = re.search(r'## Tools\n+(.*?)(?:\n##|$)', content, re.DOTALL)
        tools = []
        if tools_match:
            tools = [t.strip('- ').strip() for t in tools_match.group(1).split('\n') if t.strip()]
        
        name = metadata.get('name', 'unknown')
        
        return Skill(
            name=name,
            description=description or metadata.get('description', ''),
            source=source,
            version=metadata.get('version', '1.0.0'),
            instructions=content,
            tools_required=tools,
            metadata=metadata,
        )
    
    def _load_cached_github_skills(self, cache_path: Path) -> list[Skill]:
        """Load skills from cache directory."""
        skills = []
        for skill_file in cache_path.glob("*.json"):
            try:
                data = json.loads(skill_file.read_text())
                skills.append(Skill(
                    name=data["name"],
                    description=data["description"],
                    source="github-cached",
                    version=data.get("version", "1.0.0"),
                    instructions=data["instructions"],
                    tools_required=data.get("tools_required", []),
                    metadata=data.get("metadata", {}),
                ))
            except Exception:
                pass
        
        return skills
    
    def auto_discover(self, task: str, limit: int = 5) -> list[Skill]:
        """Automatically discover relevant skills for a task."""
        for repo, path in self.SKILL_REPOS:
            try:
                github_skills = self.fetch_from_github(repo, skill_path=path)
                for skill in github_skills:
                    self.skills[skill.name] = skill
            except Exception:
                pass

        ranked = [
            (skill, skill.matches_task(task))
            for skill in self.skills.values()
        ]
        ranked.sort(key=lambda x: x[1], reverse=True)

        return [skill for skill, score in ranked[:limit] if score > 0.1]
    
    def get_skill(self, name: str) -> Optional[Skill]:
        """Get a specific skill by name."""
        return self.skills.get(name)
    
    def list_skills(self) -> list[str]:
        """List all available skill names."""
        return sorted(self.skills.keys())
    
    def refresh_cache(self):
        """Refresh GitHub skill cache."""
        for repo, path in self.SKILL_REPOS:
            try:
                self.fetch_from_github(repo, skill_path=path, force_update=True)
            except Exception:
                pass
