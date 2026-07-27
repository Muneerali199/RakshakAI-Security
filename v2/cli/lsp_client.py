"""Language Server Protocol (LSP) client for symbol navigation, hover, refactoring.

Supports:
- pylsp (Python)
- typescript-language-server (TypeScript/JavaScript)
- rust-analyzer (Rust)
- gopls (Go)
- clangd (C/C++)

Usage:
    lsp = LSPClient(language="python")
    definition = lsp.goto_definition("src/main.py", 45, 10)
    hover_info = lsp.hover("src/main.py", 45, 10)
    references = lsp.find_references("src/main.py", 45, 10)
"""
from __future__ import annotations
import subprocess
import json
import os
from typing import Optional, List
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Location:
    """Code location (file, line, column)."""
    file: str
    line: int
    column: int
    
    def __str__(self):
        return f"{self.file}:{self.line}:{self.column}"


@dataclass
class Edit:
    """Code edit (replace range with new text)."""
    file: str
    start_line: int
    start_col: int
    end_line: int
    end_col: int
    new_text: str


class LSPClient:
    """LSP client for symbol navigation and refactoring.
    
    Automatically detects and starts appropriate language server.
    """
    
    LANGUAGE_SERVERS = {
        "python": ["pylsp"],
        "typescript": ["typescript-language-server", "--stdio"],
        "javascript": ["typescript-language-server", "--stdio"],
        "rust": ["rust-analyzer"],
        "go": ["gopls"],
        "c": ["clangd"],
        "cpp": ["clangd"],
        "java": ["jdtls"],
    }
    
    def __init__(self, language: str = "python", workspace_root: str = "."):
        self.language = language.lower()
        self.workspace_root = os.path.abspath(workspace_root)
        self.server_process: Optional[subprocess.Popen] = None
        self.message_id = 0
        
    def start(self):
        """Start the language server process."""
        cmd = self.LANGUAGE_SERVERS.get(self.language)
        if not cmd:
            raise ValueError(f"No language server configured for {self.language}")
        
        # Check if server is installed
        if not self._is_installed(cmd[0]):
            raise RuntimeError(
                f"Language server '{cmd[0]}' not found. Install with:\n"
                f"  pip install python-lsp-server  # for Python\n"
                f"  npm install -g typescript-language-server  # for TypeScript"
            )
        
        self.server_process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.workspace_root,
        )
        
        # Send initialize request
        init_response = self._send_request("initialize", {
            "processId": os.getpid(),
            "rootUri": f"file://{self.workspace_root}",
            "capabilities": {
                "textDocument": {
                    "hover": {"contentFormat": ["plaintext"]},
                    "definition": {"linkSupport": True},
                    "references": {},
                    "rename": {},
                }
            },
        })
        
        # Send initialized notification
        self._send_notification("initialized", {})
        
        return init_response
    
    def stop(self):
        """Stop the language server."""
        if self.server_process:
            self._send_request("shutdown", {})
            self._send_notification("exit", {})
            self.server_process.terminate()
            self.server_process.wait(timeout=5)
    
    def goto_definition(self, file: str, line: int, column: int) -> Optional[Location]:
        """Jump to symbol definition."""
        if not self.server_process:
            self.start()
        
        response = self._send_request("textDocument/definition", {
            "textDocument": {"uri": f"file://{os.path.abspath(file)}"},
            "position": {"line": line - 1, "character": column},  # LSP is 0-indexed
        })
        
        if not response or not response.get("result"):
            return None
        
        result = response["result"]
        if isinstance(result, list):
            result = result[0] if result else None
        
        if result:
            uri = result["uri"].replace("file://", "")
            pos = result["range"]["start"]
            return Location(uri, pos["line"] + 1, pos["character"])
        
        return None
    
    def hover(self, file: str, line: int, column: int) -> Optional[str]:
        """Get hover information (type hints, docstrings)."""
        if not self.server_process:
            self.start()
        
        response = self._send_request("textDocument/hover", {
            "textDocument": {"uri": f"file://{os.path.abspath(file)}"},
            "position": {"line": line - 1, "character": column},
        })
        
        if not response or not response.get("result"):
            return None
        
        contents = response["result"].get("contents")
        if isinstance(contents, str):
            return contents
        elif isinstance(contents, dict):
            return contents.get("value", "")
        elif isinstance(contents, list):
            return "\n".join(str(c) for c in contents)
        
        return None
    
    def find_references(self, file: str, line: int, column: int) -> List[Location]:
        """Find all references to a symbol."""
        if not self.server_process:
            self.start()
        
        response = self._send_request("textDocument/references", {
            "textDocument": {"uri": f"file://{os.path.abspath(file)}"},
            "position": {"line": line - 1, "character": column},
            "context": {"includeDeclaration": True},
        })
        
        if not response or not response.get("result"):
            return []
        
        locations = []
        for ref in response["result"]:
            uri = ref["uri"].replace("file://", "")
            pos = ref["range"]["start"]
            locations.append(Location(uri, pos["line"] + 1, pos["character"]))
        
        return locations
    
    def rename(self, file: str, line: int, column: int, new_name: str) -> List[Edit]:
        """Rename symbol across all files."""
        if not self.server_process:
            self.start()
        
        response = self._send_request("textDocument/rename", {
            "textDocument": {"uri": f"file://{os.path.abspath(file)}"},
            "position": {"line": line - 1, "character": column},
            "newName": new_name,
        })
        
        if not response or not response.get("result"):
            return []
        
        edits = []
        workspace_edit = response["result"]
        
        for uri, changes in workspace_edit.get("changes", {}).items():
            file_path = uri.replace("file://", "")
            for change in changes:
                start = change["range"]["start"]
                end = change["range"]["end"]
                edits.append(Edit(
                    file=file_path,
                    start_line=start["line"] + 1,
                    start_col=start["character"],
                    end_line=end["line"] + 1,
                    end_col=end["character"],
                    new_text=change["newText"],
                ))
        
        return edits
    
    def _send_request(self, method: str, params: dict) -> Optional[dict]:
        """Send LSP request and wait for response."""
        self.message_id += 1
        request = {
            "jsonrpc": "2.0",
            "id": self.message_id,
            "method": method,
            "params": params,
        }
        
        content = json.dumps(request)
        message = f"Content-Length: {len(content)}\r\n\r\n{content}"
        
        if self.server_process and self.server_process.stdin:
            self.server_process.stdin.write(message.encode())
            self.server_process.stdin.flush()
            
            # Read response
            return self._read_response()
        
        return None
    
    def _send_notification(self, method: str, params: dict):
        """Send LSP notification (no response expected)."""
        notification = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        }
        
        content = json.dumps(notification)
        message = f"Content-Length: {len(content)}\r\n\r\n{content}"
        
        if self.server_process and self.server_process.stdin:
            self.server_process.stdin.write(message.encode())
            self.server_process.stdin.flush()
    
    def _read_response(self) -> Optional[dict]:
        """Read LSP response from server."""
        if not self.server_process or not self.server_process.stdout:
            return None
        
        # Read Content-Length header
        header = b""
        while not header.endswith(b"\r\n\r\n"):
            char = self.server_process.stdout.read(1)
            if not char:
                return None
            header += char
        
        # Parse content length
        header_str = header.decode()
        content_length = 0
        for line in header_str.split("\r\n"):
            if line.startswith("Content-Length:"):
                content_length = int(line.split(":")[1].strip())
                break
        
        if content_length == 0:
            return None
        
        # Read content
        content = self.server_process.stdout.read(content_length)
        return json.loads(content.decode())
    
    def _is_installed(self, command: str) -> bool:
        """Check if command is installed."""
        try:
            subprocess.run([command, "--version"], capture_output=True, timeout=2)
            return True
        except (subprocess.SubprocessError, FileNotFoundError):
            return False
    
    def __enter__(self):
        self.start()
        return self
    
    def __exit__(self, *args):
        self.stop()


def detect_language(file_path: str) -> str:
    """Detect language from file extension."""
    ext = Path(file_path).suffix.lower()
    
    ext_map = {
        ".py": "python",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".js": "javascript",
        ".jsx": "javascript",
        ".rs": "rust",
        ".go": "go",
        ".c": "c",
        ".cpp": "cpp",
        ".cc": "cpp",
        ".cxx": "cpp",
        ".h": "c",
        ".hpp": "cpp",
        ".java": "java",
    }
    
    return ext_map.get(ext, "python")


# Example usage
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 4:
        print("Usage: python lsp_client.py <file> <line> <column>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    line = int(sys.argv[2])
    column = int(sys.argv[3])
    
    language = detect_language(file_path)
    
    with LSPClient(language=language) as lsp:
        # Test goto definition
        definition = lsp.goto_definition(file_path, line, column)
        if definition:
            print(f"Definition: {definition}")
        
        # Test hover
        hover = lsp.hover(file_path, line, column)
        if hover:
            print(f"Hover: {hover}")
        
        # Test find references
        references = lsp.find_references(file_path, line, column)
        if references:
            print(f"References ({len(references)}):")
            for ref in references[:10]:
                print(f"  {ref}")
