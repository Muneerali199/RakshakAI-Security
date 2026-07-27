"""Codebase vector indexing for semantic search and RAG context.

Uses sentence-transformers for embeddings and FAISS for fast similarity search.
Enables queries like:
- "find all SQL queries"
- "authentication logic"
- "file upload handlers"
"""
from __future__ import annotations
import os
import json
import pickle
from pathlib import Path
from typing import List, Tuple, Optional
from dataclasses import dataclass, asdict


@dataclass
class CodeChunk:
    """A chunk of code with metadata."""
    file_path: str
    start_line: int
    end_line: int
    content: str
    language: str
    embedding: Optional[list] = None
    
    def __str__(self):
        return f"{self.file_path}:{self.start_line}-{self.end_line}"


class CodebaseIndex:
    """Semantic search index for codebase."""
    
    def __init__(self, index_dir: str = ".rakshak_index"):
        self.index_dir = index_dir
        self.chunks: List[CodeChunk] = []
        self.index = None  # FAISS index
        self.model = None  # Sentence transformer model
        
    def embed_codebase(self, root_dir: str, chunk_size: int = 50):
        """Embed all code files in directory.
        
        Args:
            root_dir: Root directory to index
            chunk_size: Lines per chunk (default 50)
        """
        from v2.cli.scanner import collect_source_files, _should_ignore
        
        print(f"Collecting source files from {root_dir}...")
        files = collect_source_files(root_dir, max_files=1000)
        
        print(f"Found {len(files)} files. Chunking...")
        self.chunks = []
        
        for file_path in files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                    lines = f.readlines()
                
                # Split into chunks
                for i in range(0, len(lines), chunk_size):
                    chunk_lines = lines[i:i+chunk_size]
                    content = ''.join(chunk_lines).strip()
                    
                    if len(content) < 20:  # Skip tiny chunks
                        continue
                    
                    language = Path(file_path).suffix[1:] or 'txt'
                    
                    self.chunks.append(CodeChunk(
                        file_path=file_path,
                        start_line=i + 1,
                        end_line=min(i + chunk_size, len(lines)),
                        content=content,
                        language=language,
                    ))
            
            except Exception as e:
                print(f"Warning: Failed to read {file_path}: {e}")
                continue
        
        print(f"Created {len(self.chunks)} chunks. Embedding...")
        
        # Embed chunks
        self._load_model()
        texts = [chunk.content for chunk in self.chunks]
        embeddings = self.model.encode(texts, show_progress_bar=True, batch_size=32)
        
        for chunk, embedding in zip(self.chunks, embeddings):
            chunk.embedding = embedding.tolist()
        
        # Build FAISS index
        print("Building FAISS index...")
        self._build_index(embeddings)
        
        # Save to disk
        self.save()
        
        print(f"✓ Indexed {len(self.chunks)} chunks from {len(files)} files")
    
    def search(self, query: str, top_k: int = 10) -> List[Tuple[CodeChunk, float]]:
        """Semantic search for code chunks.
        
        Args:
            query: Natural language query
            top_k: Number of results to return
        
        Returns:
            List of (chunk, similarity_score) tuples
        """
        if not self.chunks or not self.index:
            return []
        
        self._load_model()
        
        # Embed query
        query_embedding = self.model.encode([query])[0]
        
        # Search FAISS index
        import numpy as np
        distances, indices = self.index.search(
            np.array([query_embedding], dtype=np.float32),
            top_k
        )
        
        # Return results
        results = []
        for idx, dist in zip(indices[0], distances[0]):
            if idx < len(self.chunks):
                # Convert distance to similarity score (cosine similarity)
                similarity = 1 - (dist / 2)  # FAISS uses L2 distance
                results.append((self.chunks[idx], float(similarity)))
        
        return results
    
    def get_context(self, file_path: str, k: int = 5) -> str:
        """Get related code context for a file (RAG).
        
        Args:
            file_path: Target file path
            k: Number of related chunks
        
        Returns:
            Concatenated context string
        """
        # Find chunks from the same file
        file_chunks = [c for c in self.chunks if c.file_path == file_path]
        if not file_chunks:
            return ""
        
        # Use first chunk as query to find related code
        query_text = file_chunks[0].content[:500]
        results = self.search(query_text, top_k=k)
        
        # Build context
        context_parts = []
        for chunk, score in results:
            if chunk.file_path != file_path:  # Exclude same file
                context_parts.append(f"# {chunk}\n{chunk.content[:300]}\n")
        
        return "\n".join(context_parts[:k])
    
    def _load_model(self):
        """Load sentence transformer model."""
        if self.model is None:
            try:
                from sentence_transformers import SentenceTransformer
                # Use lightweight code-focused model
                self.model = SentenceTransformer('all-MiniLM-L6-v2')
            except ImportError:
                raise RuntimeError(
                    "sentence-transformers not installed. Install with:\n"
                    "  pip install sentence-transformers"
                )
    
    def _build_index(self, embeddings):
        """Build FAISS index from embeddings."""
        try:
            import faiss
            import numpy as np
            
            embeddings_array = np.array(embeddings, dtype=np.float32)
            dimension = embeddings_array.shape[1]
            
            # Use IndexFlatIP for cosine similarity
            self.index = faiss.IndexFlatL2(dimension)
            self.index.add(embeddings_array)
        
        except ImportError:
            raise RuntimeError(
                "faiss-cpu not installed. Install with:\n"
                "  pip install faiss-cpu"
            )
    
    def save(self, filename: str = None):
        """Save index to disk."""
        if filename is None:
            Path(self.index_dir).mkdir(exist_ok=True)
            filename = os.path.join(self.index_dir, "index.pkl")
        
        data = {
            "chunks": [asdict(c) for c in self.chunks],
        }
        
        with open(filename, 'wb') as f:
            pickle.dump(data, f)
        
        # Save FAISS index separately
        if self.index:
            import faiss
            faiss_file = filename.replace('.pkl', '.faiss')
            faiss.write_index(self.index, faiss_file)
    
    def load(self, filename: str = None):
        """Load index from disk."""
        if filename is None:
            filename = os.path.join(self.index_dir, "index.pkl")
        
        if not os.path.exists(filename):
            return False
        
        with open(filename, 'rb') as f:
            data = pickle.load(f)
        
        self.chunks = [CodeChunk(**c) for c in data["chunks"]]
        
        # Load FAISS index
        faiss_file = filename.replace('.pkl', '.faiss')
        if os.path.exists(faiss_file):
            import faiss
            self.index = faiss.read_index(faiss_file)
        
        return True
    
    def stats(self) -> dict:
        """Get index statistics."""
        if not self.chunks:
            return {"indexed": False}
        
        files = set(c.file_path for c in self.chunks)
        languages = {}
        for c in self.chunks:
            languages[c.language] = languages.get(c.language, 0) + 1
        
        return {
            "indexed": True,
            "chunks": len(self.chunks),
            "files": len(files),
            "languages": languages,
            "index_dir": self.index_dir,
        }


# CLI usage
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python code_index.py index <directory>")
        print("  python code_index.py search <query>")
        print("  python code_index.py stats")
        sys.exit(1)
    
    command = sys.argv[1]
    index = CodebaseIndex()
    
    if command == "index":
        root_dir = sys.argv[2] if len(sys.argv) > 2 else "."
        index.embed_codebase(root_dir)
    
    elif command == "search":
        query = " ".join(sys.argv[2:])
        if not index.load():
            print("✗ No index found. Run 'index' first.")
            sys.exit(1)
        
        results = index.search(query, top_k=5)
        print(f"\nTop {len(results)} results for: {query}\n")
        
        for chunk, score in results:
            print(f"[{score:.2f}] {chunk}")
            print(f"  {chunk.content[:150]}...")
            print()
    
    elif command == "stats":
        if index.load():
            stats = index.stats()
            print(f"Indexed: {stats['indexed']}")
            print(f"Chunks: {stats['chunks']}")
            print(f"Files: {stats['files']}")
            print(f"Languages: {stats['languages']}")
        else:
            print("No index found")
