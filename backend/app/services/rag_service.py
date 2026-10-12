"""
SOCIS-AI-PT — RAG Service
Generates and stores embeddings via the external Ollama server (nomic-embed-text),
then performs similarity search against past findings to enrich LLM context.
"""

import logging
from typing import Optional

import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

logger = logging.getLogger(__name__)

# Embedding model on the EXTERNAL Ollama server (run `ollama pull nomic-embed-text` there).
# Override with OLLAMA_EMBED_MODEL.
_EMBED_MODEL = "nomic-embed-text"


class RAGService:
    async def _embed_url(self, db: Optional[AsyncSession]) -> Optional[str]:
        """Admin-configured external Ollama URL (Admin -> Settings), else OLLAMA_REMOTE_URL."""
        from app.config import settings
        url = None
        if db is not None:
            try:
                from app.services.settings_service import settings_service
                url = await settings_service.get_ollama_remote_url(db)
            except Exception:
                url = None
        url = url or settings.OLLAMA_REMOTE_URL
        return f"{url.rstrip('/')}/api/embeddings" if url else None

    async def embed(self, content: str, db: Optional[AsyncSession] = None) -> Optional[list[float]]:
        """Return a 768-dim embedding vector, or None when unavailable (no external Ollama configured)."""
        import os
        try:
            embed_url = await self._embed_url(db)
            if not embed_url:
                logger.debug("RAG embedding skipped: no external Ollama server configured")
                return None
            from app.core.netguard import acheck_url
            await acheck_url(embed_url, allow_private=True)
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    embed_url,
                    json={"model": os.environ.get("OLLAMA_EMBED_MODEL", _EMBED_MODEL), "prompt": content},
                )
                resp.raise_for_status()
                return resp.json().get("embedding")
        except Exception as e:
            logger.warning(f"RAG embed failed: {e}")
            return None

    async def store_finding(self, db: AsyncSession, vuln_id: str, content: str) -> None:
        """Generate an embedding and persist it to finding_embeddings."""
        embedding = await self.embed(content, db)
        if not embedding:
            return
        try:
            import uuid as _uuid
            from app.models.finding_embedding import FindingEmbedding
            record = FindingEmbedding(
                vuln_id=_uuid.UUID(vuln_id),
                content=content,
                embedding=embedding,
            )
            db.add(record)
            await db.commit()
        except Exception as e:
            logger.warning(f"Failed to store finding embedding: {e}")
            await db.rollback()

    async def find_similar(
        self, db: AsyncSession, query: str, limit: int = 5
    ) -> list[str]:
        """Return the top-k most similar stored findings for a query string."""
        embedding = await self.embed(query, db)
        if not embedding:
            return []
        try:
            result = await db.execute(
                text(
                    "SELECT content FROM finding_embeddings "
                    "ORDER BY embedding <-> cast(:emb AS vector) LIMIT :lim"
                ),
                {"emb": str(embedding), "lim": limit},
            )
            return [row[0] for row in result.fetchall()]
        except Exception as e:
            logger.warning(f"RAG similarity search failed: {e}")
            # Keep the parent workflow session usable after SQL errors (e.g. missing table)
            # so AI analysis can still continue and be persisted.
            await db.rollback()
            return []


rag_service = RAGService()
