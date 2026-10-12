"""
SOCIS-AI-PT — FindingEmbedding Model (pgvector RAG)
Stores vector embeddings of vulnerability findings for RAG-enhanced LLM context.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import Text, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID
from pgvector.sqlalchemy import Vector

from app.core.database import Base


class FindingEmbedding(Base):
    __tablename__ = "finding_embeddings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    vuln_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False
    )
    content: Mapped[str] = mapped_column(Text, nullable=False)
    # 768 dimensions for nomic-embed-text; adjust if using a different model
    embedding = mapped_column(Vector(768), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    def __repr__(self) -> str:
        return f"<FindingEmbedding vuln_id={self.vuln_id}>"
