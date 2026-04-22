"""
RAG Memory Store — mémoire persistante cross-runs via ChromaDB.

Référence :
  https://docs.trychroma.com/getting-started
  https://python.langchain.com/docs/integrations/vectorstores/chroma/

Chaque agent ÉCRIT ses findings après son analyse.
Le run suivant RÉCUPÈRE les findings similaires passés.
Cela permet aux agents de détecter des régressions
(un CVE qui réapparaît, un bug déjà vu).

Usage :
  from agents.memory_store import AgentMemory
  mem = AgentMemory("security_agent")
  mem.store("CVE-2024-1234 found in mbedtls 3.4.0")
  past = mem.retrieve("mbedtls vulnerability", n=3)
"""
import os
from pathlib import Path
from datetime import datetime

MEMORY_DIR = Path(os.getenv("MEMORY_DIR", ".agent_memory"))

def _get_collection(agent_name: str):
    """Retourne la collection ChromaDB pour cet agent."""
    try:
        import chromadb
        MEMORY_DIR.mkdir(exist_ok=True)
        client = chromadb.PersistentClient(path=str(MEMORY_DIR))
        return client.get_or_create_collection(
            name=agent_name.replace("-", "_"),
            metadata={"agent": agent_name},
        )
    except Exception as e:
        print(f"[Memory] ChromaDB unavailable: {e} — memory disabled")
        return None


class AgentMemory:
    """Interface mémoire pour un agent spécifique."""

    def __init__(self, agent_name: str):
        self.agent_name = agent_name
        self.collection = _get_collection(agent_name)

    def store(self, finding: str, metadata: dict = None) -> bool:
        """Stocke un finding avec timestamp et métadonnées."""
        if not self.collection:
            return False
        try:
            doc_id = f"{self.agent_name}_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"
            self.collection.add(
                documents=[finding],
                ids=[doc_id],
                metadatas=[{
                    "agent":     self.agent_name,
                    "timestamp": datetime.now().isoformat(),
                    **(metadata or {}),
                }],
            )
            return True
        except Exception as e:
            print(f"[Memory] Store failed: {e}")
            return False

    def retrieve(self, query: str, n: int = 3) -> list[str]:
        """
        Récupère les n findings les plus similaires à la query.
        Utilisé par les agents pour détecter des régressions.
        """
        if not self.collection:
            return []
        try:
            count = self.collection.count()
            if count == 0:
                return []
            results = self.collection.query(
                query_texts=[query],
                n_results=min(n, count),
            )
            return results.get("documents", [[]])[0]
        except Exception as e:
            print(f"[Memory] Retrieve failed: {e}")
            return []

    def get_summary(self) -> str:
        """Résumé de la mémoire pour injection dans les prompts."""
        if not self.collection:
            return "Memory not available."
        try:
            count = self.collection.count()
            if count == 0:
                return "No past findings stored yet (first run)."
            return f"{count} past finding(s) stored for {self.agent_name}."
        except Exception:
            return "Memory unavailable."

