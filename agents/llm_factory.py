"""
LLM Factory — provider unique pour tous les agents.

Providers supportés :
  groq    → llama-3.3-70b-versatile (défaut, gratuit)
  claude  → claude-3-5-haiku-20241022 (Anthropic API)
  openai  → gpt-4o-mini

Configuration .env :
  LLM_PROVIDER=groq          # ou claude / openai
  GROQ_API_KEY=...
  ANTHROPIC_API_KEY=...
  OPENAI_API_KEY=...
  LLM_MODEL=llama-3.3-70b-versatile   # override modèle

Référence :
  https://python.langchain.com/docs/integrations/chat/
"""
import os
from dotenv import load_dotenv

load_dotenv()

PROVIDER = os.getenv("LLM_PROVIDER", "groq").lower()
MODEL    = os.getenv("LLM_MODEL", "llama-3.3-70b-versatile")


def get_llm(temperature: float = 0.1, max_tokens: int = 2000):
    """
    Retourne le LLM configuré selon LLM_PROVIDER.
    Tous les agents appellent cette fonction — un seul changement
    dans .env suffit pour changer de provider.
    """
    if PROVIDER == "claude":
        # Anthropic Claude — meilleur pour les tâches de raisonnement complexe
        # Modèle : claude-3-5-haiku-20241022 (rapide + économique)
        # Référence : https://docs.anthropic.com/en/docs/models-overview
        try:
            from langchain_anthropic import ChatAnthropic
            model = os.getenv("LLM_MODEL", "claude-3-5-haiku-20241022")
            return ChatAnthropic(
                model=model,
                api_key=os.getenv("ANTHROPIC_API_KEY"),
                temperature=temperature,
                max_tokens=max_tokens,
            )
        except ImportError:
            print("[LLM Factory] langchain-anthropic not installed.")
            print("  Run: pip install langchain-anthropic")
            raise

    elif PROVIDER == "openai":
        # OpenAI GPT — bonne alternative si quota Groq épuisé
        # Référence : https://platform.openai.com/docs/models
        try:
            from langchain_openai import ChatOpenAI
            model = os.getenv("LLM_MODEL", "gpt-4o-mini")
            return ChatOpenAI(
                model=model,
                api_key=os.getenv("OPENAI_API_KEY"),
                temperature=temperature,
                max_tokens=max_tokens,
            )
        except ImportError:
            print("[LLM Factory] langchain-openai not installed.")
            print("  Run: pip install langchain-openai")
            raise

    else:
        # Groq — défaut : gratuit, ultra-rapide (~2s/réponse)
        # Référence : https://console.groq.com/docs/models
        from langchain_groq import ChatGroq
        model = os.getenv("LLM_MODEL", "llama-3.3-70b-versatile")
        return ChatGroq(
            model=model,
            api_key=os.getenv("GROQ_API_KEY"),
            temperature=temperature,
            max_tokens=max_tokens,
        )


def get_provider_info() -> dict:
    """Retourne les infos du provider actif — utile pour les rapports."""
    return {
        "provider": PROVIDER,
        "model":    MODEL,
        "supports_json_mode": PROVIDER in ("openai", "groq"),
    }

