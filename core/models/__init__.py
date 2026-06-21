"""LLM 인터페이스 패키지 (Ollama 클라이언트, 모델 레지스트리)."""

from .ollama_client import OllamaClient, OllamaNotRunningError
from .registry import (
    ModelInfo,
    SUPPORTED_MODELS,
    get_korean_models,
    get_model_info,
    get_models_by_vram,
    get_recommended_model,
    recommend_model_for_vram,
)

__all__ = [
    # Ollama 클라이언트
    "OllamaClient",
    "OllamaNotRunningError",
    # 모델 레지스트리
    "ModelInfo",
    "SUPPORTED_MODELS",
    "get_model_info",
    "get_recommended_model",
    "get_korean_models",
    "get_models_by_vram",
    "recommend_model_for_vram",
]
