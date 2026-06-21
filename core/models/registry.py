# anshim/core/models/registry.py
"""LLM 모델 레지스트리.

지원되는 모델 목록을 관리하고, 모델 정보를 조회합니다.
하드웨어 기반 모델 추천은 Sprint 6에서 구현 예정입니다.
"""

from typing import Optional

from pydantic import BaseModel, Field


class ModelInfo(BaseModel):
    """모델 정보 모델.

    Ollama에서 사용 가능한 LLM 모델의 메타데이터를 정의합니다.

    Attributes:
        name: Ollama 모델명 (예: exaone3.5:7.8b)
        display_name: 사용자에게 표시할 이름
        korean_support: 한국어 지원 여부
        min_vram_gb: 최소 필요 VRAM (GB)
        context_length: 컨텍스트 길이 (토큰)
        description: 모델 설명
        recommended: 기본 추천 여부
    """

    name: str = Field(..., description="Ollama 모델명")
    display_name: str = Field(..., description="표시 이름")
    korean_support: bool = Field(default=False, description="한국어 지원 여부")
    min_vram_gb: int = Field(..., ge=0, description="최소 필요 VRAM (GB)")
    context_length: int = Field(default=4096, ge=512, description="컨텍스트 길이")
    description: str = Field(default="", description="모델 설명")
    recommended: bool = Field(default=False, description="기본 추천 여부")


# 지원되는 모델 목록
# CLAUDE.md에 명시된 모델들을 포함
SUPPORTED_MODELS: list[ModelInfo] = [
    # 한국어 특화 (EXAONE - LG AI Research)
    ModelInfo(
        name="exaone3.5:7.8b",
        display_name="EXAONE 3.5 7.8B",
        korean_support=True,
        min_vram_gb=8,
        context_length=32768,
        description="LG AI Research 한국어 특화 모델. ISMS/ISMS-P 분석에 최적화된 기본 추천 모델.",
        recommended=True,
    ),
    ModelInfo(
        name="exaone3.5:2.4b",
        display_name="EXAONE 3.5 2.4B",
        korean_support=True,
        min_vram_gb=4,
        context_length=32768,
        description="EXAONE 경량 버전. 낮은 VRAM에서도 동작 가능.",
    ),
    ModelInfo(
        name="exaone3.5:32b",
        display_name="EXAONE 3.5 32B",
        korean_support=True,
        min_vram_gb=24,
        context_length=32768,
        description="EXAONE 고성능 버전. 최고 품질 분석 제공.",
    ),
    # 코딩 특화 (Qwen)
    ModelInfo(
        name="qwen2.5-coder:14b",
        display_name="Qwen 2.5 Coder 14B",
        korean_support=True,
        min_vram_gb=10,
        context_length=32768,
        description="Alibaba 코딩 특화 모델. 코드 분석 및 수정 제안에 탁월.",
    ),
    ModelInfo(
        name="qwen2.5-coder:7b",
        display_name="Qwen 2.5 Coder 7B",
        korean_support=True,
        min_vram_gb=6,
        context_length=32768,
        description="Qwen Coder 경량 버전.",
    ),
    ModelInfo(
        name="qwen2.5-coder:32b",
        display_name="Qwen 2.5 Coder 32B",
        korean_support=True,
        min_vram_gb=24,
        context_length=32768,
        description="Qwen Coder 고성능 버전.",
    ),
    # 범용 (Llama)
    ModelInfo(
        name="llama3.1:8b",
        display_name="Llama 3.1 8B",
        korean_support=False,
        min_vram_gb=8,
        context_length=131072,
        description="Meta 범용 모델. 긴 컨텍스트 지원.",
    ),
    ModelInfo(
        name="llama3.2:3b",
        display_name="Llama 3.2 3B",
        korean_support=False,
        min_vram_gb=3,
        context_length=131072,
        description="Llama 초경량 버전. 빠른 응답 속도.",
    ),
    # DeepSeek
    ModelInfo(
        name="deepseek-coder:6.7b",
        display_name="DeepSeek Coder 6.7B",
        korean_support=False,
        min_vram_gb=6,
        context_length=16384,
        description="DeepSeek 코딩 특화 모델.",
    ),
]


def get_model_info(name: str) -> Optional[ModelInfo]:
    """모델 이름으로 정보 조회.

    Args:
        name: Ollama 모델명 (예: exaone3.5:7.8b)

    Returns:
        ModelInfo 객체 또는 None
    """
    # 정확한 이름 매칭
    for model in SUPPORTED_MODELS:
        if model.name == name:
            return model

    # 기본 이름만으로 매칭 (태그 없이)
    base_name = name.split(":")[0] if ":" in name else name
    for model in SUPPORTED_MODELS:
        model_base = model.name.split(":")[0]
        if model_base == base_name:
            return model

    return None


def get_recommended_model() -> ModelInfo:
    """기본 추천 모델 반환.

    Returns:
        추천 설정된 ModelInfo 객체.
    """
    for model in SUPPORTED_MODELS:
        if model.recommended:
            return model
    # 기본값: 첫 번째 모델
    return SUPPORTED_MODELS[0]


def get_korean_models() -> list[ModelInfo]:
    """한국어 지원 모델 목록 반환.

    Returns:
        한국어를 지원하는 ModelInfo 목록.
    """
    return [m for m in SUPPORTED_MODELS if m.korean_support]


def get_models_by_vram(vram_gb: int) -> list[ModelInfo]:
    """VRAM 용량에 맞는 모델 목록 반환.

    Args:
        vram_gb: 사용 가능한 VRAM (GB).

    Returns:
        해당 VRAM으로 실행 가능한 ModelInfo 목록.
    """
    return [m for m in SUPPORTED_MODELS if m.min_vram_gb <= vram_gb]


def recommend_model_for_vram(vram_gb: int) -> Optional[ModelInfo]:
    """VRAM에 맞는 최적 모델 추천.

    CLAUDE.md 모델 추천 로직 참고:
    - GPU VRAM >= 24GB: EXAONE 32B / Qwen 32B
    - GPU VRAM 8-16GB: EXAONE 7.8B / Qwen Coder 14B (기본)
    - GPU VRAM 4-8GB: EXAONE 2.4B / Qwen 7B
    - GPU 없음 + RAM >= 16GB: CPU 모드 EXAONE 2.4B

    Args:
        vram_gb: 사용 가능한 VRAM (GB). 0이면 CPU 전용.

    Returns:
        추천 ModelInfo 또는 None (권장하지 않는 경우).
    """
    if vram_gb >= 24:
        return get_model_info("exaone3.5:32b")
    elif vram_gb >= 8:
        return get_model_info("exaone3.5:7.8b")
    elif vram_gb >= 4:
        return get_model_info("exaone3.5:2.4b")
    elif vram_gb == 0:
        # CPU 모드: 최소 RAM 16GB 권장 (여기서는 VRAM 정보만으로 판단)
        return get_model_info("exaone3.5:2.4b")
    else:
        # VRAM 4GB 미만: 권장하지 않음
        return None
