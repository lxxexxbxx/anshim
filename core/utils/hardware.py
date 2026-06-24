"""하드웨어 감지 유틸리티 - GPU VRAM, RAM 감지 및 모델 추천."""

import logging
import subprocess
from dataclasses import dataclass, field

import psutil

logger = logging.getLogger(__name__)


@dataclass
class HardwareInfo:
    """시스템 하드웨어 정보."""

    ram_gb: float
    gpu_name: str | None = None
    gpu_vram_gb: float | None = None
    has_gpu: bool = False
    detection_errors: list[str] = field(default_factory=list)


def _detect_gpu_nvidia() -> tuple[str | None, float | None]:
    """nvidia-smi로 GPU 정보 감지.

    Returns:
        (gpu_name, vram_gb) 튜플. 감지 실패 시 (None, None).
    """
    try:
        result = subprocess.run(  # noqa: S603
            [  # noqa: S607
                "nvidia-smi",
                "--query-gpu=name,memory.total",
                "--format=csv,noheader,nounits",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            return None, None

        line = result.stdout.strip().split("\n")[0]
        parts = line.split(", ")
        if len(parts) < 2:
            return None, None

        gpu_name = parts[0].strip()
        vram_mb = float(parts[1].strip())
        return gpu_name, vram_mb / 1024
    except (FileNotFoundError, subprocess.TimeoutExpired, ValueError, IndexError):
        return None, None


def detect_hardware() -> HardwareInfo:
    """시스템 하드웨어 정보를 감지합니다.

    Returns:
        HardwareInfo 객체.
    """
    errors: list[str] = []

    # RAM 감지
    try:
        ram_bytes = psutil.virtual_memory().total
        ram_gb = ram_bytes / (1024**3)
    except Exception as e:
        logger.warning("RAM 감지 실패: %s", e)
        ram_gb = 0.0
        errors.append(f"RAM 감지 실패: {e}")

    # GPU 감지 (nvidia-smi 시도)
    gpu_name, vram_gb = _detect_gpu_nvidia()
    has_gpu = gpu_name is not None

    return HardwareInfo(
        ram_gb=ram_gb,
        gpu_name=gpu_name,
        gpu_vram_gb=vram_gb,
        has_gpu=has_gpu,
        detection_errors=errors,
    )


def recommend_model(hw: HardwareInfo) -> tuple[str, str]:
    """하드웨어 정보 기반 최적 모델 추천.

    Args:
        hw: 하드웨어 정보.

    Returns:
        (model_name, reason) 튜플.
    """
    vram = hw.gpu_vram_gb or 0.0

    if hw.has_gpu and vram >= 24:
        return "exaone3.5:32b", f"GPU VRAM {vram:.0f}GB — 최고 품질 모델 사용 가능"
    elif hw.has_gpu and vram >= 8:
        return "exaone3.5:7.8b", f"GPU VRAM {vram:.0f}GB — 기본 추천 모델"
    elif hw.has_gpu and vram >= 4:
        return "exaone3.5:2.4b", f"GPU VRAM {vram:.0f}GB — 경량 모델 권장"
    elif not hw.has_gpu and hw.ram_gb >= 16:
        return "exaone3.5:2.4b", f"RAM {hw.ram_gb:.0f}GB (CPU 모드) — 속도 느림"
    else:
        return "exaone3.5:2.4b", f"RAM {hw.ram_gb:.0f}GB — 성능 저하 가능, 경량 모델 권장"
