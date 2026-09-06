"""설정 파일 관리 - ~/.anshim/config.yaml 읽기/쓰기."""

import logging
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_ANSHIM_DIR = Path.home() / ".anshim"
_CONFIG_FILE = _ANSHIM_DIR / "config.yaml"

_DEFAULTS: dict[str, Any] = {
    "model": "exaone3.5:7.8b",
    "compliance": "isms-p",
    "ollama_host": "http://localhost:11434",
    "db_path": str(_ANSHIM_DIR / "anshim.db"),
    "report_dir": str(Path.cwd()),
}


class ConfigManager:
    """~/.anshim/config.yaml 기반 설정 관리자."""

    def __init__(self, config_path: Path | None = None) -> None:
        self._path = config_path or _CONFIG_FILE
        self._data: dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        """설정 파일 로드. 없으면 기본값 사용."""
        if self._path.exists():
            try:
                with open(self._path, encoding="utf-8") as f:
                    self._data = yaml.safe_load(f) or {}
            except Exception as e:
                logger.warning("설정 파일 로드 실패, 기본값 사용: %s", e)
                self._data = {}

    def save(self) -> None:
        """설정을 파일에 저장."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "w", encoding="utf-8") as f:
            yaml.dump(self._data, f, allow_unicode=True, default_flow_style=False)
        logger.debug("설정 저장: %s", self._path)

    def get(self, key: str, fallback: Any = None) -> Any:
        """설정값 조회. 우선순위: config.yaml > 기본값 > fallback."""
        return self._data.get(key, _DEFAULTS.get(key, fallback))

    def set(self, key: str, value: Any) -> None:
        """설정값 저장 (메모리에만, save() 호출 시 파일에 반영)."""
        self._data[key] = value

    def set_and_save(self, key: str, value: Any) -> None:
        """설정값을 즉시 파일에 저장."""
        self.set(key, value)
        self.save()

    @property
    def model(self) -> str:
        """기본 LLM 모델."""
        return str(self.get("model"))

    @property
    def compliance(self) -> str:
        """기본 컴플라이언스."""
        return str(self.get("compliance"))

    @property
    def config_path(self) -> Path:
        """설정 파일 경로."""
        return self._path

    def __repr__(self) -> str:
        return f"ConfigManager(path={self._path}, data={self._data})"


_instance: ConfigManager | None = None


def get_config() -> ConfigManager:
    """싱글톤 ConfigManager 반환."""
    global _instance
    if _instance is None:
        _instance = ConfigManager()
    return _instance
