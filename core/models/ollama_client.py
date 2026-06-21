# anshim/core/models/ollama_client.py
"""Ollama REST API 클라이언트.

Ollama 서버와 통신하여 LLM 텍스트 생성을 수행합니다.
모든 데이터는 로컬에서 처리되며 외부로 전송되지 않습니다.
"""

import logging
from typing import Optional

import httpx
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class OllamaNotRunningError(Exception):
    """Ollama 서버가 실행되지 않을 때 발생하는 예외."""

    def __init__(self, message: str = "Ollama 서버가 실행되지 않습니다."):
        self.message = message
        super().__init__(self.message)


class OllamaGenerateResponse(BaseModel):
    """Ollama generate API 응답 모델."""

    model: str = Field(..., description="사용된 모델 이름")
    response: str = Field(..., description="생성된 텍스트")
    done: bool = Field(default=True, description="생성 완료 여부")
    total_duration: Optional[int] = Field(default=None, description="총 소요 시간 (ns)")
    eval_count: Optional[int] = Field(default=None, description="평가된 토큰 수")


class OllamaClient:
    """Ollama REST API 클라이언트.

    Ollama 서버와 HTTP 통신을 통해 모델 목록 조회, 텍스트 생성 등을 수행합니다.

    Attributes:
        base_url: Ollama 서버 기본 URL (기본값: http://localhost:11434)
        timeout: HTTP 요청 타임아웃 (초)
    """

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        timeout: int = 120,
    ):
        """OllamaClient 초기화.

        Args:
            base_url: Ollama 서버 URL.
            timeout: HTTP 요청 타임아웃 (초).
        """
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._client = httpx.Client(timeout=timeout)

    def __enter__(self) -> "OllamaClient":
        """Context manager 진입."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager 종료."""
        self.close()

    def close(self) -> None:
        """HTTP 클라이언트 종료."""
        self._client.close()

    def is_running(self) -> bool:
        """Ollama 서버 실행 여부 확인.

        /api/tags 엔드포인트에 요청하여 Ollama 서버 상태를 확인합니다.

        Returns:
            서버 실행 중이면 True, 아니면 False.
        """
        try:
            response = self._client.get(
                f"{self.base_url}/api/tags",
                timeout=5.0,  # 상태 확인은 짧은 타임아웃
            )
            return response.status_code == 200
        except httpx.ConnectError:
            logger.debug("Ollama 서버에 연결할 수 없습니다: %s", self.base_url)
            return False
        except httpx.TimeoutException:
            logger.debug("Ollama 서버 응답 타임아웃: %s", self.base_url)
            return False
        except Exception as e:
            logger.warning("Ollama 서버 상태 확인 중 예외 발생: %s", e)
            return False

    def list_models(self) -> list[str]:
        """설치된 모델 목록 조회.

        Returns:
            모델 이름 목록 (예: ["exaone3.5:7.8b", "qwen2.5-coder:7b"])

        Raises:
            OllamaNotRunningError: Ollama 서버가 실행되지 않을 때.
        """
        try:
            response = self._client.get(f"{self.base_url}/api/tags")
            response.raise_for_status()
            data = response.json()
            models = data.get("models", [])
            return [m.get("name", "") for m in models if m.get("name")]
        except httpx.ConnectError as e:
            logger.error("Ollama 서버에 연결할 수 없습니다: %s", e)
            raise OllamaNotRunningError() from e
        except httpx.TimeoutException as e:
            logger.error("Ollama 서버 응답 타임아웃: %s", e)
            raise OllamaNotRunningError("Ollama 서버 응답 타임아웃") from e
        except Exception as e:
            logger.error("모델 목록 조회 실패: %s", e)
            raise

    def generate(
        self,
        model: str,
        prompt: str,
        timeout: Optional[int] = None,
        system: Optional[str] = None,
        temperature: float = 0.7,
    ) -> str:
        """텍스트 생성.

        Args:
            model: 사용할 모델 이름 (예: "exaone3.5:7.8b").
            prompt: 생성 프롬프트.
            timeout: 요청별 타임아웃 (초). None이면 기본값 사용.
            system: 시스템 프롬프트 (선택).
            temperature: 생성 온도 (0.0-2.0).

        Returns:
            생성된 텍스트.

        Raises:
            OllamaNotRunningError: Ollama 서버가 실행되지 않을 때.
        """
        request_timeout = timeout or self.timeout

        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
            },
        }

        if system:
            payload["system"] = system

        try:
            logger.debug("Ollama generate 요청: model=%s, prompt_len=%d", model, len(prompt))
            response = self._client.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=request_timeout,
            )
            response.raise_for_status()
            data = response.json()

            result = data.get("response", "")
            logger.debug(
                "Ollama generate 완료: response_len=%d, eval_count=%s",
                len(result),
                data.get("eval_count"),
            )
            return result

        except httpx.ConnectError as e:
            logger.error("Ollama 서버에 연결할 수 없습니다: %s", e)
            raise OllamaNotRunningError() from e
        except httpx.TimeoutException as e:
            logger.error("Ollama 생성 타임아웃 (timeout=%ds): %s", request_timeout, e)
            raise OllamaNotRunningError(
                f"Ollama 생성 타임아웃 ({request_timeout}초 초과)"
            ) from e
        except httpx.HTTPStatusError as e:
            logger.error("Ollama HTTP 오류: %s", e)
            raise
        except Exception as e:
            logger.error("Ollama 생성 실패: %s", e)
            raise

    def pull_model(self, model_name: str) -> bool:
        """모델 다운로드.

        Args:
            model_name: 다운로드할 모델 이름.

        Returns:
            성공 시 True, 실패 시 False.

        Note:
            이 메서드는 동기 방식으로 모델을 다운로드합니다.
            대용량 모델의 경우 시간이 오래 걸릴 수 있습니다.
            CLI에서는 subprocess로 ollama pull을 직접 실행하는 것을 권장합니다.
        """
        try:
            response = self._client.post(
                f"{self.base_url}/api/pull",
                json={"name": model_name, "stream": False},
                timeout=600.0,  # 모델 다운로드는 오래 걸릴 수 있음
            )
            response.raise_for_status()
            return True
        except httpx.ConnectError as e:
            logger.error("Ollama 서버에 연결할 수 없습니다: %s", e)
            raise OllamaNotRunningError() from e
        except Exception as e:
            logger.error("모델 다운로드 실패: %s", e)
            return False
