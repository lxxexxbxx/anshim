# tests/test_llm_analyzer.py
"""LLM 분석기 테스트.

Mock OllamaClient를 사용하여 LLM 분석기 동작을 테스트합니다.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from anshim.core.analyzers.llm_analyzer import LLMAnalyzer
from anshim.core.analyzers.models import AnalysisResult
from anshim.core.models.ollama_client import OllamaClient, OllamaNotRunningError
from anshim.core.models.registry import (
    SUPPORTED_MODELS,
    get_korean_models,
    get_model_info,
    get_recommended_model,
    recommend_model_for_vram,
)


# === Fixtures ===


@pytest.fixture
def sample_result() -> AnalysisResult:
    """테스트용 분석 결과."""
    return AnalysisResult(
        rule_id="B303",
        title="Use of insecure MD5 hash function",
        description="MD5는 암호화 해시로 안전하지 않습니다.",
        severity="medium",
        file_path="/test/example.py",
        line_start=10,
        code_snippet="import hashlib\nmd5_hash = hashlib.md5()",
        source="bandit",
        confidence="high",
    )


@pytest.fixture
def mock_ollama_client():
    """Mock OllamaClient."""
    client = MagicMock(spec=OllamaClient)
    client.is_running.return_value = True
    client.list_models.return_value = ["exaone3.5:7.8b", "qwen2.5-coder:7b"]
    return client


@pytest.fixture
def mock_llm_response():
    """Mock LLM 응답."""
    return json.dumps({
        "is_false_positive": False,
        "severity_adjusted": "high",
        "analysis": "MD5는 충돌 공격에 취약하여 보안 목적으로 사용해서는 안 됩니다.",
        "isms_relevance": "2.7.1 암호화 적용"
    })


# === OllamaClient 테스트 ===


class TestOllamaClient:
    """OllamaClient 테스트."""

    def test_is_running_when_ollama_down(self):
        """Ollama 미실행 시 is_running이 False 반환."""
        client = OllamaClient(base_url="http://localhost:99999")
        assert client.is_running() is False

    def test_list_models_raises_when_not_running(self):
        """Ollama 미실행 시 list_models가 예외 발생."""
        client = OllamaClient(base_url="http://localhost:99999")
        with pytest.raises(OllamaNotRunningError):
            client.list_models()

    def test_generate_raises_when_not_running(self):
        """Ollama 미실행 시 generate가 예외 발생."""
        client = OllamaClient(base_url="http://localhost:99999")
        with pytest.raises(OllamaNotRunningError):
            client.generate(model="test", prompt="test")


# === ModelRegistry 테스트 ===


class TestModelRegistry:
    """모델 레지스트리 테스트."""

    def test_supported_models_not_empty(self):
        """지원 모델 목록이 비어있지 않음."""
        assert len(SUPPORTED_MODELS) > 0

    def test_get_model_info_exact_match(self):
        """정확한 모델명으로 조회."""
        model = get_model_info("exaone3.5:7.8b")
        assert model is not None
        assert model.name == "exaone3.5:7.8b"
        assert model.korean_support is True

    def test_get_model_info_base_name(self):
        """기본 이름으로 조회."""
        model = get_model_info("exaone3.5")
        assert model is not None
        assert "exaone3.5" in model.name

    def test_get_model_info_not_found(self):
        """존재하지 않는 모델 조회."""
        model = get_model_info("nonexistent:model")
        assert model is None

    def test_get_recommended_model(self):
        """추천 모델 조회."""
        model = get_recommended_model()
        assert model is not None
        assert model.recommended is True
        assert model.korean_support is True

    def test_get_korean_models(self):
        """한국어 지원 모델 목록."""
        korean_models = get_korean_models()
        assert len(korean_models) > 0
        for model in korean_models:
            assert model.korean_support is True

    def test_recommend_model_for_vram_high(self):
        """높은 VRAM 추천."""
        model = recommend_model_for_vram(24)
        assert model is not None
        assert "32b" in model.name

    def test_recommend_model_for_vram_medium(self):
        """중간 VRAM 추천."""
        model = recommend_model_for_vram(8)
        assert model is not None
        assert "7.8b" in model.name or "7b" in model.name

    def test_recommend_model_for_vram_low(self):
        """낮은 VRAM 추천."""
        model = recommend_model_for_vram(4)
        assert model is not None
        assert "2.4b" in model.name


# === LLMAnalyzer 테스트 ===


class TestLLMAnalyzer:
    """LLM 분석기 테스트."""

    def test_is_available_with_mock(self, mock_ollama_client):
        """Ollama 실행 시 is_available이 True."""
        analyzer = LLMAnalyzer(model="exaone3.5:7.8b", ollama_client=mock_ollama_client)
        assert analyzer.is_available() is True

    def test_is_available_when_ollama_down(self):
        """Ollama 미실행 시 is_available이 False."""
        client = OllamaClient(base_url="http://localhost:99999")
        analyzer = LLMAnalyzer(model="exaone3.5:7.8b", ollama_client=client)
        assert analyzer.is_available() is False

    def test_analyze_vulnerability_returns_original_when_unavailable(
        self, sample_result
    ):
        """Ollama 미실행 시 원본 결과 반환."""
        client = OllamaClient(base_url="http://localhost:99999")
        analyzer = LLMAnalyzer(model="exaone3.5:7.8b", ollama_client=client)

        result = analyzer.analyze_vulnerability(sample_result)
        assert result.rule_id == sample_result.rule_id
        assert result.title == sample_result.title

    def test_analyze_vulnerability_with_mock(
        self, sample_result, mock_ollama_client, mock_llm_response
    ):
        """Mock LLM으로 취약점 분석."""
        mock_ollama_client.generate.return_value = mock_llm_response

        analyzer = LLMAnalyzer(model="exaone3.5:7.8b", ollama_client=mock_ollama_client)
        result = analyzer.analyze_vulnerability(sample_result)

        # LLM 분석 결과가 추가되었는지 확인
        assert hasattr(result, "llm_analysis") or "llm_analysis" in result.model_dump()
        assert mock_ollama_client.generate.called

    def test_analyze_batch_returns_original_when_unavailable(self, sample_result):
        """Ollama 미실행 시 배치 분석도 원본 반환."""
        client = OllamaClient(base_url="http://localhost:99999")
        analyzer = LLMAnalyzer(model="exaone3.5:7.8b", ollama_client=client)

        results = analyzer.analyze_batch([sample_result, sample_result])
        assert len(results) == 2
        assert results[0].rule_id == sample_result.rule_id

    def test_filter_false_positives(self, sample_result):
        """False Positive 필터링."""
        # 원본 결과 (False Positive 아님)
        results = [sample_result]

        client = OllamaClient(base_url="http://localhost:99999")
        analyzer = LLMAnalyzer(model="exaone3.5:7.8b", ollama_client=client)

        filtered = analyzer.filter_false_positives(results)
        assert len(filtered) == 1

    def test_detect_language_python(self):
        """Python 파일 언어 감지."""
        assert LLMAnalyzer._detect_language("/test/example.py") == "python"

    def test_detect_language_javascript(self):
        """JavaScript 파일 언어 감지."""
        assert LLMAnalyzer._detect_language("/test/app.js") == "javascript"

    def test_detect_language_typescript(self):
        """TypeScript 파일 언어 감지."""
        assert LLMAnalyzer._detect_language("/test/app.tsx") == "typescript"

    def test_detect_language_java(self):
        """Java 파일 언어 감지."""
        assert LLMAnalyzer._detect_language("/test/Main.java") == "java"

    def test_detect_language_unknown(self):
        """알 수 없는 확장자."""
        assert LLMAnalyzer._detect_language("/test/file.xyz") == "unknown"

    def test_parse_json_response_valid(self):
        """유효한 JSON 응답 파싱."""
        analyzer = LLMAnalyzer(
            model="test",
            ollama_client=OllamaClient(base_url="http://localhost:99999")
        )

        response = '{"key": "value", "number": 42}'
        result = analyzer._parse_json_response(response)
        assert result == {"key": "value", "number": 42}

    def test_parse_json_response_with_markdown(self):
        """마크다운 코드 블록 내 JSON 파싱."""
        analyzer = LLMAnalyzer(
            model="test",
            ollama_client=OllamaClient(base_url="http://localhost:99999")
        )

        response = '''Here is the analysis:
```json
{"is_false_positive": false, "severity": "high"}
```
'''
        result = analyzer._parse_json_response(response)
        assert result == {"is_false_positive": False, "severity": "high"}

    def test_parse_json_response_invalid(self):
        """유효하지 않은 응답."""
        analyzer = LLMAnalyzer(
            model="test",
            ollama_client=OllamaClient(base_url="http://localhost:99999")
        )

        result = analyzer._parse_json_response("This is not JSON")
        assert result is None

    def test_parse_json_response_empty(self):
        """빈 응답."""
        analyzer = LLMAnalyzer(
            model="test",
            ollama_client=OllamaClient(base_url="http://localhost:99999")
        )

        result = analyzer._parse_json_response("")
        assert result is None


# === 프롬프트 템플릿 테스트 ===


class TestPromptTemplates:
    """프롬프트 템플릿 테스트."""

    def test_vulnerability_analysis_template_exists(self):
        """취약점 분석 템플릿 존재 확인."""
        template_path = Path(__file__).parent.parent / "core" / "prompts" / "ko" / "vulnerability_analysis.jinja2"
        assert template_path.exists(), f"템플릿이 없습니다: {template_path}"

    def test_attack_scenario_template_exists(self):
        """공격 시나리오 템플릿 존재 확인."""
        template_path = Path(__file__).parent.parent / "core" / "prompts" / "ko" / "attack_scenario.jinja2"
        assert template_path.exists(), f"템플릿이 없습니다: {template_path}"

    def test_fix_suggestion_template_exists(self):
        """수정 제안 템플릿 존재 확인."""
        template_path = Path(__file__).parent.parent / "core" / "prompts" / "ko" / "fix_suggestion.jinja2"
        assert template_path.exists(), f"템플릿이 없습니다: {template_path}"

    def test_render_template(self, sample_result):
        """템플릿 렌더링 테스트."""
        analyzer = LLMAnalyzer(
            model="test",
            ollama_client=OllamaClient(base_url="http://localhost:99999")
        )

        prompt = analyzer._render_template("vulnerability_analysis.jinja2", sample_result)

        # 템플릿 변수가 올바르게 치환되었는지 확인
        assert sample_result.rule_id in prompt
        assert sample_result.title in prompt
        assert sample_result.file_path in prompt
        assert str(sample_result.line_start) in prompt
