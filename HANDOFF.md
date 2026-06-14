# 인수인계 문서
생성: 2026-06-14

## 지금까지 한 것
1. **anshim 폴더 생성**: 프로젝트 루트 디렉토리 `anshim/` 생성 완료
2. **pyproject.toml 생성**: `anshim/pyproject.toml` 파일 작성 완료
   - Python 3.10+ 기반
   - MIT 라이센스
   - 기본 의존성 추가:
     - `typer>=0.9.0` (CLI 프레임워크)
     - `pydantic>=2.0.0` (데이터 검증)
     - `sqlalchemy>=2.0.0` (ORM)
     - `jinja2>=3.1.0` (템플릿 엔진)
   - 개발 의존성 추가: pytest, pytest-cov, mypy, ruff
   - CLI 엔트리포인트 설정: `anshim = "anshim.cli:app"`
   - ruff, mypy, pytest 설정 포함

## 다음에 해야 할 것
1. **디렉토리 구조 생성**: CLAUDE.md에 정의된 구조대로 생성
   - `core/` (analyzers, models, compliance, reporters, db, prompts, utils)
   - `cli/commands/`
   - `web/`
   - `rules/compliance/`, `rules/owasp/`, `rules/cwe/`
   - `reports/`, `tests/`, `docs/`, `docker/`, `scripts/`
2. **CLI 기본 골격 작성**: `cli/__init__.py`, `cli/commands/` 구현
3. **SQLite 스키마 설계**: `core/db/` 모델 정의
4. **README.md 작성** (한국어)

## 주의사항
- `anshim/` 폴더가 프로젝트 루트임 (현재 위치: `anshim_project/anshim/`)
- CLI 엔트리포인트가 `anshim.cli:app`으로 설정되어 있으므로, `anshim/cli/__init__.py`에 `app` 객체(Typer 인스턴스)를 정의해야 함
- uv 패키지 관리자 사용 예정 (CLAUDE.md 참고)
