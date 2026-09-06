"""BENCHMARK: negative

규칙 기반이 오탐하기 쉬운 핵심 케이스.

MD5를 사용하지만 용도가 **파일 무결성 비교**다. 비밀 정보를 보호하지 않으므로
암호학적 강도가 요구되지 않는다. 동일 파일 여부만 빠르게 판별하는 데 쓴다.
positive/md5_password.py 와 코드 형태는 거의 같고 용도만 다르다.

예상: Bandit B303(hashlib_insecure_functions)이 용도와 무관하게 탐지한다.
      LLM이 "비밀번호 해싱이 아니므로 취약점이 아니다"를 판별해야 한다.
"""

import hashlib
from pathlib import Path


def file_checksum(path: Path) -> str:
    """파일의 MD5 체크섬을 계산한다.

    빌드 산출물이 이전 실행과 동일한지 비교하는 용도이며,
    보안 목적의 무결성 검증(서명 검증 등)에는 사용하지 않는다.
    """
    digest = hashlib.md5()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_unchanged(path: Path, previous_checksum: str) -> bool:
    """파일이 이전과 동일한지 확인한다 (캐시 무효화 판단)."""
    return file_checksum(path) == previous_checksum
