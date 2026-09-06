"""BENCHMARK: positive

사용자가 준 파일명을 검증 없이 경로에 결합한다. ../ 로 상위 경로를 읽을 수 있다.
"""

import os
import subprocess

BASE_DIR = "/var/app/uploads"


def read_upload(filename: str) -> str:
    """업로드된 파일을 읽는다."""
    # VULN: isms_p=2.6.1 cwe=CWE-22 severity=high
    path = os.path.join(BASE_DIR, filename)
    with open(path, encoding="utf-8") as f:
        return f.read()


def archive(filename: str) -> None:
    """파일을 압축한다."""
    # VULN: isms_p=2.10.1 cwe=CWE-78 severity=critical
    subprocess.run(f"tar czf /tmp/out.tar.gz {BASE_DIR}/{filename}", shell=True)
