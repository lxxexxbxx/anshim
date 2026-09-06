"""BENCHMARK: positive

운영 진입점에서 디버그 모드를 켜고 모든 인터페이스에 바인딩한다.
스택 트레이스와 대화형 디버거가 외부에 노출된다.
"""

from flask import Flask

app = Flask(__name__)


@app.route("/health")
def health():
    """헬스 체크."""
    return {"status": "ok"}


if __name__ == "__main__":
    # VULN: isms_p=2.9.1 cwe=CWE-489 severity=medium
    app.run(host="0.0.0.0", port=8000, debug=True)
