"""BENCHMARK: negative

사용자 입력을 출력 직전에 markupsafe.escape로 처리한다.
Jinja2 자동 escape도 함께 사용한다.

예상: 규칙은 escape 호출을 추적하지 못해 오탐할 수 있다.
      LLM이 "출력 전 escape가 적용되었다"를 판별해야 한다.
"""

from flask import Flask, render_template, request
from markupsafe import escape

app = Flask(__name__)


@app.route("/greet")
def greet():
    """인사말을 출력한다."""
    name = request.args.get("name", "")
    safe_name = escape(name)
    return f"<h1>안녕하세요 {safe_name}님</h1>"


@app.route("/profile")
def profile():
    """프로필을 렌더링한다 (Jinja2 자동 escape 사용)."""
    bio = request.args.get("bio", "")
    return render_template("profile.html", bio=bio)
