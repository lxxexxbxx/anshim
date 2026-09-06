"""BENCHMARK: positive

사용자 입력을 escape 없이 템플릿 문자열에 넣어 렌더링한다.
render_template_string에 사용자 입력이 들어가면 SSTI/XSS로 이어진다.
"""

from flask import Flask, render_template_string, request

app = Flask(__name__)


@app.route("/greet")
def greet():
    """인사말을 출력한다."""
    name = request.args.get("name", "")
    # VULN: isms_p=2.10.2 cwe=CWE-79 severity=high
    return render_template_string("<h1>안녕하세요 " + name + "님</h1>")


@app.route("/profile")
def profile():
    """프로필을 출력한다."""
    bio = request.args.get("bio", "")
    # VULN: isms_p=2.10.2 cwe=CWE-79 severity=high
    return f"<div class='bio'>{bio}</div>"
