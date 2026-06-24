"""
AnShim 데모용 취약한 Flask 웹 애플리케이션
WARNING: 이 코드는 보안 취약점 시연 전용입니다. 절대 프로덕션에 사용하지 마세요.

포함된 취약점:
  - [2.10.1] SQL 인젝션 (로그인, 게시글 검색)
  - [2.10.2] XSS - Reflected & Stored (게시글)
  - [2.7.1]  취약한 암호 알고리즘 (MD5 비밀번호 해시)
  - [2.7.2]  하드코딩된 시크릿 키 및 DB 패스워드
  - [2.10.3] CSRF 보호 미적용
  - [2.11.1] 평문/MD5 비밀번호 저장
  - [3.3.1]  개인정보(주민번호) 평문 저장, 보유 기간 없음
  - [2.9.1]  디버그 모드 프로덕션 노출
"""
import hashlib
import os
import sqlite3
import traceback

from flask import Flask, g, jsonify, render_template_string, request

# [취약점] 2.7.2: 시크릿 키 하드코딩
SECRET_KEY = "super-secret-key-12345"
DB_PASSWORD = "admin123"
API_KEY = "sk-demo-hardcoded-api-key-abc123"

app = Flask(__name__)
# [취약점] 2.7.2: Flask 시크릿 키 하드코딩
app.config["SECRET_KEY"] = "hardcoded-flask-secret"
# [취약점] 2.9.1: 디버그 모드 활성화
app.config["DEBUG"] = True

DATABASE = "demo.db"


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db


def init_db():
    with app.app_context():
        db = get_db()
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                email TEXT,
                resident_number TEXT,
                credit_card TEXT,
                role TEXT DEFAULT 'user'
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                author TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # [취약점] 2.11.1: MD5로 비밀번호 해시
        admin_pw = hashlib.md5(b"admin").hexdigest()
        user_pw = hashlib.md5(b"password123").hexdigest()

        db.execute(
            "INSERT OR IGNORE INTO users (username, password, email, resident_number, credit_card, role) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                "admin",
                admin_pw,
                "admin@company.com",
                "900101-1234567",  # [취약점] 3.3.1: 주민번호 평문 저장
                "4532-1234-5678-9012",  # [취약점] 3.3.1: 카드번호 평문 저장
                "admin",
            ),
        )
        db.execute(
            "INSERT OR IGNORE INTO users (username, password, email, resident_number, credit_card, role) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                "user1",
                user_pw,
                "user1@example.com",
                "950515-2345678",  # [취약점] 3.3.1: 주민번호 평문 저장
                "4111-1111-1111-1111",  # [취약점] 3.3.1: 카드번호 평문 저장
                "user",
            ),
        )
        db.execute(
            "INSERT OR IGNORE INTO posts (id, title, content, author) VALUES (?, ?, ?, ?)",
            (1, "안녕하세요", "첫 번째 게시글입니다.", "admin"),
        )
        db.execute(
            "INSERT OR IGNORE INTO posts (id, title, content, author) VALUES (?, ?, ?, ?)",
            (2, "공지사항", "시스템 점검 안내입니다.", "admin"),
        )
        db.commit()


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


HOME_TEMPLATE = """
<!DOCTYPE html>
<html lang="ko">
<head><meta charset="UTF-8"><title>AnShim 데모 앱</title>
<style>
  body { font-family: Arial, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; }
  .vuln { background: #fff3cd; border: 1px solid #ffc107; padding: 10px; margin: 5px 0; border-radius: 4px; }
  .nav { background: #dc3545; padding: 10px; border-radius: 4px; }
  .nav a { color: white; text-decoration: none; margin-right: 15px; }
  form input, form textarea { width: 100%; margin: 5px 0; padding: 8px; box-sizing: border-box; }
  form button { background: #007bff; color: white; padding: 10px 20px; border: none; cursor: pointer; }
  .post { border: 1px solid #dee2e6; padding: 15px; margin: 10px 0; border-radius: 4px; }
</style>
</head>
<body>
<div class="nav">
  <a href="/">홈</a>
  <a href="/login">로그인</a>
  <a href="/posts">게시판</a>
  <a href="/search">검색</a>
  <a href="/api/users">API (관리자)</a>
</div>

<h1>🔓 AnShim 데모 취약한 웹앱</h1>
<div class="vuln">
  ⚠️ <strong>경고:</strong> 이 앱은 보안 취약점 시연 전용입니다.
</div>

<h2>포함된 취약점 목록</h2>
<div class="vuln">🔴 [2.10.1] SQL 인젝션 — <a href="/login">로그인 폼</a>, <a href="/search">검색</a></div>
<div class="vuln">🔴 [2.10.2] XSS — <a href="/posts">게시판</a></div>
<div class="vuln">🔴 [2.7.1]  MD5 비밀번호 해시 — 로그인 처리</div>
<div class="vuln">🔴 [2.7.2]  하드코딩된 시크릿 키 — app.py 소스코드</div>
<div class="vuln">🔴 [2.10.3] CSRF 보호 없음 — 모든 POST 폼</div>
<div class="vuln">🔴 [2.11.1] 평문/MD5 비밀번호 저장</div>
<div class="vuln">🔴 [3.3.1]  주민번호/카드번호 평문 DB 저장</div>
<div class="vuln">🔴 [2.9.1]  디버그 모드 활성화</div>

<p>AnShim으로 스캔 후 이 취약점들이 탐지되는지 확인하세요!</p>
</body>
</html>
"""

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="ko">
<head><meta charset="UTF-8"><title>로그인</title>
<style>
  body { font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; }
  input { width: 100%; margin: 5px 0; padding: 8px; box-sizing: border-box; }
  button { background: #007bff; color: white; padding: 10px 20px; border: none; cursor: pointer; width: 100%; }
  .error { color: red; }
  .hint { background: #f8f9fa; padding: 10px; border-radius: 4px; font-size: 12px; }
</style>
</head>
<body>
<h2>로그인</h2>
<!-- [취약점] 2.10.3: CSRF 토큰 없음 -->
<form method="POST">
  <input name="username" placeholder="사용자명" required>
  <input name="password" type="password" placeholder="비밀번호" required>
  <button type="submit">로그인</button>
</form>

{% if error %}
<p class="error">{{ error }}</p>
{% endif %}
{% if result %}
<p style="color:green">{{ result }}</p>
{% endif %}

<div class="hint">
  <strong>SQL 인젝션 테스트:</strong><br>
  사용자명: <code>admin' OR '1'='1' --</code><br>
  비밀번호: 아무거나
</div>
</body>
</html>
"""

POSTS_TEMPLATE = """
<!DOCTYPE html>
<html lang="ko">
<head><meta charset="UTF-8"><title>게시판</title>
<style>
  body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
  .post { border: 1px solid #dee2e6; padding: 15px; margin: 10px 0; border-radius: 4px; }
  input, textarea { width: 100%; margin: 5px 0; padding: 8px; box-sizing: border-box; }
  button { background: #28a745; color: white; padding: 10px 20px; border: none; cursor: pointer; }
  .hint { background: #f8f9fa; padding: 10px; border-radius: 4px; font-size: 12px; margin: 10px 0; }
</style>
</head>
<body>
<h2>📋 게시판</h2>

<div class="hint">
  <strong>XSS 테스트:</strong> 게시글 내용에 입력:<br>
  <code>&lt;script&gt;alert('XSS 성공! 쿠키: ' + document.cookie)&lt;/script&gt;</code>
</div>

<!-- [취약점] 2.10.3: CSRF 토큰 없음 -->
<form method="POST">
  <input name="title" placeholder="제목" required>
  <textarea name="content" placeholder="내용" rows="3"></textarea>
  <button type="submit">글쓰기</button>
</form>

<h3>게시글 목록</h3>
{% for post in posts %}
<div class="post">
  <strong>{{ post[1] }}</strong> — {{ post[3] }}<br>
  <!-- [취약점] 2.10.2: Stored XSS - 사용자 입력 HTML 이스케이프 없이 렌더링 -->
  <div>{{ post[2] | safe }}</div>
</div>
{% endfor %}
</body>
</html>
"""

SEARCH_TEMPLATE = """
<!DOCTYPE html>
<html lang="ko">
<head><meta charset="UTF-8"><title>검색</title>
<style>
  body { font-family: Arial, sans-serif; max-width: 700px; margin: 0 auto; padding: 20px; }
  input { width: 100%; padding: 8px; box-sizing: border-box; }
  button { background: #007bff; color: white; padding: 10px 20px; border: none; cursor: pointer; }
  .result { border: 1px solid #dee2e6; padding: 10px; margin: 5px 0; border-radius: 4px; }
  .hint { background: #f8f9fa; padding: 10px; border-radius: 4px; font-size: 12px; margin: 10px 0; }
</style>
</head>
<body>
<h2>🔍 게시글 검색</h2>
<form method="GET">
  <input name="q" placeholder="검색어" value="{{ query or '' }}">
  <button type="submit">검색</button>
</form>

<div class="hint">
  <strong>SQL 인젝션 테스트:</strong><br>
  <code>%' UNION SELECT username, password, email, resident_number, 'x' FROM users --</code>
</div>

{% if results is not none %}
<h3>검색 결과 ({{ results|length }}건)</h3>
{% for r in results %}
<div class="result">
  <strong>{{ r[0] }}</strong><br>
  <!-- [취약점] 2.10.2: Reflected XSS -->
  <div>{{ r[1] | safe }}</div>
  <small>{{ r[2] }}</small>
  {% if r[3] %}<small style="color:red">주민번호: {{ r[3] }}</small>{% endif %}
</div>
{% endfor %}
{% endif %}
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(HOME_TEMPLATE)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    result = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # [취약점] 2.11.1: MD5 비밀번호 해시
        # [취약점] 2.7.1: 취약한 암호 알고리즘 (MD5)
        hashed_pw = hashlib.md5(password.encode()).hexdigest()

        try:
            db = get_db()
            # [취약점] 2.10.1: SQL 인젝션 - 직접 문자열 포맷팅
            query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{hashed_pw}'"
            cursor = db.execute(query)
            user = cursor.fetchone()

            if user:
                result = f"✅ 로그인 성공! 역할: {user[6]}, 이메일: {user[3]}"
            else:
                error = "❌ 로그인 실패 (아이디 또는 비밀번호 오류)"
        except Exception as e:
            # [취약점] 2.9.1: 내부 오류 및 SQL 쿼리 노출
            error = f"DB 오류: {str(e)}\n쿼리: {query}\n{traceback.format_exc()}"

    return render_template_string(LOGIN_TEMPLATE, error=error, result=result)


@app.route("/posts", methods=["GET", "POST"])
def posts():
    db = get_db()
    if request.method == "POST":
        title = request.form.get("title", "")
        content = request.form.get("content", "")
        author = "anonymous"
        # [취약점] 2.10.2: XSS - 저장 시 이스케이프 없음
        # [취약점] 2.10.3: CSRF 검증 없음
        db.execute(
            "INSERT INTO posts (title, content, author) VALUES (?, ?, ?)",
            (title, content, author),
        )
        db.commit()

    cursor = db.execute("SELECT * FROM posts ORDER BY created_at DESC")
    post_list = cursor.fetchall()
    return render_template_string(POSTS_TEMPLATE, posts=post_list)


@app.route("/search")
def search():
    query = request.args.get("q", "")
    results = None
    if query:
        db = get_db()
        try:
            # [취약점] 2.10.1: SQL 인젝션 - UNION 공격으로 users 테이블 데이터 추출 가능
            sql = f"SELECT title, content, author, NULL FROM posts WHERE title LIKE '%{query}%' OR content LIKE '%{query}%'"
            cursor = db.execute(sql)
            results = cursor.fetchall()
        except Exception as e:
            # [취약점] 2.9.1: SQL 쿼리 노출
            results = [(f"오류: {sql}", str(e), "", "")]
    return render_template_string(SEARCH_TEMPLATE, query=query, results=results)


@app.route("/api/users")
def api_users():
    """관리자 API - 인증 없이 모든 사용자 정보 반환"""
    db = get_db()
    # [취약점] 인증/인가 없음 (Broken Access Control)
    # [취약점] 3.3.1: 주민번호, 카드번호 API 응답에 포함
    cursor = db.execute(
        "SELECT id, username, email, resident_number, credit_card, role FROM users"
    )
    users = cursor.fetchall()
    return jsonify(
        [
            {
                "id": u[0],
                "username": u[1],
                "email": u[2],
                "resident_number": u[3],  # [취약점] 주민번호 평문 노출
                "credit_card": u[4],  # [취약점] 카드번호 평문 노출
                "role": u[5],
            }
            for u in users
        ]
    )


if __name__ == "__main__":
    init_db()
    # [취약점] 2.9.1: 프로덕션에서 debug=True
    app.run(debug=True, host="0.0.0.0", port=5000)
