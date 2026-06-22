/**
 * 테스트용 취약한 JavaScript 코드 샘플
 * 실제 사용 금지 - 보안 테스트 목적으로만 사용
 */

const express = require('express');
const mysql = require('mysql');
const crypto = require('crypto');
const fs = require('fs');
const { exec } = require('child_process');

const app = express();

// SQL Injection 취약점 (CWE-89)
app.get('/user', (req, res) => {
  const userId = req.query.id;
  // 취약: 사용자 입력이 SQL 쿼리에 직접 삽입됨
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  connection.query(query, (err, results) => {
    res.json(results);
  });
});

// XSS 취약점 (CWE-79)
app.get('/search', (req, res) => {
  const searchTerm = req.query.q;
  // 취약: 사용자 입력이 HTML에 직접 삽입됨
  res.send(`<h1>검색 결과: ${searchTerm}</h1>`);
});

// 하드코딩된 비밀번호 (CWE-798)
const DB_PASSWORD = 'admin123!@#';
const API_KEY = 'sk-1234567890abcdef1234567890abcdef';
const JWT_SECRET = 'mysupersecretkey';

// 취약한 해시 알고리즘 사용 (CWE-327)
function hashPassword(password) {
  // 취약: MD5는 안전하지 않은 해시 알고리즘
  return crypto.createHash('md5').update(password).digest('hex');
}

function hashPasswordSHA1(password) {
  // 취약: SHA1도 안전하지 않은 해시 알고리즘
  return crypto.createHash('sha1').update(password).digest('hex');
}

// 명령어 인젝션 취약점 (CWE-78)
app.get('/ping', (req, res) => {
  const host = req.query.host;
  // 취약: 사용자 입력이 쉘 명령어에 직접 삽입됨
  exec(`ping -c 4 ${host}`, (err, stdout) => {
    res.send(stdout);
  });
});

// 경로 탐색 취약점 (CWE-22)
app.get('/file', (req, res) => {
  const filename = req.query.name;
  // 취약: 사용자 입력이 파일 경로에 직접 사용됨
  fs.readFile(`/uploads/${filename}`, (err, data) => {
    if (err) {
      res.status(404).send('File not found');
    } else {
      res.send(data);
    }
  });
});

// 안전하지 않은 리다이렉트 (OWASP A01)
app.get('/redirect', (req, res) => {
  const nextUrl = req.query.next;
  // 취약: 사용자 입력 URL로 직접 리다이렉트
  res.redirect(nextUrl);
});

// innerHTML 사용 (XSS 위험)
app.get('/render', (req, res) => {
  const content = req.query.content;
  res.send(`
    <html>
      <body>
        <div id="content"></div>
        <script>
          document.getElementById('content').innerHTML = '${content}';
        </script>
      </body>
    </html>
  `);
});

// 평문 비밀번호 저장 (CWE-256)
function saveUser(username, password) {
  // 취약: 비밀번호를 평문으로 저장
  const user = {
    username: username,
    password: password, // 암호화 없이 저장
  };
  users.push(user);
}

// eval 사용 (CWE-94)
app.get('/calculate', (req, res) => {
  const expression = req.query.expr;
  // 취약: eval()은 코드 인젝션에 취약
  const result = eval(expression);
  res.json({ result });
});

app.listen(3000);
