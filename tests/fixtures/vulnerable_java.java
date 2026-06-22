/**
 * 테스트용 취약한 Java 코드 샘플
 * 실제 사용 금지 - 보안 테스트 목적으로만 사용
 */

package com.example.vulnerable;

import java.io.*;
import java.security.MessageDigest;
import java.sql.*;
import javax.servlet.http.*;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class VulnerableController {

    // 하드코딩된 비밀번호 (CWE-798)
    private static final String DB_PASSWORD = "admin123!@#";
    private static final String API_KEY = "sk-1234567890abcdef";
    private static final String SECRET_KEY = "mysupersecretkey";

    private Connection connection;

    // SQL Injection 취약점 (CWE-89)
    public User findUser(String userId) throws SQLException {
        // 취약: 사용자 입력이 SQL 쿼리에 직접 삽입됨
        String query = "SELECT * FROM users WHERE id = " + userId;
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(query);
        return mapResultSet(rs);
    }

    // SQL Injection 취약점 - 문자열 연결
    public User findUserByName(String name) throws SQLException {
        // 취약: 문자열 연결을 사용한 쿼리 생성
        String query = "SELECT * FROM users WHERE name = '" + name + "'";
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(query);
        return mapResultSet(rs);
    }

    // 취약한 해시 알고리즘 사용 (CWE-327)
    public String hashPasswordMD5(String password) throws Exception {
        // 취약: MD5는 안전하지 않은 해시 알고리즘
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(password.getBytes());
        return bytesToHex(hash);
    }

    public String hashPasswordSHA1(String password) throws Exception {
        // 취약: SHA-1도 안전하지 않은 해시 알고리즘
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] hash = md.digest(password.getBytes());
        return bytesToHex(hash);
    }

    // 취약한 암호 알고리즘 사용 (CWE-327)
    public byte[] encryptDES(String data) throws Exception {
        // 취약: DES는 안전하지 않은 암호 알고리즘
        SecretKeySpec key = new SecretKeySpec("12345678".getBytes(), "DES");
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data.getBytes());
    }

    // 명령어 인젝션 취약점 (CWE-78)
    public String pingHost(String host) throws Exception {
        // 취약: 사용자 입력이 쉘 명령어에 직접 삽입됨
        String command = "ping -c 4 " + host;
        Process process = Runtime.getRuntime().exec(command);
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }
        return output.toString();
    }

    // 경로 탐색 취약점 (CWE-22)
    public byte[] readFile(String filename) throws Exception {
        // 취약: 사용자 입력이 파일 경로에 직접 사용됨
        File file = new File("/uploads/" + filename);
        FileInputStream fis = new FileInputStream(file);
        byte[] data = new byte[(int) file.length()];
        fis.read(data);
        fis.close();
        return data;
    }

    // XSS 취약점 (CWE-79)
    public void handleSearch(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        String searchTerm = request.getParameter("q");
        PrintWriter out = response.getWriter();
        // 취약: 사용자 입력이 HTML에 직접 삽입됨
        out.println("<h1>검색 결과: " + searchTerm + "</h1>");
    }

    // 안전하지 않은 리다이렉트 (OWASP A01)
    public void handleRedirect(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        String nextUrl = request.getParameter("next");
        // 취약: 사용자 입력 URL로 직접 리다이렉트
        response.sendRedirect(nextUrl);
    }

    // 평문 비밀번호 저장 (CWE-256)
    public void saveUser(String username, String password) throws SQLException {
        // 취약: 비밀번호를 평문으로 데이터베이스에 저장
        String query = "INSERT INTO users (username, password) VALUES (?, ?)";
        PreparedStatement pstmt = connection.prepareStatement(query);
        pstmt.setString(1, username);
        pstmt.setString(2, password); // 암호화 없이 저장
        pstmt.executeUpdate();
    }

    // XXE 취약점 (CWE-611) - 외부 엔티티 처리 허용
    public void parseXML(String xmlInput) throws Exception {
        javax.xml.parsers.DocumentBuilderFactory factory =
            javax.xml.parsers.DocumentBuilderFactory.newInstance();
        // 취약: 외부 엔티티 처리가 활성화됨
        // factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        javax.xml.parsers.DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(new java.io.ByteArrayInputStream(xmlInput.getBytes()));
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private User mapResultSet(ResultSet rs) throws SQLException {
        // 구현 생략
        return null;
    }
}
