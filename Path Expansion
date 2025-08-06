**경로 탐색(Path Expansion)** 및 **정찰 기반 보안 테스트**
공격자 관점에서 접근하면, 특정 엔드포인트(`/markup/`)나 파일 이름(`test.txt`)이 확장되거나 응답을 돌려주는 건 보안상 꽤 중요한 단서야.

---

## ✅ 테스트 목표 요약

> 📌 특정 경로나 이름 뒤에 다양한 확장자/기법을 조합해,
> 👉 **숨겨진 리소스**, **잘못된 서버 구성**, **디버깅 정보**, **취약점 노출** 등을 찾는 것.

---

## 🧪 경로 확장 테스트 체크리스트 (공격자 관점)

### 📁 1. 확장자 패턴 추가

| 테스트                                                         | 목적             |
| ----------------------------------------------------------- | -------------- |
| `/markup` → `/markup/`                                      | 디렉토리 인식 확인     |
| `/markup/test` → `/markup/test.html`, `.php`, `.js`, `.txt` | 백엔드 파일 확인      |
| `/markup/test.json`, `.xml`, `.csv`, `.yml`                 | 구성파일/API 누출 확인 |
| `/markup/test.bak`, `.old`, `.orig`, `.swp`, `.tmp`         | 백업/임시파일 누출 탐지  |
| `/markup/test.1`, `.log`, `.zip`                            | 로그/압축된 리소스 확인  |

---

### 🕳️ 2. 점(dot) 조작

| 테스트                                            | 설명                      |
| ---------------------------------------------- | ----------------------- |
| `/markup/.git/HEAD`                            | Git 저장소 노출 여부           |
| `/markup/.env`                                 | Laravel 등에서 환경변수 파일     |
| `/markup/.DS_Store`, `.htaccess`, `.ftpconfig` | OS/웹서버 설정 노출            |
| `/markup/.well-known/`                         | ACME, 인증 관련 경로 존재 여부    |
| `/markup/.idea/`, `.vscode/`, `.svn/`          | 개발 툴/버전 관리 메타디렉토리 노출 여부 |

---

### 🛠️ 3. 슬래시/트레일링 조작

| 테스트                                       | 설명            |
| ----------------------------------------- | ------------- |
| `/markup/test` → `/markup/test/`          | 디렉토리로 오해하게 유도 |
| `/markup/test/../test.txt`                | 디렉토리 역참조 우회   |
| `/markup//test.txt`, `/markup/./test.txt` | 웹서버 파싱 혼란 유도  |

---

### 🔥 4. HTTP 메서드 기반 테스트

| 메서드                       | 테스트                      |
| ------------------------- | ------------------------ |
| `OPTIONS /markup/`        | 지원하는 메서드 조회              |
| `PUT /markup/test.txt`    | 파일 업로드 가능 여부             |
| `DELETE /markup/test.txt` | 파일 삭제 허용 여부              |
| `TRACE /markup/`          | Cross-Site Tracing 가능 여부 |
| `HEAD /markup/test.txt`   | 존재 여부는 알 수 있지만 본문 없음     |

---

### 🔐 5. 인증 우회 시도

| 방법                           | 설명                 |
| ---------------------------- | ------------------ |
| `X-Original-URL: /admin`     | IIS 인증 우회          |
| `X-Forwarded-For: 127.0.0.1` | 내부 접근자 가장          |
| `Authorization: Basic ...`   | 기본 인증 우회 가능성       |
| `Referer` 조작                 | "내부에서 호출된 요청"처럼 위장 |
| `Host` 헤더 조작                 | 가짜 도메인 기반 접근 유도    |

---

### 📦 6. MIME/헤더 기반 취약점 테스트

| 항목                              | 설명                           |
| ------------------------------- | ---------------------------- |
| `Accept: application/json`      | API 응답 유도                    |
| `Accept-Encoding: gzip, br`     | 응답 압축 → **CRIME/BREACH** 가능성 |
| `Content-Type: application/xml` | XML 파서 유도 → XXE 가능성          |
| `Range: bytes=0-`               | 응답 조각화 테스트 → DoS 취약 여부 확인    |

---

### 🧪 7. 경로 내 페이로드 삽입

| 패턴                                         | 목적                |
| ------------------------------------------ | ----------------- |
| `/markup/<script>alert(1)</script>.js`     | XSS 필터 확인         |
| `/markup/%2e%2e/%2e%2e/etc/passwd`         | 경로 우회 (디렉토리 트래버설) |
| `/markup/test%20.txt`                      | 공백/인코딩 우회         |
| `/markup/test;.txt`, `/markup/test::$DATA` | IIS, NTFS 취약점 테스트 |

---

### 🕵️ 8. 자동 다운로드/0KB 응답 분석

* 파일 크기가 0KB인데 다운로드가 되는 경우:

  * 서버가 `Content-Disposition: attachment` 헤더를 포함하고 있을 수 있음
  * 또는 파일은 존재하나 실제 컨텐츠는 없음 (placeholder일 수도)
* 이걸 기반으로 시도할 수 있는 것:

  * `.php`, `.jsp`, `.aspx` 같은 **코드 노출 시도**
  * `.zip`, `.tar.gz`, `.7z` 등 **파일 리스트 노출 확인**
  * `.bak`, `.swp`, `.~` 같은 **백업 파일 요청**

---

### 🧪 9. 확장자 오용 우회

| 우회 예시                     | 설명                   |
| ------------------------- | -------------------- |
| `/markup/test.txt.php`    | 파일명 우회로 PHP 실행 유도    |
| `/markup/test.php.txt`    | 콘텐츠는 PHP인데 확장자로 우회   |
| `/markup/test.jsp%00.txt` | null byte 우회 (일부 서버) |
| `/markup/test.txt/`       | Apache의 멍청한 처리 우회    |

---

