## ✔️ 서버에 존재하는 하위 파일 목록을 볼 수 있는 URL 조작 취약점
<img width="1266" height="827" alt="image" src="https://github.com/user-attachments/assets/63e50c37-e8b3-4ac6-9fd2-91c4ba7319ac" />

---

## 🔓 디렉터리 리스팅(Directory Listing) 취약점

### ✅ 설명

서버가 디렉터리에 대해 \*\*인덱스 파일(index.html, index.php 등)\*\*이 없고, **디렉터리 리스팅 설정이 활성화**되어 있으면,
브라우저로 접근 시 해당 경로 하위에 있는 파일 목록을 자동으로 보여주는 기능.

### ✅ 예시

```
http://example.com/uploads/
```

> 이 URL로 접근 시 아래와 같은 목록이 보일 수 있음:

```
Index of /uploads

- file1.jpg
- file2.png
- backup.zip
- .env
```

### ✅ 원인

* Apache: `Options +Indexes` 설정
* Nginx: `autoindex on;`
* 미구현된 인덱스 페이지(`index.html`, `index.php` 등 없음)

### ✅ 공격자가 얻을 수 있는 정보

* 존재하는 파일 및 확장자
* 백업 파일, 민감 정보(`.zip`, `.bak`, `.sql`)
* 파일명 유추를 통한 직접 다운로드 가능

---

## 🔓 URL 조작을 통한 디렉터리 리스팅 유도

```http
http://example.com/images/     ✅ 디렉터리 리스팅
http://example.com/images      ✅ 리다이렉트 후 리스팅
http://example.com/images/?    ✅ 일부 서버에서 index 처리 무시됨
```

---

## 🔓 Path Traversal (경로 조작) 기반 디렉터리 접근

### ✅ 설명

`../` 시퀀스를 이용해 **웹 루트 바깥의 디렉터리**나 **상위 디렉터리로 접근** 가능.

### ✅ 예시

```http
http://example.com/view.php?file=../../uploads/
http://example.com/?page=../../../../var/www/
```

* 이때 서버가 디렉터리 접근을 허용하고 `Directory Listing`이 열려 있으면 **파일 목록 출력**
* 심지어 `.env`, `.git`, `config.php` 등 열람 가능

---

## 💥 위험한 조합

| 취약점                              | 설명                                             |
| -------------------------------- | ---------------------------------------------- |
| 📁 Directory Listing + LFI       | 파일 목록을 보고, LFI로 파일 내용까지 읽을 수 있음                |
| 📁 Directory Listing + 경로 조작     | 상대경로(`../`)로 여러 디렉터리 탐색 가능                     |
| 📁 Directory Listing + Backup 파일 | `.zip`, `.bak`, `.old`, `.swp` 등의 민감한 백업 파일 노출 |
| 📁 Directory Listing + SSRF      | 서버 내부 URL 경로 예측 후 내부 파일 탐색 시도 가능               |

---

## 🔐 방어 방법

| 보안 조치                              | 설명                                                  |
| ---------------------------------- | --------------------------------------------------- |
| ❌ `autoindex` 비활성화 (Apache, Nginx) | Apache: `Options -Indexes`, Nginx: `autoindex off;` |
| ✅ 인덱스 파일 배치                        | `index.html`, `index.php` 등 기본 페이지 항상 배치            |
| ✅ 경로 필터링                           | `../`, `%2e%2e/`, `%252e%252e/` 등 우회 문자열 필터링        |
| ✅ 웹 루트 외부 파일 접근 금지                 | LFI 시 루트 바깥 접근 제한                                   |
| ✅ `.git`, `.env` 등 민감 디렉터리 접근 차단   | `.htaccess`, `location` 블록 등으로 보호                   |

---

## 🧪 취약점 점검 팁

1. 경로 끝에 `/` 붙여보기
   `http://target.com/admin/`

2. URL에 `?`, `index`, `null` 파라미터 넣기
   `http://target.com/admin/?`
   `http://target.com/admin/?file=`

3. LFI 조합 테스트
   `?file=../../`
   `?page=../../../../../var/www/html/uploads/`

4. 자동화 도구 활용

   * `dirsearch`, `ffuf`, `gobuster`, `feroxbuster` 등으로 디렉터리 탐색
   * `curl -I`로 `Content-Type`, 상태 코드, 리디렉션 확인
