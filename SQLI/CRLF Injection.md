**⚠️ CRLF Injection이란? (캐리지리턴 라인피드 주입)** 

HTTP 프로토콜에서 줄바꿈을 나타내는 특수 문자 시퀀스 CR(캐리지리턴)과 LF(라인피드)
**CR** → `%0d`
**LF** → `%0a`
HTTP 헤더와 본문을 구분하는 데 사용하는 두 문자를 이용한 인젝션이다. 

* 입력값(HTTP 요청)에 CRLF (`\r\n`)를 넣어 **헤더의 끝을 강제로 종료하고, 새로운 헤더나 본문을 삽입**하는 대표적인 **HTTP Response Splitting** 기법.
* 서버의 HTTP 응답이나 헤더를 조작한다.


## 📎 관련 취약점 번호

* [CWE-93: CRLF Injection](https://cwe.mitre.org/data/definitions/93.html)
* [OWASP: HTTP Response Splitting](https://owasp.org/www-community/attacks/HTTP_Response_Splitting)


## 📌 요청 분석

```
/test.txt**%0d** **%0a**Set-Cookie:CRLFInjection=Test%0d%0aLocation:%20interact.sh%0d%0aX-XSS-Protection:0
```
`%0D%0A` = `CR` + `LF` (Carriage Return + Line Feed)

### 디코딩 결과:

```
/test.txt
Set-Cookie: CRLFInjection=Test
Location: interact.sh
X-XSS-Protection: 0
```

| 삽입 내용                            | 목적                             |
| -------------------------------- | ------------------------------ |
| `Set-Cookie: CRLFInjection=Test` | 사용자의 브라우저에 악성 쿠키 설정 시도         |
| `Location: interact.sh`          | HTTP 302 리디렉션을 유도하여 악성 사이트로 이동 |
| `X-XSS-Protection: 0`            | 브라우저의 XSS 필터를 **강제로 비활성화**     |


### ❗ 공격 과정

1. **응답 헤더 삽입 (HTTP Response Splitting)**
   공격자가 `\r\n`을 삽입하여 **서버 응답 헤더를 인위적으로 끊고 새 헤더를 삽입**하려는 시도입니다.

2. **브라우저 동작 변조**

   * `Set-Cookie:` → 브라우저에 조작된 쿠키 저장 시도
   * `Location:` → 리디렉션 유도 (`interact.sh`는 [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator) 같은 도구에서 흔히 쓰이는 외부 확인용 도메인)
   * `X-XSS-Protection: 0` → 브라우저의 XSS 방어 기능 끔

3. **Blind Injection 확인용**

   * 응답이 어떻게 바뀌는지 공격자가 직접 보지 못할 때, 외부 도메인(`interact.sh`)로 브라우저가 연결하는지 확인해 공격 성공 여부를 판단
   * 
---

## 🧪 공격 효과 

서버가 `/test.txt?...`와 같은 요청을 헤더 그대로 반영한다면 응답 헤더가 이렇게 바뀔 수 있음

```
HTTP/1.1 200 OK
Content-Type: text/plain
Set-Cookie: CRLFInjection=Test
Location: interact.sh
X-XSS-Protection: 0
```

이 상태에서 브라우저는
   * 쿠키를 저장함
   * 다른 도메인(interact.sh)로 리디렉션됨
   * XSS 방어가 꺼져 있어 이후 공격에 더 취약해짐



## ✅ 방어 방법

| 항목                    | 조치                                                            |
| --------------------- | ------------------------------------------------------------- |
| **입력값 필터링**           | `%0d`, `%0a`, `\r`, `\n` 문자 입력 차단 또는 제거                       |
| **헤더 값 검증**           | 사용자 입력을 응답 헤더에 직접 반영하지 않기                                     |
| **WAF 설정**            | 헤더 주입 시도 패턴 차단 (예: `Set-Cookie:`, `Location:` 등 포함된 경로 요청 차단) |
| **로그 모니터링**           | 비정상 응답 헤더 길이 또는 헤더 종료 문자가 있는 요청 기록 감시                         |
| **프레임워크 내장 보안 기능 활용** | Express.js, Flask, Spring 등 대부분 헤더 주입 방지 기능 내장됨               |

**경로/쿼리에 CR (`\r`) 또는 LF (`\n`) 존재 시 요청 거부**

   * Apache, nginx, WAF에서 URI에 `%0D`/`%0A` 포함된 요청 차단
   * 예:

     ```nginx
     if ($request_uri ~* "%0D|%0A") {
         return 403;
     }
     ```

**모든 출력에 대해 헤더 인젝션 필터링 적용**

   * 서버가 경로를 응답 헤더에 그대로 반영하는 경우 특히 위험함

**의심 요청 로깅 및 알림**

   * `Location`, `Set-Cookie`, `X-XSS-Protection` 등이 URL에 포함된 요청은 경고

---

## 🔍 테스트 필요 여부

이 요청을 받은 **서버의 응답 헤더**에 정말로 다음이 포함되는지 확인해보세요

```http
Set-Cookie: CRLFInjection=Test
Location: interact.sh
X-XSS-Protection: 0
```

* 포함되면 → **심각한 취약점 (HTTP Response Splitting)**
* 포함되지 않고 그대로 404/200 응답 → 상대적으로 안전, 그러나 **로그 확인 및 WAF 적용 필요**

---

