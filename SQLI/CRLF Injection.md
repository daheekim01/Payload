**CRLF Injection (캐리지리턴 라인피드 주입)** 
---

## 📌 요청 분석

```
/test.txt%0d%0aSet-Cookie:CRLFInjection=Test%0d%0aLocation:%20interact.sh%0d%0aX-XSS-Protection:0
```

### 디코딩 결과:

```
/test.txt
Set-Cookie: CRLFInjection=Test
Location: interact.sh
X-XSS-Protection: 0
```

---

## ⚠️ CRLF Injection이란?

**CRLF (Carriage Return + Line Feed)** → `%0d%0a`

* HTTP 응답 헤더를 조작하는 취약점
* 입력값에 CRLF (`\r\n`)를 넣어 **헤더의 끝을 강제로 종료하고, 새로운 헤더나 본문을 삽입**하는 공격
* 대표적인 **HTTP Response Splitting** 기법

---

## 📌 이 공격에서 시도된 것들

| 삽입 내용                            | 목적                             |
| -------------------------------- | ------------------------------ |
| `Set-Cookie: CRLFInjection=Test` | 사용자의 브라우저에 악성 쿠키 설정 시도         |
| `Location: interact.sh`          | HTTP 302 리디렉션을 유도하여 악성 사이트로 이동 |
| `X-XSS-Protection: 0`            | 브라우저의 XSS 필터를 **강제로 비활성화**     |

---

## 🧪 공격 효과 예시 (취약한 서버일 경우)

1. 서버가 `/test.txt?...`와 같은 요청을 헤더 그대로 반영한다면
2. 응답 헤더가 이렇게 바뀔 수 있음:

```
HTTP/1.1 200 OK
Content-Type: text/plain
Set-Cookie: CRLFInjection=Test
Location: interact.sh
X-XSS-Protection: 0
```

3. 이 상태에서 브라우저는:

   * 쿠키를 저장함
   * 다른 도메인(interact.sh)로 리디렉션됨
   * XSS 방어가 꺼져 있어 이후 공격에 더 취약해짐

---

## ✅ 방어 방법

| 항목                    | 조치                                                            |
| --------------------- | ------------------------------------------------------------- |
| **입력값 필터링**           | `%0d`, `%0a`, `\r`, `\n` 문자 입력 차단 또는 제거                       |
| **헤더 값 검증**           | 사용자 입력을 응답 헤더에 직접 반영하지 않기                                     |
| **WAF 설정**            | 헤더 주입 시도 패턴 차단 (예: `Set-Cookie:`, `Location:` 등 포함된 경로 요청 차단) |
| **로그 모니터링**           | 비정상 응답 헤더 길이 또는 헤더 종료 문자가 있는 요청 기록 감시                         |
| **프레임워크 내장 보안 기능 활용** | Express.js, Flask, Spring 등 대부분 헤더 주입 방지 기능 내장됨               |

---

## 📎 관련 취약점 번호

* [CWE-93: CRLF Injection](https://cwe.mitre.org/data/definitions/93.html)
* [OWASP: HTTP Response Splitting](https://owasp.org/www-community/attacks/HTTP_Response_Splitting)

---

## 요약

| 항목    | 설명                                      |
| ----- | --------------------------------------- |
| 공격 목적 | 응답 헤더 변조 → 악성 쿠키 삽입, XSS 방어 해제, 리디렉션 유도 |
| 핵심 위험 | HTTP 응답 조작, 세션 탈취, 피싱                   |
| 방어 조치 | CRLF 필터링, 헤더 출력시 사용자 입력 제거, 보안 프레임워크 사용 |

---

