## 🧨 HTTP Request Smuggling (요청 스머글링) 

### 🔍 정의:

프론트 서버(프록시, CDN, 로드밸런서)와 **백엔드 서버**가 **HTTP 요청 파싱 방식에 차이**가 있을 때,
공격자가 **한 번의 요청에 몰래 두 번째 요청을 끼워 넣어**
프론트는 무시하고 백엔드는 실행하게 만드는 **비동기 요청 오염 공격**.

---

### 1️⃣ 프록시/로드밸런서/웹서버 구조:

```
[Client] → [Proxy] → [Backend Server]
```

### 2️⃣ 요청 스머글링 발생 시:

* 클라이언트가 이상하게 구성된 요청을 보냄

* 프록시는 이렇게 해석:

  ```
  POST / HTTP/1.1
  Content-Length: 30
  ```

  (본문은 30바이트라고 판단)

* 그런데 백엔드는 이렇게 해석:

  ```
  Transfer-Encoding: chunked
  ```

  (본문은 chunked로 해석)


## ➡️ 청크 인코딩? 

* HTTP에서 서버가 클라이언트에게 데이터를 보낼 때 전체 데이터 크기를 모를 수 있는데, 데이터를 작은 덩어리(청크, chunk) 단위로 나눠서 순차적으로 전송하는 방식.
* 위에서는 백엔드 서버가 그 chunked 데이터를 받아서 청크 단위로 쪼개어 해석(파싱)했다는 의미.


💣 **서로 다르게 해석되면서** 프록시와 백엔드 간 요청 분리가 꼬이고, **숨겨진 두 번째 요청이 백엔드에 몰래 전달됨**


---

## 🧪 기본 형태 예시

```http
POST / HTTP/1.1
Host: victim.com
Content-Length: 4
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: victim.com
```

* 프록시는 `Content-Length: 4` 기준으로 **첫 요청만 처리**
* 백엔드는 `Transfer-Encoding: chunked` 기준으로 **청크 끝까지 읽고**, **숨겨진 GET /admin 처리**


💥 즉, **요청 한 개처럼 보이지만, 실제론 2개짜리 요청** → **스머글링 성공**


#### 1. **두 번째 요청이 실제로 처리됨 (Smuggled 요청 처리됨)**

* `OPTIONS`나 `POST`를 보냈는데,
  응답에서 `/admin` 같은 **두 번째 요청의 결과**가 나옴

#### 💥 위험 응답 예시

```http
HTTP/1.1 200 OK
...
Welcome to admin dashboard!
```

→ 공격자가 **숨긴 GET /admin 요청이 실행됨**
→ 즉, **Request Smuggling 성공 = 취약**

---

#### 2. **응답이 꼬임 (잘려 있음, 구조 이상함)**

* 응답이 부분적으로 잘리거나
* 두 응답이 섞여 있음
* 이상한 에러(502, 400, connection close 등)

#### 예:

```http
HTTP/1.1 200 OK
Content-Length: 0

HTTP/1.1 404 Not Found
```

또는

```http
HTTP/1.1 400 Bad Request
Transfer-Encoding error
```

→ 서버 간 요청 파싱 충돌이 발생한 것
→ 이 경우도 취약 가능성 높음

---

#### 3. **캐시 오염 (HTTP Desync 공격)**

* 공격자가 숨겨둔 요청을 캐시에 저장시키고,
* 이후 다른 사용자에게 악성 응답이 돌아감

#### 예:

공격자 요청 후:

```http
GET / HTTP/1.1
Host: site.com

0

GET /malicious-content HTTP/1.1
```

→ 이후 일반 사용자가 접속하면
`/malicious-content` 내용이 **정상 페이지처럼 응답됨** → 캐시 오염


---

## 💥 `HEAD` / `OPTIONS` 기반 Request Smuggling

### 📌 핵심 아이디어:

* `HEAD`, `OPTIONS`는 **서버가 대충 처리하거나 무시하는 경우가 많음**
* 보안 필터나 로깅 시스템도 **정상 OPTIONS는 로그 안 남기기도 함**
* → 공격자가 이 \*\*"무시되는 요청"\*\*에 **몰래 두 번째 요청을 숨김**
* 백엔드 서버는 무심코 **숨겨진 두 번째 요청까지 실행**

---

### ✅ `OPTIONS` 기반 Request Smuggling 예시

```http
OPTIONS / HTTP/1.1
Host: vulnerable.com
Content-Length: 4
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: vulnerable.com
```

> 프록시는 "OPTIONS 요청만 왔구나" 하고 종료
> 백엔드는 청크 해석 후, **숨겨진 GET 요청을 실행**
> → **인증 우회**, **비인가 접근**, **캐시 오염**, **로깅 우회** 가능

---

### ✅ `HEAD` 메서드도 악용 가능

```http
HEAD / HTTP/1.1
Host: vulnerable.com
Content-Length: 4
Transfer-Encoding: chunked

0

GET /internal-api HTTP/1.1
Host: vulnerable.com
```

> `HEAD`는 응답 body가 없기 때문에 응답 이상을 감지하기 어려움
> 관리자용 API 또는 민감 리소스가 **노출된 채 실행**

---

## ❓ CDN 공격 예시
**CDN(예: 아카마이) 뒤에 숨은 실제 서버 또는 공격면**을 찾으려는 공격

```
GET / HTTP/1.1 Host: whatismyip.akamai.com Smuggle"
```

### 📌 1. **CDN 뒤에 숨은 실제 클라이언트 IP 추적**

CDN을 사용하는 사이트들은 보통 **원래 서버의 IP를 숨기기 위해 CDN을 씀**.

* 공격자가 아카마이 CDN 엣지 서버의 IP 주소를 식별하면,
* CDN 네트워크를 우회하거나, 악용할 수 있는 루트를 탐색 가능



### 📌 2. **CDN 구성 오용 식별 (오리진 IP 노출 여부)**

#### ⚠️ 잘못된 CDN 설정:

* 오리진 서버가 **CDN 외 요청도 받도록 열려 있는 경우** (보통 막아야 함)
* 공격자는 CDN IP를 추적하거나, 우회해서 오리진 서버에 직접 공격

#### 💡 예시 시나리오:

1. 공격자가 `whatismyip.akamai.com`으로 리퀘스트 보내서
   → **아카마이 엣지 서버 IP** 식별
2. 이후 CDN을 통해 라우팅된 요청과,
   오리진 서버 직접 접속했을 때의 응답 차이를 비교
3. 오리진 IP가 노출되면, DDoS, 스캐닝, 직접 공격 가능



### 📌 3. **HTTP Request Smuggling 테스트 목적**


```http
GET https://<azurefd>.net HTTP/1.1
Smuggle:
```

이런 식이면 `Smuggle:`라는 **비정상적인 헤더**나 구문을 통해

* 프록시/CDN이 **요청을 다르게 파싱**하도록 유도 → 스머글링 실험
* 또는 **잘못된 호스트 헤더 공격**(Host header injection) 실험

---

### ✅ 다음과 같은 응답이 나오면 취약

| 응답 패턴                           | 의미                        |
| ------------------------------- | ------------------------- |
| ✅ 숨겨둔 두 번째 요청이 실행됨              | **취약 (완전한 스머글링 성공)**      |
| ⚠️ 응답이 꼬이거나 잘림                  | **취약 가능성 있음**             |
| 🛑 400 / 502 / connection reset | 파싱 충돌 발생, 취약 가능성 있음       |
| 🧪 캐시 결과가 이상하게 바뀜               | 캐시 스머글링 (Desync), 고위험 취약점 |

---

## 💡 왜 `OPTIONS` 메서드가 특히 위험한가?

| 이유                                 | 설명                                  |
| ---------------------------------- | ----------------------------------- |
| ❌ 서버가 OPTIONS 요청을 "단순한 프리플라이트"로 간주 | CORS Preflight로 처리하고 로그 남기지 않음      |
| ❌ 보안 필터에서 OPTIONS는 무시 대상           | WAF, IDS 등에서 OPTIONS 요청은 탐지 예외처리 많음 |
| ❌ 응답이 비어 있어서 이상 징후 탐지 어려움          | 로그나 리턴 body가 없음 (HEAD와 유사)          |
| ✔️ 백엔드는 여전히 전체 요청 읽음               | chunked 처리하면서 숨겨진 두 번째 요청 실행 가능     |

---

## 🚨 실제 발생 가능한 공격 영향

| 공격 유형                          | 설명                             |
| ------------------------------ | ------------------------------ |
| 🔓 **인증 우회**                   | 숨겨진 GET 요청으로 로그인 없이 관리자 페이지 접근 |
| 🎯 **세션 하이재킹**                 | `Cookie` 헤더 포함된 숨겨진 요청 실행      |
| 💾 **캐시 오염 (Cache Poisoning)** | 숨겨진 요청이 CDN/프록시 캐시에 저장됨        |
| 🪤 **XSS, CSRF 삽입**            | 스머글링된 요청을 통해 HTML/JS 삽입        |
| 🔍 **보안 우회**                   | 로깅/WAF 무력화, 요청 탐지 불가           |

---

## 🛡️ 대응 방법 (개발자/보안 담당자용)

| 조치               | 설명                                                                    |
| ---------------- | --------------------------------------------------------------------- |
| ✅ HTTP 표준 일관성 확보 | 프록시, 로드밸런서, 백엔드 모두 동일한 방식(`Content-Length` or `Transfer-Encoding`) 사용 |
| ✅ 혼합 헤더 거부       | `Content-Length`와 `Transfer-Encoding`이 **같이 들어온 요청은 무조건 거부**          |
| ✅ OPTIONS 메서드 제한 | 의심스러운 경로나 바디가 포함된 `OPTIONS` 요청은 거부하거나 로깅                              |
| ✅ 보안 장비 적용       | WAF/IDS/IPS에서 Request Smuggling 패턴 탐지 활성화                             |
| ✅ 최신 보안 패치 적용    | 특히 프록시 서버(Nginx, HAProxy, Apache 등)의 Request Parsing 관련 패치 반영         |

---

### 참고용 링크:

* 🔗 [PortSwigger: HTTP Request Smuggling Labs](https://portswigger.net/web-security/request-smuggling)
* 📘 OWASP 설명: [https://owasp.org/www-community/attacks/HTTP\_Request\_Smuggling](https://owasp.org/www-community/attacks/HTTP_Request_Smuggling)

