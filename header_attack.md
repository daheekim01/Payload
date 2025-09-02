* HTTP 헤더는 신뢰해서는 안 되며, 반드시 **서버 측에서 유효성 검증**을 해야 함.
* 특히 `X-*`, `Host`, `Authorization`, `Referer` 같은 헤더는 공격 벡터로 자주 활용되므로 **보안 헤더 설정**, **검증 로직 구현**이 필요함.

---

### 1. **X-Forwarded-For 헤더를 이용한 IP 스푸핑**

`X-Forwarded-For` 헤더는 원래 클라이언트 IP를 나타내는 데 사용됨. 공격자가 이 값을 조작해 IP를 우회하거나 신뢰받는 IP처럼 보이게 할 수 있음.

#### 공격 기법:

* IP 차단 우회, 관리자 페이지 접근 등에서 우회 시도 가능.

#### 페이로드 예시:

```http
GET /admin HTTP/1.1
Host: victim.com
X-Forwarded-For: 127.0.0.1
```

→ 로컬에서 접속한 것처럼 보이게 조작 가능.

---

### 1.1. `X-*` 헤더 계열

#### 🔸 `X-Real-IP`

`X-Forwarded-For`과 유사하게, 단일 IP 전달용으로 사용됨.

```http
X-Real-IP: 127.0.0.1
```

→ 마찬가지로 조작 가능.

#### 🔸 `X-HTTP-Method-Override`

`POST` 요청만 허용하는 서버에서 메서드를 `PUT`, `DELETE` 등으로 바꾸는 데 사용됨.

```http
POST /resource HTTP/1.1
X-HTTP-Method-Override: DELETE
```

→ 서버가 이 헤더를 신뢰하면 `DELETE`로 처리됨.

#### 🔸 `X-Original-URL` / `X-Rewrite-URL`

요청 경로를 변경해 서버가 다른 자원에 접근하도록 만들 수 있음.

```http
X-Original-URL: /admin
```

→ 실제 경로는 `/`, 내부적으로 `/admin` 접근됨.

#### 🔸 `X-Host` / `X-Forwarded-Host`

```http
Host: attacker.com
X-Forwarded-Host: victim.com
```

→ SSRF, 리디렉션, 이메일 링크 위조 등에 활용 가능.

---

### 2. **Host 헤더 인젝션**

`Host` 헤더를 조작해 리디렉션, URL 생성, 인증 링크 위조 등을 시도함.

#### 페이로드 예시:

```http
Host: victim.com
X-Forwarded-Host: attacker.com
```

→ 공격자가 의도한 호스트로 링크 생성됨.

---

### 3. **Referer 헤더를 통한 XSS**

애플리케이션이 `Referer` 값을 그대로 출력할 경우, XSS 발생 가능.

#### 페이로드 예시:

```http
Referer: <script>alert('XSS Attack!');</script>
```

→ 스크립트가 그대로 반영되면 실행됨.

---

### 4. **Authorization 헤더를 이용한 인증 우회**

`Authorization` 헤더를 조작해 인증 우회 가능. 브루트포스 시도도 가능함.

#### 페이로드 예시:

```http
Authorization: Basic YWRtaW46YWRtaW4=
```

→ `admin:admin` 인코딩한 값. 인증 우회 시도됨.

---

### 5. **User-Agent 조작**

서버가 `User-Agent` 값을 기준으로 동작을 달리할 경우 조작 가능.

#### 페이로드 예시:

```http
User-Agent: Chrome/114.0.0.0
```

→ 특정 동작 유도 가능. 취약한 브라우저로 오인 유도 가능.

---

### 6. **X-Content-Type-Options 우회**

`nosniff` 설정이 없으면, 브라우저가 MIME 타입을 추측해 실행할 수 있음.

#### 페이로드 예시:

```http
// 헤더 없음
```

→ HTML 아닌 파일을 HTML로 오인해 실행함.

---

### 7. **Cache-Control을 이용한 캐시 오염**

적절한 캐시 정책이 없으면 민감한 정보가 공유될 수 있음.

#### 페이로드 예시:

```http
Cache-Control: public
```

→ 로그인 후 페이지가 공유 캐시에 저장될 수 있음.

---
