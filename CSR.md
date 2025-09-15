## ➡️ **클라이언트 사이드 렌더링 (CSR, Client-Side Rendering)** 

```html
<!DOCTYPE html>
<html>
  <head>...</head>
  <body>
    <noscript>You need to enable JavaScript to run this app.</noscript>
    <div id="root"></div>
  </body>
</html>
```

> 응답 HTML에 `<noscript>JavaScript 필요</noscript>` + `<div id="root"></div>`만 있고 콘텐츠가 없으면:

**✅ 클라이언트 사이드 렌더링 (CSR) 방식으로 구현된 프론트엔드**
**보통 React SPA에서 이런 구조가 많이 보인다.**

## 🔍 왜 CSR인지 알 수 있는 이유

1. **HTML이 비어 있음 (`<div id="root"></div>`)**

   * 서버가 HTML 콘텐츠를 거의 제공하지 않음
   * JavaScript가 실행된 이후에야 실제 콘텐츠가 `<div id="root">` 내부에 렌더링됨
   * 이 구조는 React, Vue, Angular 등 CSR 프레임워크에서 전형적

2. **`<noscript>` 경고**

   * `JavaScript가 꺼져 있으면 작동하지 않습니다`는 메시지는 **모든 렌더링이 JS에 의존**함을 암시
   * 즉, 서버는 단순한 "껍데기"만 내려주고, 실제 콘텐츠는 JS로 렌더링됨

3. **초기 응답이 빈 HTML**

   * SEO가 고려되지 않거나, SSR이 비활성화된 프론트엔드 SPA 구조일 가능성 높음

---

## 📦 클라이언트 사이드 렌더링 (CSR) 요약

| 항목       | 설명                           |
| -------- | ---------------------------- |
| 렌더링 위치   | **브라우저(클라이언트)**              |
| 서버 응답    | 빈 HTML + JS 번들 파일            |
| 초기 로딩 속도 | 느릴 수 있음 (JS 로딩 후 렌더링됨)       |
| SEO      | 별도 SSR/프리렌더링 안 하면 취약         |
| 대표 프레임워크 | React, Vue, Angular (SPA 모드) |

### 1. **모든 로직이 클라이언트에 노출됨**

* CSR에서는 JavaScript 번들 안에 많은 로직이 포함됨
* 개발자가 숨기고 싶은 API 경로, 라우팅 규칙, 프론트에서 처리하는 인증 상태 등이 **브라우저에 노출**

### 2. **렌더링이 클라이언트에서 일어나므로 DOM 조작이 쉽다**

* 공격자가 Chrome DevTools 또는 악성 JS를 통해 **동적으로 DOM을 변경 가능**
* 예: 악성 스크립트 삽입, hook 변경, 이벤트 리스너 탈취 등

### 3. **JavaScript 기반 XSS 취약점이 흔하다**

* `innerHTML`, `document.write`, `dangerouslySetInnerHTML` 같은 위험한 렌더링 방식이 자주 사용됨
* CSR 앱은 종종 **사용자 입력 → DOM에 직접 렌더링** 구조를 갖기 때문에 XSS 공격이 성공할 확률이 높음


## 🔁 CSR vs SSR 간단 비교

| 항목       | CSR (Client-Side)            | SSR (Server-Side)                        |
| -------- | ---------------------------- | ---------------------------------------- |
| 초기 HTML  | 빈 껍데기 (`<div id="root">`)    | 실제 콘텐츠 포함                                |
| SEO      | 기본으로는 ❌                      | 기본적으로 ✅                                  |
| 초기 로딩 속도 | JS 로딩 이후 렌더링 → 느림            | 즉시 콘텐츠 렌더링됨 → 빠름                         |
| 예시       | React 앱 (`create-react-app`) | Next.js, Nuxt.js, Express, Django, PHP 등 |

---

## 🧪 예시: 같은 취약점, CSR vs SSR 비교

### 📍 XSS 예시

#### 🔹 CSR 환경 (React 등)

```javascript
// 댓글 입력값을 innerHTML로 삽입
document.getElementById("comment").innerHTML = userInput;
```

입력값에 `<script>alert(1)</script>` → 실행됨 ✅

#### 🔹 SSR 환경 (Node/Express + EJS 등)

```ejs
<!-- EJS 템플릿 --> 
<p><%= comment %></p>
```

서버 사이드 템플릿 엔진은 자동 이스케이프가 되므로 XSS 실패 ❌
(물론 이스케이프를 수동 해제하면 취약할 수 있음)

---

## 📌 **CSR에서 조작이 쉬운 이유**

### 1. **브라우저에서 JS가 모든 걸 그리기 때문에**

CSR은 서버에서 받은 HTML이 거의 빈 껍데기고,
브라우저에서 JavaScript가 동작하면서 콘텐츠를 만드는 구조야.
→ 즉, **공격자가 JS 또는 DOM 조작만으로 페이지를 조작**할 수 있는 여지가 많아.

예:

```js
document.getElementById("welcome").innerHTML = location.hash;
```

* URL에 `#<script>alert(1)</script>` 같은 걸 넣으면 DOM-based XSS 발생 가능

---

### 2. **API 의존성 = 공격 기회**

CSR 앱은 서버에서 데이터를 받아서 클라이언트에서 그리는 방식이기 때문에,
**API 호출 결과만 조작하면 전체 UI를 속일 수 있음.**

> API 응답 위조 또는 MITM 시나리오에서 공격자가 API 응답을 다음처럼 바꿀 수 있음:

```json
{
  "user": "admin",
  "isAdmin": true
}
```

* 이걸 프론트에서 그대로 렌더링하면?
* 공격자 화면에서 관리자 UI가 활성화됨

---

### 3. **JS 로직이나 구조가 노출됨**

CSR은 대부분의 렌더링 로직이 **브라우저에 그대로 다운로드**되기 때문에,

* 어떤 API를 호출하는지
* 어떤 조건에서 어떤 콘텐츠를 그리는지
  전부 디버깅 툴(F12, DevTools)로 확인 가능

➡️ 조작이나 변조가 훨씬 쉬움

---

### 4. **보안 실수도 클라이언트 쪽에서 발생하기 쉬움**

개발자들이 다음과 같은 실수를 자주 함:

* `innerHTML`에 사용자 입력 직접 렌더링
* JavaScript에서 민감 정보 로딩 (예: 토큰, 키 포함된 config)
* API 응답을 검증 없이 렌더링

➡️ 이 모든 게 **클라이언트에서 공격자가 직접 조작 가능**한 포인트가 돼.

---

## 📌 예시 시나리오 (CSR에서 조작되는 방식)

### 🔹 DOM-Based XSS

```javascript
// userProfile.js
const username = new URLSearchParams(location.search).get("username");
document.getElementById("profile").innerHTML = `<h1>${username}</h1>`;
```

➡️ 공격 URL:

```
https://victim.com/#/profile?username=<img src=x onerror=alert(1)>
```

---

### 🔹 API 응답 조작

* 원래 API:

```json
{
  "username": "guest",
  "role": "user"
}
```

* 공격자가 중간에서:

```json
{
  "username": "attacker",
  "role": "admin"
}
```

➡️ 프론트가 role 값만 보고 관리자 버튼 보여줄 수도 있음.

---

### 🔹 클라이언트에서 자바스크립트 직접 조작

브라우저 콘솔에서:

```js
window.user.isAdmin = true;
document.getElementById("admin-panel").style.display = "block";
```

➡️ 서버 검증 없이 프론트에서만 체크하는 경우 **관리자 화면 오픈됨**

