## 🔁 리다이렉트란

> **요청이나 처리를 원래 목적지 대신 다른 위치로 자동 전환하는 것**을 말합니다.

### 🌐 **웹에서의 리다이렉트 (HTTP Redirect)**

* 사용자가 어떤 URL에 접속했을 때,
  **자동으로 다른 URL로 이동시키는 것**.

#### 예시:

* 사용자가 `http://example.com`으로 접근했을 때,
  자동으로 `https://www.example.com/home`으로 이동.

### ✅ 도메인이 다른 사이트로 이동하는 리다이렉트란?

> 현재 페이지에서 사용자를 **전혀 다른 도메인 주소로 자동 이동시키는 것**

예를 들어:

* 사용자가 `http://example.com`에 접속했는데
* 브라우저가 자동으로 `https://another-site.com/login`으로 이동한다면
  → **이건 리다이렉트 + 도메인 변경**이 포함된 경우예요.


### 1. 🧠 HTML 메타 태그로 리다이렉트 (클라이언트 측) 

```html
<meta http-equiv="refresh" content="0; URL=https://another-site.com" />
```

* 페이지가 로드되자마자 (0초 후)
* 자동으로 다른 도메인으로 이동


### 2. 🧑‍💻 JavaScript를 통한 리다이렉트 (URL에 직접 쓸 ❌)

```javascript
window.location.href = "https://another-site.com";
```

또는

```javascript
location.replace("https://another-site.com");
```

#### 우회문 예시

명명(named) 문자 엔티티
&quot;https&colon;&sol;&sol;www.naver.com&quot;

10진 숫자 엔티티
&#34;https&#58;&#47;&#47;www&#46;naver&#46;com&#34;

16진 숫자 엔티티
&#x22;https&#x3A;&#x2F;&#x2F;www&#x2E;naver&#x2E;com&#x22;

<a href="location.replace('https://another-site.com')">Click me</a>
---

### ✅ 리다이렉션 취약점이 되려면?

**사용자 입력**(예: `?next=` 파라미터 등)을 통해
**원하지 않는 외부 URL로 이동할 수 있어야** 합니다.

### 예시 (취약):

```js
// 사용자 입력에 따라 외부로 이동
const redirect = new URLSearchParams(window.location.search).get("next");
window.location.href = redirect;
```

* `https://example.com/login?next=https://evil.com`
  → 사용자 클릭 시 악성 사이트로 이동



| 상황                                   | 리다이렉션 취약점인가?      |
| ------------------------------------ | ----------------- |
| 콘솔에서 `href = "https://naver.com"` 입력 | ❌ 아님 – 브라우저 정상 기능 |

---

## ✅ 1. **리다이렉션 URL을 콘솔에서 직접 변경하는 방법**

만약 `redirect` URL 파라미터를 통해 리디렉션이 이루어지는 경우라면, **콘솔에서 직접 URL 파라미터를 변경**하여 리디렉션 경로를 수정할 수 있습니다.

### 1.1 **URL 파라미터가 `window.location.search`로 처리되는 경우**

**예시 코드**:

```js
let redirectUrl = new URLSearchParams(window.location.search).get("redirect");
if (redirectUrl) {
    window.location.href = redirectUrl;
}
```

이 경우, **`redirect` 파라미터 값**을 **콘솔에서 수정**하면, 그 값으로 리디렉션됩니다.

### 1.2 **콘솔에서 리디렉션 URL 수정하기**

1. 브라우저에서 **F12**를 눌러 **개발자 도구**를 엽니다.
2. **Console** 탭을 선택합니다.
3. 아래 코드를 콘솔에 입력합니다:

```js
// 현재 URL에 파라미터를 추가해 리디렉션 URL을 변경
window.location.search = "?redirect=https://evil.com"; 
```

그럼, 페이지는 리디렉션이 되면서 **`https://evil.com`** 으로 이동하게 됩니다.

### 1.3 **콘솔에서 직접 window\.location.href 변경하기**

```js
window.location.href = "https://evil.com";
```

* 이 코드로 리디렉션 URL을 **직접 설정**할 수도 있습니다.
* 이 방법은 `redirect` 파라미터가 아닌 **직접적인 리디렉션을 유도**하는 방법입니다.

---

## ✅ 2. **Open Redirect 취약점 우회하기**

**Open Redirect 취약점**이 있다면 사용자가 특정 URL로 리디렉션될 때, 이를 악용하여 **악성 사이트로 우회**할 수 있습니다.

### 2.1 **Open Redirect 취약점이 있는 코드 예시**

```js
let redirectUrl = new URLSearchParams(window.location.search).get("redirect");
if (redirectUrl) {
    window.location.href = redirectUrl;
}
```

위와 같은 코드에서는 `?redirect=` 파라미터를 통해 리디렉션하는데, 공격자는 **악성 URL**을 파라미터로 전송할 수 있습니다.

### 2.2 **콘솔을 통해 리디렉션을 악용하는 방법**

1. 페이지 URL에서 `?redirect=...` 값을 수정하거나
2. **Console** 탭에서 `redirect` URL을 조작할 수 있습니다.

```js
// ?redirect 파라미터를 수정하여 리디렉션 URL을 변경
window.location.search = "?redirect=https://evil.com"; 
```

혹은:

```js
// 리디렉션 URL을 콘솔에서 직접 변경
window.location.href = "https://evil.com";
```

### 2.3 **파라미터 우회 시나리오 (URL 인코딩 우회)**

때로는 **URL 인코딩**을 통해 우회할 수 있습니다. 예를 들어:

```text
https://example.com/page?redirect=https://evil.com
```

이 URL을 **인코딩**하여 우회할 수 있습니다.

```text
https://example.com/page?redirect=https%3A%2F%2Fevil.com
```

위 URL은 \*\*`https://evil.com`\*\*으로 리디렉션되며, 파라미터를 우회할 수 있습니다.

---

## ✅ 3. **리다이렉션 URL을 변경하는 방어 방법**

1. **화이트리스트 기반 필터링**
   리디렉션 URL을 **화이트리스트**에 등록된 URL만 허용하도록 제한합니다.

```js
const allowedUrls = ["https://example.com", "https://trusted.com"];
let redirectUrl = new URLSearchParams(window.location.search).get("redirect");

if (allowedUrls.includes(redirectUrl)) {
    window.location.href = redirectUrl;
} else {
    console.log("Invalid redirect URL");
}
```

2. **현재 도메인 내 리디렉션만 허용**
   현재 도메인 내에서만 리디렉션이 가능하도록 제한할 수 있습니다.

```js
let redirectUrl = new URLSearchParams(window.location.search).get("redirect");
if (redirectUrl && redirectUrl.startsWith(window.location.origin)) {
    window.location.href = redirectUrl;
} else {
    console.log("Invalid redirect URL");
}
```

3. **JavaScript 필터링 및 인코딩**
   URL을 삽입하기 전에 **HTML 인코딩**을 통해 악성 스크립트가 삽입되는 것을 방지합니다.

---

## ✅ 4. **브라우저에서 다른 방식으로 리디렉션 우회하기**

리디렉션 URL을 **콘솔에서** 또는 **브라우저의 개발자 도구**를 통해 우회하고자 할 때, 반드시 아래 방법들을 사용할 수 있습니다:

* **페이지 로딩 중 URL 조작**: JavaScript를 통해 `window.location.href` 값을 **동적으로 수정**.
* **JavaScript 코드 삽입**: `eval()` 또는 `setTimeout()` 등을 사용한 공격 코드 삽입 가능.
* **URL 파라미터 우회**: URL을 인코딩하거나 파라미터 자체를 변형하여 우회 가능.

---

## 🧨 결론

* **리다이렉션 URL이 `window.location.search`로 설정된 경우**, 콘솔에서 파라미터를 변경하여 리디렉션을 악용할 수 있습니다.
* **Open Redirect** 취약점이 있다면, 악성 URL을 **파라미터로 주입**하여 다른 사이트로 우회시킬 수 있습니다.
* 보안을 강화하기 위해서는 **URL 검증** 및 **화이트리스트**를 사용하여 외부로의 리디렉션을 제한해야 합니다.

만약 **HTML 내에 `<script>` 태그** 형태로 리디렉션 URL이 기재되어 있고, 이 값이 JavaScript 코드 내에서 사용된다면, 콘솔에서 **이 값을 변경하는 방법**은 몇 가지가 있을 수 있습니다. 다만, **직접적으로 `<script>` 태그 내의 값을 수정하는 것**은 불가능할 수 있지만, **스크립트 변수**나 **DOM**에 있는 값을 수정하는 방법으로 우회할 수 있습니다.

### 예시 코드:

```html
<script>
  var redirectUrl = 'https://example.com';  // 리디렉션 URL
  window.location.href = redirectUrl;        // 리디렉션 수행
</script>
```

위와 같이 `<script>` 내에서 **리디렉션 URL**이 `var redirectUrl = 'https://example.com';`처럼 정의되어 있다면, 이 값은 JavaScript 변수에 저장되어 있으며, 콘솔에서 직접 **변수를 변경**할 수 있습니다.

---

## 🛠️ 1. **JavaScript 변수 값 변경 (콘솔에서 가능)**

리디렉션 URL이 `<script>` 태그 내의 JavaScript 변수에 저장되어 있다면, **콘솔에서 해당 변수를 수정**할 수 있습니다. 콘솔에서 다음과 같이 할 수 있습니다:

### 1.1 **`redirectUrl` 값 변경하기**

1. F12로 개발자 도구를 열고, **Console** 탭을 선택합니다.
2. 아래와 같이 변수 값을 수정합니다:

```js
// 현재 redirectUrl 변수 값을 덮어씁니다.
redirectUrl = 'https://evil.com';
```

3. 이렇게 하면, 해당 **`redirectUrl`** 변수의 값이 변경되고, 그 값을 사용하는 리다이렉션 코드가 실행됩니다. 즉, \*\*리디렉션이 `https://evil.com`\*\*으로 변경될 수 있습니다.

### 1.2 **리디렉션 URL 즉시 실행하기**

만약 스크립트 내에서 리디렉션이 바로 실행되었다면, 그 이후에도 `window.location.href` 값을 직접 변경해볼 수 있습니다:

```js
window.location.href = 'https://evil.com';
```

### 1.3 **값이 이미 리디렉션되었을 때 취소하기**

리디렉션이 이미 발생한 상태라면, **`window.location.href`** 값을 수정하여 리디렉션을 멈추거나 새로운 URL로 변경할 수 있습니다.

```js
window.location.href = 'https://evil.com'; // 리디렉션 URL을 강제로 수정
```

---

## 🧨 2. **DOM을 통한 우회**

만약 리디렉션 URL이 **`<script>`** 태그에 정의되어 있다면, 그 값은 **DOM**에 존재할 수 있습니다. 이를 **DOM에서 찾고 수정**할 수도 있습니다.

### 2.1 **DOM에서 리디렉션 URL 찾기**

```js
// 스크립트 태그 내에 정의된 redirectUrl 변수 값 찾기
document.querySelector('script').innerHTML
```

위 코드는 **첫 번째 `<script>` 태그 내의 내용**을 가져옵니다. 이 코드를 콘솔에서 실행하면 해당 스크립트의 코드 내용이 반환되므로, 그 안에 있는 **리디렉션 URL**을 확인할 수 있습니다.

### 2.2 **`script` 태그를 동적으로 수정하기**

```js
let script = document.querySelector('script');  // 첫 번째 script 태그 선택
script.innerHTML = "var redirectUrl = 'https://evil.com';";  // 리디렉션 URL을 악성 사이트로 변경
```

위 코드를 통해 `<script>` 태그를 직접 수정하여 리디렉션 URL을 악성 URL로 변경할 수 있습니다. 이후 페이지를 새로 고침하거나 해당 스크립트가 다시 실행되면, 악성 URL로 리디렉션됩니다.

---

## 🛡️ 3. **리다이렉션 우회 방어 방법**

리디렉션 URL을 콘솔에서 수정할 수 있다는 것은 **Open Redirect 취약점**이나 **XSS** 취약점이 존재할 가능성을 시사합니다. 이를 방지하려면:

### 3.1 **URL 화이트리스트 검증**

서버나 클라이언트 측에서 **리디렉션을 허용할 URL**을 제한해야 합니다. 예를 들어, **리디렉션 URL을 화이트리스트**에 포함된 도메인으로만 제한하여 **악성 사이트로의 리디렉션**을 방지할 수 있습니다.

```js
const allowedUrls = ['https://trusted.com', 'https://example.com'];

let redirectUrl = new URLSearchParams(window.location.search).get('redirect');

if (allowedUrls.includes(redirectUrl)) {
    window.location.href = redirectUrl;
} else {
    console.log('Invalid redirect URL');
}
```

### 3.2 **JavaScript에서 URL 검증**

리디렉션을 수행하기 전에 URL이 **현재 도메인**에 속하는지 확인하는 방법입니다.

```js
let redirectUrl = new URLSearchParams(window.location.search).get('redirect');
if (redirectUrl && redirectUrl.startsWith(window.location.origin)) {
    window.location.href = redirectUrl;
} else {
    console.log('Invalid redirect URL');
}
```

### 3.3 **인코딩/디코딩 문제 처리**

URL에 인코딩된 값이나 JavaScript 코드가 포함되면 이를 **정확히 디코딩하여 처리**하는 것이 필요합니다. 공격자가 **인코딩된 URL**을 삽입할 수 있기 때문입니다.


---

## **리디렉션 우회/변조를 가능하게 하는 특수문자**
여러 문자들이 브라우저, 서버, 프레임워크의 **URL 해석 방식의 허점을 노려서** 리디렉션 공격에 악용될 수 있어요.


## ✅ 리디렉션 우회에 자주 쓰이는 특수문자/패턴 정리

| 특수문자    | 설명 및 우회 용도                                                                                       |
| ------- | ------------------------------------------------------------------------------------------------ |
| `@`     | **User info 우회** → `https://evil.com@trusted.com` → 브라우저는 `trusted.com`으로 보이지만 실제 연결은 `evil.com` |
| `\`     | **백슬래시 우회** → 일부 서버/프레임워크에서 `/`로 처리됨 → 경로 구분자로 해석되어 우회 가능                                        |
| `%`     | **URL 인코딩 우회** → `%2F`, `%5C`, `%00`, `%40` 등으로 필터 우회 시도                                         |
| `//`    | **스킴 상대 URL** → `//evil.com` → 현재 스킴(`https:`)으로 붙어서 `https://evil.com`으로 리디렉션                   |
| `:`     | **스킴 선언** → `javascript:`, `data:`, `file:` 등을 통해 XSS 또는 리디렉션 우회 시도                              |
| `?`     | 쿼리 구분자 → 매개변수 변경 시도 (`?redirect=https://evil.com`)                                               |
| `&`     | 쿼리 분리자 → 여러 파라미터 우회 시도 (`?next=valid.com&evil.com`)                                              |
| `#`     | 프래그먼트 → 일부 필터 우회 시도 (`/#@evil.com`) → 브라우저에 따라 해석 방식 차이                                          |
| `%00`   | 널 바이트 — 일부 언어에서 문자열 절단 우회 (`https://evil.com%00.safe.com`)                                       |
| `%09`   | 탭 문자 — 필터/정규식 우회 (`https:%09//evil.com`)                                                         |
| `%20`   | 공백 문자 인코딩 → 우회 또는 취약 정규식 필터 우회 시도                                                                |
| `[` `]` | 일부 파서에서 URL 오류 유발 가능, 필터 우회 조합에 사용                                                               |
| `'` `"` | 문자열 닫기 → 일부 잘못된 JS 문자열 리디렉션 우회 (`window.location = 'evil.com'`)                                  |
| `;`     | 일부 오래된 브라우저에서 파라미터 구분자로 취급되기도 함                                                                  |
| `..`    | 디렉터리 상위 이동 → SSRF 또는 파일 접근 시 우회 (`/login/../evil.com`)                                           |
| `\r\n`  | 헤더 주입 시도 (CRLF) → `Location: ...` 헤더 오염 가능 (`%0d%0a`)                                            |


## 📌 실제 공격 예시들 (실제로 쓰이는 우회 패턴)

1. **@ 우회 (유명한 phishing 방식)**

   ```
   https://trusted.com@evil.com
   → 브라우저 주소창엔 trusted.com 보이지만, 실제 요청은 evil.com
   ```

2. **이중 인코딩**

   ```
   https://%252e%252e%252fevil.com → %252e → %2e → .
   ```

3. **스킴 상대 URL**

   ```
   //evil.com → 현재 스킴(https:)을 자동으로 붙여서 → https://evil.com
   ```

4. **자바스크립트 실행 (클라이언트 사이드 리디렉션)**

   ```javascript
   location.href = "javascript:alert(1)";
   ```

5. **백슬래시 우회**

   ```
   https:\evil.com → 일부 서버는 \를 /로 바꿔 → https://evil.com
   ```

---

## 🚫 리디렉션 관련 필터링 시 반드시 차단/검증해야 할 요소 요약

### 차단 대상 문자 또는 문자열:

* `@`
* `\\` (백슬래시)
* `%00`, `%2F`, `%5C`, `%3A`, `%40` 등 인코딩 문자
* `javascript:`, `data:`, `file:` 등 스킴
* `//evil.com`처럼 **절대 URL** (스킴 상대 포함)
* 이중 인코딩 `%252F`, `%255C`
* 도메인 유사 문자 (`xn--`, `IDN` 등)

### 검증 로직에 포함할 것:

* 반드시 `decodeURIComponent()` 또는 `rawurldecode()` 등을 반복 적용해서 디코딩 후 필터링
* `parse_url()` 또는 `new URL()` 같은 **정식 URL 파서 사용**
* `host`가 whitelist와 일치하는지 확인
* 가능하면 상대경로(`startsWith('/')`)만 허용


## 🧨 결론

* **콘솔에서 `redirectUrl`을 변경할 수 있습니다.** 리디렉션 URL을 **JavaScript 변수**로 처리할 경우, 콘솔에서 직접 값을 수정하여 **리디렉션을 우회**할 수 있습니다.
* 리디렉션 URL을 **HTML `<script>` 내에서 처리**하는 경우에도 **DOM을 조작**하여 이를 변경할 수 있습니다.

