## ⚠️ 위험한 JavaScript DOM 조작 API 정리 (XSS 관점)

| 위험 API/속성                                    | 설명                           | XSS 가능성           | 예시                                                             |
| -------------------------------------------- | ---------------------------- | ----------------- | -------------------------------------------------------------- |
| `innerHTML`                                  | HTML을 문자열로 삽입. JS도 삽입 가능     | 🔥 매우 높음          | `el.innerHTML = "<img src=x onerror=alert(1)>";`               |
| `outerHTML`                                  | 해당 요소 전체를 교체                 | 🔥 매우 높음          | `el.outerHTML = "<script>alert(1)</script>";`                  |
| `document.write()`                           | 문서에 문자열로 HTML/JS를 삽입         | 🔥 매우 높음          | `document.write("<script>alert(1)</script>");`                 |
| `document.writeln()`                         | 위와 같음. 개행 포함                 | 🔥 매우 높음          | `document.writeln("<img src=x onerror=alert(1)>");`            |
| `insertAdjacentHTML()`                       | 특정 위치에 HTML 삽입               | 🔥 매우 높음          | `el.insertAdjacentHTML('beforeend', '<svg onload=alert(1)>');` |
| `dangerouslySetInnerHTML` (React)            | React에서 `innerHTML`을 허용하는 방식 | 🔥 매우 높음          | `<div dangerouslySetInnerHTML={{__html: userInput}} />`        |
| `jQuery.html()`                              | jQuery의 `innerHTML`과 유사      | 🔥 매우 높음          | `$('#target').html("<script>alert(1)</script>");`              |
| `Element.outerHTML = `                       |        |          |                       |
| `Element.setAttribute()`                     | `on*` 이벤트 속성을 동적으로 삽입        | ⚠️ 조건부 위험         | `el.setAttribute("onclick", "alert(1)");`                      |
| `location.href =` (URL 조작)                   | JS로 리디렉션 시 악용 가능             | ⚠️ 중간             | `location.href = "javascript:alert(1)"` (구형 브라우저 한정)           |
| `eval()`                                     | 문자열을 코드로 실행                  | ☢️ 치명적 (원천적으로 위험) | `eval("alert(1)")`                                             |
| `new Function(string)` | 문자열로 넘기면 eval처럼 동작           | ☢️ 매우 위험          |                                  |
| `setTimeout(string)` / `setInterval(string)` | 문자열로 넘기면 eval처럼 동작           | ☢️ 매우 위험          | `setTimeout("alert(1)", 1000)`                                 |
| `on*` 이벤트 핸들러 직접 삽입 |            | ⚠️ 조건부 위험          | `el.onclick = 'alert(1)'`                                 |

---

## 📋 XSS 발생 위험이 높은 DOM API & 속성 정리표
사용자가 제어하는 문자열을 `innerHTML`, `html()`, `insertAdjacentHTML` 등 **HTML로 파싱해서 삽입하면** 스크립트/이벤트 핸들러가 실행될 수 있어 **DOM 기반 XSS**가 발생합니다.

| 🚩 메서드/속성                         | 🔍 설명                                  | 💥 XSS 발생 예시                                                                 | 🧪 필터 우회 예시                                                  |
| --------------------------------- | -------------------------------------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------ |
| `innerHTML`                       | 요소 내부에 HTML 삽입                         | `el.innerHTML = "<img src=x onerror=alert(1)>";`                             | `<img src=x oNerror=alert(1)>`                               |
| `outerHTML`                       | 요소 전체를 대체                              | `el.outerHTML = "<script>alert(1)</script>";`                                | `<scr<script>ipt>alert(1)</script>`                          |
| `document.write()`                | 문서에 직접 HTML 삽입                         | `document.write('<script>alert(1)</script>');`                               | `document.write('<img src=x oNerror=alert(1)>')`             |
| `insertAdjacentHTML()`            | 특정 위치에 HTML 삽입                         | `el.insertAdjacentHTML("beforeend", "<svg onload=alert(1)>")`                | `<sVg oNload=alert(1)>`                                      |
| `eval()`                          | 문자열을 JS 코드로 실행                         | `eval("alert(1)")`                                                           | `eval(String.fromCharCode(97,108,101,114,116,40,49,41))`     |
| `Function()`                      | `new Function("code")` 실행              | `new Function("alert(1)")()`                                                 | `new Function(String.fromCharCode(...))()`                   |
| `setTimeout()`                    | 문자열 전달 시 코드 실행                         | `setTimeout("alert(1)", 1000)`                                               | `setTimeout(String.fromCharCode(...))`                       |
| `setInterval()`                   | 동일                                     | `setInterval("alert(1)", 1000)`                                              | `setInterval("al"+"ert(1)",1000)`                            |
| `location.href`                   | 리디렉션                                   | `location.href = "javascript:alert(1)"`                                      | `location.href = "data:text/html,<script>alert(1)</script>"` |
| `on*` 이벤트 속성                      | 이벤트 핸들러 삽입 (`onclick`, `onerror`, ...) | `el.setAttribute("onmouseover", "alert(1)")`                                 | `el.setAttribute("oNclick", "alert(1)")`                     |
| `dangerouslySetInnerHTML` (React) | React에서 HTML 직접 삽입                     | `<div dangerouslySetInnerHTML={{__html: '<img src=x onerror=alert(1)>'}} />` | `'<svg oNload=alert(1)>'`                                    |
| `iframe.srcdoc`                   | iframe 안에 HTML 코드 삽입                   | `iframe.srcdoc = '<script>alert(1)</script>'`                                | `<svg onload=alert(1)>`                                      |

---

## 🔍 설명 보충

* `innerHTML`, `dangerouslySetInnerHTML` 등은 **HTML 구조를 직접 삽입**할 수 있기 때문에, 사용자 입력을 그대로 넣으면 XSS에 매우 취약
* `eval()`, `setTimeout(string)`, `Function()` 등의 **동적 코드 실행 API**는 기본적으로 사용 금지해야 함
* `Element.setAttribute()`는 이벤트 핸들러 속성(`onclick`, `onerror`, ...)에 대해 조심해야 함

---

## 🚨 패턴이 동적 데이터와 함께 쓰일 때 위험

### ✅ `innerHTML`

> 🚨 동적 HTML 삽입 시 자주 XSS 발생

```js
const userInput = `<img src=x onerror=alert(1)>`;
element.innerHTML = userInput;
```

또는

```js
element.innerHTML = `<script>alert('XSS')</script>`;  // 💥 실행됨
```

💥 결과: 이미지 로딩 실패 → `onerror` 실행 → `alert(1)` 발생

---

### ✅ `outerHTML`

> 🚨 요소 전체를 교체 → `script`, `event handler` 삽입 가능

```js
const userInput = `<script>alert(1)</script>`;
element.outerHTML = userInput;
```

💥 결과: 기존 요소가 제거되고 스크립트 실행 → `alert(1)`

---

### ✅ `document.write()`

> 🚨 HTML 전체를 문서에 삽입 → DOM 삽입 즉시 실행

```js
const userInput = `<script>alert(1)</script>`;
document.write(userInput);
```

💥 결과: 문서 파싱 도중 스크립트 실행됨

---

### ✅ `insertAdjacentHTML()`

> 🚨 HTML 조각 삽입 → 이벤트 핸들러나 `<script>` 삽입 가능

```js
const userInput = `<svg onload=alert(1)>`;
element.insertAdjacentHTML("beforeend", userInput);
```

💥 결과: SVG 요소 삽입 후 `onload` 트리거 → `alert(1)`

---

### ✅ `dangerouslySetInnerHTML` (React)

> 🚨 React에서 직접 HTML 삽입 시 사용 → 이름부터 위험

```jsx
const userInput = `<img src=x onerror=alert(1)>`;
return <div dangerouslySetInnerHTML={{ __html: userInput }} />;
```

💥 결과: `<img>` 삽입 → `onerror`로 `alert(1)`

---

### ✅ `eval()`

> 🚨 문자열이 JS 코드로 실행됨 → 공격자가 코드 주입 가능

```js
const userInput = "alert(1)";
eval(userInput);
```

💥 결과: `alert(1)` 실행

---

### ✅ `new Function()`

> 🚨 `eval`과 거의 동일, 문자열 실행

```js
const userInput = "alert(1)";
const f = new Function(userInput);
f();
```

💥 결과: `alert(1)` 실행

---

### ✅ `setTimeout()` / `setInterval()` (문자열 실행 시)

> 🚨 첫 번째 인자가 문자열이면 코드로 실행됨

```js
const userInput = "alert(1)";
setTimeout(userInput, 1000);
```

💥 결과: 1초 후 `alert(1)` 실행

---

### ✅ `on*` 이벤트 속성 (`setAttribute`, DOM 삽입 시)

> 🚨 이벤트 핸들러 속성은 바로 실행됨

```js
const userInput = "alert(1)";
element.setAttribute("onclick", userInput);
```

💥 결과: 클릭하면 `alert(1)` 실행

---

### ✅ `iframe.srcdoc`

> 🚨 HTML을 iframe 안에 직접 삽입

```js
const userInput = `<script>alert(1)</script>`;
iframe.srcdoc = userInput;
```

💥 결과: iframe 로딩 시 `alert(1)` 실행

---

### ✅ `location.href` + `javascript:` or `data:` URI

> 🚨 자바스크립트 URI나 데이터 URI를 통한 XSS

```js
location.href = "javascript:alert(1)";
```

또는:

```js
location.href = "data:text/html,<script>alert(1)</script>";
```

💥 결과: 페이지 이동 후 `alert(1)` 실행


---

## 🛸 취약 예시 

### 브라우저 JS (클라이언트) — innerHTML 예

```html
<!-- userInput은 URL 파라미터 또는 서버 응답에서 온 값 -->
<div id="profile"></div>

<script>
  const userInput = location.search.split('name=')[1] || 'Guest';
  // 위험: userInput을 인코딩하지 않고 HTML로 삽입
  document.getElementById('profile').innerHTML = `<p>안녕하세요, ${userInput}</p>`;
</script>
```

* 공격 시: `?name=<script>alert('XSS')</script>` 같은 값이 들어가면 스크립트가 실행됩니다.

### jQuery .html() 예

```js
// 서버에서 받아온 사용자 리뷰 텍스트
$('.reviews').html(response.review); // 위험
```

### 서버 템플릿(예: PHP)에서 이스케이프 생략

```php
// 위험: $_GET['q']를 그대로 출력
echo "<div>검색결과: " . $_GET['q'] . "</div>";
```

### attribute에 넣는 경우(이벤트 속성)

```html
<!-- 위험: userLink가 제어되면 javascript: 실행 가능 -->
<a id="link">클릭</a>
<script>
  const userLink = getFromServer(); // 사용자가 제어할 수 있는 값
  document.getElementById('link').setAttribute('href', userLink);
</script>
```

---

