
## ✅ DOM 기반 XSS란?

**DOM XSS**는 **클라이언트 측 JavaScript 코드가 DOM을 조작할 때 발생하는 XSS**입니다.

즉,

* 서버에서 응답을 통해 스크립트가 오는 게 아니라,
* **브라우저에서 실행 중인 JavaScript가, 사용자 입력을 그대로 DOM에 반영하면서 발생**합니다.

---

## ✅ F12 콘솔에서 `innerHTML`을 사용해 XSS 시도가 가능할지 미리 확인하기


### 🧪 예제 1: `innerHTML`을 통한 XSS 실행

1. 콘솔을 열고(F12), 아래 코드 입력:

```js
document.body.innerHTML = '<h1>Hello</h1><script>alert("XSS")</script>';
```

2. 공격이 가능하다면:

* 페이지에 "Hello"가 출력됨
* 동시에 `alert("XSS")` 팝업 발생

💥 왜냐하면 `<script>` 태그가 `innerHTML`에 들어가면서 브라우저가 **실제로 HTML로 해석**하고 스크립트를 실행하기 때문이에요.

<img width="1203" height="333" alt="image" src="https://github.com/user-attachments/assets/db9b320e-7ec5-437e-9be7-555b74c0664a" />

HTML 엔티티로 필터링 되는지 미리 확인해볼 수 있어요. 

---

### 🧪 예제 2: 사용자 입력값을 innerHTML에 넣는 경우

```js
const userInput = '<img src=x onerror=alert("Hacked")>';
document.getElementById("output").innerHTML = userInput;
```

* `<div id="output"></div>`가 있는 경우
* `.innerHTML`로 그대로 DOM에 삽입
* 브라우저는 `<img src=x onerror=alert("Hacked")>` 태그를 실제 이미지처럼 해석하려고 시도
* `src="x"`는 유효하지 않기 때문에 이미지 태그가 깨지면서 로딩 실패 → `onerror` 이벤트 발생 → `alert("Hacked")` 실행

---
## ✅ "F12 콘솔"에 넣는 건 확인이지 공격이 아니다!

F12 콘솔(개발자 도구의 콘솔 창)에 코드를 붙여넣는 건 **공격이 아니라 디버깅/테스트용**입니다.

공격자는 직접 콘솔을 쓰는 게 아니라,
👉 **피해자가 브라우저에서 악성 스크립트를 "실행하게" 유도**합니다.

---

## ✅ 그럼 XSS 공격은 어디서 실행되나?

### 공격자가 **사용자 입력을 받는 모든 경로에 악성 코드를 삽입**하는 방식입니다.

---

### 📍 예시 1: 검색창, 댓글창 같은 입력 필드

다음과 같이 웹 개발자가 실수로 작성한 코드가 웹사이트 내부페이지에 들어있는 상황입니다.

```html
<form>
  <input id="search" name="q">
  <div id="result"></div>
</form>

<script>
  const q = new URLSearchParams(location.search).get('q');
  document.getElementById("result").innerHTML = q;
</script>
```

URL로 접속:

```
https://example.com/?q=<img src=x onerror=alert('XSS')>
```

👆 그러면 `innerHTML`로 삽입되면서 `alert('XSS')`가 실행됨.

---

### 📍 예시 2: 게시판/댓글에 악성 코드 삽입

```html
<div id="comment"></div>

<script>
  const userComment = getCommentFromServer(); // 가짜 함수
  document.getElementById("comment").innerHTML = userComment;
</script>
```

💀 사용자가 이런 댓글을 입력:

```html
<img src=x onerror=alert("XSS")>
```

→ 다음에 누군가 페이지 방문 시 alert 실행

---

### 📍 예시 3: URL fragment/hash (클라이언트 전용)

```javascript
const hash = location.hash.substring(1); // #<script>alert(1)</script>
document.getElementById("output").innerHTML = hash;
```

URL:

```
https://example.com/#<img src=x onerror=alert('XSS')>
```

👆 이렇게 "주소창"을 조작하는 것도 **DOM XSS** 공격의 한 예입니다. **서버는 모름**, 오직 브라우저 안에서 발생.

---

## ❌ 위험한 코드 사용 예시

### 1. `innerHTML`에 사용자 입력을 넣는 경우

```javascript
const name = location.hash.substring(1); // #<img src=x onerror=alert(1)>
document.getElementById("greeting").innerHTML = "Hello " + name;
```

```html
<div id="greeting"></div>
```

사용자가 URL에 `#<img src=x onerror=alert(1)>` 붙여서 접속하면 alert 실행됨.

---

### 2. `document.write()`에 사용자 입력을 사용하는 경우

```javascript
const userInput = prompt("Type something:");
document.write(userInput);
```

입력: `<script>alert("Hacked!")</script>` → 스크립트가 실행됨.

---

### 3. `eval()`을 사용하는 경우

```javascript
const userCode = location.search.split('=')[1]; // ?code=alert("Hacked")
eval(userCode);
```

사용자가 URL에 `?code=alert("Hacked")` 넣으면 바로 실행됨.

```javascript
const userInput = new URLSearchParams(location.search).get('code');
// https://example.com/?code=alert("XSS")
eval(userInput); 
```

사용자가 URL에 `?code=alert("XSS")` 넣으면, 그대로 실행됩니다.

---

### 4. `setTimeout()`에 문자열 형태로 코드 전달

```javascript
const userInput = 'alert("Hacked")';
setTimeout(userInput, 1000); // Bad!
```

→ `setTimeout()`에 문자열 전달 시 내부적으로 `eval()`처럼 동작


```javascript
setTimeout("alert('XSS')", 1000); 
```

→ 문자열 eval로 처리됨

✔️ 안전한 버전:

```javascript
setTimeout(() => alert('safe'), 1000);  // 함수 전달 → 안전
```

---

## ❌ eval XSS 위험 요약

| 문제 코드                         | 결과                         |
| ----------------------------- | -------------------------- |
| `eval(userInput)`             | 입력값이 코드로 실행됨               |
| `setTimeout(userInput, 1000)` | userInput이 문자열이면 eval처럼 동작 |
| `Function(userInput)()`       | 이것도 eval처럼 위험함             |
| ----------------------------- | -------------------------- |
---

---

## ✅ 안전하게 처리되어 있는 경우?

### 1. innerText 또는 textContent 사용

```javascript
document.getElementById("output").textContent = userInput;
```

→ HTML이 아닌 "텍스트"로 출력됨 → 스크립트 실행 안 됨

---

### 2. DOMPurify 같은 라이브러리 사용 (sanitize)

```javascript
const cleanHTML = DOMPurify.sanitize(userInput);
document.getElementById("output").innerHTML = cleanHTML;
```

→ XSS 공격 요소 제거됨

---

### 3. 템플릿 엔진 사용

서버 렌더링 시에는 EJS, Pug, Mustache 등 템플릿 엔진이 자동으로 escape 처리해줘서 XSS 예방 가능

---


