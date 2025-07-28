
---

## ✅ 1. F12 콘솔에서 `innerHTML`을 사용해 XSS 시도하는 방법

### 💬 목표: 사용자 입력을 `innerHTML`로 삽입하면 XSS가 발생하는 이유 이해하기

브라우저의 개발자 도구(F12) 콘솔에서 직접 실험할 수 있습니다.

---

### 🧪 예제 1: `innerHTML`을 통한 XSS 실행

1. 콘솔을 열고(F12), 아래 코드 입력:

```js
document.body.innerHTML = '<h1>Hello</h1><script>alert("XSS")</script>';
```

2. 결과:

* 페이지에 "Hello"가 출력됨
* 동시에 `alert("XSS")` 팝업 발생

💥 왜냐하면 `<script>` 태그가 `innerHTML`에 들어가면서 브라우저가 **실제로 HTML로 해석**하고 스크립트를 실행하기 때문이에요.

---

### 🧪 예제 2: 사용자 입력값을 innerHTML에 넣는 경우

```js
const userInput = '<img src=x onerror=alert("Hacked")>';
document.getElementById("output").innerHTML = userInput;
```

* `<div id="output"></div>`가 있는 경우
* 이미지 태그가 깨지면서 `onerror` 이벤트가 트리거됨 → alert 발생

✅ 이게 \*\*DOM XSS (DOM-based Cross-Site Scripting)\*\*의 대표적인 예입니다.

---

### 🛡️ 방어 방법

```js
document.getElementById("output").textContent = userInput; // 안전
```

---

