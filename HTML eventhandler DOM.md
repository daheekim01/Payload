좋은 촉이야. `onchange`나 `oncomplete` 같은 이벤트 핸들러가 **콘솔에 노출**되는 걸 봤다면, 그건 다음 중 하나일 가능성이 커:

---

## 🔍 어떤 상황인지 정리해보자

* **비밀번호를 변경하고 저장했을 때**,
* 브라우저 콘솔에 `onchange`, `oncomplete` 이벤트 관련 **로그나 정보가 찍힘**
* 이게 자바스크립트 코드에서 발생하는 로그라면, 아마도 이 페이지는 **클라이언트에서 많은 DOM 조작을 한다는 의미**

---

## 🚨 이게 의미하는 바: **DOM-Based XSS 가능성**

`onchange`, `oncomplete`는 **HTML 속성 기반 이벤트 핸들러**인데, 만약 다음과 같은 형태로 **동적으로 삽입**된다면 매우 위험해:

```js
element.setAttribute('onchange', userInput);
```

또는

```html
<input onchange="[사용자 입력]">
```

이런 식이라면, 공격자가 사용자 입력에 악의적인 자바스크립트 코드를 넣을 수 있어:

```html
" onfocus=alert(1) autofocus="
```

결국 이게 DOM 안에 삽입되면 다음처럼 될 수 있어:

```html
<input onchange="" onfocus=alert(1) autofocus>
```

👈 **자동 실행되는 XSS**

---

## ✅ 너가 확인해볼 수 있는 것들

### 1. DOM에서 `onchange`, `oncomplete`가 어떻게 삽입되는지 확인

* 개발자 도구(F12) → Elements 탭
* 비밀번호 입력 후 저장 시, 관련된 `<input>`이나 `<form>` 요소 확인
* 혹시 사용자 입력이 HTML 속성으로 들어가나?

### 2. 사용자 입력이 이벤트 핸들러로 반영되는지 테스트

입력값에 이런 걸 넣어봐:

```
" onfocus=alert(1) autofocus="
```

또는

```
" onchange=alert(1) "
```

그리고 저장 → 콘솔 / DOM / 팝업 여부 확인

### 3. 콘솔에 찍히는 로그에 사용자 입력이 포함되는지

```js
console.log("onchange: " + userInput);
```

같은 코드가 있다면, 크로스사이트 로그 주입(XSS 로그 유출)의 가능성도 생겨.

---

## 🛡️ 만약 보안 취약점이라면?

* **이벤트 핸들러를 문자열 기반으로 삽입하고 있다면** → 매우 위험
* `innerHTML`로 삽입 → XSS 취약
* `eval()`이나 `new Function()` 사용 → 매우 위험
* `onchange`, `oncomplete`가 사용자 제어를 받는다면 → 조작 가능성 있음

* 좋아, 아주 좋은 질문이고 예리한 시도야.
보자:

```js
document.getElementById('userId').setAttribute('onchange', passwd);
```

---

## 🔍 이 코드가 실제로 하는 일

이 코드는 자바스크립트에서 다음을 시도하는 거야:

* `document.getElementById('userId')`: `id="userId"`인 HTML 요소를 찾고
* `.setAttribute('onchange', passwd)`: 그 요소에 `"onchange"`라는 **HTML 속성**을 설정하는데
  그 값으로는 `passwd`라는 **변수의 값**을 넣어줌

---

## 🤔 그런데 `passwd`가 뭐냐에 따라 결과가 완전히 달라져

### 📌 1. `passwd`가 `<input>` 요소라면:

```js
let passwd = document.getElementById('passwd');
```

그럼 이 코드는 다음처럼 해석돼:

```js
document.getElementById('userId').setAttribute('onchange', [object HTMLInputElement]);
```

즉, 최종적으로 이렇게 됨:

```html
<input id="userId" onchange="[object HTMLInputElement]">
```

> 🚫 아무 일도 안 일어나. 그냥 무효한 문자열일 뿐

---

### 📌 2. `passwd`가 어떤 값의 문자열이라면:

```js
let passwd = 'alert(1)';
```

그럼 이건 다음처럼 작동해:

```html
<input id="userId" onchange="alert(1)">
```

➡️ 이 상태에서 `userId` 필드에서 **포커스를 잃으면 `alert(1)`이 실행됨**
✅ **이건 XSS 가능성 있음**

---

## 🚨 핵심: `setAttribute('onchange', someValue)`는 실제로 **HTML 속성처럼 등록**하지만, 그 값은 문자열로 변환됨

그래서 `passwd`가:

* 단순 문자열이면 → 실행 가능 (예: `"alert(1)"`)
* DOM 객체면 → 그냥 `"object HTMLInputElement"` 같은 무쓸모 텍스트가 들어감
* 함수면 → `passwd.toString()` 결과가 들어가는데 실행되진 않음

---

## ✅ 활용 예 (XSS 컨텍스트에서)

### 💣 공격자가 이런 걸 조작할 수 있을 때:

```js
el.setAttribute('onchange', userInput);
```

그리고 `userInput` 값이:

```html
alert('XSS')
```

그럼 브라우저는:

```html
<input onchange="alert('XSS')">
```

이 되니까, onchange 발생 시 **XSS가 실행됨**

---

## 🧠 정리

| 코드                                                  | 의미                                 | 실행 가능성 |
| --------------------------------------------------- | ---------------------------------- | ------ |
| `setAttribute('onchange', passwd)` (passwd가 DOM 객체) | `"[object HTMLInputElement]"`로 설정됨 | ❌      |
| `setAttribute('onchange', 'alert(1)')`              | `"onchange"` 이벤트로 alert 설정됨        | ✅      |
| \`setAttribute('onchange                            |                                    |        |


---

## 🎯 실전 팁 (CTF에서 자주 나옴)

* DOM XSS는 종종 사용자 입력이 `setAttribute`, `innerHTML`, `document.write` 등에 쓰일 때 발생
* `onchange`, `oncomplete`, `onmouseover`, `onfocus`, `onload` 등은 자동 실행 이벤트라 XSS에 자
