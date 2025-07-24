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

---

## 🎯 실전 팁 (CTF에서 자주 나옴)

* DOM XSS는 종종 사용자 입력이 `setAttribute`, `innerHTML`, `document.write` 등에 쓰일 때 발생
* `onchange`, `oncomplete`, `onmouseover`, `onfocus`, `onload` 등은 자동 실행 이벤트라 XSS에 자
