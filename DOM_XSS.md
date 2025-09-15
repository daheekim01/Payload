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
| `Element.setAttribute()`                     | `on*` 이벤트 속성을 동적으로 삽입        | ⚠️ 조건부 위험         | `el.setAttribute("onclick", "alert(1)");`                      |
| `location.href =` (URL 조작)                   | JS로 리디렉션 시 악용 가능             | ⚠️ 중간             | `location.href = "javascript:alert(1)"` (구형 브라우저 한정)           |
| `eval()`                                     | 문자열을 코드로 실행                  | ☢️ 치명적 (원천적으로 위험) | `eval("alert(1)")`                                             |
| `new Function(string)` | 문자열로 넘기면 eval처럼 동작           | ☢️ 매우 위험          |                                  |
| `setTimeout(string)` / `setInterval(string)` | 문자열로 넘기면 eval처럼 동작           | ☢️ 매우 위험          | `setTimeout("alert(1)", 1000)`                                 |
| `on*` 이벤트 핸들러 직접 삽입 | 문자열로 넘기면 eval처럼 동작           | ⚠️ 조건부 위험          | `el.onclick = 'alert(1)'`                                 |

---

## 🔍 설명 보충

* `innerHTML`, `dangerouslySetInnerHTML` 등은 **HTML 구조를 직접 삽입**할 수 있기 때문에, 사용자 입력을 그대로 넣으면 XSS에 매우 취약
* `eval()`, `setTimeout(string)`, `Function()` 등의 **동적 코드 실행 API**는 기본적으로 사용 금지해야 함
* `Element.setAttribute()`는 이벤트 핸들러 속성(`onclick`, `onerror`, ...)에 대해 조심해야 함

---

## 🚨 패턴이 동적 데이터와 함께 쓰일 때 위험

예시:

```js
// 사용자 입력이 들어온 경우 (XSS 발생)
const userInput = `<img src=x onerror=alert(1)>`;
element.innerHTML = userInput;  // 💥 XSS 취약
```

또는

```js
element.innerHTML = `<script>alert('XSS')</script>`;  // 💥 실행됨
```


