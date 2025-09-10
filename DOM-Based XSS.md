# 🛡️ DOM 기반 XSS와 HTML 이벤트 핸들러 공격 분석

## 📌 DOM-Based XSS란?

**DOM 기반 XSS**는 **클라이언트 사이드**에서 발생하는 XSS입니다. 즉, 서버가 XSS 페이로드를 필터링하더라도, 브라우저에서 동적으로 조작된 DOM 요소가 악성 스크립트를 실행할 수 있는 상황입니다.
서버 사이드 필터링 없이 클라이언트 사이드에서 동적으로 데이터를 처리할 때 발생하는 것으로, 클라이언트 측 자바스크립트 코드에서 처리되어 페이지가 동적으로 HTML을 수정하거나 출력할 때 발생합니다. (서버사이드 렌더링 vs 클라이언트 사이드 렌더링)
사용자가 URL 파라미터나 쿠키 같은 클라이언트에서 전달된 데이터를 서버에서 검증 없이 그대로 사용하는 상황에서 발생할 수 있는 보안 취약점입니다.

### 🔥 DOM XSS의 특징

* 서버 응답에는 스크립트가 **직접 포함되지 않음**
* 브라우저에서 DOM API (예: `innerHTML`, `setAttribute`, `document.write`)를 통해 스크립트가 **동적으로 삽입됨**
* 필터 우회, 클라이언트 조작, 이벤트 핸들러 삽입 등을 통해 공격 가능

### 🧪 예시

```html
" onfocus=alert(1) autofocus="
```

사용자 입력 필드에 위와 같은 문자열을 삽입하고 DOM에서 다음처럼 삽입된다면:

```html
<input onchange="" onfocus=alert(1) autofocus>
```

➡️ **자동 실행되는 XSS**
---

## ⚠️ 이벤트 핸들러 기반 DOM XSS 공격

### 예: HTML 속성에 사용자 입력을 삽입하는 경우

```js
element.setAttribute('onchange', userInput);
```

* `userInput`이 공격자가 조작 가능한 값이라면, 다음처럼 변조될 수 있음:

```html
<input onchange="alert(1)">
```

➡️ 사용자가 해당 필드에서 포커스를 잃을 때 `alert(1)` 실행
✅ **XSS 발생**

---

## 🧩 실제로 관찰된 현상 예시

### 상황

* **비밀번호 변경 후 저장** 등의 이벤트 후
* **브라우저 콘솔**에 `onchange`, `oncomplete` 관련 로그가 출력됨
* 이는 해당 페이지가 **많은 DOM 조작을 수행**하고 있고, 이벤트 핸들러가 사용자 입력 기반으로 설정될 가능성이 있다는 신호

---

## 🧪 확인해야 할 것들

| 확인 항목                      | 설명                                                           |
| -------------------------- | ------------------------------------------------------------ |
| **1. DOM 조작 방식**           | F12 → Elements 탭에서 `input`, `form` 태그가 어떻게 렌더링되는지 확인         |
| **2. 사용자 입력 값이 속성에 들어가는지** | `setAttribute('onchange', userInput)` 같은 코드가 있는지 확인          |
| **3. 콘솔 로그 조작 가능성**        | `console.log("onchange: " + userInput);` 등 사용자 입력이 로그에 노출되는지 |

---

## 🔬 동작 방식 요약

### `element.setAttribute('onchange', userInput)`의 실행 결과

| `userInput` 값                           | 실제 삽입되는 HTML                                   | XSS 발생 가능    |
| --------------------------------------- | ---------------------------------------------- | ------------ |
| `'alert(1)'`                            | `<input onchange="alert(1)">`                  | ✅ 가능         |
| DOM 객체 (`document.getElementById(...)`) | `<input onchange="[object HTMLInputElement]">` | ❌ 없음         |
| 함수 객체 (`() => {}`)                      | `<input onchange="() => {}">`                  | ❌ 없음 (실행 안됨) |

---

## 🧷 방어 전략

| 전략                                      | 설명                                         |
| --------------------------------------- | ------------------------------------------ |
| **1. 사용자 입력을 이벤트 핸들러에 직접 넣지 않기**        | `setAttribute('onchange', userInput)` → 위험 |
| **2. `addEventListener` 사용**            | 문자열이 아닌 함수로 직접 이벤트 연결                      |
| **3. `innerHTML` 대신 `textContent` 사용**  | DOM 삽입 시 HTML 태그 해석 방지                     |
| **4. Content Security Policy (CSP) 적용** | 인라인 스크립트 실행 제한, 외부 스크립트 제한                 |
| **5. 입력값 검증 및 이스케이프**                   | 특수 문자, `<script>` 태그 필터링 등                 |


## 🧰 CSP (Content Security Policy) 간단 요약

| 항목        | 내용                                                               |
| --------- | ---------------------------------------------------------------- |
| **정의**    | 브라우저가 로드 가능한 콘텐츠 출처를 제어하는 보안 정책                                  |
| **주 목적**  | XSS, 데이터 삽입 방어                                                   |
| **예시 헤더** | `Content-Security-Policy: default-src 'self'; script-src 'self'` |
| **적용 위치** | HTTP 응답 헤더 / `<meta>` 태그                                         |
| **보완 기능** | `report-uri`, `nonce`, `strict-dynamic` 등으로 확장 가능                |

