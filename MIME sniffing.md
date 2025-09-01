## 🔍 1. MIME 타입과 MIME 스니핑(MIME Sniffing)이란?

### 📌 MIME 타입(MIME Type)이란?

MIME (Multipurpose Internet Mail Extensions) 타입은 **파일의 콘텐츠 종류를 식별하는 문자열**입니다.
웹에서는 서버가 클라이언트(브라우저 등)에게 콘텐츠를 보낼 때, 해당 콘텐츠가 어떤 종류인지 알려주기 위해 `Content-Type`이라는 HTTP 헤더를 사용합니다.

예:

| 파일 종류     | Content-Type             |
| --------- | ------------------------ |
| HTML 문서   | `text/html`              |
| CSS 파일    | `text/css`               |
| JS 파일     | `application/javascript` |
| 이미지(JPEG) | `image/jpeg`             |

---

### ⚠ MIME 스니핑(MIME Sniffing)이란?

브라우저가 서버에서 받은 `Content-Type`을 **무시하고**, 파일 내용을 직접 분석하여 \*\*자체적으로 콘텐츠의 유형을 "추측(sniff)"\*\*하는 행위입니다.

#### 🧠 왜 이렇게 할까요?

* 어떤 서버는 `Content-Type`을 잘못 설정하거나 아예 누락하는 경우가 있습니다.
* 이럴 때 브라우저가 내용을 기반으로 파일 타입을 **자동 판단해서 보여주는 사용자 편의 기능**입니다.

#### 🚨 그런데 이것이 보안에 위험한 이유는?

공격자가 다음과 같은 상황을 유도할 수 있습니다:

1. 서버가 사용자의 파일 업로드를 받아 `.txt`로 저장합니다.
2. 공격자가 내부에 `HTML`이나 `JavaScript`를 삽입한 `.txt` 파일을 업로드합니다.
3. 서버는 `Content-Type: text/plain`으로 응답하지만,
4. 브라우저는 파일 내용을 분석하여 **실제로는 `text/html` 또는 `application/javascript`로 오해**하고, 해당 스크립트를 실행합니다.
5. 결과적으로 **Cross-Site Scripting (XSS)** 같은 보안 취약점이 발생합니다.

---

## 🛡️ 2. `X-Content-Type-Options: nosniff`의 역할

이 헤더는 **브라우저에게 강제로 서버의 MIME 타입만 따르도록** 명령합니다.

```http
X-Content-Type-Options: nosniff
```

### ✅ 적용 시 결과

| 항목           | 결과                                                                                    |
| ------------ | ------------------------------------------------------------------------------------- |
| `nosniff` 사용 | 브라우저는 **절대 MIME 스니핑을 하지 않음**. 서버가 `text/plain`이라면 아무리 내부에 `<script>`가 있어도 그냥 텍스트로 처리함 |
| `nosniff` 없음 | 브라우저는 내용을 보고 타입을 **자동 추측**, 보안에 취약해질 수 있음                                             |

---

## 🖥️ 3. 주요 브라우저의 동작

| 브라우저       | `nosniff` 적용 시 | 미적용 시             |
| ---------- | -------------- | ----------------- |
| Chrome     | 스니핑 차단         | MIME 스니핑 시도       |
| Firefox    | 스니핑 차단         | 일부 상황에서 스니핑       |
| Edge       | 스니핑 차단         | MIME 스니핑 가능       |
| IE (옛날 버전) | 스니핑 차단         | 적극적으로 스니핑 (보안 취약) |

---

## 🏗️ 4. 보안 관점에서의 요약

| 구분         | 설명                                              |
| ---------- | ----------------------------------------------- |
| 🔐 목적      | 클라이언트가 MIME 타입을 **수정하거나 추측하지 못하게 막음**           |
| 🧨 방지하는 공격 | XSS, 콘텐츠 인젝션, 클릭재킹 등                            |
| 💡 추천 대상   | **모든 웹 애플리케이션**, 특히 **파일 업로드 기능이 있는 경우 필수**     |
| 🧾 설정 방법   | 서버에서 `X-Content-Type-Options: nosniff` 응답 헤더 추가 |

---

## 💡 실제 예시 시나리오

```plaintext
1. 공격자가 "malicious.js"라는 악성 스크립트를 .txt 확장자로 업로드합니다.
2. 서버는 응답 시 "Content-Type: text/plain"으로 처리.
3. 브라우저는 내용 분석 후 이 파일을 JavaScript로 해석하고 실행해버립니다.
4. 결과적으로 사용자 브라우저에서 악성 코드 실행 (XSS).
5. nosniff 헤더가 있었다면 실행되지 않았을 것.
```

---

## ✅ 종합 정리

| 항목    | 설명                                              |
| ----- | ----------------------------------------------- |
| 문제    | 브라우저가 MIME 타입을 추측해서 잘못 해석할 수 있음 (MIME Sniffing) |
| 결과    | XSS 등 보안 취약점 발생 위험                              |
| 해결책   | `X-Content-Type-Options: nosniff` 헤더 추가         |
| 적용 위치 | 웹 서버 또는 웹 프레임워크의 응답 처리 설정                       |

---

### 🌐 서버 설정 예시 다시 정리

#### Apache

```apache
Header set X-Content-Type-Options "nosniff"
```

#### Nginx

```nginx
add_header X-Content-Type-Options "nosniff";
```

#### Express (Node.js)

```js
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  next();
});
```


도움이 더 필요하시면 말씀해 주세요.
