
* 네가 URL 뒤에 `<script></script>`를 붙이니까,
* **페이지의 원래 HTML `<script>` 태그 일부가 화면에 노출됨**.

이건 단순히 네가 넣은 `<script>`가 출력되는 게 아니라, **페이지 내의 기존 스크립트 일부가 "깨져서" 화면에 나타난다는 말이지?**

---

## 🔍 **XSS 가능성 매우 큼**

이건 **HTML 파싱이 깨졌다**는 뜻이야. 네가 삽입한 태그 때문에 브라우저가 DOM을 비정상적으로 파싱하고, 기존 `<script>` 블록이 종료되거나 망가져서 일부 코드가 **화면에 렌더링**된 거야.

즉, 이런 구조일 가능성이 높아:

```html
<script>
    var msg = "Hello";  // 기존 스크립트
</script>
```

근데 네가 다음과 같이 URL을 만듦:

```
http://example.com/page?name=</script><script>alert(1)</script>
```

그럼 서버 코드에서 이렇게 들어가면:

```html
<script>
    var name = "<사용자 입력값>";  // 이 줄에 네 XSS 코드가 들어가면 파싱이 깨짐
</script>
```

결과적으로:

* 첫 번째 `</script>`로 기존 `<script>`가 조기 종료
* 그 뒤의 `<script>alert(1)</script>`가 **브라우저에서 실행**
* 그 이후 남은 스크립트는 깨진 상태로 렌더링됨 → 그래서 HTML 일부가 "화면에 보이는" 현상이 발생

---

## ✅ 확실한 XSS 공격 가능성 테스트

아래처럼 시도해봐:

```url
http://example.com/page?name=</script><script>alert(1)</script>
```

또는 우회용 페이로드:

```url
http://example.com/page?name=</script><img src=x onerror=alert(1)>
```

이런 페이로드를 넣었을 때 **팝업이 뜨면 XSS 성공**이야.

---

## 🎯 이게 중요한 이유

이런 상황은 **Reflected XSS** 또는 **DOM-Based XSS** 중 하나일 가능성이 크고, 특히 서버가 사용자 입력을 그대로 `<script>` 태그 안에 넣고 있다면 매우 취약해.

---

## 📌 다음 단계 추천

1. \*\*페이지 소스(view-source:)\*\*에서 삽입 위치 확인 (스크립트 블록 안인지, HTML 태그 안인지)

2. 가능하면 입력값을 다음으로 넣어봐:

   ```
   </script><script>alert(1)</script>
   ```

3. 개발자 도구(F12) → 콘솔 확인: 에러 메시지나 unexpected token 발생 여부

4. 만약 `innerHTML`이나 `document.write`로 출력 중이면 **DOM-Based XSS** 가능성도 있음

---

HTML 파서(브라우저의 DOM 해석기)의 동작 방식

---

## 🔥 요점 먼저

* ✅ `</script><script>alert(1)</script>`는 **기존 `<script>` 태그를 종료**하고 새로운 `<script>`를 열기 때문에 **JS가 실행됨**
* ❌ `<script>alert(1)</script>`는 브라우저가 **중첩된 `<script>`로 보지 않고**, 그냥 **문자열로 처리**하거나 **필터링**하기 때문에 실행되지 않음

---

## 🔍 HTML 안에 `<script>`를 넣으면 생기는 일

### 예를 들어 이런 코드가 있다고 하자:

```html
<script>
  var name = "[사용자 입력]";
</script>
```

### Case 1: 입력값에 `<script>alert(1)</script>`를 넣은 경우

```html
<script>
  var name = "<script>alert(1)</script>";
</script>
```

#### 결과:

* 브라우저는 이걸 **문자열 안의 HTML**로 봐.
* 즉, 그냥 `var name = "<script>alert(1)</script>";` 이렇게 실행될 뿐이야.
* 자바스크립트 구문상 문제가 없기 때문에 **alert는 실행되지 않음** (그냥 변수에 저장됐을 뿐)

---

### Case 2: 입력값에 `</script><script>alert(1)</script>`를 넣은 경우

```html
<script>
  var name = "</script><script>alert(1)</script>";
</script>
```

#### 결과:

1. 첫 번째 `</script>`가 **기존 `<script>`를 닫아버림**
2. 그 다음 `<script>alert(1)</script>`는 **완전히 새로운 스크립트 블록**이 됨
3. 브라우저는 이걸 진짜 자바스크립트로 해석하고 `alert(1)` 실행

📌 이게 바로 XSS 페이로드에서 `</script>`를 앞에 붙이는 이유야!

---

## ✅ 정리: 왜 앞에 `</script>`를 붙이면 되나?

| 입력값                                  | 브라우저 동작                                     | 실행 여부 |
| ------------------------------------ | ------------------------------------------- | ----- |
| `<script>alert(1)</script>`          | `<script>` 안에 또 `<script>` → 무시되거나 문자열로 처리됨 | ❌     |
| `</script><script>alert(1)</script>` | 기존 스크립트 닫힘 → 새 스크립트 열림 → 코드 실행됨             | ✅     |

---

## 🔐 참고

이건 실제 공격에서도 자주 쓰이는 기법이야. 특히 HTML 안에 삽입되는 경우엔 다음 같은 형태로 변형됨:

```html
<script>var user = "[[INPUT_HERE]]";</script>
```

여기에서 `[[INPUT_HERE]]` 자리에 `</script><script>/*payload*/</script>`를 넣으면 바로 XSS가 되는 거지.

---
