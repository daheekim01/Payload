## 🎀 스크립트 태그 안에 사용할 수 있는 자주 쓰이는 자바스크립트 함수와 이벤트 핸들러

1. **`confirm()`**:

   * 사용자에게 확인 창을 띄우는 함수입니다.
   * 사용자가 "확인" 또는 "취소"를 클릭하면 그에 따라 `true` 또는 `false` 값을 반환합니다.

   ```javascript
   <script>confirm('Are you sure?');</script>
   ```

2. **`prompt()`**:

   * 사용자에게 입력을 받는 팝업 창을 띄우는 함수입니다.
   * 텍스트 입력을 받으며, 취소를 눌렀을 경우 `null`을 반환합니다.

   ```javascript
   <script>prompt('Enter your name:');</script>
   ```

3. **`console.log()`**:

   * 콘솔에 메시지를 출력하는 함수로, 디버깅 시 사용됩니다.
   * 악의적인 목적에는 주로 서버와의 통신을 확인하거나 정보를 로그로 출력하는 데 사용될 수 있습니다.

   ```javascript
   <script>console.log('malicious data');</script>
   ```

4. **`eval()`**:

   * 문자열로 받은 JavaScript 코드를 실행하는 함수입니다.
   * **주의!**: 이 함수는 **매우 위험**하며, 코드 인젝션 취약점을 유발할 수 있습니다.

   ```javascript
   <script>eval('alert("Evaluated!")');</script>
   ```

5. **`setTimeout()` / `setInterval()`**:

   * 주어진 시간 후에 특정 함수를 실행하는 함수입니다.
   * 예를 들어, 스크립트를 지연 실행하거나 반복적으로 실행할 수 있습니다.

   ```javascript
   <script>setTimeout(function() { alert("This is delayed!"); }, 1000);</script>
   ```

6. **`document.location` 또는 `window.location`**:

   * 페이지를 다른 URL로 리디렉션하는 함수입니다. XSS 공격에서 종종 사용됩니다.

   ```javascript
   <script>window.location="https://evil.com";</script>
   ```

7. **`window.open()`**:

   * 새로운 브라우저 창을 여는 함수입니다.

   ```javascript
   <script>window.open('https://evil.com');</script>
   ```

8. **`window.close()`**:

   * 현재 브라우저 창을 닫는 함수입니다.

   ```javascript
   <script>window.close();</script>
   ```

9. **`document.write()`**:

   * 문서의 내용을 동적으로 수정할 때 사용됩니다. XSS 공격에서 매우 위험할 수 있습니다.

   ```javascript
   <script>document.write('<h1>Malicious content</h1>');</script>
   ```

10. **`parent.location`**:

    * 현재 페이지의 상위 프레임(부모 프레임)을 변경하는 함수입니다.

    ```javascript
    <script>parent.location = 'https://evil.com';</script>
    ```

11. **`open` 메서드와 `postMessage`**:

    * 다른 창 또는 iframe과 통신할 때 `postMessage()`가 사용될 수 있습니다.

    ```javascript
    <script>window.postMessage("malicious message", "*");</script>
    ```


---

## ✨ 괄호 없이 사용 가능한 이벤트 핸들러와 내장 함수들

### 1️⃣ **이벤트 핸들러 (Event Handlers)**

자바스크립트 이벤트 핸들러는 **함수 호출 시 괄호 없이 지정할 수 있습니다**.
이벤트가 발생할 때, 해당 핸들러가 실행되도록 설정되기 때문입니다.

#### 예시:

```html
<button onclick="alert('Hello World!')">Click Me</button>
```

* 여기서 `alert()` 함수는 괄호 없이 `onclick` 속성에 바로 작성되었어요.
* 이벤트가 발생하면 브라우저가 자동으로 해당 함수를 호출합니다.

#### 다양한 이벤트 속성 (이벤트 핸들러)

* `onclick`: 클릭 이벤트
* `onmouseover`: 마우스가 요소 위로 올라갔을 때
* `onmouseout`: 마우스가 요소를 벗어났을 때
* `onkeydown`: 키보드 키를 눌렀을 때
* `onchange`: 폼 필드 값이 변경될 때
* `onfocus`: 포커스가 해당 요소에 갔을 때
* `onblur`: 포커스가 해당 요소를 떠났을 때

#### 예시 2: `onmouseover` (괄호 없이 사용)

```html
<button onmouseover="this.style.backgroundColor='yellow'">Hover over me</button>
```

* 마우스가 버튼 위로 올라갈 때 배경색이 `yellow`로 바뀝니다.
  이때 `this.style.backgroundColor='yellow'`는 괄호 없이 이벤트 속성에 지정된 상태로 처리됩니다.

---

### 2️⃣ **특수한 자바스크립트 함수**

일부 내장 함수들은 **브라우저가 자동으로 특정 동작을 실행**할 때, 괄호 없이 사용할 수 있습니다. 대표적으로 **DOM 관련 메서드**에서 발생할 수 있습니다.

#### 예시:

```html
<button onClick="console.log('Button clicked')">Click me</button>
```

* `onClick` 속성에서 `console.log()`는 괄호 없이 사용할 수 있지만, 실제로는 실행될 때 브라우저가 자동으로 괄호를 처리해줍니다.

---

### 3️⃣ **`this`와 관련된 함수**

`this` 키워드가 사용된 함수에서는 괄호 없이도 참조할 수 있는 경우가 많습니다. `this`가 **자동으로 특정 객체를 참조**하도록 설정되는 경우가 그렇죠.

#### 예시:

```html
<button onClick="this.innerHTML = 'Clicked!'">Click Me</button>
```

* 이 예시에서 `this`는 버튼 자체를 참조하고, 클릭할 때마다 버튼의 `innerHTML`을 `Clicked!`로 변경합니다.
* `this.innerHTML = 'Clicked!'`는 괄호 없이 `this`를 참조하여 DOM 요소를 변경합니다.

---

### 4️⃣ **자주 쓰이는 기본 자바스크립트 함수 (자동 호출 가능)**

* **`alert()`**: 사용자에게 경고 메시지 박스를 띄움
* **`confirm()`**: 확인/취소 버튼이 있는 팝업을 띄워 사용자의 응답을 받음
* **`prompt()`**: 사용자에게 텍스트 입력을 받을 수 있는 팝업을 띄움

### 예시:

```html
<button onclick="alert('Hello World!')">Show Alert</button>
<button onclick="confirm('Are you sure?')">Show Confirm</button>
<button onclick="prompt('Enter your name:')">Show Prompt</button>
```

* 위의 예시에서 `alert`, `confirm`, `prompt` 함수들은 **자바스크립트에서 직접 호출하지 않고, 이벤트가 발생했을 때 자동으로 실행**됩니다.

---

### 5️⃣ **브라우저의 내장 객체나 메서드**

브라우저의 내장 객체 중에서도 **일부 메서드**는 괄호 없이도 자동으로 실행될 수 있는 경우가 많습니다. 예를 들어 `setTimeout` 같은 것들입니다.

#### 예시:

```html
<button onClick="setTimeout('alert(\'Hello\')', 1000)">Click Me</button>
```

* `setTimeout()`은 시간 지연 후 특정 함수를 실행하도록 하지만, 이때도 함수명만 사용하면 **괄호 없이** 동작합니다. 그러나 권장되는 방법은 **함수를 직접 전달**하는 것입니다.

---



