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
