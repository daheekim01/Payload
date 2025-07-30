### 1. **X-Powered-By** 헤더 노출

`X-Powered-By` 헤더에 서버의 기술 스택이 노출되면, 공격자는 해당 기술에 특화된 취약점을 알고 이를 **악의적인 요청**에 포함시킬 수 있습니다. 예를 들어, `X-Powered-By: PHP/7.4.3`가 노출되면 PHP에서 발생할 수 있는 특정 취약점을 악용할 수 있습니다.

#### **공격 시나리오**: PHP 객체 주입 취약점

**1. 요청 보내기**:

* 공격자는 **PHP 7.4.3**에 존재하는 객체 주입 취약점(CVE-2020-7066)을 이용할 수 있습니다. 이 취약점은 서버가 특정 객체를 `unserialize()`할 때 발생할 수 있습니다.
* 공격자는 `unserialize()`를 호출하는 서버의 **입력값**에 악의적인 객체를 전달하는 페이로드를 보낼 수 있습니다.

**2. 페이로드**:

```php
O:8:"TestClass":1:{s:4:"test";s:9:"malicious";}
```

**3. 요청 예시**:

```http
POST /example_endpoint HTTP/1.1
Host: victim.com
X-Powered-By: PHP/7.4.3
Content-Type: application/x-www-form-urlencoded

data=O:8:"TestClass":1:{s:4:"test";s:9:"malicious";}
```

### 2. **X-XSS-Protection: 0** 노출

`X-XSS-Protection` 헤더가 **0**으로 설정되어 있으면, 브라우저의 XSS 보호 기능이 비활성화됩니다. 이는 XSS 공격이 성공할 가능성이 높다는 의미입니다.

#### **공격 시나리오**: DOM 기반 XSS 공격

**1. 요청 보내기**:

* 공격자는 사용자가 입력할 수 있는 필드(예: 댓글, 검색창 등)에 **악성 스크립트**를 삽입할 수 있습니다.
* 예를 들어, 사용자가 검색창에 악성 스크립트를 삽입하면 이를 실행하여 **세션 하이재킹**이나 **정보 탈취** 등의 공격을 할 수 있습니다.

**2. 페이로드**:

```html
<script>alert('XSS Attack!');</script>
```

**3. 요청 예시**:

```http
GET /search?q=<script>alert('XSS Attack!');</script> HTTP/1.1
Host: victim.com
X-XSS-Protection: 0
```

브라우저에서 **X-XSS-Protection: 0**이 설정되어 있으면, XSS 필터링이 작동하지 않아 이 **악성 스크립트**가 실행됩니다.

---

### 3. **X-Response-Time** 노출

`X-Response-Time` 헤더가 노출되면, 공격자는 **응답 시간 차이**를 분석하여 **서버의 동작**을 유추할 수 있습니다. 예를 들어, 로그인 요청 시 **정상 계정**과 **비정상 계정**에 대해 다른 응답 시간을 보낼 수 있습니다. 이 정보를 통해 **무차별 대입 공격**을 시도할 수 있습니다.

#### **공격 시나리오**: 로그인 우회 (타이밍 공격)

**1. 요청 보내기**:

* 공격자는 가짜 계정과 실제 계정에 대한 로그인 요청을 반복하여 응답 시간을 비교합니다.
* 정상 계정에 대해서는 빠른 응답을, 비정상 계정에 대해서는 **느린 응답**을 보낸다면 공격자는 이를 통해 유효한 계정을 식별할 수 있습니다.

**2. 요청 예시** (로그인 시도):

```http
POST /login HTTP/1.1
Host: victim.com
X-Response-Time: 150ms
Content-Type: application/x-www-form-urlencoded

username=attacker&password=wrongpassword
```

**3. 반복적인 로그인 시도**:

* 공격자는 위의 로그인 요청을 **다양한 사용자 이름과 비밀번호** 조합으로 반복하여 보내면서 `X-Response-Time` 값의 차이를 분석합니다. 정상 계정에 대한 로그인 요청은 **빠른 응답**, 잘못된 계정에 대한 로그인 요청은 **느린 응답**을 받게 될 수 있습니다.
* 이 정보를 통해 **유효한 계정을 확인**하고 **비밀번호를 추측**할 수 있습니다.

---

### 4. **API 이름 노출** (API 이름이 URL에 노출된 경우)

서버가 사용하는 **API 이름**이나 **경로**가 노출되면, 공격자는 이를 이용해 **API에 대한 정보를 파악**하고 **공격**을 시도할 수 있습니다. 예를 들어, `/GetUserAuth`와 같은 API 경로가 노출되면 해당 API가 사용되는 **인증 관련 취약점**을 찾기 위해 공격을 시작할 수 있습니다.

#### **공격 시나리오**: API 엔드포인트 노출

**1. 요청 보내기**:

* 공격자는 노출된 API 경로 (`/GetUserAuth`)를 통해 **API 엔드포인트**에 대한 정보를 획득하고, **미비한 인증 시스템**을 발견할 수 있습니다.

**2. 페이로드 예시**:

```http
POST /GetUserAuth HTTP/1.1
Host: victim.com
Content-Type: application/json

{
  "username": "attacker",
  "password": "maliciouspassword"
}
```

**3. 공격 방법**:

* API 이름(`GetUserAuth`)이 노출된 상황에서, 공격자는 이를 통해 **잘못된 인증 처리**나 **API 취약점**을 시도할 수 있습니다. 예를 들어, **무차별 대입 공격**(Brute Force)을 통해 인증을 우회할 수 있습니다.
* 만약 API가 제대로 보호되지 않거나 입력값 검증이 없다면, **부적절한 인증 처리를 통한 권한 상승** 공격이 발생할 수 있습니다.

