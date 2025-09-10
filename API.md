## 🐈 **API 이름 노출** (API 이름이 URL에 노출된 경우)

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
---


## 🐈‍⬛ PHP 페이지에서 API를 통해 값을 불러오는 구조

위 구조에서 발생할 수 있는 취약점은 **API 요청 처리**, **입력 검증 부족**, **정상적인 동작을 교란하는 조작** 등입니다. 

### 주요 공격 시나리오 및 가능한 페이로드


### **1. API를 통한 리디렉션 공격 (Open Redirect)**

API 요청을 통해 **리디렉션**을 처리하는 경우, 사용자가 입력한 값을 기반으로 리디렉션 URL을 결정하는 경우 **Open Redirect** 취약점이 발생할 수 있습니다. 이를 통해 공격자는 **피싱 사이트**로 사용자를 유도할 수 있습니다.

#### **페이로드 예시:**

```http
GET /api.php?redirect=http://evil.com
```

이 요청은 사용자가 `redirect` 파라미터로 제공한 URL로 리디렉션시킬 수 있습니다. 만약 이 API에서 리디렉션을 처리할 때 **입력 검증**을 하지 않으면, 공격자는 **피싱 사이트**로 유도할 수 있습니다.

---

### **2. XML Injection (API가 XML로 응답할 때)**

만약 API가 XML 형식으로 응답을 보내고, 이 XML을 처리하는 과정에서 **XML Injection**이 발생할 수 있습니다. 공격자는 **XML 구조를 변조**하거나 **악성 외부 엔티티**를 포함시켜 **정보 탈취**를 유도할 수 있습니다.

#### **페이로드 예시:**

```http
GET /api.php?data=<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><user>&xxe;</user>
```

이 요청은 \*\*External Entity Injection (XXE)\*\*을 통해 **/etc/passwd**와 같은 민감한 파일을 서버로 읽어올 수 있습니다.

---

### **3. JSON Injection**

만약 API가 **JSON 형식**으로 응답을 보내는 경우, **JSON Injection** 공격이 가능할 수 있습니다. API의 응답으로 JSON 데이터를 처리할 때 **사용자 입력을 필터링하지 않으면**, 공격자는 **JSON 구조를 변경**하여 악의적인 결과를 유발할 수 있습니다.

#### **페이로드 예시:**

```http
GET /api.php?name={"name":"John","role":"admin"}&action="update"
```

위와 같이 JSON 구조를 변형시켜, **API 처리 로직을 교란**할 수 있습니다. 예를 들어, API가 사용자의 \*\*`role`\*\*을 처리하는 로직이 있을 때, 이를 변조하여 **권한 상승**을 유도할 수 있습니다.

---

### **4. CSRF (Cross-Site Request Forgery)**

만약 API에서 중요한 작업을 처리할 때 **세션 기반 인증**을 사용한다면, **CSRF 공격**을 통해 사용자가 의도하지 않은 요청을 보내도록 유도할 수 있습니다.

#### **페이로드 예시:**

```html
<img src="http://target.com/api.php?delete=true" />
```

위의 이미지 태그는 사용자가 의도하지 않게 **삭제 작업**을 수행하게 할 수 있습니다. 이 공격은 사용자가 이미 **인증된 세션**을 가지고 있을 때 발생할 수 있습니다.

---
