
* **탐지된 패턴**:
  `3 SELECT Statement Keywords found within: 22' and (select 1 from(select count(*),concat(...`
* **의미**:

  * 이 규칙은 **한 쿼리 내에서 SELECT가 여러 번 중첩되어 사용된 경우**를 감지합니다.
  * 특히 `CONCAT`와 함께 사용되어, **오류 메시지를 통해 내부 정보를 노출**시키려는 시도를 탐지합니다.

#### 🔹 Blind SQL Injection에서 이 패턴이 의미하는 것:

* 예시 쿼리 (의심되는 악성 쿼리):

  ```sql
  ' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT('c4c...', FLOOR(RAND()*2)) x FROM information_schema.tables GROUP BY x) a) -- 
  ```
* 이 쿼리는 주로 다음 목적을 위해 사용됩니다:

  1. **중첩된 SELECT**를 이용해 DB 동작을 복잡하게 만들고
  2. `CONCAT`으로 특정 문자열을 조합하여 응답에 노출시키고
  3. 결과가 에러를 유발하게 하여, **오류 메시지를 통해 내부 정보를 유출**하려는 것입니다.
  4. 이는 **Blind SQLi의 에러 기반 방식 (Error-Based Blind SQL Injection)** 입니다.

---

### 🔸 **Rule 959073**

#### 🔹 설명:

* **탐지된 패턴**:
  `SELECT 1 FROM(SELECT COUNT(*),CONCAT('c4ca4238a0b923820dcc509a6f75849b',...`
* **의미**:

  * `CONCAT`, `COUNT`, `RAND` 등 **MySQL 내장 함수**들을 활용한 **정보 유출 시도**를 감지합니다.
  * `c4ca4238a0b923820dcc509a6f75849b` 같은 해시(이 경우는 md5('1'))는 **서버 응답에 특정한 값이 포함되는지를 확인하려는 수단**입니다.

#### 🔹 Blind SQL Injection에서 이 패턴이 의미하는 것:

* 이 쿼리는 종종 **결과가 참일 경우 특정 문자열이 응답에 포함**되게 만들고, 이를 통해 참/거짓을 판단합니다.
* 예시 공격 쿼리:

  ```sql
  ' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT('c4ca4238a0b923820dcc509a6f75849b', FLOOR(RAND()*2)) AS x FROM information_schema.tables GROUP BY x) y) --
  ```
* 작동 방식:

  * `FLOOR(RAND()*2)`는 `0` 또는 `1`을 랜덤하게 만들고, 중복된 `x` 값을 `GROUP BY` 하려고 하여 **"Duplicate entry" 오류**를 발생시킴.
  * 오류 메시지 안에 `CONCAT`된 문자열(`c4ca4238...`)이 포함되면, 공격자는 쿼리의 조건이 **실행되었는지 여부를 판단**할 수 있습니다.
  * 이는 **Blind SQL Injection의 오류 기반(Error-Based)** 기법이며, 일반적으로 응답을 통해 참/거짓을 추론하는 데 사용됩니다.

---

### 🔸 두 규칙에서 공통적으로 탐지하는 핵심 포인트:

| 항목                   | 설명                                   |
| -------------------- | ------------------------------------ |
| `SELECT` 중첩          | 여러 개의 SELECT 문을 중첩시켜 DB 내부 구조에 접근    |
| `CONCAT()`           | 문자열을 응답에 노출시켜 참/거짓 판별 또는 정보 추출       |
| `COUNT(*)`           | 테이블 존재 여부를 판단하는 데 사용                 |
| `RAND()`             | 랜덤성으로 GROUP BY 오류를 유도 (에러 메시지 기반 공격) |
| `information_schema` | DB 구조(테이블, 컬럼 등)를 알기 위한 정보 수집 시도     |

---

### 🔒 보안 관점에서 대응 방안:

1. **Prepared Statements (Prepared SQL)** 사용으로 SQL Injection 원천 차단
2. \*\*WAF (Web Application Firewall)\*\*에서 이러한 룰 활성화 및 모니터링
3. **오류 메시지 노출 방지** (DB 오류는 사용자에게 직접 보여지지 않도록 설정)
4. **입력값 필터링 및 검증 강화**

---

필요하시면, 이런 쿼리가 **어떻게 작성되고 탐지되는지** 더 구체적인 예제나 분석도 도와드릴 수 있어요.
