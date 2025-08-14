
**Blind SQL Injection** 중 **XML 기반 오류 생성 기법**

### ❗ 공격 예시:

* `extractvalue()`는 MySQL에서 XML 데이터를 파싱하는 함수입니다.
* 이 함수에 잘못된 인자를 주면 오류 메시지에 내부 정보를 노출할 수 있습니다.
* 예시:

  ```sql
  1' and extractvalue(1, concat(0x7e,(SELECT user()),0x7e)) -- 
  ```


### 1. `extractvalue(1, concat(0x7e, (select user()), 0x7e))`

* `extractvalue()`는 MySQL에서 XML XPath를 평가할 때 사용하는 함수입니다.
* 첫 번째 인자: `1` (의도적으로 잘못된 입력)
* 두 번째 인자: `concat(0x7e, (select user()), 0x7e)` — 여기서 `0x7e`는 `~` 문자, `user()`는 현재 DB 접속 사용자 정보를 반환함.

### 2. 오류 기반 정보 노출 (Error-Based Blind SQLi)

* `extractvalue()`에 올바르지 않은 XPath 인자를 전달하면 오류 메시지가 발생합니다.
* 오류 메시지에 두 번째 인자의 값(즉, `~root~` 등)이 포함되기 때문에, 이를 통해 DB 내부 정보를 유추할 수 있습니다.

  ```sql
  SELECT extractvalue(1, concat(0x3a, version()));
  -- 결과: XPATH syntax error: ':5.7.29-...'
  ```
  
### 3. 페이로드 동작 방식 요약:

1. 사용자가 `keyword` 매개변수에 위 페이로드를 삽입합니다.
2. 서버가 이를 SQL 쿼리 내에 포함하게 되면, `extractvalue()` 호출로 인해 오류 발생.
3. 오류 메시지에 `concat`함수로 만든 값이 포함되어, DB 사용자 정보 등을 노출.
4. 공격자는 이를 통해 내부 정보를 수집할 수 있습니다.

이 방식은 **Blind SQL Injection 중 오류 기반(Error-Based)** 기법의 대표적인 예입니다.

---

## 관련 참고 자료

* `extractvalue()` 함수가 에러 메시지에 XPath 식을 포함해 반환함을 설명한 자료 ([DaDa's blog][1])
* `extractvalue()`를 사용한 공격 예시 (user(), version(), information\_schema 데이터 추출 등) ([f002.backblazeb2.com][2], [CSDN][3])
* 다양한 Error-Based SQLi 페이로드 정리 (extractvalue, updatexml, group by rand 등) ([blog.ssrf.kr][4])

---

## 요약: 공격 패턴 정리

| 요소                                    | 설명                              |
| ------------------------------------- | ------------------------------- |
| `extractvalue(1, ...)`                | XML 파싱 함수에 잘못된 XPath 전달 → 오류 유발 |
| `concat(0x7e, (select user()), 0x7e)` | `'~root~'`와 같은 문자열을 오류 메시지로 노출  |
| `user()`                              | 현재 DB 접속 사용자의 계정 정보를 반환         |
| `#`                                   | SQL 주석 처리 기호 — 뒤의 내용 무시         |

---

## 방어 및 대응 방법

* **Prepared Statements (Prepared SQL)** 사용: 파라미터 바인딩으로 SQLi 원천 차단.
* **입력값 필터링 및 검증 강화**: 특수문자, 함수 호출 패턴 검출.
* **WAF 규칙 적용**: `extractvalue`, `updatexml`, `user()` 등이 포함된 요청 차단.
* **오류 메시지 감추기**: DB 오류를 사용자에게 직접 노출하지 않도록 설정.
