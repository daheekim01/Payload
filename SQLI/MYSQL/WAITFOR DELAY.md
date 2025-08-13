
# `WAITFOR DELAY` 기반 SQL 인젝션 탐지 
** Time-based Blind SQLi


## 1. 배경: `WAITFOR DELAY`란?

* `WAITFOR DELAY`는 **MS SQL Server**에서 쿼리 실행을 지연시키는 명령어입니다.
* 형식:

  ```sql
  WAITFOR DELAY 'hh:mm:ss'
  ```
* 예: `WAITFOR DELAY '0:0:6'`는 6초간 대기하는 명령입니다.

---

## 2. `WAITFOR DELAY`와 SQL 인젝션

* 공격자는 보통 **타임 기반 블라인드 SQL 인젝션**(Time-based Blind SQLi)을 수행할 때 `WAITFOR DELAY` 명령어를 삽입해 DB 응답 시간을 조작합니다.
* 정상 응답 지연 시간과 비교하여 쿼리 조건의 참/거짓을 판별하는 기법입니다.
* 예를 들어:

  ```sql
  ' OR IF(condition, WAITFOR DELAY '0:0:6', 0)--
  ```

  → 조건이 참이면 6초 지연, 거짓이면 즉시 반환

---

## 3. 룰별 상세 설명

* **match:** `1;WAITFOR DELAY '0:0:6'--`
* **설명:**

  * `1;` → 쿼리 종료 후 새로운 명령 시작 시도
  * `WAITFOR DELAY '0:0:6'` → 6초 지연 명령 삽입
  * `--` → SQL 주석 처리, 뒷부분 무력화



* **match:** `WAITFOR DELAY '0:0:6'`
* **설명:**

  * 단순히 `WAITFOR DELAY '0:0:6'` 포함 여부 탐지



* **match:** `WAITFOR DELAY '0`
* **설명:**

  * 공격자가 `WAITFOR DELAY` 명령어를 입력할 때 `'` 등의 문자로 변형하거나 조각내서 보내는 경우도 탐지



## 4. 공격자가 `WAITFOR DELAY`를 쓰는 이유

* DB 응답 시간이 지연되는지 확인 → 조건 참/거짓 판단 → 데이터 유출
* 예)

  ```sql
  ' IF (SUBSTRING(@@version,1,1)='M') WAITFOR DELAY '0:0:6' --
  ```

  → MS SQL 버전 확인 시 6초 지연 발생 여부로 판단

