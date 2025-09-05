## 📌 **Command Injection (명령어 주입)**

**Command Injection (명령어 주입)** 공격은 사용자가 입력한 데이터를 서버에서 실행되는 시스템 명령어나 쉘 명령어에 **직접 삽입**하는 방식으로 발생하는 취약점입니다. 이 공격은 사용자가 원하지 않는 명령을 실행하게 하여 **서버 시스템을 제어하거나 손상시킬 수 있습니다**.

---

### 공격 방식

```bash
someinput; rm -rf /
```

* **명령어 주입 공격**은 사용자가 웹 애플리케이션에서 입력하는 데이터가 서버의 **OS 명령어**로 처리될 때 발생합니다.
* 예를 들어, 사용자 입력값이 **`ping`** 명령어에 \*\*`ip 주소`\*\*를 추가하는 코드에서, 악의적인 사용자는 **명령어 구분자**인 \*\*`;`\*\*를 이용해 악성 명령을 추가할 수 있습니다.

```python
# 취약한 코드
user_input = "127.0.0.1"  # 예: 사용자가 입력한 IP 주소
os.system("ping " + user_input)  # ping 명령어에 사용자 입력을 직접 전달
```

위 코드에서 `user_input`에 사용자가 입력한 값이 그대로 **`ping`** 명령어에 삽입되어 실행됩니다. 그런데 악의적인 사용자가 \*\*`;`\*\*를 사용하여 추가적인 명령어를 실행할 수 있습니다:

```bash
user_input = "127.0.0.1; rm -rf /"  # 악의적 입력
```

이 입력은 \*\*`ping 127.0.0.1`\*\*을 실행한 뒤 **`rm -rf /`** 명령어로 **서버의 모든 파일을 삭제**하는 명령을 실행할 수 있게 됩니다.

### 실제 예시: 웹 애플리케이션에서의 명령어 주입

#### 1. **취약한 코드 예시**

```python
import os

def get_server_status(user_input):
    # 사용자 입력을 OS 명령어로 처리
    os.system("ping " + user_input)
```

이 코드는 사용자가 입력한 IP 주소를 `ping` 명령어에 추가하여 서버에서 **ping**을 실행합니다. 만약 사용자가 \*\*`127.0.0.1; rm -rf /`\*\*와 같은 악의적인 입력을 전달하면, 서버에서 **파일 삭제 명령**이 실행될 수 있습니다.

#### 2. **악성 입력 예시**

```bash
127.0.0.1; rm -rf /
```

이 입력은 \*\*`ping 127.0.0.1`\*\*을 실행한 뒤, **`rm -rf /`** 명령어를 추가로 실행하여 서버의 모든 파일을 삭제하려는 시도입니다. \*\*`rm -rf /`\*\*는 **리눅스/유닉스 시스템에서 모든 파일을 삭제하는 명령**입니다.

---

## 🛡️ **방어법**

### 1. **입력값을 절대 직접 연결하지 않기**

* **입력값을 직접 시스템 명령어에 연결**하는 방식은 매우 위험합니다. 사용자 입력을 명령어에 포함시키기 전에 반드시 **적절한 검증과 필터링**을 해야 합니다.

```python
# 안전한 코드 예시
import subprocess

def get_server_status(user_input):
    if user_input == "127.0.0.1":
        subprocess.run(["ping", user_input], shell=False)
    else:
        print("허용되지 않는 IP 주소입니다.")
```

### 2. **`subprocess.run` 사용 시 `shell=False`**

* **`subprocess` 모듈**을 사용하여 외부 명령어를 실행할 때, **`shell=False`** 옵션을 사용하여 **쉘 명령어 구문**(예: `;`, `&&`, `||` 등)을 **차단**할 수 있습니다.

```python
# subprocess.run을 사용할 때 shell=False로 설정
subprocess.run(["ping", user_input], shell=False)
```

`subprocess.run`을 사용하면 **명령어 인자**가 **리스트** 형태로 전달되므로, 쉘 명령어를 조작하는 특수 문자를 **자동으로 차단**합니다. `shell=True`일 경우 **쉘 인젝션**을 허용할 수 있기 때문에 반드시 `shell=False`를 설정해야 합니다.

### 3. **명령어 파라미터에 대한 allowlist 사용**

* 사용자가 입력할 수 있는 **명령어**를 제한하는 방식입니다. 예를 들어, **`ping`** 명령어만을 허용하고, 다른 명령어는 아예 차단하는 방법입니다.

```python
# 안전한 명령어 allowlist
allowed_commands = ["ping"]

def get_server_status(user_input):
    if user_input in allowed_commands:
        subprocess.run([user_input, "127.0.0.1"], shell=False)
    else:
        print("허용되지 않는 명령어입니다.")
```

이 방법은 **허용된 명령어만 실행**하도록 제한할 수 있습니다.

### 4. **입력값 검증 및 필터링**

* **입력값 검증**을 통해 **특수 문자**(`;`, `&`, `|`, `\`, 등)나 예상치 못한 문자가 입력되지 않도록 처리합니다.
* 예를 들어, **IP 주소**만 허용해야 하는 입력 필드에 대해서 **정규 표현식**을 사용하여 **잘못된 입력**을 필터링할 수 있습니다.

```python
import re

def validate_ip(user_input):
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", user_input):  # 간단한 IP 주소 검증
        return True
    else:
        return False

def get_server_status(user_input):
    if validate_ip(user_input):
        subprocess.run(["ping", user_input], shell=False)
    else:
        print("유효하지 않은 IP 주소입니다.")
```

---

