# **SQL Injection**

공격자가 웹 애플리케이션의 보안 취약점을 이용해 악의적인 SQL 쿼리를 삽입하여 데이터베이스를 조작하는 공격 방법

주로 사용자 입력값이 적절히 검증되지 않을 때 발생한다.

이를 통해 공격자는 데이터 조회, 수정, 삭제, 관리자 권한 탈취 등의 행동을 할 수 있다.

<br>
<br>

## **SQL Injection 공격의 종류**

### 1. Classic SQL Injection

가장 일반적인 공격방식으로,
직접 SQL 문을 조작하여 데이터베이스에서 정보를 탈취하는 방식

```php
<?php
$username = $_GET['username'];
$query = "SELECT * FROM users WHERE username = '$username'";
$result = mysqli_query($conn, $query);
?>
```

```sql
SELECT * FROM users WHERE username = '' OR '1'='1' --
```

공격자가 `' OR '1'='1' --` 과 같이 입력하면
-- 뒤로부터는 주석처리 되고 `'1'='1'`은 항상 참이므로, 모든 사용자 정보가 조회된다.

이러한 방식으로 ID가 `admin`, PW가 `' or 1=1--` 로 준다면 관리자 계정의 로그인이 성공하게 된다.

<br>

### 2. Error-Based SQL Injection

데이터베이스 에러 메세지를 이용하여 데이터베이스에 대한 정보를 가져오는 방식

개발시 코드의 오류 확인을 위해 에러 메세지가 출력되게 설정한다.

잘못된 SQL 문을 삽입해서 나오는 에러 메세지를 통해 공격자는 데이터베이스의 구조와 정보를 파악할 수 있다.

**DB 종류에 따라 다양한 문법과 함수를 활용**하는 특징이 있다.

에러의 종류에는 크게 **문법 에러**와 **로직 에러**가 있는데, 여기서는 로직 에러를 사용한다.

- **문법 에러**는 주로 작은따옴표(')나 큰따옴표(")가 올바르게 닫히지 않은 경우 발생한다.
  이 경우 SQL 문 자체가 유효하지 않아 실행되지 않는다.

- **로직 에러**는 사용자가 의도한 작업을 프로그램에서 수행하지 못하는 오류이다.
  SQL 문에는 오류가 없어 실행될 수 있지만 결과가 개발자의 의도와 다르게 출력된다.
  Error Based SQLi가 이용하는 에러가 바로 이것이다.

<br>

### 3. Union-Based SQL Injection

`UNION` 키워드를 사용하여 2개의 쿼리를 요청하여 공격자가 원하는 데이터를 가져오는 방식

원래의 요청에 `UNION`으로 한 개의 쿼리를 추가하여 정보를 얻어내는 것이 목적이다.

보통 게시글 페이지 같이 데이터 베이스에 저장된 데이터가 보이는 경우에 사용한다.

```sql
SELECT username, password FROM users WHERE id = '1' UNION SELECT database(), user();
```

이러한 방식으로 데이터베이스 이름과 DB 사용자 계정을 확인할 수 있다.

<br>

### 4. Blind SQL Injection

에러 메세지가 출력되지 않도록 막혀 있는 경우, 참/거짓 응답을 통해 데이터를 추출하는 방식

조작된 SQL 문을 삽입해도 어떠한 정보가 뜨지 않는 경우 쓰는 **최후의 보루**이다.

SQL 문의 결과가 참/거짓에 따라 서버의 응답이 달라지는 경우에 사용된다.

공격자는 참/거짓 여부로 공격의 성공여부를 판단한다.

대표적으로는 로그인 성공 혹은 실패를 알려주는 로그인 페이지가 있다.

이 공격은 데이터베이스의 이름, 테이블 이름, 컬럼 이름, 저장된 데이터를 순서대로 한글자씩 SQL 문을 변경해가며 추출해야하므로 시간이 매우 오래 걸리는 공격 방법이다.

그러므로 **자동화**가 필수이다.

```sql
SELECT * FROM users WHERE id = '1' AND 1=1;
SELECT * FROM users WHERE id = '1' AND 1=2;  -- 거짓이므로 결과 없음
```

이러한 방식으로 데이터가 존재하는지 유추할 수 있다.

<br>

### 5. Time-Based Blind SQL Injection

SQL의 `SLEEP()` 함수를 이용하여 실행 시간을 조작하고, 참/거짓을 판단하는 방식

```sql
SELECT * FROM users WHERE id = '1' AND IF(1=1, SLEEP(5), 0);
```

참이면 5초 동안 대기하므로, 응답 속도를 보고 공격자는 조건이 참인지 판단할 수 있다.

<br>
<br>

## **SQL Injection 방어 기법**

SQL Injection을 방어하는 방법은 여러가지가 있지만

가장 중요한 방법은 **사용자 입력값을 철저히 검증**하고, **SQL 쿼리를 안전하게 실행**하는 것이다.

<br>

### 1. SQL 쿼리에서 Prepared Statements 준비된 쿼리 사용

PHP에서 Prepared Statements를 사용하면 사용자 입력값이 자동으로 이스케이프 처리되어 안전해진다.

SQLi 에 쓰이는 특수문자나 SQL 명령어들이 있는지 검사하는 방식도 존재한다.
하지만 이러한 입력값을 검사하여 SQLi 를 예방하는 Input Validation 방식은
정교하게 입력값을 검사하지 않는다면 **검증을 우회하는 방법**이 존재하므로 사용에 주의해야 한다.

구문 분석(parse) 과정을 최초 1회만 수행하고,
생성된 SQL 문을 컴파일하여 메모리에 저장한 뒤, 필요할 때마다 실행하는 방식이다.

사용자 입력값을 변수로 선언하여 미리 컴파일된 SQL 구문에 대입하기 때문에
SQL 문법에 영향을 미치는 특수문자나 구문이 입력되어도 문법적인 의미로 작용하지 못하게 만든다.

이미 대부분의 기업에서는 처리의 효율성과 보안성 때문에 Prepared Statement를 사용중이나
아직까지 보안 허점을 종종 발견할 수 있기에 중요하다.

- SQL 구문을 잘못 작성 한 경우: 사용자 입력값을 받는 부분을 '?'로 두고 컴파일 해야하나, 이를 사용하지 않은 경우가 가끔 존재한다.
- Prepared Statement를 사용하지 못하는 경우: `ORDER BY` 같은 동적 SQL 구문에서는 사용할 수 없다. 따라서 `ORDER BY` 구문에서 발생하는 경우가 많다.

```php
// MySQLi
<?php
$stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
$stmt->bind_param("s", $username);
$stmt->execute();
$result = $stmt->get_result();
?>
```

이 방식은 SQL 코드와 데이터가 분리되어 실행되므로, SQL Injection 공격이 불가능하다.

```php
// PDO
<?php
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username");
$stmt->bindParam(':username', $username, PDO::PARAM_STR);
$stmt->execute();
?>
```

<br>

### 2. 사용자 입력값 필터링 및 검증

`filter_input()`, `filter_var()` 등의 함수를 사용하여 입력값을 검증한다.

숫자 입력값이면 `intval()`, `ctype_digit()` 등을 이용해 숫자로 변환 후 처리한다.

```php
<?php
$username = filter_input(INPUT_GET, 'username', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
?>
```

<br>

### 3. 데이터베이스 계정 권한 최소화

DB 계정에 최소 권한만 부여하여 공격자가 DB를 완전히 조작하지 못하도록 제한한다.

예를 들어, 웹 애플리케이션이 단순 조회 기능만 필요하다면 SELECT 권한만 부여한다.

```sql
GRANT SELECT ON mydb.users TO 'webuser'@'localhost';
```

<br>

### 4. 웹 방화벽(WAF) 적용

ModSecurity 같은 WAF(Web Application Firewall)를 사용하면 SQL Injection을 자동으로 감지하고 차단할 수 있다.

<br>
<br>

## **SQL Injection 공격 시나리오**

### 1. 로그인 페이지에서 SQL Injection 공격

로그인 폼에서 `username`과 `password`를 입력하는 곳에 `' OR '1'='1'` 입력

```sql
SELECT * FROM users WHERE username = '' OR '1'='1' AND password = '';
```

로그인 성공 → 관리자 권한 탈취

<br>

### 2. 데이터베이스 정보 유출

`UNION` 공격을 사용하여 DB 테이블 이름 확인

```sql
SELECT column_name FROM information_schema.columns WHERE table_name = 'users';
```

<br>

### 3. 계정 비밀번호 변경

SQL Injection을 이용해 관리자의 비밀번호 변경

```sql
UPDATE users SET password = 'newpassword' WHERE username = 'admin';
```
