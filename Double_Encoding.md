# **Double Encoding**

이중 인코딩은 한 번 인코딩된 문자를 다시 한 번 인코딩하여 보안 시스템을 우회하는 기법이다.

주로 웹 애플리케이션에서 필터링을 우회하거나 보안 검사를 회피하는데 사용된다.

예를 들어, URL 인코딩을 사용하면 `%` 문자는 `%25`로 변환된다.
그런데 다시 한 번 인코딩하면 `%25`가 `%2525`로 변환된다.

<br>
<br>

## **Double Encoding의 공격 방식**

### 1. SQL Injection 우회

일부 웹 어플리케이션에서는 `"`나 `'`와 같은 위험한 문자를 필터링한다.

하지만 이 문자들을 URL 인코딩하고 다시 한 번 인코딩하면 필터를 우회할 수 있다.

```sql
SELECT * FROM users WHERE username = 'admin' AND password = 'password';
```

위와 같은 쿼리가 실행되는 로그인 폼이 있다고 가정한다.
일반적인 SQL Injection 공격은 다음과 같다.

```sql
' OR '1'='1
```

그러나 `'` 문자가 필터링되는 경우, URL 인코딩을 적용하여 `%27 OR '1'='1`로 만들 수 있다.
그런데 `%27`(=`'`)도 필터링된다면, 다시 한 번 URL 인코딩하여 `%2527`을 사용하면 필터를 우회할 수 있다.

<br>

### 2. XSS (Cross-Site Scripting) 우회

웹 애플리케이션이 `<script>` 태그를 필터링할 때, 이중 인코딩을 이용하여 우회할 수도 있다.

사용자가 입력한 `<script>alert('XSS');</script>`가 필터링된다면,

1. `<script>`를 URL 인코딩 → `%3Cscript%3Ealert('XSS');%3C/script%3E`
2. 다시 한 번 URL 인코딩 → `%253Cscript%253Ealert('XSS');%253C/script%253E`

이런 식으로 변형된 입력값이 서버에서 두 번 디코딩되면 원래의 `<script>` 태그가 복원되면서 공격이 성공할 수 있다.

<br>

### 3. Directory Traversal 우회

파일 경로를 조작하여 시스템 내부 파일에 접근하는 공격 기법인 디렉터리 이동 공격도 이중 인코딩을 이용하여 우회할 수 있다.

`../`가 필터링된 경우, URL을 인코딩하면 `..%2F`가 된다.
그런데 `../2F`도 필터링된다면, 다시 한 번 인코딩하여 `..%252F`를 사용하면 필터를 우회할 수 있다.

예를 들어, `/var/www/html/index.php`에서 `page` 파라미터로 파일을 로드하는 경우

```bash
http://example.com/index.php?page=../../etc/passwd
```

위의 요청이 필터링 된 경우

```perl
http://example.com/index.php?page=..%2F..%2Fetc%2Fpasswd
```

위의 요청도 필터링된다면

```perl
http://example.com/index.php?page=..%252F..%252Fetc%252Fpasswd
```

서버가 두 번 디코딩하면 최종적으로 `../../etc/passwd`가 되어 공격이 가능해진다.

<br>
<br>

## **Double Encoding 방어 방법**

### 1. Input Validation, 입력값 검증

- Whitelist 적용: 허용할 문자만 남기고 모두 차단 (예: `^[a-zA-Z0-9]+$` 영문과 숫자만 허용)
- Blacklist 차단: `../`, `<script>`, `'` 등의 위험한 문자열 탐지 및 차단

<br>

### 2. Decoding 횟수 제한

- 입력값을 여러 번 디코딩하지 않도록 제한
- 사용자 입력값이 여러 번 디코딩될 가능성이 있는지 점검

<br>

### 3. 웹 방화벽 (WAF) 사용

웹 방화벽은 일반적인 이중 인코딩 기법을 탐지하고 차단이 가능하다.

<br>

### 4. SQL Injection 및 XSS 방어

**SQL Injection 방어**:

- Prepared Statement `prepareStatement()` 를 사용하여 SQL Injection 차단
- 입력값을 직접 쿼리에 삽입하지 않고, 바인딩 변수를 사용

<br>

**XSS 방어**:

- HTML 특수문자를 이스케이프 `htmlspecialchars()` 를 모든 사용자 입력값을 출력할 때 사용
