# **CSRF (Cross-Site Request Forgery)**

: 사이트 간 요청 위조는 사용자가 신뢰하는 웹사이트에서 의도하지 않은 요청을 보내도록 속이는 공격

공격자는 사용자의 인증 정보를 악용해 사용자가 모르는 사이에 중요한 요청을 서버에 전달한다.

예를 들어, 사용자가 은행 사이트에 로그인한 상태에서 공격자의 악성 웹사이트를 방문하면
공격자가 사용자의 계좌에서 돈을 이체하는 요청을 은행 서버로 보낼 수 있다.

<br>
<br>

## **CSRF 공격 시나리오**

### 1. 공격 준비

공격자는 사용자가 자주 방문하는 웹사이트 SNS, 은행 쇼핑몰 등을 목표로 한다.

피해자가 해당 사이트에 로그인한 상태에서 특정 요청을 실행하도록 유도하는 페이지나 스크립트를 만든다.

### 2. 공격 방식

온라인 송금 조작을 예로 들면

① 사용자가 로그인한 상태 유지

- 피해자가 은행 사이트에 로그인한 상태에서 세션이 유지되고 있는 상태

② 악성 링크 클릭 유도

- 공격자는 CSRF 공격을 수행하는 악성 페이지를 만들고, 피해자가 해당 페이지를 방문하도록 유도한다.

```html
<img
  src="https://bank.com/transfer?to=attacker&amount=10000"
  style="display: none;" />
```

- 위 코드를 포함한 페이지를 피해자가 방문하면, 은행 서버에 자동으로 요청이 전송된다.
- 사용자는 요청을 보냈다는 사실조차 모른다.

③ 은행 서버는 요청을 정상적인 사용자 요청으로 처리

- 은행 사이트는 쿠키 기반 세션을 사용하고 있기 때문에 피해자의 로그인된 세션 정보를 자동으로 포함한 상태로 요청을 처리한다.
- 공격자는 피해자의 계좌에서 돈을 이체하는 데 성공한다.

<br>
<br>

## **CSRF 공격의 종류**

### 1. GET 요청 기반 CSRF

: 공격자가 URL에 요청을 포함하여 피해자가 클릭하면 실행되는 방식

```html
<img src="https://bank.com/transfer?to=attacker&amount=10000" />
```

<br>

### 2. POST 요청 기반 CSRF

: 공격자가 폼을 만들어 사용자가 페이지 방문 시 자동으로 제출되도록 하는 방식

```html
<form action="https://bank.com/transfer" method="POST">
  <input type="hidden" name="to" value="attacker" />
  <input type="hidden" name="amount" value="10000" />
  <input type="submit" />
</form>
<script>
  document.forms[0].submit();
</script>
```

<br>

### 3. AJAX 기반 CSRF

: JavaScript를 이용해 피해자의 브라우저에서 AJAX 요청을 보내는 방식

```javascript
var xhr = new XMLHttpRequest();
xhr.open("POST", "https://bank.com/transfer", true);
xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
xhr.send("to=attacker&amount=10000");
```

최근 브라우저 보안 정책(CORS)으로 인해 이 방식의 공격 성공률은 낮다.

<br>
<br>

## **CSRF 방어 방법**

### 1. CSRF 토큰 사용 (가장 효과적)

: 서버가 각 요청에 대해 **랜덤한 CSRF 토큰**을 생성하여 클라이언트가 요청 시 함께 전송하도록 요구, 서버는 해당 토큰을 검증하여 요청이 유효한지 확인한다.

사용자가 보내는 요청 폼에 랜덤한 토큰을 삽입한다.
서버는 이 토큰을 세션이나 DB에 저장해두고, 사용자가 폼을 제출할 때마다 서버는 저장된 토큰과 비교해서 일치하는 경우에 요청을 처리한다.

```php
// CSRF 토큰 생성
session_start();
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// 폼에 CSRF 토큰 포함
?>
<form action="transfer.php" method="POST">
    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
    <input type="text" name="to">
    <input type="number" name="amount">
    <input type="submit">
</form>
```

<br>

```php
// CSRF 토큰 검증
session_start();
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("CSRF 공격 감지됨!");
    }
    // 정상적인 요청 처리
}
```

<br>

### 2. SameSite 속성 사용 (쿠키 보호)

: 쿠키에 `SameSite` 속성을 설정하여 CSRF 공격을 방어

SameSite 옵션:

- `Strict`: 외부 사이트에서 쿠키 전송 차단 (강력한 보안)
- `Lax`: GET 요청만 허용 (일반적인 보안)
- `None`: 모든 요청 허용 (보안 취약)

```php
session_set_cookie_params([
    'samesite' => 'Strict', // 또는 'Lax'
    'secure' => true,
    'httponly' => true
]);
session_start();
```

<br>

### 3. Referer / Origin 헤더 검사

: 서버에서 요청의 `Referer` 또는 `Origin` 헤더를 확인하여 신뢰할 수 없는 출처에서 온 요청 차단

일반적인 상황에서 비밀번호 변경 요청으느 마이페이지에서 일어나지만 CSRF 공격이 발생한 경우 게시판에서 일어날 수 있다.
이렇게 뜬금없는 곳에서 발생한 요청을 막기위해 Referer 검증을 실시한다.

Referer는 조작이 불가능하기 때문에 서버에서 제대로 확인한다면 우회 방법이 없다.
하지만 간혹 Referer를 지우고 보내면 처리되는 경우가 존재한다.

이런 경우에는 `<meta name="referer" content="no-referer">` 를 이용하여 우회한다.

```php
if (!isset($_SERVER['HTTP_REFERER']) || !str_starts_with($_SERVER['HTTP_REFERER'], 'https://trusted-site.com')) {
    die("잘못된 요청!");
}
```

<br>

### 4. CORS 정책 강화

: CORS(Cross-Origin Resource Sharing) 정책을 설정하여 외부 도메인에서 API 요청을 차단

```php
header("Access-Control-Allow-Origin: https://trusted-site.com");
header("Access-Control-Allow-Methods: POST, GET");
header("Access-Control-Allow-Headers: X-Requested-With");
```

<br>

### 5. 사용자 입력에 의존하지 않는 중요한 요청 방식 적용

: 사용자가 계좌 이체, 이메일 변경 등의 중요한 작업을 수행할 때 **추가 인증(비밀번호 입력, OTP 등)을 요구**하는 방식

공격자가 파라미터를 임의로 세팅하지 못하도록 요청 폼에 인증정보를 추가하는 방식이다.

예를 들면, 비밀번호 입력 후 중요한 요청을 수행하는 방식을 말한다.

<br>
<br>

## **CSRF vs XSS 차이점**

## CSRF vs XSS 차이점

| 구분          | CSRF (Cross-Site Request Forgery)                | XSS (Cross-Site Scripting)                   |
| ------------- | ------------------------------------------------ | -------------------------------------------- |
| **공격 방식** | 사용자의 인증 정보를 이용하여 서버에 요청을 위조 | 악성 스크립트를 주입하여 클라이언트에서 실행 |
| **피해자**    | 웹 애플리케이션 서버                             | 웹사이트 방문 사용자                         |
| **공격 대상** | 인증된 사용자의 세션을 이용한 요청 조작          | 웹사이트에 악성 코드 삽입                    |
| **방어 방법** | CSRF 토큰, SameSite 쿠키, Referer 검사           | CSP(Content Security Policy), XSS 필터링     |

XSS와 CSRF의 차이점은 공격 위치(방식)에서 존재한다.

- XSS: 사용자의 웹 브라우저
- CSRF: 웹 서버
