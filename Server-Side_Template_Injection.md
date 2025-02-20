# **Server-Side Template Injection**

: 서버 측 템플릿 엔진이 사용자 입력을 안전하게 처리하지 못해 발생하는 보안 취약점

사용자가 입력한 값이 그대로 템플릿 엔진에 의해 실행되면서 임의의 코드 실행(RCE, Remote Code Execution)까지 가능해질 수 있는 위험한 취약점이다.

템플릿 엔진은 동적 웹 페이지를 생성하기 위해 템플릿 파일과 데이터를 결합하여 최종 HTML 페이지를 만드는 도구이다.

<br>
<br>

## **SSTI 발생 원인**

웹 애플리케이션에서 템플릿 엔진을 사용할 때, 사용자 입력을 적절히 필터링하지 않으면 SSTI가 발생한다.

예를 들어 아래와 같이 서버 측 코드에서 사용자 입력을 직접 템플릿 엔진에 전달하는 경우를 생각해 볼 수 있다.

```python
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/ssti")
def ssti():
    user_input = request.args.get("input")  # 사용자의 입력값을 받음
    return render_template_string("결과: " + user_input)  # 직접 템플릿 렌더링

app.run()
```

`render_template_string`은 Flask의 Jinja2 템플릿 엔진을 사용하여 문자열을 템플릿으로 렌더링한다.

그러나 `user_input`을 직접 전달했기 때문에 공격자가 템플릿 구문을 사용하여 악의적인 코드를 실행할 수 있게 된다.

<br>
<br>

## **SSTI 공격 방식**

다음은 Twig를 사용할 때 발생 가능한 SSTI를 보여준다.

```php
<?php
require_once 'vendor/autoload.php';

use Twig\Environment;
use Twig\Loader\ArrayLoader;

$loader = new ArrayLoader([
    'index' => '결과: {{ user_input }}'
]);
$twig = new Environment($loader);

$user_input = $_GET['input'] ?? ''; // 사용자의 입력값을 받음
echo $twig->render('index', ['user_input' => $user_input]); // 직접 렌더링
?>
```

공격자가 다음과 같이 입력하면 서버에서 실행된다.

```arduino
http://example.com/ssti.php?input={{ 7 * 7 }}
```

서버에서 실행된 결과는 다음과 같다.

```makefile
결과: 49
```

이는 템플릿 엔진이 사용자 입력을 해석하여 실행했음을 의미한다.

공격자는 더 나아가 PHP 객체나 시스템 명령어를 실행할 수도 있다.

```bash
http://example.com/ssti.php?input={{ constant('PHP_VERSION') }}
```

```perl
http://example.com/ssti.php?input={{ system('id') }}
```

이러한 방식으로 공격자는 더 복잡한 페이로드를 입력하는 방식으로 **임의 코드 실행(RCE)**까지 가능해진다.

<br>

### 위험한 SSTI 공격 예시 (Python Flask + Jinja2)

공격자가 `__class__`, `__mro__` 같은 Python 내부 객체에 접근하면 서버에서 직접 명령어를 실행할 수도 있다.

```
// markdown
http://example.com/ssti?input={{ ''.__class__.__mro__[1].__subclasses__() }}
```

일부 템플릿 엔진에서는 다음과 같이 시스템 명령어를 실행할 수도 있다.

```lua
http://example.com/ssti?input={{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}
```

이 경우 공격자는 서버에서 `id` 명령어를 실행하여 현재 실행 중인 프로세스의 사용자 정보를 알아낼 수 있다.

SSTI는 다양한 서버 측 템플릿 엔진에서 발생할 수 있다.

Jinja2(Python), Twig & Smarty(PHP), FreeMarker(Java) 같은 템플릿 엔진을 사용할 때 SSTI가 발생할 가능성이 높다.

<br>
<br>

## **SSTI 방어 방법**

### 1. 사용자 입력을 직접 템플릿 엔진에 전달하지 않음

**위험한 코드**:

```python
return render_template_string("결과: " + user_input)
```

```php
echo $twig->render('index', ['user_input' => $_GET['input']]);
```

<br>

**안전한 코드**:

```python
return render_template_string("결과: {{ safe_value }}", safe_value=user_input)
```

```php
$safe_input = htmlspecialchars($_GET['input'], ENT_QUOTES, 'UTF-8'); // XSS 방지
echo $twig->render('index', ['user_input' => $safe_input]);
```

사용자 입력을 `htmlspecialchars()`로 필터링하여 HTML 엔티티로 변환하면 템플릿 엔진이 해석하지 않는다.

템플릿 변수에 직접 바인딩하여 사용자가 템플릿 문법을 실행하지 못하도록 막을 필요가 있다.

<br>

### 2. 템플릿 엔진의 sandboxing, autoescape 기능 사용

일부 템플릿 엔진(Jinja2 등)은 Sandbox(보안 격리)를 제공하여 위험한 코드 실행을 제한할 수 있다.

```python
from jinja2.sandbox import SandboxedEnvironment

env = SandboxedEnvironment()
template = env.from_string("결과: {{ user_input }}")
output = template.render(user_input="7 * 7")
```

Twig의 경우, `autoescape` 설정을 활성화하면 위험한 코드 실행을 막을 수 있다.

```php
$twig = new Environment($loader, ['autoescape' => 'html']); // 자동 이스케이프 활성화
```

<br>

### 3. Input Validation, 입력값 검증

사용자가 입력할 수 있는 값을 제한하면 SSTI 공격을 방지할 수 있다.

```php
if (!preg_match('/^[a-zA-Z0-9 ]+$/', $_GET['input'])) {
    die('Invalid input');
}
```

이런식으로 작성하면 **알파벳, 숫자, 공백** 외에는 입력할 수 없다.

<br>

### 4. 웹 방어벽(WAF) 및 보안 솔루션 사용

ModSecurity 같은 **웹 방어벽(WAF)**을 사용하면 SSTI 공격 패턴을 차단할 수 있다.
