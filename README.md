```
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░░░  ░░░░░░░░░░░░░░░░░░░   ░░░░░░░░░░░░░░░░░░░░░░░░░░     ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░   ░
▒▒▒▒▒▒  ▒  ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒   ▒▒▒   ▒▒▒▒▒▒▒   ▒  ▒▒▒▒▒  ▒▒▒▒   ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒   ▒
▒▒▒▒▒  ▒▒   ▒▒▒▒▒   ▒▒   ▒    ▒  ▒   ▒▒▒▒▒▒  ▒▒▒▒▒   ▒  ▒▒▒▒▒▒▒▒▒▒▒   ▒▒   ▒▒▒▒   ▒▒▒▒▒  ▒    ▒▒▒▒▒▒   ▒
▓▓▓▓   ▓▓▓   ▓▓▓▓   ▓▓   ▓▓▓   ▓▓▓     ▓▓▓▓▓▓▓▓▓   ▓▓▓   ▓▓▓▓▓▓▓▓▓▓   ▓▓   ▓▓   ▓▓   ▓▓▓   ▓▓▓▓▓   ▓   ▓
▓▓▓       ▓   ▓▓▓   ▓▓   ▓▓▓   ▓▓▓   ▓▓  ▓▓▓▓▓   ▓▓▓▓▓   ▓▓▓      ▓   ▓▓   ▓   ▓▓▓   ▓▓▓   ▓▓▓▓  ▓▓▓   ▓
▓▓   ▓▓▓▓▓▓▓   ▓▓   ▓▓   ▓▓▓   ▓ ▓  ▓▓▓   ▓▓   ▓▓▓▓▓▓▓▓   ▓▓▓▓  ▓▓▓   ▓▓   ▓   ▓▓▓   ▓▓▓   ▓▓▓▓  ▓▓▓   ▓
█   █████████   ███      ████   ██  ███   █         ████      ███████      ███   █    █    █████   █   █
████████████████████████████████████████████████████████████████████████████████████████████████████████
By: CenturyBoys
```

A simple route decorator JWT scope validator.

This project work with the follow frameworks:

✅ [FastApi](https://fastapi.tiangolo.com/)

✅ [aiohttp](https://docs.aiohttp.org/en/stable/)

## Config

Configuration are exposed and can be set in any time including out of the use scope.

Obs: all configs are saved as singleton.

### jwk

The jwk key to validate JWT can be bytes, str or dict. This config need to be set!

### http_header_name_token

If your application use a custom header to send the authentication token you can use this param to indicate his name. By default, the value is 'Authorization'

### request_token_callback

If to extract the request token you need to perform some operation you can set a callback for it. Will receive the request as param and must return a str with token type and the token 'Basic XXX'

```python
import auth2guard

class Request:
    def __init__(self, headers: dict):
        self._headers = headers

    @property
    def headers(self) -> dict:
        return self._headersclass
    
request = Request(headers={"x-token": f"Basic Akj817Hakn122i..."})

def request_token_callback(request: Request):
        return request.headers.get("x-token")
    
    
auth2guard.set_config(
    jwk='{"p":"-7pCvLlzsNIRD7utbLZqB...',
    http_header_name_token="x-token",
    request_token_callback=request_token_callback
)
```

## Exceptions

The package raise exceptions for some cases se bellow.

Obs: By default, all exception are ValueError.

### token_not_found
Error when token was not found. 

Obs: The config `request_token_callback` can be the problem.

### not_from_origin
Error when token was generated not by the giving JWK. 

Obs: Validate the config jwk.

### expired
Error when exp JWT param exceeded the time.

### unauthorized
Error when the JWT has not all necessary scope to proceed.

```python
import auth2guard

class MyException(Exception):
    pass

auth2guard.overwrite_exceptions(unauthorized=MyException)
```

## Validator

Can be used as decorator and receive a list of scopes. The validator will operate AND validation or a OR validation with the token scope content. For the AND validation all scopes in the `allowed_scopes` param need to be present in the jwt scope and in the OR if any scope is present that's enough. You can receive the token content if you want by setting `token_content` to `True` this will inject the param `token_content: dict` into your function as `kwargs`

```python
import auth2guard


class Request:
    def __init__(self, headers: dict):
        self._headers = headers

    @property
    def headers(self) -> dict:
        return self._headers

auth2guard.set_config(jwk='{"p":"-7pCvLlzsNIRD7utbLZqB...')

@auth2guard.validate(["test1"], and_validation=True, token_content=True)
def route_callback(request, token_content: dict):
    pass

request = Request(headers={"Authorization": f"Basic XXX"})
route_callback(request=request)
```