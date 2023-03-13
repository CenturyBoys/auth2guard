import json
from datetime import datetime

import pytest
import jwt

import auth2guard


def test_set_config_wrong_type_jwk():
    jwk = 1
    with pytest.raises(ValueError):
        auth2guard.set_config(jwk=jwk)


def test_set_config_wrong_type_http_header_name_token():
    http_header_name_token = 1
    with pytest.raises(ValueError):
        auth2guard.set_config(http_header_name_token=http_header_name_token)


def test_set_config_wrong_type_request_token_callback():
    request_token_callback = 1
    with pytest.raises(ValueError):
        auth2guard.set_config(request_token_callback=request_token_callback)


def test_overwrite_exceptions_wrong_type():
    class MyException:
        pass

    with pytest.raises(ValueError):
        auth2guard.overwrite_exceptions(unauthorized=MyException)


class Request:
    def __init__(self, headers: dict):
        self._headers = headers

    @property
    def headers(self) -> dict:
        return self._headers


jwk = (
    b'{"p":"-7pCvLlzsNIRD7utbLZqBW4h0upJIOkCu4JqR0GtNRCmZCjRzf_K9S4HTO5qHbEyhrwLwBYu2vgAs-0VCB'
    b"D_CIMGvo44bLLfsqR0gbGW3KQjhBPysy2LMHkU5Urxs0KiZgFH0-q1HvrcERvQ0PjQ8OSqOT6jQf2x4zD7RDHulu"
    b'E","kty":"RSA","q":"lfUZMlx4Tf4uHcXGhTltzbQ1jIPUuQzOCB0IDlBUAVhxYtIyfNRe_zjkmo2g_xEwoXmF'
    b"dYvf-G5uPkl-5VPGe1eTk72X4ixhPYanPiO_oW3zMO2CAPnBHSl6FjLmXeDsOPx0IdUVOQMegHY11pSyiuwBp4A0"
    b'FhP2Yz6O4OZYbjE","d":"cLV11CFDDVYk8zleBPx7XdUeFzYjiIoUY1vZPsgn-KoWHrLtVsDuUYpYdrwQEQm66h'
    b"Hn8tzkfRsYiTh_WMeSR5HFgxWTmDSOSQEJ9_1lrf0KtS25myKKPZv65SGkdc_Y15iXbDCf0Dy7ZBQw0PG1shVxAY"
    b"8GNhkqAeUtNQHNt1A-vlNvED4v2VkPTcwEp-WlaWZpCVbCC2oYd0Z9Gui-2HuvBgz952py_wWXnESoBc9eRdeC9t"
    b"Rz9I8VuLIVKPFjStT3_8PL0WQInYnZxERSvASIUM8xzhAwp1DVrRxLPM2o9lRxKR77uWpKYETfW-TdebCzfy-OZl"
    b'9zi48-U1rMAQ","e":"AQAB","use":"enc","kid":"e89dbc82-e702-4eb8-bc17-90a387f91ad2","qi":"'
    b"G-sMcylkZFoJNIOXWnNpra8nZkKXQXW6bbXpvhQXRSWsY-cA0KG2mE6jE9J6-NZXUhGzzsBpLsvbYMXB9F5fEazd"
    b'NGohYa54sWO3KNFmtyUUxGQW1W-KrcS-2zccRoFiO4NT_AQBsETAVjVOFLQ-CFoasOlkHorcH462IL7DXxU","dp'
    b'":"D54UueS_mr7NtC4uqkn-9etJSe6jLtmGA-Ape9ZFSr-HszsdGSy_iMqcRVedWc4-lkFgcUBvE8LDOGaDIYb8a'
    b'6jFaFkmgwft_QVa_RjphTLhyTX7nsY6ln1MoJUvvbFqpe16aVlsd0mVEbKqF-z3-ZoWPYr3UgbNXI0Tab23UcE",'
    b'"dq":"JhtIseGJuNgUxAAUOJqlapaW3QRLNFMqsCkgePK0xjrBZYlgxxP4qAa_IP9IoEiwAPiuj3ZiDfGSFkX69y'
    b"_YylMw72RIinMYqtfi_Al9kvoryI0ycikFh_GYUrfQjp6vqLOOl2JcqEZApAhmGgdjb6YVrYkIs2uTOxkUmdYvNq"
    b'E","n":"k3Rq4GxghJcTK8RbnFb10ltAMsxoxtfomgyDaW8_MwW_gsfBVbFDua80aFDmz7dKAfdx_xBhb0rAw__B'
    b"8ifQvBVJAu2_yB0PaSNERRbaG8DMWGQ9P1GJyYOdmZcpz3kpGE1Yi_F3T8ao1MDz2nD5PjWiT6k0NAqB6_vI0aTI"
    b"fyRsGIrIazND7ytXsPSlws02R_aNssdexR05qNLuzrcmx2xXbfW0_oAL5ZxzelkebX2JjuVSCdD72_JyvQqe3MQw"
    b'A5GtznxCrK4yyQg5XorJgHWOwZLOnH_xPJAM6FLxaLHxYX8KniePxNraO5r8om_LkhxiWC3E0_bCl730FtePEQ"}'
)


@pytest.fixture()
def route_callback():
    @auth2guard.validate(["test1", "test2"])
    def callback(request):
        pass

    return callback


def test_set_config_wrong_type_request_token_callback_with_custom_error(route_callback):
    class MyException(Exception):
        pass

    request = Request(headers={})
    auth2guard.overwrite_exceptions(token_not_found=MyException)
    with pytest.raises(MyException) as error:
        route_callback(request=request)

    auth2guard.overwrite_exceptions(token_not_found=ValueError)
    assert error.value.args[0] == "authentication.token_not_found"


def test_validation_with_token_not_supplied_exception(route_callback):
    request = Request(headers={})

    with pytest.raises(ValueError) as error:
        route_callback(request=request)
    assert error.value.args[0] == "authentication.token_not_found"


def test_validation_with_jwt_not_supplied_exception(route_callback):
    token = gen_token("", 2)
    request = Request(headers={"Authorization": f"Basic {token[:-1]}@"})

    with pytest.raises(ValueError) as error:
        route_callback(request=request)
    assert error.value.args[0] == "authentication.jwt_not_supplied"


def gen_token(scope, time):
    jwt_instance = jwt.JWT()
    global jwk
    payload = {
        "scope": scope,
        "exp": int(datetime.now().timestamp() + time),
    }
    jwk_dict = json.loads(jwk)
    jwt_key = jwt.jwk_from_dict(jwk_dict)
    token = jwt_instance.encode(payload=payload, key=jwt_key, alg="RS256")
    return token


@pytest.fixture()
def with_jwk():
    global jwk
    auth2guard.set_config(jwk=jwk)
    yield None
    auth2guard.Sentinel._Sentinel__config = {}


def test_validation_with_token_expired_exception(route_callback, with_jwk):
    token = gen_token("", -1)
    request = Request(headers={"Authorization": f"Basic {token}"})

    with pytest.raises(ValueError) as error:
        route_callback(request=request)
    assert error.value.args[0] == "authentication.expired_token"


def test_validation_with_not_from_origin_exception(route_callback, with_jwk):
    token = gen_token("", -1)
    request = Request(headers={"Authorization": f"Basic {token[:-1]}@"})

    with pytest.raises(ValueError) as error:
        route_callback(request=request)
    assert error.value.args[0] == "authentication.not_from_origin"


def test_validation_with_unauthorized_exception(route_callback, with_jwk):
    token = gen_token("", 2)
    request = Request(headers={"Authorization": f"Basic {token}"})

    with pytest.raises(ValueError) as error:
        route_callback(request=request)
    assert error.value.args[0] == "authentication.unauthorized"


def test_validation_with_http_header_name_token_config(route_callback, with_jwk):
    token = gen_token("test1 test2", 2)
    request = Request(headers={"x-token": f"Basic {token}"})
    auth2guard.set_config(http_header_name_token="x-token")
    route_callback(request=request)


def test_validation_with_request_token_callback_config(route_callback, with_jwk):
    token = gen_token("test1 test2", 2)
    request = Request(headers={"x-token": f"Basic {token}"})

    def request_token_callback(request: Request):
        return request.headers.get("x-token")

    auth2guard.set_config(request_token_callback=request_token_callback)
    route_callback(request=request)


def test_validation_with_and_validation_true_raise_exception(route_callback, with_jwk):
    token = gen_token("test1", 2)
    request = Request(headers={"Authorization": f"Basic {token}"})
    with pytest.raises(ValueError) as error:
        route_callback(request=request)
    assert error.value.args[0] == "authentication.unauthorized"


def test_validation_with_and_validation_true(route_callback, with_jwk):
    token = gen_token("test1 test2", 2)
    request = Request(headers={"Authorization": f"Basic {token}"})
    route_callback(request=request)


def test_validation_with_and_validation_false_raise_exception(with_jwk):
    @auth2guard.validate(["test1", "test2"], and_validation=False)
    def callback(request):
        pass

    token = gen_token("test3", 2)
    request = Request(headers={"Authorization": f"Basic {token}"})
    with pytest.raises(ValueError) as error:
        callback(request=request)


def test_validation_with_and_validation_false(with_jwk):
    @auth2guard.validate(["test1", "test2"], and_validation=False)
    def callback(request):
        pass

    token = gen_token("test3 test1", 2)
    request = Request(headers={"Authorization": f"Basic {token}"})
    callback(request=request)


@pytest.mark.asyncio
async def test_validation_async(with_jwk):
    @auth2guard.validate(["test1", "test2"])
    async def callback(request):
        pass

    token = gen_token("test1 test2", 2)
    request = Request(headers={"Authorization": f"Basic {token}"})
    await callback(request=request)
