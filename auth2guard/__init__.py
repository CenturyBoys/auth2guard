"""
Welcome to auth2guard stay alert! We will help you ;)
"""

from typing import List, Union, Type

from auth2guard.sentinel import Sentinel


def validate(
    allowed_scopes: List[str],
    and_validation: bool = True,
    inject_token_content: bool = False,
) -> Sentinel:
    """
    This is a decorator for you routes. Will return a Sentinel instance.
    :param allowed_scopes: List of scopes that is required for access this route
    :param and_validation: Boolean to define if the allowed_scopes is AND operation or a OR operaion
    :param inject_token_content: Boolean will inject the token_content
    :return: Sentinel function wrapper
    """
    return Sentinel(
        allowed_scopes=set(allowed_scopes),
        and_validation=and_validation,
        inject_token_content=inject_token_content,
    )


def set_config(
    jwk: Union[dict, str, bytes] = None,
    http_header_name_token: str = None,
    request_token_callback=None,
):
    """
    All configs are saved as singleton. All params are validated for
    his types and will raise exceptions.
    :param jwk: The jwk key to validate JWT
    :param http_header_name_token: The header field hare te token is sent. Default 'Authorization'
    :param request_token_callback:  Callback if necessary to extract the token from request.
    Must return a str with token type and the token 'Basic XXX'
    :return: None
    """
    Sentinel.set_config(
        jwk=jwk,
        http_header_name_token=http_header_name_token,
        request_token_callback=request_token_callback,
    )


def overwrite_exceptions(
    token_not_found: Type[Exception] = None,
    not_from_origin: Type[Exception] = None,
    expired: Type[Exception] = None,
    unauthorized: Type[Exception] = None,
):
    """
    The default ValueError can be overwrite.
    :param token_not_found: Error when token was not found. The config
    request_token_callback can be the problem.
    :param not_from_origin: Error when token was generated not by the giving JWK.
    Validate the config jwk.
    :param expired: Error when exp JWT param exceeded the time.
    :param unauthorized: Error when the JWT has not all necessary scope to proceed.
    :return: None
    """
    Sentinel.overwrite_exceptions(
        token_not_found=token_not_found,
        not_from_origin=not_from_origin,
        expired=expired,
        unauthorized=unauthorized,
    )


__all__ = [
    "validate",
    "set_config",
    "overwrite_exceptions",
]
