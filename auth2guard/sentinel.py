"""
Function wrapper that validate de JWT scope
"""

import asyncio
import json
from enum import Enum
from typing import Protocol, Type, Union, Tuple

from jwt import jwt, jwk_from_dict, AbstractJWKBase


class Request(Protocol):  # pylint: disable=R0903
    def headers(self) -> dict:
        pass


class ExceptionType(Enum):
    TOKEN_NOT_FOUND = "token_not_found"
    NOT_FROM_ORIGIN = "not_from_origin"
    EXPIRED = "expired"
    CONFIG_ERROR = "config_error"
    UNAUTHORIZED = "unauthorized"


class Sentinel:
    __exception_class = {}
    __jwt = jwt.JWT()
    __default_http_header_name_token = "Authorization"
    __config = {}

    @classmethod
    def overwrite_exceptions(
        cls,
        token_not_found: Type[Exception] = None,
        not_from_origin: Type[Exception] = None,
        expired: Type[Exception] = None,
        unauthorized: Type[Exception] = None,
    ):  # pylint: disable=R0913
        exceptions_map = {
            ExceptionType.TOKEN_NOT_FOUND: token_not_found,
            ExceptionType.NOT_FROM_ORIGIN: not_from_origin,
            ExceptionType.EXPIRED: expired,
            ExceptionType.UNAUTHORIZED: unauthorized,
        }
        filtered_exceptions_map = {
            k: v for k, v in exceptions_map.items() if v is not None
        }
        for value in filtered_exceptions_map.values():
            if not issubclass(value, Exception):
                cls.exception_raiser(
                    exception_type=ExceptionType.CONFIG_ERROR,
                    message=f"{value} is not subclass of Exception",
                )

        cls.__exception_class.update(filtered_exceptions_map)

    @classmethod
    def set_config(
        cls,
        jwk: Union[dict, str, bytes] = None,
        http_header_name_token: str = None,
        request_token_callback=None,
    ):
        if http_header_name_token:
            cls._set_http_header_name_token(
                http_header_name_token=http_header_name_token
            )
        if jwk:
            cls._set_jwk(jwk=jwk)
        if request_token_callback:
            cls._set_request_token_callback(
                request_token_callback=request_token_callback
            )

    @classmethod
    def _set_http_header_name_token(cls, http_header_name_token):
        if not isinstance(http_header_name_token, str):
            cls.exception_raiser(
                exception_type=ExceptionType.CONFIG_ERROR,
                message="http_header_name_token.wrong_type",
            )
        cls.__config.update({"http_header_name_token": http_header_name_token})

    @classmethod
    def _set_jwk(cls, jwk):
        if not isinstance(jwk, (dict, str, bytes)):
            cls.exception_raiser(
                exception_type=ExceptionType.CONFIG_ERROR,
                message="jwk.wrong_type",
            )
        if isinstance(jwk, bytes):
            jwk = jwk.decode()
        if isinstance(jwk, str):
            jwk = json.loads(jwk)
        cls.__config.update({"jwk": jwk_from_dict(jwk)})

    @classmethod
    def _set_request_token_callback(cls, request_token_callback):
        if not hasattr(request_token_callback, "__call__"):
            cls.exception_raiser(
                exception_type=ExceptionType.CONFIG_ERROR,
                message="request_token_callback.wrong_type",
            )
        cls.__config.update({"request_token_callback": request_token_callback})

    def __init__(
        self, allowed_scopes: set, and_validation: bool, inject_token_content: bool
    ):
        self.__allowed_scopes = allowed_scopes
        self.__and_validation = and_validation
        self.__inject_token_content = inject_token_content

    def __call__(self, func):
        is_sync_function = asyncio.iscoroutinefunction(func)
        if is_sync_function:

            async def async_checker(*args, request: Request, **kwargs):
                kwargs.update({"request": request})
                token_content = self._supervision(request=request)
                if self.__inject_token_content:
                    kwargs.update({"token_content": token_content})
                return await func(*args, **kwargs)

            checker = async_checker

        else:

            def sync_checker(*args, request: Request, **kwargs):
                kwargs.update({"request": request})
                token_content = self._supervision(request=request)
                if self.__inject_token_content:
                    kwargs.update({"token_content": token_content})
                return func(*args, **kwargs)

            checker = sync_checker
        checker.__wrapped__ = func
        return checker

    @classmethod
    def exception_raiser(cls, exception_type: ExceptionType, message: str):
        to_raise = cls.__exception_class.get(exception_type, ValueError)
        raise to_raise(message)

    @classmethod
    def __get_token(cls, request: Request) -> Tuple[str, str]:
        http_header_name_token = cls.__config.get(
            "http_header_name_token", cls.__default_http_header_name_token
        )
        handler = cls.__config.get(
            "request_token_callback", lambda r: r.headers.get(http_header_name_token)
        )
        raw_token = handler(request)
        if not raw_token:
            cls.exception_raiser(
                exception_type=ExceptionType.TOKEN_NOT_FOUND,
                message="authentication.token_not_found",
            )
        token_parts = raw_token.split(" ")
        token_type, token_content = token_parts
        return token_type, token_content

    @property
    def jwk(self) -> AbstractJWKBase:  # pylint: disable=R1710
        if jwk := self.__config.get("jwk"):
            return jwk
        self.exception_raiser(
            exception_type=ExceptionType.CONFIG_ERROR,
            message="authentication.jwt_not_supplied",
        )

    def __decode_token(self, token_content: str) -> dict:  # pylint: disable=R1710
        _jwk = self.jwk
        try:
            content = self.__jwt.decode(message=token_content, key=_jwk)
            return content
        except Exception as original_error:  # pylint: disable=W0703
            if "JWT Expired" in original_error.args:
                self.exception_raiser(
                    exception_type=ExceptionType.EXPIRED,
                    message="authentication.expired_token",
                )
            self.exception_raiser(
                exception_type=ExceptionType.NOT_FROM_ORIGIN,
                message="authentication.not_from_origin",
            )

    def _supervision(self, request: Request) -> dict:
        token_type_and_content = self.__get_token(request=request)
        token_content = self.__decode_token(token_content=token_type_and_content[1])
        token_scope = token_content.get("scope", "")
        scopes = set(
            token_scope.split(" ") if isinstance(token_scope, str) else token_scope
        )
        scopes_sub_set = self.__allowed_scopes - scopes
        and_validation_satisfied = not scopes_sub_set and self.__and_validation
        or_operation_satisfied = (
            bool(len(self.__allowed_scopes) - len(scopes_sub_set))
            and not self.__and_validation
        )
        if not (and_validation_satisfied or or_operation_satisfied):
            self.exception_raiser(
                exception_type=ExceptionType.UNAUTHORIZED,
                message="authentication.unauthorized",
            )
        return token_content
