# Copyright 2024-2025 Planet Labs PBC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import functools
import json
import logging
import importlib.metadata

from contextlib import suppress
from typing import Dict

from .events import AuthEvent
from planet_auth.auth_exception import AuthException, InvalidTokenException

# from planet_auth.oidc.token_validator import InvalidTokenException

# _lib_global_py_logger = logging.getLogger(__name__)

_lib_global_py_logger = logging.getLogger("planet_auth")
_lib_global_do_structured_logging = False
_lib_global_nested_logging_key = None

# Some services use the `json_logging` module which expects
# additional logging parameters to be stored under the 'props' key. This is
# the default for now so we don't break those dependant services' logging.
DEFAULT_NESTED_KEY = "props"


# class AuthLogger(logging.Logger):  # TODO?: is this a good idea, or a better approach?
class AuthLogger:
    """
    Class that wraps the Python logger so that all logs emitted from
    this library may be logged with the same consistent JSON format.
    This is being done so that dashboards may be built using structured
    data over string reg-ex parsing.
    """

    def __init__(self):
        # self._py_logger = logging.getLogger(__name__)
        # self._py_logger = logger
        self._msg_prefix = "[planet-auth-python] "
        self._auth_libraries = self._get_auth_libraries()

    def _get_auth_libraries(self):
        libs = {"planet-auth": importlib.metadata.version("planet-auth")}
        for optional_lib in (
            "planet-auth-config",
            "planet-auth-django",
        ):
            libs[optional_lib] = "N/A"
            with suppress(importlib.metadata.PackageNotFoundError):
                libs[optional_lib] = importlib.metadata.version(optional_lib)
        return libs

    def _get_py_logger(self):
        # _py_logger is not simply a member so that users of our library can call
        # setPyLoggerForAuthLogger and the library will work as expected.
        # if self._py_logger:
        #     return self._py_logger
        # pylint: disable=global-variable-not-assigned
        global _lib_global_py_logger
        return _lib_global_py_logger

    # TODO: should log level be encapsulated by the AuthLogger class?
    def log(
        self,
        level: int,
        msg: str = "",
        event: AuthEvent = None,
        jwt_header_json: Dict = None,
        jwt_body_json: Dict = None,
        exception: Exception = None,
    ) -> None:
        _logger = self._get_py_logger()
        if not _logger:
            return

        if level < _logger.getEffectiveLevel():
            return

        if exception:
            _log_msg = msg or str(exception)

            if not event and isinstance(exception, AuthException):
                event = exception.event()

            # Note: This is a little hacky. The lib is designed to handle more than just JWTs and OAuth,
            #     but it is a very common use case and this makes for an ergonomic development experience,
            #     making it easy to have the raise pass context in the exception to a distant point
            #     in the code responsible for logging.
            if isinstance(exception, InvalidTokenException):
                if not jwt_header_json:
                    jwt_header_json = exception.jwt_header()
                if not jwt_body_json:
                    jwt_body_json = exception.jwt_body()
        else:
            _log_msg = msg

        _log_msg = self._msg_prefix + _log_msg

        if not event:
            event = AuthEvent.TRACE

        log_json = {
            # "msg": _log_msg,
            "event": str(event),
            "auth_libraries": self._auth_libraries,
        }

        # TODO: Is this actually right?  The library is more general than OAuth and JWTs, but this
        #       is a common need when we log, so we've done this in our logger.
        if jwt_header_json:
            log_json["jwt_header"] = {"alg": jwt_header_json.get("alg")}
        if jwt_body_json:
            log_json["jwt_payload"] = {
                "iss": jwt_body_json.get("iss"),  # Standard claim
                "cid": jwt_body_json.get("cid"),  # Standard claim
                # "sub": jwt_body_json.get("sub"),  # Standard claim (may contain PII in some implementations)
                "aud": jwt_body_json.get("aud"),  # Standard claim
                "scope": jwt_body_json.get("scope"),  # RFC 8693, 9068 claim used for scope
                "scp": jwt_body_json.get("scp"),  # Okta claim used for scope
                "pl_principal": jwt_body_json.get("pl_principal"),  # Planet claim
                "organization_id": jwt_body_json.get("organization_id"),  # Planet claim
            }

        if exception:
            log_json["error"] = str(exception)
            # log_json["stack_trace"] =

        if _lib_global_do_structured_logging:
            final_log_msg = _log_msg
            if _lib_global_nested_logging_key:
                final_log_extra = {_lib_global_nested_logging_key: log_json}
            else:
                final_log_extra = log_json
        else:
            log_json["msg"] = _log_msg
            final_log_msg = json.dumps(log_json)
            final_log_extra = None

        _logger.log(level=level, msg=final_log_msg, extra=final_log_extra)

    def critical(self, **kwargs) -> None:
        return self.log(level=logging.CRITICAL, **kwargs)

    def error(self, **kwargs) -> None:
        return self.log(level=logging.ERROR, **kwargs)

    def warning(self, **kwargs) -> None:
        return self.log(level=logging.WARNING, **kwargs)

    def info(self, **kwargs) -> None:
        return self.log(level=logging.INFO, **kwargs)

    def debug(self, **kwargs) -> None:
        return self.log(level=logging.DEBUG, **kwargs)

    def log_exception(
        self,
        default_event: AuthEvent = AuthEvent.TRACE,
        override_event: AuthEvent = None,
        level: int = logging.WARNING,
        exception_cls=Exception,
        **params,
    ):
        """
        Decorator to log exceptions.
        Parameters:
            default_event : Event to log when the exception does not include a more specific event.
            override_event : Event to log regardless of whether or not the exception includes another event.
            level : Log level
            exception_cls : Exception class to catch and log.
        Example:
            ```python
            @AuthLogger.log_exception(level=logging.WARNING, event=AuthEvent.INVALID_TOKEN)
            def raise_my_exception():
                raise Some_Exception()
            ```
        """
        # some_param = params.get("some_param", default_value)

        def decorator(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                try:
                    return func(*args, **kwargs)
                except exception_cls as e:
                    log_event = None
                    if override_event:
                        log_event = override_event
                    elif isinstance(e, AuthException):
                        log_event = e.event()
                    if not log_event:
                        log_event = default_event

                    self.log(event=log_event, level=level, exception=e)
                    raise e

            return wrapper

        return decorator


_default_auth_logger = AuthLogger()


# This is really only intended for use inside the library, not for use by library users.
def getAuthLogger():
    # pylint: disable=global-variable-not-assigned
    global _default_auth_logger
    return _default_auth_logger


def setPyLoggerForAuthLogger(py_logger: logging.Logger):
    """
    Set the python logger that should be used by the library.
    Parameters:
        py_logger: The python logger that the library should use.
            Set this to None to completely mute logging.
    """
    # pylint: disable=global-statement
    global _lib_global_py_logger
    _lib_global_py_logger = py_logger


def setStructuredLogging(nested_key=DEFAULT_NESTED_KEY):
    """
    Configure the library to emit structured log messages.  When this
    mode is set, logs will be emitted specifying information using the logger's
    `extra` field.

    Parameters:
        nested_key : dict key in which to wrap the library's data logged under
            the `extra` field.  The default is to include all library logged
            extra fields encapsulated inside a dictionary with the single key
            `props`.  This default was chosen to comform to the expectations of
            the `json_logging` python module. For example, by default extra data
            will be submitted to the logger as
            `log(msg="log msg", extra={"props": {library_provided_extra_keys}})`.

            Set this to `None` to forego wrapping.
    """
    # pylint: disable=global-statement
    global _lib_global_do_structured_logging
    _lib_global_do_structured_logging = True
    global _lib_global_nested_logging_key
    _lib_global_nested_logging_key = nested_key


def setStringLogging():
    """
    Configure the library to emit simple string log messages.  When this
    mode is set, logs will be emitted with all information in the log message,
    ahd the logger's `extra` field will be set to None.
    """
    # pylint: disable=global-statement
    global _lib_global_do_structured_logging
    _lib_global_do_structured_logging = False
