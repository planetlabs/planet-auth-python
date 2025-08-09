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
from typing import Optional

from planet_auth.logging.events import AuthEvent


class AuthException(Exception):
    """
    Base Exception class for all exceptions thrown from the planet_auth library.
    """

    def __init__(
        self,
        message: Optional[str] = None,
        inner_exception: Optional[Exception] = None,
        event: Optional[AuthEvent] = None,
        **kwargs,
    ):
        super().__init__(message)
        self._inner_exception = inner_exception
        self._event = event

    def event(self) -> Optional[AuthEvent]:
        return self._event

    @classmethod
    def recast(cls, *exceptions, **params):
        """
        Decorator to recast an exception as the specified exception:
        Example:
            ```python
            @AuthException.recast(Exception)
            @AuthException_SubClass.recast(Some_Specific_Exception)
            def raise_my_exception2():
                raise Some_Specific_Exception()
            ```

        Exercise caution when using multiple re-casts.  Recasting as something
        that is then caught by a decorator further up the stack causes problems:
        Example:
            ```python
            @AuthException.recast(Exception) # Causes a problem, since it will catch
                                             # the results of the recasts below
            @AuthException_SomeSubException.recast(Some_Specific_Exception)
            def raise_my_exception2():
                raise Some_Specific_Exception()
            ```
        """
        if not exceptions:
            exceptions = (Exception,)
        # some_parameter = params.get("some_parameter", some_default)

        def decorator(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    raise cls(message="{} ({})".format(str(e), e.__class__.__name__)) from e

            return wrapper

        return decorator


# TODO: should there be a general authentication/authorization base class?
class InvalidTokenException(AuthException):
    """
    Base class for all exceptions that indicate a failure when
    authenticating a token.  Sub-classes may be used to indicate
    more specific errors.

    This exception should not be used to indicate other error
    conditions that may arise during authentication/authorization.
    """

    def __init__(
        self, event: AuthEvent = AuthEvent.TOKEN_INVALID, jwt_header: dict = None, jwt_body: dict = None, **kwargs
    ):
        super().__init__(event=event, **kwargs)
        self._jwt_header = jwt_header
        self._jwt_body = jwt_body

    def jwt_header(self):
        return self._jwt_header

    def jwt_body(self):
        return self._jwt_body
