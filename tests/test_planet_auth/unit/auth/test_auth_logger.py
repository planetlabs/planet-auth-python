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

import logging
import sys
import unittest
from unittest import mock

import pytest as pytest

from planet_auth.auth_exception import AuthException, InvalidTokenException
import planet_auth.logging.auth_logger

# TODO: better assert that the right thing is being logged.
from planet_auth.logging.events import AuthEvent

MOCK_JWT_BODY_CLAIMS = {
    "iss": "unit-test-jwt-issuer",
    "aud": "unit-test-jwt-audience",
    "pl_principal": "unit-test-pl_principal",
}
MOCK_JWT_HEADER_CLAIMS = {"alg": "RS256"}


class MyException1(Exception):
    def __init__(self, msg):
        super().__init__(msg)
        self.message = msg


class MyException1Sub1(MyException1):
    pass


class MyException2(Exception):
    def __init__(self, msg):
        super().__init__(msg)
        self.message = msg


class AuthLoggerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.under_test = planet_auth.logging.auth_logger.getAuthLogger()
        planet_auth.logging.auth_logger.setPyLoggerForAuthLogger(logging.getLogger("AuthLoggerTest-unit-test-logger"))

    def test_auth_logger_without_jwt(self):
        self.under_test.log(level=logging.INFO, msg="test log message")

    def test_auth_logger_with_jwt(self):
        self.under_test.log(
            level=logging.INFO,
            msg="test log message",
            jwt_header_json=MOCK_JWT_HEADER_CLAIMS,
            jwt_body_json=MOCK_JWT_BODY_CLAIMS,
        )

    def test_log_auth_exception(self):
        self.under_test.log(
            level=logging.INFO, msg="test log message", exception=AuthException(message="Test Exception")
        )

    def test_log_invalid_token_exception(self):
        self.under_test.log(
            level=logging.INFO, msg="test log message", exception=InvalidTokenException(message="Test Exception")
        )
        self.under_test.log(
            level=logging.INFO,
            msg="test log message",
            exception=InvalidTokenException(message="Test Exception"),
            jwt_header_json=MOCK_JWT_HEADER_CLAIMS,
            jwt_body_json=MOCK_JWT_BODY_CLAIMS,
        )
        self.under_test.log(
            level=logging.INFO,
            msg="test log message",
            exception=InvalidTokenException(
                message="Test Exception", jwt_header=MOCK_JWT_HEADER_CLAIMS, jwt_body=MOCK_JWT_BODY_CLAIMS
            ),
        )
        self.under_test.log(
            level=logging.INFO,
            msg="test log message",
            exception=InvalidTokenException(
                message="Test Exception", jwt_header=MOCK_JWT_HEADER_CLAIMS, jwt_body=MOCK_JWT_BODY_CLAIMS
            ),
            jwt_header_json=MOCK_JWT_HEADER_CLAIMS,
            jwt_body_json=MOCK_JWT_BODY_CLAIMS,
        )

    def test_log_exception(self):
        self.under_test.log(level=logging.INFO, msg="test log message", exception=Exception("Test Exception"))

    @mock.patch("logging.Logger.log")
    def test_decorator_logs_caught_exception(self, mock_logger):
        @self.under_test.log_exception(exception_cls=MyException1)
        def raise_my_exception1():
            raise MyException1Sub1(msg="test")

        with self.assertRaises(MyException1):
            raise_my_exception1()

        self.assertEqual(mock_logger.call_count, 1)

    @mock.patch("logging.Logger.log")
    def test_decorator_does_not_log_uncaught_exception(self, mock_logger):
        @self.under_test.log_exception(exception_cls=MyException2)
        def raise_my_exception1():
            raise MyException1(msg="test")

        with self.assertRaises(MyException1):
            raise_my_exception1()

        self.assertEqual(mock_logger.call_count, 0)

    @mock.patch("logging.Logger.log")
    def test_default_pylogger_used(self, mock_logger):
        under_test = planet_auth.logging.auth_logger.getAuthLogger()
        self.assertEqual(under_test._get_py_logger(), planet_auth.logging.auth_logger._lib_global_py_logger)
        self.assertIsNotNone(under_test._get_py_logger())
        under_test.critical(msg="test log message")
        self.assertEqual(mock_logger.call_count, 1)

    @mock.patch("logging.Logger.log")
    def test_mute_logging_with_none_pylogger(self, mock_logger):
        under_test = planet_auth.logging.auth_logger.getAuthLogger()
        planet_auth.logging.auth_logger.setPyLoggerForAuthLogger(None)
        self.assertIsNone(under_test._get_py_logger())
        under_test.critical(msg="test log message")
        self.assertEqual(mock_logger.call_count, 0)

    @mock.patch("logging.Logger.log")
    @pytest.mark.skipif(
        sys.version_info < (3, 8), reason="test requires python3.8 or higher (I believe the function should be fine)"
    )
    def test_set_structured_logging_config(self, mock_logger):
        under_test = planet_auth.logging.auth_logger.getAuthLogger()
        planet_auth.logging.auth_logger.setStructuredLogging()
        under_test.critical(msg="test log message", event=AuthEvent.TRACE)
        self.assertEqual(mock_logger.call_count, 1)
        self.assertIsNotNone(mock_logger.call_args.kwargs.get("extra"))

    @mock.patch("logging.Logger.log")
    @pytest.mark.skipif(
        sys.version_info < (3, 8),
        reason="test requires python3.8 or higher (I believe the function should be fine, since it is tested in CI/CD with other python versions)",
    )
    def test_set_structured_logging_default_nesting(self, mock_logger):
        under_test = planet_auth.logging.auth_logger.getAuthLogger()
        planet_auth.logging.auth_logger.setStructuredLogging()
        under_test.critical(msg="test log message", event=AuthEvent.TRACE)

        # The thing the test asserts is that we are nesting the extra arguments in a specific
        # dict key. We are not asserting the entire contexts of the extra data.
        # (The default value of 'props' is from json_logging)
        self.assertEqual(mock_logger.call_count, 1)
        self.assertIsNotNone(mock_logger.call_args.kwargs.get("extra"))
        self.assertIsInstance(mock_logger.call_args.kwargs.get("extra"), dict)
        self.assertIsNotNone(mock_logger.call_args.kwargs.get("extra").get("props"))
        self.assertIsInstance(mock_logger.call_args.kwargs.get("extra").get("props"), dict)
        self.assertEqual(mock_logger.call_args.kwargs.get("extra").get("props").get("event"), AuthEvent.TRACE)

    @mock.patch("logging.Logger.log")
    @pytest.mark.skipif(
        sys.version_info < (3, 8),
        reason="test requires python3.8 or higher (I believe the function should be fine, since it is tested in CI/CD with other python versions)",
    )
    def test_set_structured_logging_custom_nesting(self, mock_logger):
        under_test = planet_auth.logging.auth_logger.getAuthLogger()
        planet_auth.logging.auth_logger.setStructuredLogging(nested_key="custom_nesting_key")
        under_test.critical(msg="test log message", event=AuthEvent.TRACE)

        # The thing the test asserts is that we are nesting the extra arguments in a specific
        # dict key. We are not asserting the entire contexts of the extra data.
        # (The default value of 'props' is from json_logging)
        self.assertEqual(mock_logger.call_count, 1)
        self.assertIsNotNone(mock_logger.call_args.kwargs.get("extra"))
        self.assertIsInstance(mock_logger.call_args.kwargs.get("extra"), dict)
        self.assertIsNotNone(mock_logger.call_args.kwargs.get("extra").get("custom_nesting_key"))
        self.assertIsInstance(mock_logger.call_args.kwargs.get("extra").get("custom_nesting_key"), dict)
        self.assertEqual(
            mock_logger.call_args.kwargs.get("extra").get("custom_nesting_key").get("event"), AuthEvent.TRACE
        )

    @mock.patch("logging.Logger.log")
    @pytest.mark.skipif(
        sys.version_info < (3, 8),
        reason="test requires python3.8 or higher (I believe the function should be fine, since it is tested in CI/CD with other python versions)",
    )
    def test_set_structured_logging_no_nesting(self, mock_logger):
        under_test = planet_auth.logging.auth_logger.getAuthLogger()
        planet_auth.logging.auth_logger.setStructuredLogging(nested_key=None)
        under_test.critical(msg="test log message", event=AuthEvent.TRACE)

        # The thing the test asserts is that we are nesting the extra arguments in a specific
        # dict key. We are not asserting the entire contexts of the extra data.
        # (The default value of 'props' is from json_logging)
        self.assertEqual(mock_logger.call_count, 1)
        self.assertIsNotNone(mock_logger.call_args.kwargs.get("extra"))
        self.assertIsInstance(mock_logger.call_args.kwargs.get("extra"), dict)
        self.assertIsNotNone(mock_logger.call_args.kwargs.get("extra").get("event"))
        self.assertEqual(mock_logger.call_args.kwargs.get("extra").get("event"), AuthEvent.TRACE)

    @mock.patch("logging.Logger.log")
    @pytest.mark.skipif(
        sys.version_info < (3, 8), reason="test requires python3.8 or higher (I believe the function should be fine)"
    )
    def test_set_string_logging_config(self, mock_logger):
        under_test = planet_auth.logging.auth_logger.getAuthLogger()
        planet_auth.logging.auth_logger.setStringLogging()
        under_test.critical(msg="test log message", event=AuthEvent.TRACE)
        self.assertEqual(mock_logger.call_count, 1)
        self.assertIsNone(mock_logger.call_args.kwargs.get("extra"))

    @pytest.mark.xfail(reason="Test not yet implemented.")
    def test_decorator_event_from_default(self):
        under_test = planet_auth.logging.auth_logger.getAuthLogger()

        @under_test.log_exception(default_event=AuthEvent.TOKEN_VALID)
        def raise_my_exception1():
            raise MyException1(msg="test")

        with self.assertRaises(MyException1):
            raise_my_exception1()

        # TODO: Assert that under_test.log(event... ) got the right event (== TOKEN_VALID)
        self.fail("Test not implemented")

    @pytest.mark.xfail(reason="Test not yet implemented.")
    def test_decorator_event_from_exception(self):
        under_test = planet_auth.logging.auth_logger.getAuthLogger()

        @under_test.log_exception(default_event=AuthEvent.TOKEN_VALID)
        def raise_auth_exception():
            raise AuthException(event=AuthEvent.TOKEN_INVALID, message="test")

        with self.assertRaises(AuthException):
            raise_auth_exception()

        # TODO: Assert that under_test.log(event... ) got the right event (== TOKEN_INVALID)
        self.fail("Test not implemented")

    @pytest.mark.xfail(reason="Test not yet implemented.")
    def test_decorator_event_from_override(self):
        under_test = planet_auth.logging.auth_logger.getAuthLogger()

        @under_test.log_exception(
            default_event=AuthEvent.TOKEN_VALID, override_event=AuthEvent.TOKEN_INVALID_BAD_ISSUER
        )
        def raise_auth_exception():
            raise AuthException(event=AuthEvent.TOKEN_INVALID, message="test")

        with self.assertRaises(AuthException):
            raise_auth_exception()

        # TODO: Assert that under_test.log(event... ) got the right event (== TOKEN_INVALID_BAD_ISSUER)
        self.fail("Test not implemented")
