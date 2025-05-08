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

import unittest

from planet_auth import AuthException


class MyException1(Exception):
    def __init__(self, msg):
        super().__init__(msg)
        self.message = msg


class MyException1Sub1(MyException1):
    pass


class MyException1Sub2(MyException1):
    pass


class MyException2(Exception):
    def __init__(self, msg):
        super().__init__(msg)
        self.message = msg


class MyAuthException(AuthException):
    def __init__(self, message=None):
        super().__init__(message)


class MyAuthExceptionSub1(MyAuthException):
    pass


class MyAuthExceptionSub2(MyAuthException):
    pass


class MyAuthException2(AuthException):
    def __init__(self, message=None):
        super().__init__(message)


class MyAuthException3(AuthException):
    def __init__(self, message=None):
        super().__init__(message)


class TestAuthException(unittest.TestCase):
    def test_decorator_default(self):
        @AuthException.recast()
        def raise_my_exception1():
            raise MyException1(msg="test")

        with self.assertRaises(AuthException):
            raise_my_exception1()

    def test_decorator_explicit(self):
        @AuthException.recast(MyException1)
        def raise_my_exception1():
            raise MyException1(msg="test")

        with self.assertRaises(AuthException):
            raise_my_exception1()

    def test_passes_not_recast_exception(self):
        @AuthException.recast(MyException1)
        def raise_my_exception2():
            raise MyException2(msg="test")

        with self.assertRaises(MyException2):
            raise_my_exception2()

    def test_recast_child_exception(self):
        @MyAuthException.recast(MyException1)
        def raise_my_exception1():
            raise MyException1(msg="test raising MyException1 that should be recast to MyAuthException")

        with self.assertRaises(MyAuthException):
            raise_my_exception1()

    def test_multi_recast1(self):
        @MyAuthExceptionSub2.recast(MyException1)
        @MyAuthExceptionSub1.recast(MyException1Sub1)
        def raise_my_exception1sub1():
            raise MyException1Sub1(msg="Test")

        with self.assertRaises(MyAuthExceptionSub1):
            raise_my_exception1sub1()

    def test_multi_recast2(self):
        @MyAuthExceptionSub2.recast(MyException1)
        @MyAuthExceptionSub1.recast(MyException1Sub1)
        def raise_my_exception1():
            raise MyException1(msg="Test")

        with self.assertRaises(MyAuthExceptionSub2):
            raise_my_exception1()

    def test_multi_recast3(self):
        # @MyAuthException3.recast(Exception) Catching and recasting to something caught higher up the stack is problematic.
        @MyAuthException2.recast(MyException2)
        @MyAuthExceptionSub2.recast(MyException1)
        @MyAuthExceptionSub1.recast(MyException1Sub1)
        def raise_my_exception2():
            raise MyException2(msg="Test")

        with self.assertRaises(MyAuthException2):
            raise_my_exception2()
