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

import copy
import datetime
import json
import os
import pathlib
import shutil
import tempfile
import freezegun
import unittest
import unittest.mock
import pytest

from planet_auth.credential import Credential
from planet_auth.static_api_key.request_authenticator import FileBackedApiKey
from planet_auth.storage_utils import (
    FileBackedJsonObjectException,
    InvalidDataException,
    FileBackedJsonObject,
)

from tests.test_planet_auth.unit.auth.util import MockObjectStorageProvider, MockStorageObjectNotFound
from tests.test_planet_auth.util import tdata_resource_file_path


# class MockFileBackedEntity(FileBackedJsonObject):
#     def __init__(self, data=None, file_path=None):
#         super().__init__(data=data, file_path=file_path)


class TestEntity(FileBackedJsonObject):
    def __init__(self, data=None, file_path=None):
        super().__init__(data=data, file_path=file_path)

    def check_data(self, data):
        super().check_data(data)
        # key 1 is mandatory
        if data.get("test_key_1") == "required_value_1" or data.get("test_key_1") == "required_value_2":
            pass
        else:
            raise InvalidDataException(
                "test entity requires that 'test_key_1' be 'required_value_1' or 'required_value_2"
            )

        # key 2 is optional
        if data.get("test_key_2"):
            if data.get("test_key_2") == "required_value_1" or data.get("test_key_2") == "required_value_2":
                return
            else:
                raise InvalidDataException(
                    "test entity requires that 'test_key_2' be 'required_value_1' or 'required_value_2"
                )


class TestFileBackedJsonObjectException(unittest.TestCase):
    def test_str_without_filepath(self):
        under_test = FileBackedJsonObjectException(message="test message")
        self.assertEqual("test message", f"{under_test}")

    def test_str_with_filepath(self):
        under_test = FileBackedJsonObjectException(
            message="test message", file_path=pathlib.Path("/some/unit-test/file")
        )
        self.assertEqual("test message (File: /some/unit-test/file)", f"{under_test}")


class TestFileBackedJsonObject(unittest.TestCase):
    # "FileBackedJsonObject" was originally written for the Credential
    # base class. From there, it's use expanded.  But, that remains a
    # strong influence the priority given to base functionality, and is
    # why for many test cases we simply use the Credential base class.

    def setUp(self):
        # The interactions of freezegun and the filesystem mtimes have been... quirky.
        # This seems to help.
        os.environ["TZ"] = "UTC"

    def test_set_data_asserts_valid(self):
        under_test = Credential(data=None, file_path=None)
        with self.assertRaises(FileBackedJsonObjectException):
            under_test.set_data(None)

        under_test.set_data({})

    def test_update_data_asserts_valid(self):
        under_test = TestEntity(data=None, file_path=None)
        with self.assertRaises(InvalidDataException):
            under_test.update_data(None)

        under_test.update_data({"test_key_1": "required_value_1"})
        self.assertEqual(under_test.data(), {"test_key_1": "required_value_1"})

        with self.assertRaises(InvalidDataException):
            under_test.update_data({"test_key_1": "invalid_value"})
        self.assertEqual(under_test.data(), {"test_key_1": "required_value_1"})

        under_test.update_data({"test_key_1": "required_value_2"})
        self.assertEqual(under_test.data(), {"test_key_1": "required_value_2"})

        # The update should not only be valid, but sparse.
        with self.assertRaises(InvalidDataException):
            under_test.update_data({"test_key_2": "invalid_value"})
        self.assertEqual(under_test.data(), {"test_key_1": "required_value_2"})

        under_test.update_data({"test_key_2": "required_value_1"})
        self.assertEqual(under_test.data(), {"test_key_1": "required_value_2", "test_key_2": "required_value_1"})

    def test_load_and_failed_reload(self):
        under_test = Credential(data=None, file_path=None)

        # Load fails where there is no file
        # This is no longer true.  We allow in memory use cases.
        # with self.assertRaises(FileBackedJsonObjectException):
        #     under_test.load()

        # Load works when we have a valid file
        under_test.set_path(tdata_resource_file_path("keys/base_test_credential.json"))
        under_test.load()
        self.assertEqual({"test_key": "test_value"}, under_test.data())

        # A subsequent failed load should throw, but leave the data unchanged.
        under_test.set_path(tdata_resource_file_path("keys/FILE_DOES_NOT_EXIST.json"))
        with self.assertRaises(FileNotFoundError):
            under_test.load()

        self.assertEqual({"test_key": "test_value"}, under_test.data())

    def test_load_file_not_found(self):
        under_test = Credential(data=None, file_path=tdata_resource_file_path("keys/FILE_DOES_NOT_EXIST.json"))
        with self.assertRaises(FileNotFoundError):
            # In normal operations, we would let underlying exception
            # pass to the application to handle.
            under_test.load()

    def test_load_invalid_file(self):
        # leverage a derived class we know has simple requirements we can
        # use to test the base class.
        under_test = FileBackedApiKey(
            api_key=None, api_key_file=tdata_resource_file_path("keys/invalid_test_credential.json")
        )

        with self.assertRaises(InvalidDataException):
            under_test.load()

        self.assertIsNone(under_test.data())

        with self.assertRaises(InvalidDataException):
            under_test.check()

    def test_lazy_load(self):
        # If data is not set, it should be loaded from the path, but not until
        # the data is requested.
        under_test = Credential(data=None, file_path=tdata_resource_file_path("keys/base_test_credential.json"))
        self.assertIsNone(under_test.data())
        under_test.lazy_load()
        self.assertEqual({"test_key": "test_value"}, under_test.data())

        # if the path is invalid, it should error.
        under_test = Credential(data=None, file_path=tdata_resource_file_path("keys/FILE_DOES_NOT_EXIST.json"))
        with self.assertRaises(FileNotFoundError):
            under_test.lazy_load()

        # We now permit in memory use to work.
        # under_test = Credential(data=None, file_path=None)
        # with self.assertRaises(FileBackedJsonObjectException):
        #     under_test.lazy_load()

        # Should be fine if data is set, and a lazy_load() is tried with no
        # path set or an invalid path set, no load should be performed and the
        # data should be unchanged.
        under_test = Credential(data={"ctor_key": "ctor_value"}, file_path=None)
        under_test.lazy_load()
        self.assertEqual({"ctor_key": "ctor_value"}, under_test.data())

        under_test = Credential(
            data={"ctor_key": "ctor_value"}, file_path=tdata_resource_file_path("keys/base_test_credential.json")
        )
        under_test.lazy_load()
        self.assertEqual({"ctor_key": "ctor_value"}, under_test.data())

        under_test = Credential(
            data={"ctor_key": "ctor_value"}, file_path=tdata_resource_file_path("keys/FILE_DOES_NOT_EXIST.json")
        )
        under_test.lazy_load()
        self.assertEqual({"ctor_key": "ctor_value"}, under_test.data())

    def test_lazy_reload_initial_load_behavior(self):
        # Behaves like lazy load when there is no data:
        # If data is not set, it should be loaded from the path, but not until
        # the data is asked for.
        under_test = Credential(data=None, file_path=tdata_resource_file_path("keys/base_test_credential.json"))
        self.assertIsNone(under_test.data())
        under_test.lazy_reload()
        self.assertEqual({"test_key": "test_value"}, under_test.data())

        # if the path is invalid, it should error.
        under_test = Credential(data=None, file_path=tdata_resource_file_path("keys/FILE_DOES_NOT_EXIST.json"))
        with self.assertRaises(FileNotFoundError):
            under_test.lazy_reload()

        # We now permit in memory use to work.
        # under_test = Credential(data=None, file_path=None)
        # with self.assertRaises(FileBackedJsonObjectException):
        #     under_test.lazy_reload()

        # Behaves like lazy_load when there is data but no file - contiues
        # with in memory data
        under_test = Credential(data={"ctor_key": "ctor_value"}, file_path=None)
        under_test.lazy_reload()
        self.assertEqual({"ctor_key": "ctor_value"}, under_test.data())

        # But, if the file is set, problems with the file are an error, which
        # differs from lazy_load()
        under_test = Credential(
            data={"ctor_key": "ctor_value"}, file_path=tdata_resource_file_path("keys/FILE_DOES_NOT_EXIST.json")
        )
        with self.assertRaises(FileNotFoundError):
            under_test.lazy_reload()

    @freezegun.freeze_time(as_kwarg="frozen_time")
    def test_lazy_reload_reload_behavior(self, frozen_time):
        tmp_dir = tempfile.TemporaryDirectory()
        test_path = pathlib.Path(tmp_dir.name) / "lazy_reload_test.json"
        shutil.copyfile(tdata_resource_file_path("keys/base_test_credential.json"), test_path)

        # Freezegun doesn't seem to extend to file system recorded times,
        # so monkey-patch that throughout the test, too.
        # t0 - test prep
        t0 = datetime.datetime.now(tz=datetime.timezone.utc)
        os.utime(test_path, (t0.timestamp(), t0.timestamp()))

        # t1 - object under test created
        frozen_time.tick(2)
        under_test = Credential(data=None, file_path=None)

        # test that it doesn't load until asked for
        under_test.set_path(test_path)
        self.assertIsNone(under_test.data())
        test_key_value = under_test.lazy_get("test_key")
        self.assertEqual("test_value", test_key_value)

        # t2 - update the backing file via sideband.
        # Check that changing the file DOES trigger a reload.
        # (We use a separate instance of Credential as a convenient writer to the test file.)
        new_test_data = copy.deepcopy(under_test.data())
        new_test_data["test_key"] = "new_data"
        new_credential = Credential(data=new_test_data, file_path=test_path)
        t2 = frozen_time.tick(2)
        new_credential.save()
        os.utime(test_path, (t2.timestamp(), t2.timestamp()))

        # t3 - reload the time sometime later.
        # Check to make sure we now have the new data, and that the load time was updated
        t3 = frozen_time.tick(2)
        under_test.lazy_reload()
        test_key_value = under_test.lazy_get("test_key")
        self.assertEqual("new_data", test_key_value)
        self.assertEqual(int(t3.timestamp()), under_test._load_time)

        # t4 - lazy reload the file sometime later.
        # This should NOT trigger a reload, since the file has not changed.
        old_load_time = under_test._load_time
        frozen_time.tick(2)
        under_test.lazy_reload()
        new_load_time = under_test._load_time
        self.assertEqual(old_load_time, new_load_time)

    def test_save(self):
        tmp_dir = tempfile.TemporaryDirectory()
        test_path = pathlib.Path(tmp_dir.name) / "save_test.json"
        test_data = {"some_key": "some_data"}

        # invalid data refuses to save
        under_test = Credential(data=None, file_path=test_path)
        with self.assertRaises(FileBackedJsonObjectException):
            under_test.save()

        # Path must be set - This isn't true anymore. We now allow in memory use cases.
        # under_test = Credential(data=test_data, file_path=None)
        # with self.assertRaises(FileBackedJsonObjectException):
        #     under_test.save()

        # Validate data saved correctly, and can be reconstituted in an
        # equivalent credential object.
        under_test = Credential(data=test_data, file_path=test_path)
        under_test.save()
        test_reader = Credential(data=None, file_path=test_path)
        test_reader.load()
        self.assertEqual(test_data, test_reader.data())

    def test_getters_setters(self):
        test_path = pathlib.Path("/test/test_credential.json")
        test_data = {"some_key": "some_data"}

        under_test = Credential(data=None, file_path=None)
        self.assertIsNone(under_test.data())
        self.assertIsNone(under_test.path())
        under_test.set_path(test_path)
        under_test.set_data(test_data)
        self.assertEqual(test_data, under_test.data())
        self.assertEqual(test_path, under_test.path())

    @pytest.mark.skip("No test for SOPS encryption at this time")
    def test_sops_read(self):
        pass

    @pytest.mark.skip("No test for SOPS encryption at this time")
    def test_sops_write(self):
        pass

    def test_pretty_json(self):
        def _custom_json_class_dumper(obj):
            try:
                return obj.__json_pretty_dumps__()
            except Exception:
                return obj

        def pretty_obj_str(obj):
            return json.dumps(obj, indent=0, sort_keys=True, default=_custom_json_class_dumper)

        test_data = {
            "data_1": "some_data_1",
            "data_2": None,
            "data_3": {
                "data_3_1": "some_data_3_1",
                "data_3_2": None,
            },
        }

        # In memory pretty dump
        under_test = Credential(data=test_data, file_path=None)
        pretty_str = pretty_obj_str(under_test)
        self.assertEqual('{\n"data_1": "some_data_1",\n"data_3": {\n"data_3_1": "some_data_3_1"\n}\n}', pretty_str)

        # file backed pretty dump
        under_test = Credential(data=test_data, file_path=pathlib.Path("/unit/test/dummy.json"))
        pretty_str = pretty_obj_str(under_test)
        self.assertEqual(
            '{\n"_file_path": "/unit/test/dummy.json",\n"data_1": "some_data_1",\n"data_3": {\n"data_3_1": "some_data_3_1"\n}\n}',
            pretty_str,
        )


class TestFileBackedJsonObjectCustomStorage(unittest.TestCase):
    def setUp(self):
        # Note: FileBackedJsonObject binds an instance to a path, but the storage
        #   provider is _not_ bound by that cardinality.  Multiple FileBackedJsonObject
        #   instances can use the same instances of a storage provider.
        self.utest_path1 = pathlib.Path("/utest/custom_storage/path_1")
        self.utest_path2 = pathlib.Path("/utest/custom_storage/path_2")
        self.utest_path3 = pathlib.Path("/utest/custom_storage/path_3")
        self.initial_mock_storage_1 = {self.utest_path1: {"field_1": "stored_data_1"}}
        self.initial_mock_storage_2 = {}
        self.wrapped_storage_1 = unittest.mock.Mock(
            wraps=MockObjectStorageProvider(initial_mock_storage=self.initial_mock_storage_1)
        )
        self.wrapped_storage_2 = unittest.mock.Mock(
            wraps=MockObjectStorageProvider(initial_mock_storage=self.initial_mock_storage_2)
        )

    def test_custom_load_1(self):
        under_test = FileBackedJsonObject(
            data=None, file_path=self.utest_path1, storage_provider=self.wrapped_storage_1
        )
        self.assertIsNone(under_test.data())
        under_test.lazy_load()
        self.assertEqual(self.wrapped_storage_1.load_obj.call_count, 1)
        self.assertEqual(under_test.data(), self.initial_mock_storage_1[self.utest_path1])

    def test_custom_load_2(self):
        under_test = FileBackedJsonObject(
            data={"field_1": "testcase_initial_data_1"},
            file_path=self.utest_path1,
            storage_provider=self.wrapped_storage_1,
        )
        self.assertEqual(under_test.data(), {"field_1": "testcase_initial_data_1"})
        under_test.load()  # storage data newer than initial data.
        self.assertEqual(self.wrapped_storage_1.load_obj.call_count, 1)
        self.assertEqual(under_test.data(), self.initial_mock_storage_1[self.utest_path1])

    def test_custom_load_no_path_1(self):
        under_test = FileBackedJsonObject(data=None, file_path=None, storage_provider=self.wrapped_storage_1)
        under_test.load()
        self.assertIsNone(under_test.data())
        self.assertEqual(self.wrapped_storage_1.load_obj.call_count, 0)

    def test_custom_load_no_path_2(self):
        under_test = FileBackedJsonObject(
            data={"field_1": "testcase_initial_data_1"}, file_path=None, storage_provider=self.wrapped_storage_1
        )
        under_test.load()
        self.assertEqual(under_test.data(), {"field_1": "testcase_initial_data_1"})
        self.assertEqual(self.wrapped_storage_1.load_obj.call_count, 0)

    def test_custom_load_update_path(self):
        under_test = FileBackedJsonObject(
            data=None, file_path=self.utest_path1, storage_provider=self.wrapped_storage_1
        )
        under_test.load()
        under_test.set_path(self.utest_path3)
        under_test.save()

        # Peek into mock to see that the changes we intended happened.
        # Nothing changed our mock storage at path1, so it should be the same.
        self.assertEqual(
            self.wrapped_storage_1._peek()[self.utest_path1], self.wrapped_storage_1._peek()[self.utest_path3]
        )

    def test_custom_load_not_in_storage(self):
        under_test = FileBackedJsonObject(
            data=None, file_path=self.utest_path3, storage_provider=self.wrapped_storage_2
        )
        with self.assertRaises(MockStorageObjectNotFound):
            under_test.load()

    def test_update_storage_provider_save(self):
        under_test = FileBackedJsonObject(
            data=None, file_path=self.utest_path1, storage_provider=self.wrapped_storage_1
        )
        under_test.load()
        orig_loaded_data = copy.deepcopy(under_test.data())
        under_test.set_path(self.utest_path3)
        under_test.set_storage_provider(self.wrapped_storage_2)
        self.assertEqual(under_test.storage_provider(), self.wrapped_storage_2)
        under_test.save()

        # a new object in the same storage realm gets the data from the old
        # objet writing it to the new realm after updating storage params.
        # This probes that the storage provider update happened as expected.
        # It is outside the scope of this test that custom providers work
        # as expected. Storage semantics may vary between providers.
        under_test_new = FileBackedJsonObject(
            data=None, file_path=self.utest_path3, storage_provider=self.wrapped_storage_2
        )
        under_test_new.lazy_load()
        self.assertEqual(under_test_new.data(), orig_loaded_data)

    def test_custom_save_path_saves(self):
        test_data = {"field_1": "test_custom_save_path_saves data"}
        under_test = FileBackedJsonObject(
            data=test_data, file_path=self.utest_path2, storage_provider=self.wrapped_storage_1
        )
        under_test.save()
        self.assertEqual(self.wrapped_storage_1.save_obj.call_count, 1)

        under_test_new = FileBackedJsonObject(
            data=None, file_path=self.utest_path2, storage_provider=self.wrapped_storage_1
        )
        under_test_new.load()
        self.assertEqual(under_test.data(), test_data)
        self.assertEqual(under_test.data(), under_test_new.data())

    def test_custom_save_no_path_does_not_save(self):
        test_data = {"field_1": "test_custom_save_no_path_does_not_save data"}
        under_test = FileBackedJsonObject(data=test_data, file_path=None, storage_provider=self.wrapped_storage_1)
        under_test.save()
        self.assertEqual(self.wrapped_storage_1.save_obj.call_count, 0)

        under_test_new = FileBackedJsonObject(
            data=None, file_path=self.utest_path2, storage_provider=self.wrapped_storage_1
        )
        with self.assertRaises(MockStorageObjectNotFound):
            under_test_new.load()

        self.assertIsNone(under_test_new.data())

    def test_check_if_in_storage_none(self):
        under_test = FileBackedJsonObject(file_path=None, storage_provider=self.wrapped_storage_1)
        self.assertFalse(under_test.is_persisted_to_storage())

    def test_check_if_in_storage_path_exists(self):
        under_test = FileBackedJsonObject(file_path=self.utest_path1, storage_provider=self.wrapped_storage_1)
        self.assertTrue(under_test.is_persisted_to_storage())

    def test_check_if_in_storage_path_does_not_exist(self):
        under_test = FileBackedJsonObject(file_path=self.utest_path3, storage_provider=self.wrapped_storage_1)
        self.assertFalse(under_test.is_persisted_to_storage())

    def test_check_if_in_storage_path_does_not_exist_with_init_data(self):
        test_data = {"field_1": "test_custom_save_no_path_does_not_save data"}
        under_test = FileBackedJsonObject(
            data=test_data, file_path=self.utest_path3, storage_provider=self.wrapped_storage_1
        )
        self.assertFalse(under_test.is_persisted_to_storage())
        under_test.save()
        self.assertTrue(under_test.is_persisted_to_storage())
