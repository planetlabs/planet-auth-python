# Copyright 2024 Planet Labs PBC.
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
import os
import pathlib
import shutil
import tempfile
import freezegun
import unittest
import pytest

from planet_auth.credential import Credential
from planet_auth.util import FileBackedJsonObjectException
from tests.test_planet_auth.util import tdata_resource_file_path


# This is essentially a test of the base class, FileBackedJsonObject.
# It's just that FileBackedJsonObject was initially written for credential
# handling, and then we expended its use.
class TestCredential(unittest.TestCase):
    def setUp(self):
        # The interactions of freezegun and the filesystem mtimes have been... quirky.
        # This seems to help.
        os.environ["TZ"] = "UTC"

    def test_set_data_asserts_valid(self):
        under_test = Credential(data=None, file_path=None)
        with self.assertRaises(FileBackedJsonObjectException):
            under_test.set_data(None)

        under_test.set_data({})

    def test_load(self):
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
            # let underlying exception pass to the application
            under_test.load()

        self.assertEqual({"test_key": "test_value"}, under_test.data())

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
