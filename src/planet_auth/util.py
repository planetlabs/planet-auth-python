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

import json
import os
import pathlib
import stat
import subprocess
import time
from typing import Any, Dict, Optional

import planet_auth.logging.auth_logger
from planet_auth.auth_exception import AuthException

auth_logger = planet_auth.logging.auth_logger.getAuthLogger()


def parse_content_type(content_type: str) -> Dict[str, Optional[str]]:
    result: Dict[str, Optional[str]] = {
        "content-type": None,
    }
    if content_type:
        ct = content_type.split(";")
        result["content-type"] = ct.pop(0).strip()
        if not result["content-type"]:
            # Don't return blank strings
            result["content-type"] = None
        for subfield in ct:
            sf = subfield.split("=", 1)
            if sf[0].strip():
                if len(sf) == 1:
                    result[sf[0].strip()] = None
                else:
                    result[sf[0].strip()] = sf[1].strip()
    return result


class FileBackedJsonObjectException(AuthException):
    """
    Exception indicating a problem with a file backed json object.
    """

    def __init__(self, file_path=None, **kwargs):
        super().__init__(**kwargs)
        self._file_path = file_path

    def set_file_path(self, file_path):
        self._file_path = file_path

    def __str__(self):
        if self._file_path:
            return "{} (File: {})".format(super().__str__(), self._file_path)
        else:
            return super().__str__()


class FileBackedJsonObject:
    """
    A file backed json object for storing information. Base class provides
    lazy loading and validation before saving or setting the data.  Derived
    classes should provide type specific validation and convenience data
    accessors. The intent is that this provides a way to have an object
    backed by a file, and rails are in place to prevent invalid data from
    being saved or used.

    Data is allowed to be initialized as None so that JIT load() use cases
    can be supported with the data not being read until needed.  Care
    should be taken when constructing from an in-memory data value, as
    leaf class data validation is not performed during construction.

    The None data structure is treated as a special case, and means that the
    class has been constructed, but the data has never been set.  Once data has
    been set, either by calling set_data() or by loading data from a file,
    it is only permitted to be set to valid values.

    Saving to the backing is also optional. Uses in this way, this class
    behaves as a validating in-memory json object holder.  To disable
    on disk saving, construct objects with a None file_path.
    """

    # TODO: Consider a shift to a schema framework for validation?
    #       E.g. schematics Model.

    def __init__(self, data: Optional[Dict[str, Any]] = None, file_path: Optional[pathlib.Path] = None):
        # Derived classes should not do anything to make the base class's
        # self._data non-falsey based on empty init to keep JIT lazy_load()
        # use cases from file backed object working as expected.
        self._file_path = pathlib.Path(file_path) if file_path else None
        self._load_time = 0
        self._data: Dict[str, Any] = data  # type: ignore
        if data:
            # We used to do a self.check_data(data) to try and prevent
            # invalid data from being constructed, but that's dubious in
            # a base class when the goal of check_data() was to enforce leaf
            # class requirements. The leaf classes are likely not fully
            # constructed at this point.
            # self.check_data(data)
            self._load_time = int(time.time())

    def __json_pretty_dumps__(self):
        # This is just to work with pretty-print object dumper in
        # the plauth CLI.  We prefer to not strip the null/None
        # entries when we dump to a file so the act as guideposts
        # to folks manually editing the file. And, when we dump to
        # a file we do not write the path of the file into the
        # file - it's self-evident, and would be over constrained.
        def _del_none(d):
            for key, value in list(d.items()):
                if value is None:
                    del d[key]
                elif isinstance(value, dict):
                    _del_none(value)
            return d

        json_dumps = self._data.copy()
        json_dumps["_file_path"] = str(self._file_path)
        _del_none(json_dumps)
        return json_dumps

    def path(self) -> Optional[pathlib.Path]:
        """
        Retrieve the currently configured path for saved data.
        """
        return self._file_path

    def set_path(self, file_path):
        """
        Set the path for saved data.
        """
        self._file_path = pathlib.Path(file_path) if file_path else None

    def data(self):
        """
        Retrieve the current data that is in memory. This method will
        not load the data from storage.
        """
        return self._data

    def update_data(self, sparse_update_data):
        """
        Update the data set with the provided sparse update.
        Updates that result in a data-set that will not pass
        check_data() will be rejected, and the will be unchanged.
        """
        old_data = self._data
        if old_data:
            new_data = old_data.copy()
            new_data.update(sparse_update_data)
        else:
            new_data = sparse_update_data
        self.set_data(new_data)

    def set_data(self, data):
        """
        Set the current in memory data. The data will be checked for validity
        before in memory values are set.  Invalid data will result in an exception
        being thrown and no change being made to the in memory object.
        """
        self.check_data(data)
        self._data = data.copy()
        self._load_time = int(time.time())

    def check_data(self, data):
        """
        Check that the provided data is valid.  Throws an exception if the
        data is not valid. This allows the base class to refuse to store or
        use data, while leaving it to child classes to know what constitutes
        "valid". Child classes should raise FileBackedJsonObjectException
        exception.

        Child classes should override this method as required to do more
        application specific data integrity checks. They should also
        call validation on their base classes so that all layers of
        validation are performed.

        The base assertion is that the data structure has been set.
        It may be empty, but may not be None.  The None data structure
        is treated as a special case, and means that the class has been
        constructed, but the data has never been set.  Once data has
        been set, it is only permitted to be set to valid values.
        The intent of this behavior is to support JIT loading semantics.
        """
        # Allow empty, but not None
        if not data:
            if data == {}:
                return
            raise FileBackedJsonObjectException(
                message="None is not valid data for {} type, backed by file '{}'".format(
                    self.__class__.__name__, self._file_path
                )
            )

    def check(self):
        """
        Run check_data against our current state.  An exception will be thrown
        if the current data is found to be invalid.  Subclasses should not
        need to override this method ,as they are expected to implement
        check_data().  This method will not perform a load() before checking
        the data. That is considered an application responsibility.
        """
        try:
            self.check_data(self._data)
        except FileBackedJsonObjectException as e:
            if self._file_path:
                e.set_file_path(self._file_path)
            raise e

    def save(self):
        """
        Save the data to disk.  If the data is invalid according
        to the child class's check_data() method, the data will
        not be saved and an error will be thrown.
        If the path has not been set, nothing will be saved
        to disk, and this will silently succeed. This is to
        allow for transparent in memory only use cases.
        """
        self.check_data(self._data)

        if not self._file_path:
            # We now allow for in memory operation
            # raise FileBackedJsonObjectException(message="Cannot save data to file. File path is not set.")
            return

        self._file_path.parent.mkdir(parents=True, exist_ok=True)
        if self._is_sops_path(self._file_path):
            self._write_json_sops(self._file_path, self._data)
        else:
            self._write_json(self._file_path, self._data)

        self._load_time = int(time.time())

    def is_loaded(self) -> bool:
        return bool(self._data)

    def load(self):
        """
        Force a data load from disk.  If the file path has not been set,
        this will be a no-op to allow for in memory operations.

        If the data loaded from disk is invalid, an will be thrown, and the
        currently held data will be left unchanged.  When in memory
        data is invalid and no file path has been set, an error IS NOT
        thrown - there would be nothing to fall back to. In memory users
        should expect to call check() or check_data() on their own.
        """
        if not self._file_path:
            # raise FileBackedJsonObjectException(message="Cannot load data from file. File path is not set.")
            return  # we now allow in memory operation.  Should we raise an error if the current data is invalid?

        if self._is_sops_path(self._file_path):
            new_data = self._read_json_sops(self._file_path)
        else:
            new_data = self._read_json(self._file_path)

        self.check_data(new_data)

        self._data = new_data
        self._load_time = int(time.time())

    def lazy_load(self):
        """
        Lazy load the data from disk.

        If the data has already been set, whether by an the constructor, an
        explicit set_data(), or a previous load from disk, no attempt is made
        to refresh the data.  Object will behave as an in memory object.

        If the data is not set, it will attempt to load the data from disk.
        An error will be thrown if the loaded data is invalid, the file has
        not been set, or the file has been set to a non-existent path.

        For updating the data from disk even if an in memory copy exists,
        see lazy_reload().

        Users may always force a load at any time by calling load()
        """
        if not self.is_loaded():
            self.load()

    def lazy_reload(self):
        """
        Lazy reload the data from disk.

        If the data is set, a reload will be attempted if the data on disk
        appears to be newer if a path is set.  if a path is not set, no
        attempt will be made to load the data.

        If the data is not set, an error will be thrown if the loaded data is
        invalid, the file has not been set, or the file has been set to a
        non-existent path.
        """
        if not self.is_loaded():
            # No data, behave like load()
            self.load()
            return

        if not self._file_path:
            # Have data. No path. Continue with in memory value.
            return

        if int(self._file_path.stat().st_mtime) > self._load_time:
            self.load()

    def lazy_get(self, field):
        """
        Lazy load the data and retrieve the requested field.
        """
        self.lazy_load()
        return self._data.get(field)

    # This is probably a bad idea, since it would encourage development
    # that makes it more likely that data may change in between get()'s
    # of multiple fields in the same object, leading to inconsistency.
    # Only the application knows what transaction boundaries are.
    # def lazy_reload_get(self, field):
    #    self.lazy_reload()
    #    if self._data:
    #        return self._data.get(field)
    #    return None

    @staticmethod
    def _read_json(data_file):
        auth_logger.debug(msg="Loading JSON data from file {}".format(data_file))
        with open(data_file, mode="r", encoding="UTF-8") as file_r:
            return json.load(file_r)

    @staticmethod
    def _read_json_sops(data_file):
        auth_logger.debug(msg="Loading JSON data from SOPS encrypted file {}".format(data_file))
        data_b = subprocess.check_output(["sops", "-d", data_file])
        return json.loads(data_b)

    @staticmethod
    def _write_json(data_file, data):
        auth_logger.debug(msg="Writing JSON data to file {}".format(data_file))
        with open(data_file, mode="w", encoding="UTF-8") as file_w:
            os.chmod(data_file, stat.S_IREAD | stat.S_IWRITE)
            _no_none_data = {key: value for key, value in data.items() if value is not None}
            file_w.write(json.dumps(_no_none_data, indent=2, sort_keys=True))

    @staticmethod
    def _write_json_sops(data_file, data):
        # TODO: It would be nice to only encrypt the fields we need to.
        #       It would be a better user experience.  Probably the thing to
        #       do is let derived classes tell us what fields are to
        #       be encrypted.
        # Seems to blow up. I guess we have to write clear text,
        # then encrypt in place?
        # with io.StringIO(json.dumps(data)) as data_f:
        #     subprocess.check_call(
        #         ['sops', '-e', '--input-type', 'json', '--output-type',
        #          'json', '--output', data_file, '/dev/stdin'],
        #         stdin=data_f)
        auth_logger.debug(msg="Writing JSON data to SOPS encrypted file {}".format(data_file))
        FileBackedJsonObject._write_json(data_file, data)
        subprocess.check_call(["sops", "-e", "--input-type", "json", "--output-type", "json", "-i", data_file])

    @staticmethod
    def _is_sops_path(file_path):
        # FIXME?: Could be ".json.sops", or ".sops.json", depending on file
        #         level or field level encryption, respectively.  We currently
        #         only look for and support field level encryption in json
        #         files with a ".sops.json" suffix.
        return bool(file_path.suffixes == [".sops", ".json"])
