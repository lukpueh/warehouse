# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import glob
import os.path
import shutil
import warnings

from contextlib import contextmanager

from securesystemslib.exceptions import StorageError
from securesystemslib.interface import (
    import_ed25519_privatekey_from_file,
    import_ed25519_publickey_from_file,
)
from zope.interface import implementer

from warehouse.tuf.constants import Role
from warehouse.tuf.interfaces import IKeyService, IStorageService
from warehouse.tuf.tasks import add_target
from warehouse.tuf.utils import GCSBackend, make_fileinfo


class InsecureKeyWarning(UserWarning):
    pass


@implementer(IKeyService)
class LocalKeyService:
    def __init__(self, key_path, request):
        warnings.warn(
            "LocalKeyService is intended only for use in development, you "
            "should not use it in production to avoid unnecessary key exposure.",
            InsecureKeyWarning,
        )

        self._key_path = key_path
        self._request = request

    @classmethod
    def create_service(cls, context, request):
        return cls(request.registry.settings["tuf.key.path"], request)

    def get(self, rolename, key_type):
        """
        Gets the Key based on role name and key type

        Args:
            rolename: role name
            key_type: 'private' or 'public'

        """
        if key_type == "private":
            privkey_path = os.path.join(self._key_path, f"{rolename}")
            key_sslib = import_ed25519_privatekey_from_file(
                privkey_path, self._request.registry.settings[f"tuf.{rolename}.secret"]
            )
        elif key_type == "public":
            pubkey_path = os.path.join(self._key_path, f"{rolename}.pub")
            key_sslib = import_ed25519_publickey_from_file(pubkey_path)
        else:
            raise ValueError(f"invalid key_type '{key_type}'")

        return key_sslib


@implementer(IStorageService)
class LocalStorageService:
    def __init__(self, repo_path, executor):
        self._repo_path = repo_path
        self._executor = executor

    @classmethod
    def create_service(cls, context, request):
        return cls(
            request.registry.settings["tuf.repo.path"],
            request.task(add_target).delay,
        )

    @contextmanager
    def get(self, role, version=None):
        if role == Role.TIMESTAMP.value:
            filename = os.path.join(self._repo_path, f"{role}.json")
        else:
            if version is None:
                filenames = glob.glob(os.path.join(self._repo_path, f"*.{role}.json"))
                versions = [
                    int(name.split("/")[-1].split(".", 1)[0]) for name in filenames
                ]
                try:
                    version = max(versions)
                except ValueError:
                    version = 1

            filename = os.path.join(self._repo_path, f"{version}.{role}.json")
            if not os.path.isfile(filename):
                filename = os.path.join(self._repo_path, f"{role}.json")

        file_object = None
        try:
            file_object = open(filename, "rb")
            yield file_object
        except OSError:
            raise StorageError(f"Can't open {filename}")
        finally:
            if file_object is not None:
                file_object.close()

    def put(self, file_object, filename):
        file_path = os.path.join(self._repo_path, filename)
        if not file_object.closed:
            file_object.seek(0)

        try:
            with open(file_path, "wb") as destination_file:
                shutil.copyfileobj(file_object, destination_file)
                destination_file.flush()
                os.fsync(destination_file.fileno())
        except OSError:
            raise StorageError(f"Can't write file {filename}")

    def store(self, file_object, filename):
        self.put(file_object, filename)

    def load_repository(self):
        return repository_tool.load_repository(self._repo_path)

    def add_target(self, file, custom=None):
        fileinfo = make_fileinfo(file, custom=custom)
        self._executor(file.path, fileinfo)


@implementer(IStorageService)
class GCSStorageService:
    def __init__(self, request):
        self._store = GCSBackend(request)

    @classmethod
    def create_service(cls, context, request):
        return cls(request)

    def get_backend(self):
        return self._store
