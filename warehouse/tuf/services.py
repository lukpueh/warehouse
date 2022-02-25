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
from warehouse.tuf.interfaces import IKeyService, IRepositoryService, IStorageService
from warehouse.tuf.repository import MetadataRepository, TargetsPayload
from warehouse.tuf.tasks import add_target
from warehouse.tuf.utils import GCSBackend, make_fileinfo, set_expiration_for_role


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
            privkey_path = os.path.join(self._key_path, f"{rolename}*")
            role_keys = glob.glob(privkey_path)
            keys_sslib = [
                import_ed25519_privatekey_from_file(
                    key, self._request.registry.settings[f"tuf.{rolename}.secret"]
                )
                for key in role_keys
                if "pub" not in key
            ]
        elif key_type == "public":
            pubkey_path = os.path.join(self._key_path, f"{rolename}*.pub")
            role_keys = glob.glob(pubkey_path)
            keys_sslib = [import_ed25519_publickey_from_file(key) for key in role_keys]
        else:
            raise ValueError(f"invalid key_type '{key_type}'")

        return keys_sslib


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


@implementer(IRepositoryService)
class LocalRepositoryService:
    def __init__(self, storage_service, key_service, request):
        warnings.warn(
            "LocalRepositoryService is intended only for use in development, you "
            "should not use it in production to avoid unnecessary key exposure.",
            InsecureKeyWarning,
        )
        self._storage_backend = storage_service
        self._key_storage_backend = key_service
        self._request = request

    @classmethod
    def create_service(cls, context, request):
        storage_service = request.find_service(IStorageService)
        key_service = request.find_service(IKeyService)
        return cls(storage_service, key_service, request)

    def bump_snapshot(self):
        """
        Bump Snapshot Role Metadata
        """
        # Bumping the Snapshot role involves the following steps:
        # 1. Initiate Metadata Repository.
        # 2. Load the Snapshot Role.
        # 3. Bump Snapshot role (and write to the Storage).
        # 4. Bump Timestamp role using the new Snapshot Metadata.
        # 1. Metadata Repository.
        metadata_repository = MetadataRepository(
            self._storage_backend, self._key_storage_backend
        )

        # 2. Snapshot role metadata.
        snapshot_metadata = metadata_repository.load_role(Role.SNAPSHOT.value)

        # 3. Bump Snapshot role metadata.
        snapshot_metadata = metadata_repository.snapshot_bump_version(
            snapshot_expires=set_expiration_for_role(
                self._request, Role.SNAPSHOT.value
            ),
            snapshot_metadata=snapshot_metadata,
            store=True,
        )

        # 4. Bump Snapshot role etadata using Timestamp metadata.
        metadata_repository.timestamp_bump_version(
            snapshot_version=snapshot_metadata.signed.version,
            timestamp_expires=set_expiration_for_role(
                self._request, Role.TIMESTAMP.value
            ),
            store=True,
        )

    def bump_bins_ns(self):
        """
        Bump all BIN-S delegate roles Metadata
        """
        # Bumping all of the delegated bin roles in the TUF repository involves
        # the following steps:
        # 1. Metadata Repository.
        # 2. Load Snapshot role.
        # 3. Load BIN-S role.
        # 4. For each delegated hashed bin targets role in the BIN-S, fetch the
        #    role, bump, write back to the repo and update Snapshot role MetaFile.
        # 5. Bump BIN-S and write back to repository.
        # 6. Bump Snapshot and write back to repository.
        # 7. Bump Timestamp role (using updated Snapshot) and write back to
        #    repository.

        # 1. Metadata Repository
        metadata_repository = MetadataRepository(
            self._storage_backend, self._key_storage_backend
        )

        # 2. Load Snapshot role.
        snapshot_metadata = metadata_repository.load_role(Role.SNAPSHOT.value)

        # 3 Load BIN-S role.
        bins_metadata = metadata_repository.load_role(Role.BINS.value)

        # 4. Fore each delegated hashed bin target role, bump and update Snapshot
        for role in bins_metadata.signed.delegations.roles.keys():
            role_metadata = metadata_repository.load_role(role)
            metadata_repository.bump_role_version(
                rolename=role,
                role_metadata=role_metadata,
                role_expires=set_expiration_for_role(self._request, Role.BINS.value),
                snapshot_metadata=snapshot_metadata,
                key_rolename=Role.BIN_N.value,
                store=True,
            )
            snapshot_metadata = metadata_repository.snapshot_update_meta(
                role, role_metadata.signed.version, snapshot_metadata
            )

        # 5. Bump BIN-S with updated metadata
        snapshot_metadata = metadata_repository.bump_role_version(
            rolename=Role.BINS.value,
            role_metadata=bins_metadata,
            role_expires=set_expiration_for_role(self._request, Role.BINS.value),
            snapshot_metadata=snapshot_metadata,
            key_rolename=None,
            store=True,
        )

        # 6. Bump Snapshot with updated metadata
        snapshot_metadata = metadata_repository.snapshot_bump_version(
            snapshot_expires=set_expiration_for_role(
                self._request, Role.SNAPSHOT.value
            ),
            snapshot_metadata=snapshot_metadata,
            store=True,
        )

        # Bump Timestamp with updated Snapshot metadata
        metadata_repository.timestamp_bump_version(
            snapshot_version=snapshot_metadata.signed.version,
            timestamp_expires=set_expiration_for_role(
                self._request, Role.TIMESTAMP.value
            ),
            store=True,
        )

    def add_target(self, path, fileinfo, rolename):
        """
        Add Target File
        """

        # The Repository toll accept a payload with multiple targets file for a
        # single delegated hashed bin role.
        payload = {rolename: [TargetsPayload(fileinfo, path)]}

        metadata_repository = MetadataRepository(
            self._storage_backend, self._key_storage_backend
        )
        metadata_repository.add_targets(
            payload=payload,
            timestamp_expires=set_expiration_for_role(
                self._request, Role.TIMESTAMP.value
            ),
            snapshot_expires=set_expiration_for_role(
                self._request, Role.SNAPSHOT.value
            ),
        )
