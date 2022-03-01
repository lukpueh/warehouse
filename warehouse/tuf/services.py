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


import datetime
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

from warehouse.config import Environment
from warehouse.tuf.constants import BIN_N_COUNT, Role
from warehouse.tuf.hash_bins import HashBins
from warehouse.tuf.interfaces import IKeyService, IRepositoryService, IStorageService
from warehouse.tuf.repository import (
    TOP_LEVEL_ROLE_NAMES,
    MetadataRepository,
    RolesPayload,
    TargetsPayload,
)


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
    def __init__(self, repo_path):
        self._repo_path = repo_path

    @classmethod
    def create_service(cls, context, request):
        return cls(
            request.registry.settings["tuf.repo.path"],
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

    def _get_hash_bins(self):

        if self._request.registry.settings["warehouse.env"] == Environment.development:
            number_of_bins = 32
        else:
            number_of_bins = BIN_N_COUNT

        return HashBins(number_of_bins)

    def _make_fileinfo(self, file, custom=None):
        """
        Create a TUF-compliant "fileinfo" dictionary suitable for addition to a
        delegated bin.

        The optional "custom" kwarg can be used to supply additional custom
        metadata (e.g., metadata for indicating backsigning).
        """
        hashes = {"blake2b-256": file.blake2_256_digest}
        fileinfo = dict()
        fileinfo["length"] = file.size
        fileinfo["hashes"] = hashes
        if custom:
            fileinfo["custom"] = custom

        return fileinfo

    def _set_expiration_for_role(self, role_name):
        # If we're initializing TUF for development purposes, give
        # every role a long expiration time so that developers don't have to
        # continually re-initialize it.
        if self._request.registry.settings["warehouse.env"] == Environment.development:
            return datetime.datetime.now().replace(microsecond=0) + datetime.timedelta(
                seconds=self._request.registry.settings[
                    "tuf.development_metadata_expiry"
                ]
            )
        else:
            return datetime.datetime.now().replace(microsecond=0) + datetime.timedelta(
                seconds=self._request.registry.settings[f"tuf.{role_name}.expiry"]
            )

    def init_repository(self):
        metadata_repository = MetadataRepository(
            self._storage_backend, self._key_storage_backend
        )

        if metadata_repository.is_initialized:
            raise FileExistsError("TUF Metadata Repository files already exists.")

        top_roles_payload = dict()
        for role in TOP_LEVEL_ROLE_NAMES:
            top_roles_payload[role] = RolesPayload(
                expiration=self._set_expiration_for_role(role),
                threshold=self._request.registry.settings[f"tuf.{role}.threshold"],
                keys=self._key_storage_backend.get(role, "private"),
            )

        metadata_repository.initialize(top_roles_payload, True)

    def init_targets_delegation(self):
        """
        Delegate targets role bins further delegates to the bin-n roles,
        which sign for all distribution files belonging to registered PyPI
        projects.
        """

        hash_bins = self._get_hash_bins()
        metadata_repository = MetadataRepository(
            self._storage_backend, self._key_storage_backend
        )

        # Delegate first targets -> BINS
        delegate_roles_payload = dict()
        delegate_roles_payload["targets"] = list()
        delegate_roles_payload["targets"].append(
            RolesPayload(
                expiration=self._set_expiration_for_role(Role.BINS.value),
                threshold=self._request.registry.settings[
                    f"tuf.{Role.BINS.value}.threshold"
                ],
                keys=self._key_storage_backend.get(Role.BINS.value, "private"),
                delegation_role=Role.BINS.value,
                paths=["*/*/*/*"],
            )
        )

        metadata_repository.delegate_targets_roles(
            delegate_roles_payload,
            self._set_expiration_for_role(Role.TIMESTAMP.value),
            self._set_expiration_for_role(Role.SNAPSHOT.value),
        )

        # Delegates all BINS -> BIN_N (Hash bin prefixes)
        delegate_roles_payload = dict()
        delegate_roles_payload[Role.BINS.value] = list()
        for bin_n_name, bin_n_hash_prefixes in hash_bins.generate():
            delegate_roles_payload[Role.BINS.value].append(
                RolesPayload(
                    expiration=self._set_expiration_for_role(Role.BIN_N.value),
                    threshold=self._request.registry.settings[
                        f"tuf.{Role.BIN_N.value}.threshold"
                    ],
                    keys=self._key_storage_backend.get(Role.BIN_N.value, "private"),
                    delegation_role=bin_n_name,
                    path_hash_prefixes=bin_n_hash_prefixes,
                )
            )

        metadata_repository.delegate_targets_roles(
            delegate_roles_payload,
            self._set_expiration_for_role(Role.TIMESTAMP.value),
            self._set_expiration_for_role(Role.SNAPSHOT.value),
        )

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
            snapshot_expires=self._set_expiration_for_role(
                self._request, Role.SNAPSHOT.value
            ),
            snapshot_metadata=snapshot_metadata,
            store=True,
        )

        # 4. Bump Snapshot role metadata using Timestamp metadata.
        metadata_repository.timestamp_bump_version(
            snapshot_version=snapshot_metadata.signed.version,
            timestamp_expires=self._set_expiration_for_role(
                self._request, Role.TIMESTAMP.value
            ),
            store=True,
        )

    def bump_bin_n_roles(self):
        """
        Bump all BIN-N delegate roles Metadata
        """
        # Bumping all of the delegated bin roles in the TUF repository involves
        # the following steps:
        # 1. Metadata Repository.
        # 2. Load Snapshot role.
        # 3. Load BINS role.
        # 4. For each BIN-N role (hash bin) in BINS, fetch the
        #    role, bump, write back to the repo and update Snapshot role MetaFile.
        # 5. Bump Snapshot and write back to repository.
        # 6. Bump Timestamp role (using updated Snapshot) and write back to
        #    repository.

        # 1. Metadata Repository
        metadata_repository = MetadataRepository(
            self._storage_backend, self._key_storage_backend
        )

        # 2. Load Snapshot role.
        snapshot_metadata = metadata_repository.load_role(Role.SNAPSHOT.value)

        # 3 Load BINS role.
        bins_metadata = metadata_repository.load_role(Role.BINS.value)

        # 4. Fore each delegated hashed bin target role, bump and update Snapshot
        for role in bins_metadata.signed.delegations.roles.keys():
            role_metadata = metadata_repository.load_role(role)
            metadata_repository.bump_role_version(
                rolename=role,
                role_metadata=role_metadata,
                role_expires=self._set_expiration_for_role(Role.BINS.value),
                snapshot_metadata=snapshot_metadata,
                key_rolename=Role.BIN_N.value,
                store=True,
            )
            snapshot_metadata = metadata_repository.snapshot_update_meta(
                role, role_metadata.signed.version, snapshot_metadata
            )

        # 5. Bump Snapshot with updated metadata
        snapshot_metadata = metadata_repository.snapshot_bump_version(
            snapshot_expires=self._set_expiration_for_role(
                self._request, Role.SNAPSHOT.value
            ),
            snapshot_metadata=snapshot_metadata,
            store=True,
        )

        # 6. Bump Timestamp with updated Snapshot metadata
        metadata_repository.timestamp_bump_version(
            snapshot_version=snapshot_metadata.signed.version,
            timestamp_expires=self._set_expiration_for_role(
                self._request, Role.TIMESTAMP.value
            ),
            store=True,
        )

    def add_hashed_targets(self, targets):
        """
        Add Target File
        """
        hash_bins = self._get_hash_bins()
        targets_payload = dict()
        for target in targets:
            fileinfo = target.get("info")
            filepath = target.get("path")
            delegated_role_bin_name = hash_bins.get_delegate(filepath)
            target_file = TargetsPayload(fileinfo, filepath)
            if targets_payload.get(delegated_role_bin_name) is None:
                targets_payload[delegated_role_bin_name] = list()

            targets_payload[delegated_role_bin_name].append(target_file)

        metadata_repository = MetadataRepository(
            self._storage_backend, self._key_storage_backend
        )

        metadata_repository.add_targets(
            targets_payload,
            self._set_expiration_for_role(Role.TIMESTAMP.value),
            self._set_expiration_for_role(Role.SNAPSHOT.value),
        )
