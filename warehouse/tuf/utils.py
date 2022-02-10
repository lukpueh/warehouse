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
import os

from contextlib import contextmanager
from io import BytesIO

from google.cloud.exceptions import GoogleCloudError, NotFound
from securesystemslib.exceptions import StorageError
from securesystemslib.interface import generate_and_write_ed25519_keypair
from securesystemslib.storage import FilesystemBackend, StorageBackendInterface

from warehouse.config import Environment
from warehouse.tuf.constants import Role
from warehouse.tuf.repository import MetadataRepository, TargetsPayload


def set_expiration_for_role(config, role_name):
    # If we're initializing TUF for development purposes, give
    # every role a long expiration time so that developers don't have to
    # continually re-initialize it.
    if config.registry.settings["warehouse.env"] == Environment.development:
        return datetime.datetime.now().replace(microsecond=0) + datetime.timedelta(
            seconds=config.registry.settings["tuf.development_metadata_expiry"]
        )
    else:
        return datetime.datetime.now().replace(microsecond=0) + datetime.timedelta(
            seconds=config.registry.settings[f"tuf.{role_name}.expiry"]
        )


def create_dev_keys(password, filepath) -> None:
    generate_and_write_ed25519_keypair(password, filepath=filepath)


def make_fileinfo(file, custom=None):
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


def repository_bump_snapshot(config, storage_service, key_service):
    # Bumping the Snapshot role involves the following steps:
    # 1. Initiate Metadata Repository.
    # 2. Load the Snapshot Role.
    # 3. Bump Snapshot role (and write to the Storage).
    # 4. Bump Timestamp role using the new Snapshot Metadata.

    # 1. Metadata Repository.
    metadata_repository = MetadataRepository(storage_service, key_service)

    # 2. Snapshot role metadata.
    snapshot_metadata = metadata_repository.load_role(Role.SNAPSHOT.value)

    # 3. Bump Snapshot role metadata.
    snapshot_metadata = metadata_repository.snapshot_bump_version(
        snapshot_expires=set_expiration_for_role(config, Role.SNAPSHOT.value),
        snapshot_metadata=snapshot_metadata,
        store=True,
    )

    # 4. Bump Snapshot role etadata using Timestamp metadata.
    metadata_repository.timestamp_bump_version(
        snapshot_version=snapshot_metadata.signed.version,
        timestamp_expires=set_expiration_for_role(config, Role.TIMESTAMP.value),
        store=True,
    )


def repository_bump_bins_ns(config, storage_service, key_service):
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
    metadata_repository = MetadataRepository(storage_service, key_service)

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
            role_expires=set_expiration_for_role(config, Role.BINS.value),
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
        role_expires=set_expiration_for_role(config, Role.BINS.value),
        snapshot_metadata=snapshot_metadata,
        key_rolename=None,
        store=True,
    )

    # 6. Bump Snapshot with updated metadata
    snapshot_metadata = metadata_repository.snapshot_bump_version(
        snapshot_expires=set_expiration_for_role(config, Role.SNAPSHOT.value),
        snapshot_metadata=snapshot_metadata,
        store=True,
    )

    # Bump Timestamp with updated Snapshot metadata
    metadata_repository.timestamp_bump_version(
        snapshot_expires=snapshot_metadata.signed.version,
        timestamp_expires=set_expiration_for_role(config, Role.TIMESTAMP.value),
        store=True,
    )


def repository_add_target(config, fileinfo, path, storage_service, key_service):
    payload = [TargetsPayload(fileinfo, path)]

    metadata_repository = MetadataRepository(storage_service, key_service)
    metadata_repository.add_targets(
        payload=payload,
        timestamp_expires=set_expiration_for_role(config, Role.TIMESTAMP.value),
        snapshot_expires=set_expiration_for_role(config, Role.SNAPSHOT.value),
    )


class LocalBackend(StorageBackendInterface):
    def __init__(self, request):
        self._filesystem_backend = FilesystemBackend()
        self._repo_path = os.path.join(
            request.registry.settings["tuf.repo.path"], "metadata.staged"
        )

    def get(self, filepath):
        return self._filesystem_backend.get(os.path.join(self._repo_path, filepath))

    def put(self, fileobj, filepath):
        return self._filesystem_backend.put(
            fileobj, os.path.join(self._repo_path, filepath)
        )

    def remove(self, filepath):
        return self._filesystem_backend.remove(os.path.join(self._repo_path, filepath))

    def getsize(self, filepath):
        return self._filesystem_backend.getsize(os.path.join(self._repo_path, filepath))

    def create_folder(self, filepath):
        return self._filesystem_backend.create_folder(
            os.path.join(self._repo_path, filepath)
        )

    def list_folder(self, filepath):
        return self._filesystem_backend.list_folder(
            os.path.join(self._repo_path, filepath)
        )


class GCSBackend(StorageBackendInterface):
    def __init__(self, request):
        self._client = request.find_service(name="gcloud.gcs")
        # NOTE: This needs to be created.
        self._bucket = self._client.get_bucket(request.registry.settings["tuf.bucket"])

    @contextmanager
    def get(self, filepath):
        try:
            contents = self._bucket.blob(filepath).download_as_string()
            yield BytesIO(contents)
        except NotFound as e:
            raise StorageError(f"{filepath} not found")

    def put(self, fileobj, filepath):
        try:
            blob = self._bucket.blob(filepath)
            # NOTE(ww): rewind=True reflects the behavior of the securesystemslib
            # implementation of StorageBackendInterface, which seeks to the file start.
            # I'm not sure it's actually required.
            blob.upload_from_file(fileobj, rewind=True)
        except GoogleCloudError:
            # TODO: expose details of the underlying error in the message here?
            raise StorageError(f"couldn't store to {filepath}")

    def remove(self, filepath):
        try:
            self._bucket.blob(filepath).delete()
        except NotFound:
            raise StorageError(f"{filepath} not found")

    def getsize(self, filepath):
        blob = self._bucket.get_blob(filepath)

        if blob is None:
            raise StorageError(f"{filepath} not found")

        return blob.size

    def create_folder(self, filepath):
        if not filepath:
            return

        if not filepath.endswith("/"):
            filepath = f"{filepath}/"

        try:
            blob = self._bucket.blob(filepath)
            blob.upload_from_string(b"")
        except GoogleCloudError as e:
            raise StorageError(f"couldn't create folder: {filepath}")

    def list_folder(self, filepath):
        if not filepath.endswith("/"):
            filepath = f"{filepath}/"

        # NOTE: The `nextPageToken` appears to be required due to an implementation detail leak.
        # See https://github.com/googleapis/google-cloud-python/issues/7875
        blobs = self._client.list_blobs(
            self._bucket, prefix=filepath, fields="items(name),nextPageToken"
        )
        return [blob.name for blob in blobs]
