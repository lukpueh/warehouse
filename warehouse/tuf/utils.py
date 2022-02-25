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
