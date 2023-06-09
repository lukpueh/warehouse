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

import requests

from pyramid.httpexceptions import HTTPBadGateway

from warehouse.packaging.models import File
from warehouse.packaging.utils import current_simple_details_path, render_simple_detail

targets_url = lambda request: request.registry.settings["tuf.api.targets.url"]
publish_url = lambda request: request.registry.settings["tuf.api.publish.url"]


def _target_post(path, size, blake2_256_digest):
    return {
        "path": path,
        "info": {
            "length": size,
            "hashes": {"blake2b-256": blake2_256_digest},
        },
    }


def _post_targets(request, targets, publish=True):
    payload = {
        "targets": targets,
        "publish_targets": publish,
    }

    rstuf_response = requests.post(targets_url(request), json=payload)
    if rstuf_response.status_code != 202:
        raise HTTPBadGateway(f"Unexpected TUF Server response: {rstuf_response.text}")

    return rstuf_response.json()


def _delete_targets(request, targets, publish=True):
    payload = {
        "targets": targets,
        "publish_targets": publish,
    }

    rstuf_response = requests.delete(targets_url(request), json=payload)
    if rstuf_response.status_code != 202:
        raise HTTPBadGateway(f"Unexpected TUF Server response: {rstuf_response.text}")

    return rstuf_response.json()


def add(request, project, file=None):
    simple_index = render_simple_detail(project, request, store=True)
    targets = []
    targets.append(_target_post(simple_index[1], simple_index[2], simple_index[0]))
    if file:
        targets.append(_target_post(file.path, file.size, file.blake2_256_digest))

    task = _post_targets(request, targets)

    return task


def delete_file(request, project, file):
    # Delete the file and the current simple index from TUF Metadata
    current_simple_index = current_simple_details_path(request, project)
    targets_to_delete = [file.path, current_simple_index]
    task = _delete_targets(request, targets_to_delete)

    return task


def delete_release(request, release):
    files = request.db.query(File).filter(File.release_id == release.id).all()

    tasks = []
    for file in files:
        tasks.append(delete_file(request, release.project, file))

    return tasks
