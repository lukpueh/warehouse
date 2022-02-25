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
import redis

from warehouse.tasks import task
from warehouse.tuf.constants import TUF_REPO_LOCK
from warehouse.tuf.interfaces import IRepositoryService


@task(bind=True, ignore_result=True, acks_late=True)
def bump_snapshot(task, request):
    """
    Re-signs the TUF snapshot role, incrementing its version and renewing its
    expiration period.

    Bumping the snapshot transitively bumps the timestamp role.
    """
    r = redis.StrictRedis.from_url(request.registry.settings["celery.scheduler_url"])

    with r.lock(TUF_REPO_LOCK):
        repository_service = request.find_service(IRepositoryService)
        repository_service.bump_snapshot()


@task(bind=True, ignore_result=True, acks_late=True)
def bump_bin_ns(task, request):
    r = redis.StrictRedis.from_url(request.registry.settings["celery.scheduler_url"])

    with r.lock(TUF_REPO_LOCK):
        repository_service = request.find_service(IRepositoryService)
        repository_service.bump_bins_ns()


@task(bind=True, ignore_result=True, acks_late=True)
def add_target(task, request, filepath, fileinfo, rolename):
    r = redis.StrictRedis.from_url(request.registry.settings["celery.scheduler_url"])

    with r.lock(TUF_REPO_LOCK):
        repository_service = request.find_service(IRepositoryService)
        repository_service.add_target(filepath, fileinfo, rolename)
