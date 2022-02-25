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

import click

from warehouse.cli import warehouse
from warehouse.config import Environment
from warehouse.tuf import utils
from warehouse.tuf.constants import BIN_N_COUNT, Role
from warehouse.tuf.hash_bins import HashBins
from warehouse.tuf.repository import (
    TOP_LEVEL_ROLE_NAMES,
    MetadataRepository,
    RolesPayload,
    TargetsPayload,
)
from warehouse.tuf.tasks import (
    add_target as _add_target,
    bump_bin_ns as _bump_bin_ns,
    bump_snapshot as _bump_snapshot,
)
from warehouse.tuf.utils import set_expiration_for_role


def _make_hash_bins(config):
    if config.registry.settings["warehouse.env"] == Environment.development:
        number_of_bins = 32
    else:
        number_of_bins = BIN_N_COUNT

    return HashBins(number_of_bins)


def _make_backsigned_fileinfo_from_file(file):
    return utils.make_fileinfo(file, custom={"backsigned": True})


def _key_service(config):
    key_service_class = config.maybe_dotted(config.registry.settings["tuf.key_backend"])
    return key_service_class.create_service(None, config)


def _storage_service(config):
    storage_service_class = config.maybe_dotted(
        config.registry.settings["tuf.storage_backend"]
    )
    return storage_service_class.create_service(None, config)


@warehouse.group()  # pragma: no-branch
def tuf():
    """
    Manage Warehouse's TUF state.
    """


@tuf.group()
def dev():
    """
    TUF Development purposes commands
    """


@dev.command()
@click.pass_obj
@click.option("--name", "name_", help="The name of the TUF role for this keypair")
@click.option("--path", "path_", help="The basename of the Ed25519 keypair to generate")
def keypair(config, name_, path_):
    """
    Generate a new TUF keypair, for development purposes.
    """
    utils.create_dev_keys(config.registry.settings[f"tuf.{name_}.secret"], path_)


@dev.command()
@click.pass_obj
def new_repo(config):
    """
    Initialize new TUF repository from scratch, for development purposes.
    """

    key_service = _key_service(config)
    storage_service = _storage_service(config)
    metadata_repository = MetadataRepository(storage_service, key_service)

    if metadata_repository._is_initialized:
        raise click.ClickException("TUF Metadata Repository already initialized.")

    top_roles_payload = dict()
    for role in TOP_LEVEL_ROLE_NAMES:
        top_roles_payload[role] = RolesPayload(
            expiration=set_expiration_for_role(config, role),
            threshold=config.registry.settings[f"tuf.{role}.threshold"],
            keys=key_service.get(role, "private"),
        )

    try:
        metadata_repository.initialize(top_roles_payload, True)
    except (ValueError, FileExistsError) as err:
        raise click.ClickException(str(err))

    if metadata_repository.is_initialized is False:
        raise click.ClickException("TUF Metadata Repository failed to initialized.")


@dev.command()
@click.pass_obj
def add_targets(config):
    """
    Collect the "paths" for every PyPI package. These are packages already in
    existence, so we'll add some additional data to their targets to
    indicate that we're back-signing them.
    """
    from warehouse.db import Session
    from warehouse.packaging.models import File

    key_service = _key_service(config)
    storage_service = _storage_service(config)
    metadata_repository = MetadataRepository(storage_service, key_service)
    hash_bins = _make_hash_bins(config)

    db = Session(bind=config.registry["sqlalchemy.engine"])

    payload = dict()
    for file in db.query(File).all():
        fileinfo = _make_backsigned_fileinfo_from_file(file)
        delegated_role_bin_name = hash_bins.get_delegate(file.path)
        target_file = TargetsPayload(fileinfo, file.path)
        if payload.get(delegated_role_bin_name) is None:
            payload[delegated_role_bin_name] = list()

        payload[delegated_role_bin_name].append(target_file)

    metadata_repository.add_targets(
        payload,
        set_expiration_for_role(config, Role.TIMESTAMP.value),
        set_expiration_for_role(config, Role.SNAPSHOT.value),
    )


@tuf.group()
def admin():
    """
    TUF Administrative commands
    """


@admin.command()
@click.pass_obj
def bump_snapshot(config):
    """
    Bump Snapshot metadata
    """
    request = config.task(_bump_snapshot).get_request()
    config.task(_bump_snapshot).run(request)
    click.echo("Snapshot bump finished.")


@admin.command()
@click.pass_obj
def bump_bin_ns(config):
    """
    Bump BIN-S roles
    """
    request = config.task(_bump_bin_ns).get_request()
    config.task(_bump_bin_ns).run(request)
    click.echo("Hash-bins BIN-S Roles bump finished.")


@admin.command()
@click.pass_obj
def delegate_targets_roles(config):
    """
    Create delegated targets roles (BINS and BIN-N).

    Given an initialized (but empty) TUF repository, create the delegated
    targets role (bins) and its hashed bin delegations (each bin-n).
    """

    key_service = _key_service(config)
    storage_service = _storage_service(config)
    metadata_repository = MetadataRepository(storage_service, key_service)
    hash_bins = _make_hash_bins(config)

    # Delegate first targets -> BINS
    delegate_roles_payload = dict()
    delegate_roles_payload["targets"] = list()
    delegate_roles_payload["targets"].append(
        RolesPayload(
            expiration=set_expiration_for_role(config, Role.BINS.value),
            threshold=config.registry.settings[f"tuf.{Role.BINS.value}.threshold"],
            keys=key_service.get(Role.BINS.value, "private"),
            delegation_role=Role.BINS.value,
            paths=["*/*/*/*"],
        )
    )

    try:
        metadata_repository.delegate_targets_roles(
            delegate_roles_payload,
            set_expiration_for_role(config, Role.TIMESTAMP.value),
            set_expiration_for_role(config, Role.SNAPSHOT.value),
        )
    except FileExistsError as err:
        raise click.ClickException(str(err))

    # Delegates all BINS -> BIN_N (Hash bin prefixes)
    delegate_roles_payload = dict()
    delegate_roles_payload[Role.BINS.value] = list()
    for bin_n_name, bin_n_hash_prefixes in hash_bins.generate():
        delegate_roles_payload[Role.BINS.value].append(
            RolesPayload(
                expiration=set_expiration_for_role(config, Role.BIN_N.value),
                threshold=config.registry.settings[f"tuf.{Role.BIN_N.value}.threshold"],
                keys=key_service.get(Role.BIN_N.value, "private"),
                delegation_role=bin_n_name,
                path_hash_prefixes=bin_n_hash_prefixes,
            )
        )

    try:
        metadata_repository.delegate_targets_roles(
            delegate_roles_payload,
            set_expiration_for_role(config, Role.TIMESTAMP.value),
            set_expiration_for_role(config, Role.SNAPSHOT.value),
        )
    except FileExistsError as err:
        raise click.ClickException(str(err))
