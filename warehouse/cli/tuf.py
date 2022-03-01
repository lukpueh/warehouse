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

from securesystemslib.interface import generate_and_write_ed25519_keypair

from warehouse.cli import warehouse
from warehouse.packaging.utils import render_simple_detail
from warehouse.tuf.tasks import (
    add_hashed_targets as _add_hashed_targets,
    bump_bin_n_roles as _bump_bin_n_roles,
    bump_snapshot as _bump_snapshot,
    init_targets_delegation as _init_targets_delegation,
    init_repository as _init_repository,
)


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
    password = config.registry.settings[f"tuf.{name_}.secret"]
    generate_and_write_ed25519_keypair(password, filepath=path_)


@dev.command()
@click.pass_obj
def new_repo(config):
    """
    Initialize new TUF repository from scratch, for development purposes.
    """
    try:
        request = config.task(_init_repository).get_request()
        config.task(_init_repository).run(request)
    except FileExistsError as err:
        raise click.ClickException(str(err))

    click.echo("Repository Initialization finished.")


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
def bump_bin_n_roles(config):
    """
    Bump BIN-N roles
    """
    request = config.task(_bump_bin_n_roles).get_request()
    config.task(_bump_bin_n_roles).run(request)
    click.echo("BIN-N roles (hash bins) bump finished.")


@admin.command()
@click.pass_obj
def delegate_targets_roles(config):
    """
    Create delegated targets roles (BINS and BIN-N).

    Given an initialized (but empty) TUF repository, create the delegated
    targets role (bins) and its hashed bin delegations (each bin-n).
    """
    request = config.task(_init_targets_delegation).get_request()
    try:
        config.task(_init_targets_delegation).run(request)
    except FileExistsError as err:
        raise click.ClickException(str(err))

    click.echo("BINS and BIN-N roles targets delegation finished.")


@admin.command()
@click.pass_obj
def add_all_packages(config):
    """
    Collect the "paths" for every PyPI package. These are packages already in
    existence, so we'll add some additional data to their targets to
    indicate that we're back-signing them.
    """
    from warehouse.db import Session
    from warehouse.packaging.models import File

    request = config.task(_add_hashed_targets).get_request()
    db = Session(bind=request.registry["sqlalchemy.engine"])

    targets = list()
    for file in db.query(File).all():
        hashes = {"blake2b-256": file.blake2_256_digest}
        targetinfo = dict()
        targetinfo["length"] = file.size
        targetinfo["hashes"] = hashes
        targetinfo["custom"] = {"backsigned": True}
        targets.append({"info": targetinfo, "path": file.path})

    config.task(_add_hashed_targets).run(request, targets)
