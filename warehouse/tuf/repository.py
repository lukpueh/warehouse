from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

from securesystemslib.exceptions import StorageError
from securesystemslib.signer import SSlibSigner
from tuf.api.metadata import (
    SPECIFICATION_VERSION,
    TOP_LEVEL_ROLE_NAMES,
    DelegatedRole,
    Delegations,
    Key,
    Metadata,
    MetaFile,
    Role,
    Root,
    Snapshot,
    StorageBackendInterface,
    TargetFile,
    Targets,
    Timestamp,
)
from tuf.api.serialization.json import JSONSerializer

from warehouse.tuf.constants import Role as RoleWarehouse
from warehouse.tuf.interfaces import IKeyService

SPEC_VERSION = ".".join(SPECIFICATION_VERSION)


@dataclass
class TUFRepositoryFiles:
    filename: str
    data: Metadata


@dataclass
class RolesPayload:
    expiration: datetime
    threshold: int
    keys: List[Dict[str, Any]]
    delegation_role: str = None
    paths: List[str] = None
    path_hash_prefixes: List[str] = None


@dataclass
class TargetsPayload:
    fileinfo: str
    path: str


class MetadataRepository:
    def __init__(
        self,
        storage_backend: StorageBackendInterface,
        key_backend: IKeyService,
    ):
        """
        TUF Metadata Repository Management

        Args:
            storage_backend: Storage Backend
            key_backend: Key Sorage Backend
        """
        self.storage_backend: StorageBackendInterface = storage_backend
        self.key_backend: IKeyService = key_backend
        self._is_initialized: bool = self._check_is_initialized()

    @property
    def is_initialized(self) -> bool:
        """State of repository

        Returns:
            bool
        """
        return self._is_initialized

    def _create_delegated_targets_roles(
        self,
        delegator_metadata: Metadata,
        snapshot_metadata: Optional[Metadata[Snapshot]],
        delegate_role_parameters: List[RolesPayload],
    ) -> Metadata[Snapshot]:
        """
        Creates delegated targets roles based on delegator metadata and a
        list of roles parameters (``RolesPayload``).

        1. Creates the DelegatedRole Object
        2. Adds to the Delegator Metadata Delegations
        3. Generates the new Delegated Role Metadata
        4. Add the keys and signs (using keys from Key backend)
        5. stores it in the repository storage (using the storage backend)

        Args
            delegator_metadata: Delegator Metadata
            snapshot_metadata: Snapshot Metadata
            delegated_role_parameters: List of Roles Parameters

        Returns:
             The updated Snapshot Metadata
             ``tuf.api.metadata.Metadata``
        """
        if not snapshot_metadata:
            snapshot_metadata = self.load_role(Snapshot.Type)

        for role_parameter in delegate_role_parameters:
            rolename = role_parameter.delegation_role
            try:
                if self.load_role(rolename):
                    raise FileExistsError(f"Role {rolename} already exists.")
            except StorageError:
                pass

            delegated_role = DelegatedRole(
                name=rolename,
                keyids=[key["keyid"] for key in role_parameter.keys],
                threshold=role_parameter.threshold,
                terminating=None,
                paths=role_parameter.paths,
                path_hash_prefixes=role_parameter.path_hash_prefixes,
            )

            if delegator_metadata.signed.delegations is None:
                delegation = self._build_delegations(
                    rolename, delegated_role, role_parameter.keys
                )
                delegator_metadata.signed.delegations = delegation
            else:
                delegator_metadata.signed.delegations.roles[rolename] = delegated_role

            targets = Targets(1, SPEC_VERSION, role_parameter.expiration, {}, None)
            role_metadata = Metadata(targets, {})

            for key in role_parameter.keys:
                delegator_metadata.signed.add_key(
                    rolename, Key.from_securesystemslib_key(key)
                )
                role_metadata.sign(SSlibSigner(key), append=True)

            self._store(rolename, role_metadata)
            snapshot_metadata = self.snapshot_update_meta(
                rolename, role_metadata.signed.version, snapshot_metadata
            )

        return snapshot_metadata

    def _check_is_initialized(self) -> None:
        """
        Check if Repository metadata is initialized based on the top-level
        metadata files in the storage backend and update the ``is_initialized``
        state.
        """
        try:
            if any(
                role
                for role in TOP_LEVEL_ROLE_NAMES
                if isinstance(self.load_role(role), Metadata)
            ):
                self._is_initialized = True
        except StorageError:
            pass

    def _filename(self, rolename: str, version: int) -> str:
        """Build the filename based in the role name and version.

        Args:
            rolename: Role name
            version: Role version

        Returns:
             File name
        """
        if rolename == Timestamp.type:
            filename = f"{rolename}.json"
        else:
            filename = f"{version}.{rolename}.json"

        return filename

    def _store(self, rolename: str, metadata: Metadata) -> None:
        """
        Stores (writes) the Metadata to the Storage using the Storage Backend.

        Args:
            rolename: Role name
            metadata: Role Metadata
        """
        filename = self._filename(rolename, metadata.signed.version)
        metadata.to_file(filename, JSONSerializer(), self.storage_backend)

    def _build_delegations(
        self, rolename: str, delegated_role: DelegatedRole, keys: List[Dict[str, Any]]
    ) -> Delegations:
        """
        Builds the Delegations container object storing keys and DelegatedRole
        information.

        Args:
            rolename: Role name
            delegated_role: Delegated Role
            keys: List of Keys Dictionary

        Returns
             The Delegations container object
             ``tuf.api.metadata.Delegations``
        """
        return Delegations(
            keys={key["keyid"]: Key.from_securesystemslib_key(key) for key in keys},
            roles={rolename: delegated_role},
        )

    def initialize(
        self, payload: Dict[str, RolesPayload], store: Optional[bool]
    ) -> Dict[str, Metadata]:
        """
        Initialize the TUF repository from scratch, including a brand new root.

        Args:
            payload: Dictionary of the role name and the role parameters
            store: After initialization stores the metadata files

        Returns:
             Dictionary with key as role name and value as Metadata
             ``Dict[str, Metadata]``
        """

        self._check_is_initialized()

        top_level_roles_metadata = dict()
        if self.is_initialized:
            raise FileExistsError("Metadata already exists in the Storage Service")

        targets = Targets(1, SPEC_VERSION, payload[Targets.type].expiration, {}, None)
        targets_metadata = Metadata(targets, {})
        top_level_roles_metadata[Targets.type] = targets_metadata

        meta = {"targets.json": MetaFile(targets.version)}
        snapshot = Snapshot(1, SPEC_VERSION, payload[Snapshot.type].expiration, meta)
        snapshot_metadata = Metadata(snapshot, {})
        top_level_roles_metadata[Snapshot.type] = snapshot_metadata

        snapshot_meta = MetaFile(snapshot.version)
        timestamp = Timestamp(
            1, SPEC_VERSION, payload[Timestamp.type].expiration, snapshot_meta
        )
        timestamp_metadata = Metadata(timestamp, {})
        top_level_roles_metadata[Timestamp.type] = timestamp_metadata

        roles = {
            role_name: Role([], payload[role_name].threshold)
            for role_name in TOP_LEVEL_ROLE_NAMES
        }
        root = Root(1, SPEC_VERSION, payload[Root.type].expiration, {}, roles, True)

        # Sign all top level roles metadata
        signers = dict()
        for role in TOP_LEVEL_ROLE_NAMES:
            if payload[role].threshold < len(payload[role].keys):
                raise ValueError(
                    f"Role {role} has missing Key(s) "
                    f"to match to defined threshold {payload[role].threshold}."
                )

            for key in payload[role].keys:
                root.add_key(role, Key.from_securesystemslib_key(key))

            signers[role] = {
                key["keyid"]: SSlibSigner(key) for key in payload[role].keys
            }

        root_metadata = Metadata(root, {})
        top_level_roles_metadata[Root.type] = root_metadata
        for role in signers:
            for signer in signers[role].values():
                top_level_roles_metadata[role].sign(signer, append=True)

            if store:
                self._store(role, top_level_roles_metadata[role])

        self._is_initialized = True
        return top_level_roles_metadata

    def load_role(self, rolename: str) -> Metadata:
        """
        Loads a specific metadata by role name.

        Args:
            rolename: Role name

        Returns:
             Role Metadata
             ``tuf.api.metadata.Metadata``
        """
        return Metadata.from_file(rolename, None, self.storage_backend)

    def delegate_targets_roles(
        self,
        payload: Dict[str, List[RolesPayload]],
        timestamp_expires: datetime,
        snapshot_expires: datetime,
    ) -> None:
        """
        Delegates a list of targets roles.
        It will create the new role based in the parameters, sign and store,
        updating the Delegator role, Snapshot and Timestamp roles.

        Args:
            payload: Dictionary of delegators with the delegated role parameters
                     as RolePayload
            timestamp_expires: New Timestamp expiration datetime
            snapshot_expires: New Snapshot expiration datetime
        """

        snapshot_metadata = self.load_role(Snapshot.type)
        for delegator, delegate_role_parameters in payload.items():
            delegator_metadata = self.load_role(delegator)
            snapshot_metadata = self._create_delegated_targets_roles(
                delegator_metadata, snapshot_metadata, delegate_role_parameters
            )
            self.bump_role_version(
                rolename=delegator,
                role_metadata=delegator_metadata,
                role_expires=delegator_metadata.signed.expires,
                snapshot_metadata=snapshot_metadata,
                key_rolename=None,
                store=True,
            )
            snapshot_metadata = self.snapshot_update_meta(
                delegator, delegator_metadata.singed.version, snapshot_metadata
            )

        snapshot_metadata = self.snapshot_bump_version(
            snapshot_expires, snapshot_metadata, True
        )
        self.timestamp_bump_version(
            snapshot_metadata.signed.version, timestamp_expires, True
        )

    def bump_role_version(
        self,
        rolename: str,
        role_metadata: Metadata,
        role_expires: datetime,
        key_rolename: Optional[str] = None,
        store: Optional[bool] = False,
    ) -> None:
        """
        Bump an specific Role Metadata (ex: delegated target role) version,
        optionaly stores it in the repository storage.

        Args:
            rolename: Specific Role name to have the version bumped
            role_metadata: Specific Role Metadata
            role_expires: expiration datetime
            key_rolename: Different signing Key role name
            store: Optional, Default False, stores in the repository storage
        """
        if key_rolename:
            key_rolename = key_rolename
        else:
            key_rolename = rolename
        role_metadata.signed.expires = role_expires
        role_metadata.signed.version += 1
        key_rolename_keys = self.key_backend.get(key_rolename, "private")
        for key in key_rolename_keys:
            role_metadata.sign(SSlibSigner(key), append=True)

        if store:
            self._store(rolename, role_metadata)

    def timestamp_bump_version(
        self,
        snapshot_version: int,
        timestamp_expires: datetime,
        store: bool = False,
    ) -> Metadata[Timestamp]:
        """
        Bump the Timestamp Role Metadata updating the Snapshot version, and
        optionally stores it in the repository storage.

        Args:
            snapshot_version: Snapshot version to be updated on Timestamp role
            timestamp_expires: New Timestamp expiration datetime
            store: Optional, Default False, stores in the repository storage

        Returns:
            Timestamp Metadata
            ``Metadata[Timestamp]``
        """
        timestamp_metadata = self.load_role(Timestamp.type)
        timestamp_metadata.signed.version += 1
        timestamp_metadata.signed.expires = timestamp_expires
        timestamp_metadata.signed.snapshot_meta = MetaFile(version=snapshot_version)
        timestamp_keys = self.key_backend.get(Timestamp.type, "private")
        for key in timestamp_keys:
            timestamp_metadata.sign(SSlibSigner(key), append=True)

        if store:
            self._store(Timestamp.type, timestamp_metadata)

        return timestamp_metadata

    def snapshot_bump_version(
        self,
        snapshot_expires: datetime,
        snapshot_metadata: Optional[Metadata[Snapshot]] = None,
        store: Optional[bool] = False,
    ) -> Metadata[Snapshot]:
        """
        Bump Snapshot Role Metadata version and optionally stores it.

        Args:
            snapshot_expires: New Snapshot expiration datetime
            snapshot_metadata: Optional, specific Snapshot Metadata
            store: Optional, Default False, stores in the repository storage

        Returns:
            Snapshot metadata
            ``Metadata[Snapshot]``
        """
        if snapshot_metadata is None:
            snapshot_metadata = self.load_role(Snapshot.type)

        snapshot_metadata.signed.version += 1
        snapshot_metadata.signed.expires = snapshot_expires
        snapshot_keys = self.key_backend.get(Snapshot.type, "private")
        for key in snapshot_keys:
            snapshot_metadata.sign(SSlibSigner(key), append=True)

        if store is True:
            self._store(Snapshot.type, snapshot_metadata)

        return snapshot_metadata

    def snapshot_update_meta(
        self,
        meta_role_name: str,
        meta_role_version: int,
        snapshot_metadata: Optional[Metadata[Snapshot]] = None,
    ) -> Metadata[Snapshot]:
        """
        Update the Snapshot Metadata Meta.

        Args:
            meta_role_name: role name
            meta_role_version: role version
            snapshot_metadata: Optional, specific Snapshot Metadata

        Return:
            Snapshot metadata with updated Meta
            ``Metadata[Snapshot]``
        """
        if snapshot_metadata is None:
            snapshot_metadata = self.load_role(Snapshot.type)

        snapshot_metadata.signed.meta[f"{meta_role_name}.json"] = MetaFile(
            version=meta_role_version
        )

        return snapshot_metadata

    def add_targets(
        self,
        payload: Dict[str, List[TargetsPayload]],
        timestamp_expires: datetime,
        snapshot_expires: datetime,
    ) -> None:
        """
        Add a list of targets from a payload to the Role Metadata, bumps the
        role Metadata version, stores, bumps Timestamp and
        Snapshot Metadata version and store them.

        Args:
            payload: Dictionary with role names and list of ``TargetPayload``
            timestamp_expires: New Timestamp expiration datetime
            snapshot_expires: New Snapshot expiration datetime
        """
        snapshot_metadata = self.load_role(Snapshot.type)

        for rolename, targets in payload.items():
            role_metadata = self.load_role(rolename)
            for target in targets:
                target_file = TargetFile.from_dict(target.fileinfo, target.path)
                role_metadata.signed.targets[target.path] = target_file

            role_metadata.signed.version += 1
            role_keys = self.key_backend.get(RoleWarehouse.BIN_N.value, "private")
            for key in role_keys:
                role_metadata.sign(SSlibSigner(key), append=True)

            self._store(rolename, role_metadata)
            self.bump_role_version(
                rolename=rolename,
                role_metadata=role_metadata,
                role_expires=role_metadata.signed.expires,
                snapshot_metadata=snapshot_metadata,
                key_rolename=RoleWarehouse.BIN_N.value,
                store=True,
            )
            snapshot_metadata = self.snapshot_update_meta(
                rolename, role_metadata.singed.version, snapshot_metadata
            )

        snapshot_metadata = self.snapshot_bump_version(
            snapshot_expires, snapshot_metadata, True
        )
        self.timestamp_bump_version(
            snapshot_metadata.signed.version, timestamp_expires, True
        )
