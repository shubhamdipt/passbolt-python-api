# Library Imports
from typing import List, Union, Mapping, NamedTuple

from typing_extensions import TypeAlias

try:
    from typing import Literal
except ImportError:
    from typing_extensions import Literal

# User-Defined Structs
# > Passbolt types
PassboltFolderIdType: TypeAlias = str
PassboltResourceIdType: TypeAlias = str
PassboltResourceTypeIdType: TypeAlias = str
PassboltUserIdType: TypeAlias = str
PassboltRoleIdType: TypeAlias = str
PassboltOpenPgpKeyIdType: TypeAlias = str
PassboltGroupIdType: TypeAlias = str
PassboltSecretIdType: TypeAlias = str
PassboltPermissionIdType: TypeAlias = str

# refers to the response from passbolt which is a string representation of datetime
PassboltDateTimeType: TypeAlias = str
PassboltFavoriteDetailsType: TypeAlias = dict


class PassboltSecretTuple(NamedTuple):
    id: PassboltSecretIdType
    user_id: PassboltUserIdType
    resource_id: PassboltResourceIdType
    data: str
    created: PassboltDateTimeType
    modified: PassboltDateTimeType


class PassboltPermissionTuple(NamedTuple):
    id: PassboltPermissionIdType
    aco: Literal["User", "Group"]
    aco_foreign_key: Union[PassboltUserIdType, PassboltGroupIdType]
    aro: Literal["Resource", "Folder"]
    aro_foreign_key: Union[PassboltResourceIdType, PassboltFolderIdType]
    type: int


class PassboltOpenPgpKeyTuple(NamedTuple):
    id: PassboltOpenPgpKeyIdType
    armored_key: str
    created: PassboltDateTimeType
    key_created: PassboltDateTimeType
    bits: int
    deleted: bool
    modified: PassboltDateTimeType
    key_id: str
    fingerprint: str
    type: Literal["RSA", "ELG", "DSA", "ECDH", "ECDSA", "EDDSA"]
    expires: PassboltDateTimeType


class PassboltUserTuple(NamedTuple):
    id: PassboltUserIdType
    created: PassboltDateTimeType
    active: bool
    deleted: bool
    modified: PassboltDateTimeType
    username: str
    role_id: PassboltRoleIdType
    profile: dict
    role: dict
    gpgkey: PassboltOpenPgpKeyTuple
    last_logged_in: PassboltDateTimeType


class PassboltResourceTuple(NamedTuple):
    id: PassboltResourceIdType
    created: PassboltDateTimeType
    created_by: PassboltUserIdType
    deleted: bool
    description: str
    modified: PassboltDateTimeType
    modified_by: PassboltUserIdType
    name: str
    uri: str
    username: str
    resource_type_id: PassboltResourceIdType
    folder_parent_id: PassboltFolderIdType
    creator: Union[None, PassboltUserTuple] = None
    favorite: Union[None, PassboltFavoriteDetailsType] = None
    modifier: Union[None, PassboltUserTuple] = None
    permission: Union[PassboltPermissionTuple] = None


class PassboltFolderTuple(NamedTuple):
    id: PassboltFolderIdType
    name: str
    created: PassboltDateTimeType
    modified: PassboltDateTimeType
    created_by: PassboltUserIdType
    modified_by: PassboltUserIdType
    folder_parent_id: PassboltFolderIdType
    personal: bool


class PassboltGroupTuple(NamedTuple):
    id: PassboltGroupIdType
    created: PassboltDateTimeType
    created_by: PassboltUserIdType
    deleted: bool
    modified: PassboltDateTimeType
    modified_by: PassboltUserIdType
    name: str


AllPassboltTupleTypes = Union[
    PassboltSecretTuple,
    PassboltPermissionTuple,
    PassboltResourceTuple,
    PassboltFolderTuple,
    PassboltGroupTuple,
    PassboltUserTuple,
    PassboltOpenPgpKeyTuple
]


def constructor(_namedtuple: AllPassboltTupleTypes,
                renamed_fields: Union[None, dict] = None,
                filter_fields: bool = True,
                subconstructors: Union[None, dict] = None):
    def namedtuple_constructor(data: Union[Mapping, List[Mapping]]) -> List[AllPassboltTupleTypes]:
        """Returns a namedtuple constructor function that can --
            1. Ingest dictionaries or list of dictionaries directly
            2. Renames field names from dict -> namedtuple
            3. Filters out dictionary keys that do not exist in namedtuple
            4. Can apply further constructors to subfields"""
        # 1. ingest datatypes
        if isinstance(data, dict):
            # if single, data is a singleton list
            data = [data]
        elif isinstance(data, list):
            # if list, assert that all elements are dicts
            assert all(map(lambda datum: type(datum) == dict, data)), "All records must be dicts"
        else:
            raise ValueError(f"Data ingested by {_namedtuple} cannot be {type(data)}")

        # TODO: should the listcomps be made lazy?

        # 2. rename fields
        if renamed_fields:
            # make sure that all final fieldnames are present in the namedtuple
            assert not set(renamed_fields.values()).difference(_namedtuple._fields)
            data = [
                {
                    (renamed_fields[k] if k in renamed_fields.keys() else k): v
                    for k, v in datum.items()
                }
                for datum in data
            ]

        # 3. Filter extra fields not present in namedtuple definition
        if filter_fields:
            _ = data[0]
            data = [
                {k: v for k, v in datum.items() if k in _namedtuple._fields}
                for datum in data
            ]

        # 4. [Composition] Apply constructors like this to individual fields
        if subconstructors:
            data = [
                {
                    k: (subconstructors[k](v) if k in subconstructors.keys() else v)
                    for k, v in datum.items()
                    if k in _namedtuple._fields
                }
                for datum in data
            ]
        # handle singleton lists
        if len(data) == 1:
            return _namedtuple(**data[0])
        return [_namedtuple(**datum) for datum in data]

    return namedtuple_constructor
