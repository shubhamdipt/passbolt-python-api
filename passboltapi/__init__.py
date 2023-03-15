import configparser
import json
import logging
import urllib.parse
from typing import List, Mapping, Optional, Tuple, Union

import gnupg
import requests

from passboltapi.schema import (
    AllPassboltTupleTypes,
    PassboltDateTimeType,
    PassboltFavoriteDetailsType,
    PassboltFolderIdType,
    PassboltFolderTuple,
    PassboltGroupIdType,
    PassboltGroupTuple,
    PassboltOpenPgpKeyIdType,
    PassboltOpenPgpKeyTuple,
    PassboltPermissionIdType,
    PassboltPermissionTuple,
    PassboltResourceIdType,
    PassboltResourceTuple,
    PassboltResourceType,
    PassboltResourceTypeIdType,
    PassboltResourceTypeTuple,
    PassboltRoleIdType,
    PassboltSecretIdType,
    PassboltSecretTuple,
    PassboltUserIdType,
    PassboltUserTuple,
    constructor,
)

LOGIN_URL = "/auth/login.json"
VERIFY_URL = "/auth/verify.json"


class PassboltValidationError(Exception):
    pass


class PassboltError(Exception):
    pass


class APIClient:
    def __init__(
        self,
        config: Optional[str] = None,
        config_path: Optional[str] = None,
        new_keys: bool = False,
        delete_old_keys: bool = False,
    ):
        """
        :param config: Config as a dictionary
        :param config_path: Path to the config file.
        :param delete_old_keys: Set true if old keys need to be deleted
        """
        self.config = config
        if config_path:
            self.config = configparser.ConfigParser()
            self.config.read_file(open(config_path, "r"))
        self.requests_session = requests.Session()

        if not self.config:
            raise ValueError("Missing config. Provide config as dictionary or path to configuration file.")
        if not self.config["PASSBOLT"]["SERVER"]:
            raise ValueError("Missing value for SERVER in config.ini")

        self.server_url = self.config["PASSBOLT"]["SERVER"].rstrip("/")
        self.user_fingerprint = self.config["PASSBOLT"]["USER_FINGERPRINT"].upper()
        self.gpg = gnupg.GPG()
        if delete_old_keys:
            self._delete_old_keys()
        if new_keys:
            self._import_gpg_keys()
        try:
            self.gpg_fingerprint = [i for i in self.gpg.list_keys() if i["fingerprint"] == self.user_fingerprint][0][
                "fingerprint"
            ]
        except IndexError:
            raise Exception("GPG public key could not be found. Check: gpg --list-keys")

        if self.user_fingerprint not in [i["fingerprint"] for i in self.gpg.list_keys(True)]:
            raise Exception("GPG private key could not be found. Check: gpg --list-secret-keys")
        self._login()

    def __enter__(self):
        return self

    def __del__(self):
        self.close_session()

    def __exit__(self, exc_type, exc_value, traceback):
        self.close_session()

    def _delete_old_keys(self):
        for i in self.gpg.list_keys():
            self.gpg.delete_keys(i["fingerprint"], True, passphrase="")
            self.gpg.delete_keys(i["fingerprint"], False)

    def _import_gpg_keys(self):
        if not self.config["PASSBOLT"]["USER_PUBLIC_KEY_FILE"]:
            raise ValueError("Missing value for USER_PUBLIC_KEY_FILE in config.ini")
        if not self.config["PASSBOLT"]["USER_PRIVATE_KEY_FILE"]:
            raise ValueError("Missing value for USER_PRIVATE_KEY_FILE in config.ini")
        self.gpg.import_keys(open(self.config["PASSBOLT"]["USER_PUBLIC_KEY_FILE"], "r").read())
        self.gpg.import_keys(open(self.config["PASSBOLT"]["USER_PRIVATE_KEY_FILE"], "r").read())

    def _login(self):
        r = self.requests_session.post(self.server_url + LOGIN_URL, json={"gpg_auth": {"keyid": self.gpg_fingerprint}})
        encrypted_token = r.headers["X-GPGAuth-User-Auth-Token"]
        encrypted_token = urllib.parse.unquote(encrypted_token)
        encrypted_token = encrypted_token.replace("\+", " ")
        token = self.decrypt(encrypted_token)
        self.requests_session.post(
            self.server_url + LOGIN_URL,
            json={
                "gpg_auth": {"keyid": self.gpg_fingerprint, "user_token_result": token},
            },
        )
        self._get_csrf_token()

    def _get_csrf_token(self):
        self.get("/users/me.json", return_response_object=True)  # Fetches the X-CSRF-Token header for future requests

    def encrypt(self, text, recipients=None):
        return str(self.gpg.encrypt(data=text, recipients=recipients or self.gpg_fingerprint, always_trust=True))

    def decrypt(self, text):
        return str(self.gpg.decrypt(text, always_trust=True, passphrase=str(self.config["PASSBOLT"]["PASSPHRASE"])))

    def get_headers(self):
        return {
            "X-CSRF-Token": self.requests_session.cookies["csrfToken"]
            if "csrfToken" in self.requests_session.cookies
            else ""
        }

    def get_server_public_key(self):
        r = self.requests_session.get(self.server_url + VERIFY_URL)
        return r.json()["body"]["fingerprint"], r.json()["body"]["keydata"]

    def delete(self, url):
        r = self.requests_session.delete(self.server_url + url, headers=self.get_headers())
        try:
            r.raise_for_status()
            return r.json()
        except requests.exceptions.HTTPError as e:
            logging.error(r.text)
            raise e

    def get(self, url, return_response_object=False, **kwargs):
        r = self.requests_session.get(self.server_url + url, headers=self.get_headers(), **kwargs)
        try:
            r.raise_for_status()
            if return_response_object:
                return r
            return r.json()
        except requests.exceptions.HTTPError as e:
            logging.error(r.text)
            raise e

    def put(self, url, data, return_response_object=False, **kwargs):
        r = self.requests_session.put(self.server_url + url, json=data, headers=self.get_headers(), **kwargs)
        try:
            r.raise_for_status()
            if return_response_object:
                return r
            return r.json()
        except requests.exceptions.HTTPError as e:
            logging.error(r.text)
            raise e

    def post(self, url, data, return_response_object=False, **kwargs):
        r = self.requests_session.post(self.server_url + url, json=data, headers=self.get_headers(), **kwargs)
        try:
            r.raise_for_status()
            if return_response_object:
                return r
            return r.json()
        except requests.exceptions.HTTPError as e:
            logging.error(r.text)
            raise e

    def close_session(self):
        self.requests_session.close()


class PassboltAPI(APIClient):
    """Adding a convenience method for getting resources.

    Design Principle: All passbolt aware public methods must accept or output one of PassboltTupleTypes"""

    def _json_load_secret(self, secret: PassboltSecretTuple) -> Tuple[str, Optional[str]]:
        try:
            secret_dict = json.loads(self.decrypt(secret.data))
            return secret_dict["password"], secret_dict["description"]
        except (json.decoder.JSONDecodeError, KeyError):
            return self.decrypt(secret.data), None

    def _encrypt_secrets(self, secret_text: str, recipients: List[PassboltUserTuple]) -> List[Mapping]:
        return [
            {"user_id": user.id, "data": self.encrypt(secret_text, user.gpgkey.fingerprint)} for user in recipients
        ]

    def _get_secret(self, resource_id: PassboltResourceIdType) -> PassboltSecretTuple:
        response = self.get(f"/secrets/resource/{resource_id}.json")
        assert "body" in response.keys(), f"Key 'body' not found in response keys: {response.keys()}"
        return PassboltSecretTuple(**response["body"])

    def _update_secret(self, resource_id: PassboltResourceIdType, new_secret):
        return self.put(f"/resources/{resource_id}.json", {"secrets": new_secret}, return_response_object=True)

    def _get_secret_type(self, resource_type_id: PassboltResourceTypeIdType) -> PassboltResourceType:
        resource_type: PassboltResourceTypeTuple = self.read_resource_type(resource_type_id=resource_type_id)
        resource_definition = json.loads(resource_type.definition)
        if resource_definition["secret"]["type"] == "string":
            return PassboltResourceType.PASSWORD
        if resource_definition["secret"]["type"] == "object" and set(
            resource_definition["secret"]["properties"].keys()
        ) == {"password", "description"}:
            return PassboltResourceType.PASSWORD_WITH_DESCRIPTION
        raise PassboltError("The resource type definition is not valid or supported yet. ")

    def get_password_and_description(self, resource_id: PassboltResourceIdType) -> dict:
        resource: PassboltResourceTuple = self.read_resource(resource_id=resource_id)
        secret: PassboltSecretTuple = self._get_secret(resource_id=resource_id)
        secret_type = self._get_secret_type(resource_type_id=resource.resource_type_id)
        if secret_type == PassboltResourceType.PASSWORD:
            return {"password": self.decrypt(secret.data), "description": resource.description}
        elif secret_type == PassboltResourceType.PASSWORD_WITH_DESCRIPTION:
            pwd, desc = self._json_load_secret(secret=secret)
            return {"password": pwd, "description": desc}

    def get_password(self, resource_id: PassboltResourceIdType) -> str:
        return self.get_password_and_description(resource_id=resource_id)["password"]

    def get_description(self, resource_id: PassboltResourceIdType) -> str:
        return self.get_password_and_description(resource_id=resource_id)["description"]

    def iterate_resources(self, params: Optional[dict] = None):
        params = params or {}
        url_params = urllib.parse.urlencode(params)
        if url_params:
            url_params = "?" + url_params
        response = self.get("/resources.json" + url_params)
        assert "body" in response.keys(), f"Key 'body' not found in response keys: {response.keys()}"
        resources = response["body"]
        for resource in resources:
            yield resource

    def list_resources(self, folder_id: Optional[PassboltFolderIdType] = None):
        params = {
            **({"filter[has-id][]": folder_id} if folder_id else {}),
            "contain[children_resources]": True,
        }
        url_params = urllib.parse.urlencode(params)
        if url_params:
            url_params = "?" + url_params
        response = self.get("/folders.json" + url_params)
        assert "body" in response.keys(), f"Key 'body' not found in response keys: {response.keys()}"
        response = response["body"][0]
        assert "children_resources" in response.keys(), (
            f"Key 'body[].children_resources' not found in response " f"keys: {response.keys()} "
        )
        return constructor(PassboltResourceTuple)(response["children_resources"])

    def list_users_with_folder_access(self, folder_id: PassboltFolderIdType) -> List[PassboltUserTuple]:
        folder_tuple = self.describe_folder(folder_id)
        # resolve users
        user_ids = set()
        # resolve users from groups
        for perm in folder_tuple.permissions:
            if perm.aro == "Group":
                group_tuple: PassboltGroupTuple = self.describe_group(perm.aro_foreign_key)
                for group_user in group_tuple.groups_users:
                    user_ids.add(group_user["user_id"])
            elif perm.aro == "User":
                user_ids.add(perm.aro_foreign_key)
        return [user for user in self.list_users() if user.id in user_ids]

    def list_users(
        self, resource_or_folder_id: Union[None, PassboltResourceIdType, PassboltFolderIdType] = None, force_list=True
    ) -> List[PassboltUserTuple]:
        if resource_or_folder_id is None:
            params = {}
        else:
            params = {"filter[has-access]": resource_or_folder_id, "contain[user]": 1}
        params["contain[permission]"] = True
        response = self.get(f"/users.json", params=params)
        assert "body" in response.keys(), f"Key 'body' not found in response keys: {response.keys()}"
        response = response["body"]
        users = constructor(
            PassboltUserTuple,
            subconstructors={
                "gpgkey": constructor(PassboltOpenPgpKeyTuple),
            },
        )(response)
        if isinstance(users, PassboltUserTuple) and force_list:
            return [users]
        return users

    def import_public_keys(self, trustlevel="TRUST_FULLY"):
        # get all users
        users = self.list_users()
        for user in users:
            self.gpg.import_keys(user.gpgkey.armored_key)
            self.gpg.trust_keys(user.gpgkey.fingerprint, trustlevel)

    def read_resource(self, resource_id: PassboltResourceIdType) -> PassboltResourceTuple:
        response = self.get(f"/resources/{resource_id}.json", return_response_object=True)
        response = response.json()["body"]
        return constructor(PassboltResourceTuple)(response)

    def read_resource_type(self, resource_type_id: PassboltResourceTypeIdType) -> PassboltResourceTypeTuple:
        response = self.get(f"/resource-types/{resource_type_id}.json", return_response_object=True)
        response = response.json()["body"]
        return constructor(PassboltResourceTypeTuple)(response)

    def read_folder(self, folder_id: PassboltFolderIdType) -> PassboltFolderTuple:
        response = self.get(
            f"/folders/{folder_id}.json", params={"contain[permissions]": True}, return_response_object=True
        )
        response = response.json()
        return constructor(PassboltFolderTuple, subconstructors={"permissions": constructor(PassboltPermissionTuple)})(
            response["body"]
        )

    def describe_folder(self, folder_id: PassboltFolderIdType):
        """Shows folder details with permissions that are needed for some downstream task."""
        response = self.get(
            f"/folders/{folder_id}.json",
            params={
                "contain[permissions]": 1,
                "contain[permissions.user.profile]": 1,
                "contain[permissions.group]": 1,
            },
        )
        assert "body" in response.keys(), f"Key 'body' not found in response keys: {response.keys()}"
        assert (
            "permissions" in response["body"].keys()
        ), f"Key 'body.permissions' not found in response: {response['body'].keys()}"
        return constructor(
            PassboltFolderTuple,
            subconstructors={
                "permissions": constructor(PassboltPermissionTuple),
            }
        )(response["body"])

    def move_resource_to_folder(self, resource_id: PassboltResourceIdType, folder_id: PassboltFolderIdType):
        r = self.post(
            f"/move/resource/{resource_id}.json", {"folder_parent_id": folder_id}, return_response_object=True
        )
        return r.json()

    def create_resource(
        self,
        name: str,
        password: str,
        username: str = "",
        description: str = "",
        uri: str = "",
        resource_type_id: Optional[PassboltResourceTypeIdType] = None,
        folder_id: Optional[PassboltFolderIdType] = None,
    ):
        """Creates a new resource on passbolt and shares it with the provided folder recipients"""
        if not name:
            raise PassboltValidationError(f"Name cannot be None or empty -- {name}!")
        if not password:
            raise PassboltValidationError(f"Password cannot be None or empty -- {password}!")

        r_create = self.post(
            "/resources.json",
            {
                "name": name,
                "username": username,
                "description": description,
                "uri": uri,
                **({"resource_type_id": resource_type_id} if resource_type_id else {}),
                "secrets": [{"data": self.encrypt(password)}],
            },
            return_response_object=True,
        )
        resource = constructor(PassboltResourceTuple)(r_create.json()["body"])
        if folder_id:
            folder = self.read_folder(folder_id)
            # get users with access to folder
            users_list = self.list_users_with_folder_access(folder_id)
            lookup_users: Mapping[PassboltUserIdType, PassboltUserTuple] = {user.id: user for user in users_list}
            self_user_id = [user.id for user in users_list if self.user_fingerprint == user.gpgkey.fingerprint]
            if self_user_id:
                self_user_id = self_user_id[0]
            else:
                raise ValueError("User not in passbolt")
            # simulate sharing with folder perms
            permissions = [
                {
                    "is_new": True,
                    **{k: v for k, v in perm._asdict().items() if k != "id"},
                }
                for perm in folder.permissions
                if (perm.aro_foreign_key != self_user_id)
            ]
            share_payload = {
                "permissions": permissions,
                "secrets": self._encrypt_secrets(password, lookup_users.values()),
            }
            # simulate sharing with folder perms
            r_simulate = self.post(
                f"/share/simulate/resource/{resource.id}.json", share_payload, return_response_object=True
            )
            r_share = self.put(f"/share/resource/{resource.id}.json", share_payload, return_response_object=True)

            self.move_resource_to_folder(resource_id=resource.id, folder_id=folder_id)
        return resource

    def update_resource(
        self,
        resource_id: PassboltResourceIdType,
        name: Optional[str] = None,
        username: Optional[str] = None,
        description: Optional[str] = None,
        uri: Optional[str] = None,
        resource_type_id: Optional[PassboltResourceTypeIdType] = None,
        password: Optional[str] = None,
    ):
        resource: PassboltResourceTuple = self.read_resource(resource_id=resource_id)
        secret = self._get_secret(resource_id=resource_id)
        secret_type = self._get_secret_type(resource_type_id=resource.resource_type_id)
        resource_type_id = resource_type_id if resource_type_id else resource.resource_type_id
        payload = {
            "name": name,
            "username": username,
            "description": description,
            "uri": uri,
            "resource_type_id": resource_type_id,
        }
        if name is None:
            payload.pop("name")
        if username is None:
            payload.pop("username")
        if description is None:
            payload.pop("description")
        if uri is None:
            payload.pop("uri")

        recipients = self.list_users(resource_or_folder_id=resource_id)
        if secret_type == PassboltResourceType.PASSWORD:
            if password is not None:
                assert isinstance(password, str), f"password has to be a string object -- {password}"
                payload["secrets"] = self._encrypt_secrets(secret_text=password, recipients=recipients)
        elif secret_type == PassboltResourceType.PASSWORD_WITH_DESCRIPTION:
            pwd, desc = self._json_load_secret(secret=secret)
            secret_dict = {}
            if description is not None or password is not None:
                secret_dict["description"] = description if description else desc
                secret_dict["password"] = password if password else pwd
            if secret_dict:
                secret_text = json.dumps(secret_dict)
                payload["secrets"] = self._encrypt_secrets(secret_text=secret_text, recipients=recipients)

        if payload:
            r = self.put(f"/resources/{resource_id}.json", payload, return_response_object=True)
            return r

    def describe_group(self, group_id: PassboltGroupIdType):
        response = self.get(f"/groups/{group_id}.json", params={"contain[groups_users]": 1})
        return constructor(PassboltGroupTuple)(response["body"])
