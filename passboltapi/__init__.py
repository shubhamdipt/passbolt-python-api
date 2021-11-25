import configparser
import urllib.parse
from typing import List, Union, Mapping, Optional

import gnupg
import requests

from passboltapi.schema import (
    constructor,
    PassboltFolderIdType,
    PassboltGroupIdType,
    PassboltUserIdType,
    PassboltResourceTypeIdType,
    PassboltResourceTuple,
    PassboltFolderTuple,
    PassboltOpenPgpKeyTuple,
    PassboltUserTuple,
    PassboltSecretTuple,
    PassboltDateTimeType,
    PassboltRoleIdType,
    PassboltSecretIdType,
    PassboltGroupTuple,
    PassboltResourceIdType,
    PassboltPermissionTuple,
    PassboltPermissionIdType,
    PassboltFavoriteDetailsType,
    PassboltOpenPgpKeyIdType,
    AllPassboltTupleTypes
)

LOGIN_URL = "/auth/login.json"
VERIFY_URL = "/auth/verify.json"


class APIClient:

    def __init__(self, config: Optional[str] = None, config_path: Optional[str] = None, new_keys: bool = False,
                 delete_old_keys: bool = False):
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
            self.gpg_fingerprint = [
                i for i in self.gpg.list_keys() if i["fingerprint"] == self.user_fingerprint
            ][0]["fingerprint"]
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
        r = self.requests_session.post(self.server_url + LOGIN_URL, json={
            "gpg_auth": {"keyid": self.gpg_fingerprint}})
        encrypted_token = r.headers["X-GPGAuth-User-Auth-Token"]
        encrypted_token = urllib.parse.unquote(encrypted_token)
        encrypted_token = encrypted_token.replace("\+", " ")
        token = self.decrypt(encrypted_token)
        self.requests_session.post(self.server_url + LOGIN_URL, json={
            "gpg_auth": {
                "keyid": self.gpg_fingerprint,
                "user_token_result": token
            },
        })
        self._get_csrf_token()

    def _get_csrf_token(self):
        self.get("/users/me.json", return_response_object=True)  # Fetches the X-CSRF-Token header for future requests

    def encrypt(self, text, recipients=None):
        return str(self.gpg.encrypt(
            data=text,
            recipients=recipients or self.gpg_fingerprint,
            always_trust=True
        ))

    def decrypt(self, text):
        return str(self.gpg.decrypt(
            text,
            always_trust=True,
            passphrase=str(self.config["PASSBOLT"]["PASSPHRASE"])
        ))

    def get_headers(self):
        return {"X-CSRF-Token": self.requests_session.cookies[
            'csrfToken'] if 'csrfToken' in self.requests_session.cookies else ''}

    def get_server_public_key(self):
        r = self.requests_session.get(self.server_url + VERIFY_URL)
        return r.json()["body"]["fingerprint"], r.json()["body"]["keydata"]

    def delete(self, url):
        r = self.requests_session.delete(self.server_url + url, headers=self.get_headers())
        return r.json()

    def get(self, url, return_response_object=False, **kwargs):
        r = self.requests_session.get(self.server_url + url, headers=self.get_headers(), **kwargs)
        if return_response_object:
            return r
        return r.json()

    def put(self, url, data, return_response_object=False, **kwargs):
        r = self.requests_session.put(self.server_url + url, json=data, headers=self.get_headers(), **kwargs)
        if return_response_object:
            return r
        return r.json()

    def post(self, url, data, return_response_object=False, **kwargs):
        r = self.requests_session.post(self.server_url + url, json=data, headers=self.get_headers(), **kwargs)
        if return_response_object:
            return r
        return r.json()

    def close_session(self):
        self.requests_session.close()


class PassboltAPI(APIClient):
    """Adding a convenience method for getting resources.

    Design Principle: All passbolt aware public methods must accept or output one of PassboltTupleTypes"""

    def iterate_resources(self, params: Optional[dict] = None):
        params = params or {}
        url_params = urllib.parse.urlencode(params)
        if url_params:
            url_params = "?" + url_params
        response = self.get('/resources.json' + url_params)
        assert "body" in response.keys(), f"Key 'body' not found in response keys: {response.keys()}"
        resources = response["body"]
        for resource in resources:
            yield resource

    def list_resources(self, folder_id: Union[None, PassboltFolderIdType] = None):
        params = {
            **({"filter[has-id][]": folder_id} if folder_id else {}),
            "contain[children_resources]": True,
        }
        url_params = urllib.parse.urlencode(params)
        if url_params:
            url_params = "?" + url_params
        response = self.get('/folders.json' + url_params)
        assert "body" in response.keys(), f"Key 'body' not found in response keys: {response.keys()}"
        response = response["body"][0]
        assert "children_resources" in response.keys(), f"Key 'body[].children_resources' not found in response " \
                                                        f"keys: {response.keys()} "
        return constructor(PassboltResourceTuple)(response["children_resources"])

    def get_secret(self, resource: PassboltResourceTuple) -> PassboltSecretTuple:
        response = self.get(f"/secrets/resource/{resource.id}.json")
        assert "body" in response.keys(), f"Key 'body' not found in response keys: {response.keys()}"
        return PassboltSecretTuple(**response["body"])

    def update_secret(self, resource: PassboltResourceTuple, new_secret):
        return self.put(f"/resources/{resource.id}.json", {
            "secrets": new_secret
        }, return_response_object=True)

    def list_users(self, can_access: Union[None, PassboltResourceTuple, PassboltFolderTuple] = None) \
            -> List[PassboltUserTuple]:
        if can_access is not None:
            params = {"filter[has-access]": can_access.id}
        else:
            params = {}
        response = self.get(f"/users.json", params=params)
        assert "body" in response.keys(), f"Key 'body' not found in response keys: {response.keys()}"

        response["body"]: List[Mapping]

        return constructor(
            PassboltUserTuple,
            subconstructors={"gpgkey": constructor(PassboltOpenPgpKeyTuple)},
        )(response["body"])

    def import_public_keys(self, trustlevel='TRUST_FULLY'):
        # get all users
        users = self.list_users()
        for user in users:
            self.gpg.import_keys(user.gpgkey.armored_key)
            self.gpg.trust_keys(user.gpgkey.fingerprint, trustlevel)

    def describe_folder(self, folder_id):
        return self.get(f"/folders/{folder_id}.json")

    def create_resource(self, name: str, username: str, password: str, uri: Optional[str] = None,
                        description: Optional[str] = None, folder: Optional[str] = None):
        """Creates a new resource on passbolt and shares it with the provided group and folder"""
        r = self.post("/resources.json", {
            "name": name,
            "username": username,
            "description": description or "",
            "uri": uri or "",
            "secrets": [
                {
                    "data": self.encrypt(password)
                }
            ],
            **({"folder_parent_id": folder} if folder else {}),
        }, return_response_object=True)
        r.raise_for_status()
        r_json = r.json()
        new_resource_id = r_json.get("body", {}).get("id")
        if new_resource_id is None:
            raise ValueError(f"Unexpected resource creation: {r_json}")
        if folder:
            self.move_resource_to_folder(new_resource_id, folder)
        return r_json

    def move_resource_to_folder(self, resource_id, folder_id):
        r = self.post(f"/move/resource/{resource_id}.json", {"folder_parent_id": folder_id},
                      return_response_object=True)
        r.raise_for_status()
        return r.json()
