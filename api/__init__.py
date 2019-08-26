import requests
import configparser
import gnupg
import urllib.parse


CONFIG = configparser.ConfigParser()
CONFIG.read("config.ini")

VERIFY_URL = "/auth/verify.json"
LOGIN_URL = "/auth/login.json"
RESOURCE_URL = "/resources.json?api-version=v2"
SECRET_RESOURCE_ID_URL = "/secrets/resource/{}.json?api-version=v2"


class PassboltAPI:

    def __init__(self, config_path):
        self.config = configparser.ConfigParser()
        self.config.read(config_path)
        self.server_url = self.config["PASSBOLT"]["SERVER"]

        self.gpg = gnupg.GPG(gnupghome="/tmp")
        self.gpg.delete_keys([i["fingerprint"] for i in self.gpg.list_keys()], False)
        self.gpg.import_keys(open(self.config["PASSBOLT"]["USER_PUBLIC_KEY_FILE"], "r").read())
        self.gpg.import_keys(open(self.config["PASSBOLT"]["USER_PRIVATE_KEY_FILE"], "r").read())
        self.requests_session = requests.Session()

    def get_server_public_key(self):
        r = self.requests_session.get(self.server_url + VERIFY_URL)
        return r.json()["body"]["fingerprint"], r.json()["body"]["keydata"]

    def login(self):
        r = self.requests_session.post(self.server_url + LOGIN_URL, json={
            "gpg_auth": {"keyid": self.gpg.list_keys()[0]["fingerprint"]}})
        encrypted_token = r.headers["X-GPGAuth-User-Auth-Token"]
        encrypted_token = urllib.parse.unquote(encrypted_token)
        encrypted_token = encrypted_token.replace("\+", " ")
        token = str(self.gpg.decrypt(encrypted_token, always_trust=True, passphrase=self.config["PASSBOLT"]["PASSPHRASE"]))
        r = self.requests_session.post(self.server_url + LOGIN_URL, json={
            "gpg_auth": {
                "keyid": self.gpg.list_keys()[0]["fingerprint"],
                "user_token_result": token
            },
        })

    def get_resources(self):
        r = self.requests_session.get(self.server_url + RESOURCE_URL)
        return r.json()

    def get_secret(self, resource_id):
        r = self.requests_session.get(self.server_url + SECRET_RESOURCE_ID_URL.format(resource_id))
        data = r.json()["body"]["data"]
        secret = str(self.gpg.decrypt(data, always_trust=True, passphrase=self.config["PASSBOLT"]["PASSPHRASE"]))
        return secret

    def close_session(self):
        self.requests_session.close()



