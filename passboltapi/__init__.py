import requests
import configparser
import gnupg
import urllib.parse

LOGIN_URL = "/auth/login.json"
VERIFY_URL = "/auth/verify.json"


class PassboltAPI:

    def __init__(self, config_path, delete_old_keys=False):
        """
        :param config_path: Path to the config file.
        :param delete_old_keys: Set true if old keys need to be deleted
        """
        self.requests_session = requests.Session()
        self.config = configparser.ConfigParser()
        self.config.read_file(open(config_path, "r"))

        if not self.config["PASSBOLT"]["SERVER"]:
            raise ValueError("Missing value for SERVER in config.ini")

        self.server_url = self.config["PASSBOLT"]["SERVER"]
        self.gpg = gnupg.GPG()
        if delete_old_keys:
            self._delete_old_keys()
        self._import_gpg_keys()
        self._login()

    def __enter__(self):
        return self

    def __del__(self):
        self.close_session()

    def __exit__(self, exc_type, exc_value, traceback):
        self.close_session()

    def _delete_old_keys(self):
        self.gpg.delete_keys([i["fingerprint"] for i in self.gpg.list_keys()], False)

    def _import_gpg_keys(self):
        if not self.config["PASSBOLT"]["USER_PUBLIC_KEY_FILE"]:
            raise ValueError("Missing value for USER_PUBLIC_KEY_FILE in config.ini")
        if not self.config["PASSBOLT"]["USER_PRIVATE_KEY_FILE"]:
            raise ValueError("Missing value for USER_PRIVATE_KEY_FILE in config.ini")
        self.gpg.import_keys(open(self.config["PASSBOLT"]["USER_PUBLIC_KEY_FILE"], "r").read())
        self.gpg.import_keys(open(self.config["PASSBOLT"]["USER_PRIVATE_KEY_FILE"], "r").read())

    def _login(self):
        r = self.requests_session.post(self.server_url + LOGIN_URL, json={
            "gpg_auth": {"keyid": self.gpg.list_keys()[0]["fingerprint"]}})
        encrypted_token = r.headers["X-GPGAuth-User-Auth-Token"]
        encrypted_token = urllib.parse.unquote(encrypted_token)
        encrypted_token = encrypted_token.replace("\+", " ")
        token = self.decrypt(encrypted_token)
        self.requests_session.post(self.server_url + LOGIN_URL, json={
            "gpg_auth": {
                "keyid": self.gpg.list_keys()[0]["fingerprint"],
                "user_token_result": token
            },
        })

    def encrypt(self, text):
        return str(self.gpg.encrypt(
            data=text,
            recipients=self.gpg.list_keys()[0]["fingerprint"],
            always_trust=True
        ))

    def decrypt(self, text):
        return str(self.gpg.decrypt(
            text,
            always_trust=True,
            passphrase=str(self.config["PASSBOLT"]["PASSPHRASE"])
        ))

    def get_server_public_key(self):
        r = self.requests_session.get(self.server_url + VERIFY_URL)
        return r.json()["body"]["fingerprint"], r.json()["body"]["keydata"]

    def get(self, url):
        r = self.requests_session.get(self.server_url + url)
        return r.json()

    def post(self, url, data):
        r = self.requests_session.post(self.server_url + url, json=data)
        return r.json()

    def put(self, url, data):
        r = self.requests_session.put(self.server_url + url, json=data)
        return r.json()

    def delete(self, url):
        r = self.requests_session.delete(self.server_url + url)
        return r.json()

    def close_session(self):
        self.requests_session.close()



