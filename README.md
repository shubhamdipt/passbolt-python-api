[![DeepSource](https://deepsource.io/gh/Pitenager/passbolt-python-api.svg/?label=active+issues&show_trend=true)](https://deepsource.io/gh/Pitenager/passbolt-python-api/?ref=repository-badge)
# Passbolt-python-API

## Installation

    $git clone https://github.com/Pitenager/passbolt-python-api.git
    $cd passbolt-python-api.git/
    $pip install passbolt-python-api

## Dependencies

- Python3
- GPG (also known as GnuPG) software

## Configuration

Fill the config.ini file with the following contents.

    [PASSBOLT]
    SERVER = http://<server_ip or domain>
    SERVER_PUBLIC_KEY_FILE = <optional: server_public.asc>
    USER_FINGERPRINT = <user_fingerprint>
    USER_PUBLIC_KEY_FILE = <optional: passbolt_public.asc>
    USER_PRIVATE_KEY_FILE = <optional: passbolt_private.asc>
    PASSPHRASE = <passbolt_password>

## CLI usage

    usage: passbolt_manager.py [-h] [-c CHANGE] [-u UPLOAD] [-d DELETE] [-r READ]

    Client to operate Stratio's Passbolt server

    optional arguments:
        -h, --help                   show this help message and exit
        -c CHANGE, --change CHANGE   Change an existing password in Passbolt
        -u UPLOAD, --upload UPLOAD   Upload new password to Passbolt
        -d DELETE, --delete DELETE   Delete an existing password in Passbolt
        -r READ, --read READ         Read an existing password in Passbolt

## API Usage

    >>>import passboltapi
    >>>passbolt = passboltapi.PassboltAPI(config_path="config.ini")

    # Now you may do any get, post, put and delete request.
    >>>r = passbolt.get(url="/resources.json?api-version=v2")
    >>>r = passbolt.post(self.server_url + url, json=data)

    # One can also use it as context manager
    >>>with passboltapi.PassboltAPI(config_path="config.ini") as passbolt:

Check test.py for an example.

If new keys needs to be imported, then USER_PUBLIC_KEY_FILE and USER_PRIVATE_KEY_FILE settings
should be in the config ini having the path of the public and private keys file respectively.

To import new keys:

    >>>import passboltapi
    >>>passbolt = passboltapi.PassboltAPI(config_path="config.ini", new_keys=True)

To delete old keys and import only the new ones.

    >>>import passboltapi
    >>>passbolt = passboltapi.PassboltAPI(config_path="config.ini", new_keys=True, delete_old_keys=True)

Recommended to do: Do not keep private and public files.
Rather just import them using gpg command one time and delete those files.

    $gpg --import public.asc
    $gpg --batch --import private.asc

### Passbolt API

For more API related questions, visit Passbolt API documentation:

<https://help.passbolt.com/api>
