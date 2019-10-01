# Passbolt-python-API

## Installation

    $pip install passbolt-python-api 

## Dependencies

  - Python3
  - GPG (also known as GnuPG) software

## Configuration

Create a config file with the following contents.

    [PASSBOLT]
    SERVER = http://<server_ip or domain>
    SERVER_PUBLIC_KEY_FILE = <optional: server_public.asc>
    USER_FINGERPRINT = <user_fingerprint>
    USER_PUBLIC_KEY_FILE = passbolt_public.asc
    USER_PRIVATE_KEY_FILE = passbolt_private.asc
    PASSPHRASE = <passbolt_password>

## Usage

    >>>import passboltapi
    >>>passbolt = passboltapi.PassboltAPI(config_path="config.ini")
    
    # Now you may do any get, post, put and delete request.
    >>>r = passbolt.get(url="/resources.json?api-version=v2")
    >>>r = passbolt.post(self.server_url + url, json=data)
    
    # One can also use it as context manager
    >>>with passboltapi.PassboltAPI(config_path="config.ini") as passbolt:

Check test.py for an example.

### Passbolt API

For more API related questions, visit Passbolt API documentation:

<https://help.passbolt.com/api>
