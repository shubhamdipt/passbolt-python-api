# Passbolt-python-API

It is a python api client for Passbolt.

#### Disclaimer
* This project is a community driven project that is not associated with Passbolt S.A.
* Passbolt and the Passbolt logo are registered trademarks of Passbolt S.A.

## Installation

    $pip install passbolt-python-api 

## Dependencies

  - Python >= 3.6
  - GPG (also known as GnuPG) software

## Configuration

Create a config file with the following contents.

    [PASSBOLT]
    SERVER = http://<server_ip or domain>
    SERVER_PUBLIC_KEY_FILE = <optional: server_public.asc>
    USER_FINGERPRINT = <user_fingerprint>
    USER_PUBLIC_KEY_FILE = <optional: passbolt_public.asc>
    USER_PRIVATE_KEY_FILE = <optional: passbolt_private.asc>
    PASSPHRASE = <passbolt_password>
    SERVER_CERT_AUTH_KEY= <optional: client.pem>
    SERVER_CERT_AUTH_CRT= <optional: client.crt>

Or as a dictionary

    config = {
        "PASSBOLT": {
            "SERVER": "http://<server_ip or domain>"
            ....(same as above)
        }
    }

## Usage


### Import GPG keys from Passbolt

The first step will be to import the private and public keys using gpg for encryption.

Note: Do not keep private and public files. Rather just import them using gpg command one time and delete those files.

#### Using Python
To import new keys using Python:

    >>>import passboltapi
    >>>passbolt = passboltapi.PassboltAPI(config_path="config.ini", new_keys=True)
    
To delete old keys and import only the new ones.

    >>>import passboltapi
    >>>passbolt = passboltapi.PassboltAPI(config_path="config.ini", new_keys=True, delete_old_keys=True)

To use with client certificate authentication use `SERVER_CERT_AUTH_CRT` and `SERVER_CERT_AUTH_KEY` (pem) in config file and:

    >>>import passboltapi
    >>>passbolt = passboltapi.PassboltAPI(config_path="config.ini", cert_auth=True)

#### Using GPG

Import new keys:

    $gpg --import public.asc
    $gpg --batch --import private.asc

Deleting existing keys:

    $gpg --delete-secret-keys <fingerprint>
    $gpg --delete-key <fingerprint>


## How to use PassboltAPI client

    >>>import passboltapi
    >>>passbolt = passboltapi.PassboltAPI(config_path="config.ini")
    # Or pass the configuration settings as a dict
    >>>passbolt = passboltapi.PassboltAPI(config=<dictionary as the given example config.ini>)
    
    # Now you may do any get, post, put and delete request.
    >>>r = passbolt.get(url="/resources.json?api-version=v2")
    >>>r = passbolt.post(self.server_url + url, json=data)
    
    # One can also use it as context manager
    >>>with passboltapi.PassboltAPI(config_path="config.ini") as passbolt:

    # One needs to periodically import the public keys from the passbolt server to their local gpg
    >>>passbolt.import_public_keys("TRUST_FULLY")


To get all resources

    resources = {record.username: record for record in passbolt.list_resources(folder_id=folder_id)}

To create new resource (optional: folder)
    
    response = passbolt.create_resource(
        name=name,
        username=username,
        password=password,
        uri=uri, # optional
        description=description,  # optional
        folder_id=passbolt_folder_id  # optional
    )
    # Note: if you add folder_id, you need to have the public keys of all the users who have access to the foler.
    # This can be easily achieved as follows:
    passbolt.import_public_keys()

To move resource to folder

    passbolt.move_resource_to_folder(resource_id, folder_id)


### Sample test
Check test.py for an example.

If new keys needs to be imported, then USER_PUBLIC_KEY_FILE and USER_PRIVATE_KEY_FILE settings
should be in the config ini having the path of the public and private keys file respectively.


### Passbolt API

For more API related questions, visit Passbolt API documentation:

<https://help.passbolt.com/api>
