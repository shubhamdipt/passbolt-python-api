# Passbolt-python-API

## Dependencies

* Python3
* GPG (also known as GnuPG) software


## Create a config file with the following contents.

```
[PASSBOLT]
SERVER = http://<server_ip or domain>
SERVER_PUBLIC_KEY_FILE = <optional: server_public.asc>
USER_PUBLIC_KEY_FILE = passbolt_public.asc
USER_PRIVATE_KEY_FILE = passbolt_private.asc
PASSPHRASE = <passbolt_password>
```

Check test.py for examples.