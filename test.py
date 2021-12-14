import time

import passboltapi


def get_my_passwords(passbolt_obj):
    result = list()
    for i in passbolt_obj.get(url="/resources.json?api-version=v2")["body"]:
        result.append({
            "id": i["id"],
            "name": i["name"],
            "username": i["username"],
            "uri": i["uri"]
        })
        print(i)
    for i in result:
        resource = passbolt_obj.get(
            "/secrets/resource/{}.json?api-version=v2".format(i["id"]))
        i["password"] = passbolt_obj.decrypt(resource["body"]["data"])
    print(result)


def get_passwords_basic():
    # A simple example to show how to retrieve passwords of a user.
    # Note the config file is placed in the project directory.
    passbolt_obj = passboltapi.PassboltAPI(config_path="config.ini")
    result = list()
    for i in passbolt_obj.get(url="/resources.json?api-version=v2")["body"]:
        result.append({
            "id": i["id"],
            "name": i["name"],
            "username": i["username"],
            "uri": i["uri"]
        })
        print(i)
    for i in result:
        resource = passbolt_obj.get(
            "/secrets/resource/{}.json?api-version=v2".format(i["id"]))
        i["password"] = passbolt_obj.decrypt(resource["body"]["data"])
    print(result)
    passbolt_obj.close_session()

    # Or using context managers
    # with passboltapi.PassboltAPI(config_path="config.ini") as passbolt:
    #     get passwords....


if __name__ == '__main__':
    folder_id = "1d932dc0-d0a3-4a44-80c7-4701f84dc307"
    with passboltapi.PassboltAPI(config_path="config.ini") as passbolt:
        # required: passbolt.import_public_keys() when the folder has more users.
        print(passbolt.create_resource(
            name='Sample Name',
            username='Sample username',
            password='password_test',
            uri='https://www.passbolt_uri.com',
            folder_id=folder_id
        ))
