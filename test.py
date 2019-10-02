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


def main():
    # A simple example to show how to retrieve passwords of a user.
    # Note the config file is placed in the project directory.
    passbolt = passboltapi.PassboltAPI(config_path="config.ini")
    get_my_passwords(passbolt_obj=passbolt)
    passbolt.close_session()

    # Or using context managers
    with passboltapi.PassboltAPI(config_path="config.ini") as passbolt:
        get_my_passwords(passbolt_obj=passbolt)


if __name__ == '__main__':
    main()