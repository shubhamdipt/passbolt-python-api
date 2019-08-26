import api


if __name__ == '__main__':
    result = list()
    passbolt = api.PassboltAPI(config_path="config.ini")
    passbolt.login()
    for i in passbolt.get_resources()["body"]:
        result.append({
            "id": i["id"],
            "name": i["name"],
            "username": i["username"],
            "uri": i["uri"]
        })
    for i in result:
        i["password"] = passbolt.get_secret(i["id"])
    print(result)
    passbolt.close_session()
